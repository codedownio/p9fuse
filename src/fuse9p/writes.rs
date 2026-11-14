//! Open handles and the write pipelines behind them.

use super::write_pipeline::{InodeWrites, WriteError};
use super::{FileHandle, Fuse9p};
use std::sync::Arc;

impl Fuse9p {
    /// The flags to open a file's fid with, given the kernel's `flags`, and whether writes through
    /// it go through the write pipeline.
    pub(super) fn open_flags(&self, flags: i32) -> (u32, bool) {
        let mut oflags = (flags as u32) & !(libc::O_CLOEXEC as u32);
        let access = oflags & libc::O_ACCMODE as u32;
        let append = oflags & libc::O_APPEND as u32 != 0;
        if self.tuning.writeback_cache {
            // The kernel reads pages back through write-only handles to fill partial pages, so
            // those must be readable. It also decides where appends go and may write any dirty
            // page through any handle, so the server must use our offsets: no O_APPEND.
            if access == libc::O_WRONLY as u32 {
                oflags = (oflags & !(libc::O_ACCMODE as u32)) | libc::O_RDWR as u32;
            }
            oflags &= !(libc::O_APPEND as u32);
        }
        // Without the cache the server appends on an O_APPEND fid and ignores our offsets, so two
        // appends in flight could land in either order: those handles write synchronously.
        let writable = access != libc::O_RDONLY as u32;
        let pipelined =
            writable && self.tuning.write_pipeline && (self.tuning.writeback_cache || !append);
        (oflags, pipelined)
    }

    /// Register an opened fid as a new handle on `ino` and return its number.
    pub(super) fn insert_handle(&mut self, fid: u32, ino: u64, pipelined: bool) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        let write_error = pipelined.then(|| {
            let (client, chunk, depth) = (
                self.client.clone(),
                self.io_chunk() as usize,
                self.tuning.wb_depth,
            );
            self.writes
                .entry(ino)
                .or_insert_with(|| InodeWrites::new(client, chunk, depth));
            WriteError::default()
        });
        self.handles.insert(
            fh,
            FileHandle {
                fid,
                ino,
                write_error,
            },
        );
        fh
    }

    /// Close handle `fh`: finish its pending writes, release its fid, and drop its inode's write
    /// pipeline with the last handle that used it. Returns the first unreported write error.
    pub(super) fn close_handle(&mut self, fh: u64) -> Option<i32> {
        let h = self.handles.remove(&fh)?;
        let err = self.take_write_error(&h);
        self.clunk(h.fid);
        let pipelined = |o: &FileHandle| o.ino == h.ino && o.write_error.is_some();
        if h.write_error.is_some() && !self.handles.values().any(pipelined) {
            self.writes.remove(&h.ino);
        }
        err
    }

    /// The most bytes one `Twrite` or `Tread` carries: the msize less the message header.
    pub(super) fn io_chunk(&self) -> u32 {
        self.client.msize.saturating_sub(24)
    }

    /// Wait until the pipelined writes to `ino` (or to every file, for `None`) have reached the
    /// server. Without the writeback cache the kernel takes sizes and contents from us, so anything
    /// that reports them, and any synchronous write or truncate, has to come after those writes.
    pub(super) fn settle_writes(&self, ino: Option<u64>) {
        let pipelines: Vec<Arc<InodeWrites>> = match ino {
            Some(ino) => self.writes.get(&ino).cloned().into_iter().collect(),
            None => self.writes.values().cloned().collect(),
        };
        let busy: Vec<_> = pipelines.into_iter().filter(|w| w.busy()).collect();
        if !busy.is_empty() {
            self.rt.block_on(async {
                for w in busy {
                    w.settle().await;
                }
            });
        }
    }

    /// Settle the writes to the handle's file and take the first error a write through the handle
    /// has hit since the last call.
    pub(super) fn take_write_error(&self, h: &FileHandle) -> Option<i32> {
        let err = h.write_error.as_ref()?;
        self.settle_writes(Some(h.ino));
        err.lock().unwrap().take()
    }
}
