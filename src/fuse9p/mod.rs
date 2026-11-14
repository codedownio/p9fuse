//! `mount9p-fuse`: a FUSE filesystem that speaks 9p2000.L to a server through a [`NineClient`].
//! Unlike the kernel's v9fs client it mounts without privilege (through `fusermount3`), and
//! 9p2000.L still carries full POSIX metadata.
//!
//! The FUSE session calls into [`Fuse9p`] from one thread, so its tables need no locks; each
//! callback waits for its 9p requests with `block_on`.
//!
//! - `filesystem`: the FUSE callbacks.
//! - `mount`: connecting and running the FUSE session.
//! - `invalidate`: dropping paths changed outside the mount from the kernel's caches.
//! - `writes` and `write_pipeline`: open handles, and writes sent in the background.
//! - `attr`: converting 9p attributes to FUSE ones.

mod attr;
mod filesystem;
mod invalidate;
mod mount;
mod tuning;
mod write_pipeline;
mod writes;

pub use tuning::Tuning;

use crate::client::NineClient;
use crate::ninep::{Attr, Qid};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::runtime::Handle;
use write_pipeline::{InodeWrites, WriteError};

const ROOT_INO: u64 = 1;

/// Answer the FUSE request `reply` with the errno in `result` and return, or unwrap its value.
macro_rules! or_reply {
    ($reply:ident, $result:expr) => {
        match $result {
            Ok(v) => v,
            Err(e) => return $reply.error(e),
        }
    };
}
use or_reply;

pub struct Fuse9p {
    client: Arc<NineClient>,
    rt: Handle,
    tuning: Tuning,
    /// Inodes the kernel holds lookup references to.
    inodes: HashMap<u64, Inode>,
    /// The export root's qid path, which is FUSE inode 1 rather than itself. See `qid_to_ino`.
    root_qid_path: u64,
    /// Open files and directories, by FUSE handle number.
    handles: HashMap<u64, FileHandle>,
    next_fh: u64,
    /// The write pipeline of each inode open through a pipelined handle.
    writes: HashMap<u64, Arc<InodeWrites>>,
}

struct Inode {
    /// A fid walked to the file but not opened, used for getattr/setattr and to walk or open from.
    fid: u32,
    lookups: u64,
}

struct FileHandle {
    /// The opened fid.
    fid: u32,
    ino: u64,
    /// For a handle that writes through the pipeline: the first error one of its writes hit.
    write_error: Option<WriteError>,
}

/// The FUSE inode number of a file: its qid path, except that the export root must be inode 1.
/// Because it is the qid path, a fresh walk is enough to find a path's inode.
fn qid_to_ino(qid_path: u64, root_qid_path: u64) -> u64 {
    if qid_path == root_qid_path {
        ROOT_INO
    } else {
        qid_path
    }
}

impl Fuse9p {
    fn ino(&self, qid: &Qid) -> u64 {
        qid_to_ino(qid.path, self.root_qid_path)
    }

    /// The fid of an inode the kernel looked up.
    fn fid_of(&self, ino: u64) -> Result<u32, i32> {
        self.inodes.get(&ino).map(|i| i.fid).ok_or(libc::ENOENT)
    }

    fn handle(&self, fh: u64) -> Result<&FileHandle, i32> {
        self.handles.get(&fh).ok_or(libc::EBADF)
    }

    fn clunk(&self, fid: u32) {
        let _ = self.rt.block_on(self.client.clunk(fid));
    }

    /// Walk a new fid from `from` through `names` (none: a copy of `from`). The fid only exists if
    /// this succeeds.
    fn walk(&self, from: u32, names: &[&str]) -> Result<(u32, Vec<Qid>), i32> {
        let fid = self.client.alloc_fid();
        let qids = self.rt.block_on(self.client.walk(from, fid, names))?;
        Ok((fid, qids))
    }

    /// Get `fid`'s attributes, releasing the fid if that fails.
    fn getattr_or_clunk(&self, fid: u32) -> Result<Attr, i32> {
        self.rt
            .block_on(self.client.getattr(fid))
            .inspect_err(|_| self.clunk(fid))
    }

    /// Walk to entry `name` of directory `parent` and get its attributes.
    fn walk_attr(&self, parent: u32, name: &str) -> Result<(u32, Attr), i32> {
        let (fid, _) = self.walk(parent, &[name])?;
        Ok((fid, self.getattr_or_clunk(fid)?))
    }

    /// Open a copy of `base` with `flags`.
    fn open_fid(&self, base: u32, flags: u32) -> Result<u32, i32> {
        let (fid, _) = self.walk(base, &[])?;
        match self.rt.block_on(self.client.lopen(fid, flags)) {
            Ok(_) => Ok(fid),
            Err(e) => {
                self.clunk(fid);
                Err(e)
            }
        }
    }

    /// Count a lookup reference the kernel now holds to `ino`, which we reached through `fid`. A new
    /// inode keeps `fid`; a known one already has a fid, so `fid` is released.
    fn add_lookup(&mut self, ino: u64, fid: u32) {
        match self.inodes.get_mut(&ino) {
            Some(inode) => inode.lookups += 1,
            None => {
                self.inodes.insert(ino, Inode { fid, lookups: 1 });
                return;
            }
        }
        self.clunk(fid);
    }
}
