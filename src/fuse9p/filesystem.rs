//! The FUSE callbacks.

use super::attr::{dirent_attr, kind_from_qid, negative_attr, time_or_now, to_fileattr};
use super::write_pipeline::{write_all, Write};
use super::{or_reply, Fuse9p, ROOT_INO};
use crate::client::NineClient;
use crate::ninep::{
    Attr, SETATTR_ATIME, SETATTR_ATIME_SET, SETATTR_GID, SETATTR_MODE, SETATTR_MTIME,
    SETATTR_MTIME_SET, SETATTR_SIZE, SETATTR_UID,
};
use fuser::{
    FileAttr, Filesystem, KernelConfig, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request,
    TimeOrNow,
};
use std::ffi::OsStr;
use std::path::Path;
use std::time::SystemTime;

// Capability flags fuser doesn't export.
const FUSE_DO_READDIRPLUS: u32 = 1 << 13;
const FUSE_READDIRPLUS_AUTO: u32 = 1 << 14;
const FUSE_WRITEBACK_CACHE: u32 = 1 << 16;

/// How many bytes of directory entries to ask the server for at a time.
const READDIR_BYTES: u32 = 8192;

impl Filesystem for Fuse9p {
    fn init(&mut self, _req: &Request<'_>, config: &mut KernelConfig) -> Result<(), libc::c_int> {
        // Let reads and writes be as large as a 9p message allows, rather than 128 KiB.
        let max = self.client.msize.saturating_sub(64).max(8192);
        let _ = config.set_max_write(max);
        let _ = config.set_max_readahead(max);
        if self.tuning.writeback_cache {
            let _ = config.add_capabilities(FUSE_WRITEBACK_CACHE);
        }
        if self.tuning.readdirplus {
            let _ = config.add_capabilities(FUSE_DO_READDIRPLUS | FUSE_READDIRPLUS_AUTO);
        }
        Ok(())
    }

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let parent_fid = or_reply!(reply, self.fid_of(parent));
        let name = name.to_string_lossy();
        let found = self.walk(parent_fid, &[&name]).and_then(|(fid, qids)| {
            // The size we report must include writes we have acknowledged but not sent yet.
            if let Some(qid) = qids.last() {
                self.settle_writes(Some(self.ino(qid)));
            }
            Ok((fid, self.getattr_or_clunk(fid)?))
        });
        match (found, self.tuning.negative_ttl) {
            (Ok((fid, attr)), _) => {
                let (attr, generation) = self.add_entry(parent, &name, fid, &attr);
                reply.entry(&self.tuning.entry_ttl, &attr, generation);
            }
            (Err(libc::ENOENT), Some(ttl)) => reply.entry(&ttl, &negative_attr(), 0),
            (Err(e), _) => reply.error(e),
        }
    }

    fn forget(&mut self, _req: &Request<'_>, ino: u64, nlookup: u64) {
        if ino != ROOT_INO {
            self.forget_lookups(ino, nlookup);
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        let fid = or_reply!(reply, self.fid_of(ino));
        self.settle_writes(Some(ino));
        let attr = or_reply!(reply, self.rt.block_on(self.client.getattr(fid)));
        reply.attr(&self.tuning.attr_ttl, &to_fileattr(ino, &attr));
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let fid = or_reply!(reply, self.fid_of(ino));
        let specific = |t: Option<TimeOrNow>| matches!(t, Some(TimeOrNow::SpecificTime(_)));
        let valid = [
            (mode.is_some(), SETATTR_MODE),
            (uid.is_some(), SETATTR_UID),
            (gid.is_some(), SETATTR_GID),
            (size.is_some(), SETATTR_SIZE),
            (atime.is_some(), SETATTR_ATIME),
            (specific(atime), SETATTR_ATIME_SET),
            (mtime.is_some(), SETATTR_MTIME),
            (specific(mtime), SETATTR_MTIME_SET),
        ]
        .into_iter()
        .filter(|&(set, _)| set)
        .fold(0, |valid, (_, bit)| valid | bit);
        // A truncate must come after earlier writes, and the size we report must include them.
        self.settle_writes(Some(ino));
        let attr = self.rt.block_on(async {
            self.client
                .setattr(
                    fid,
                    valid,
                    mode.unwrap_or(0) & 0o7777,
                    uid.unwrap_or(0),
                    gid.unwrap_or(0),
                    size.unwrap_or(0),
                    atime.map_or((0, 0), time_or_now),
                    mtime.map_or((0, 0), time_or_now),
                )
                .await?;
            self.client.getattr(fid).await
        });
        let attr = or_reply!(reply, attr);
        reply.attr(&self.tuning.attr_ttl, &to_fileattr(ino, &attr));
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let base = or_reply!(reply, self.fid_of(ino));
        let (oflags, pipelined) = self.open_flags(flags);
        if oflags & libc::O_TRUNC as u32 != 0 {
            // The server truncates on open, which must come after writes already queued.
            self.settle_writes(Some(ino));
        }
        let fid = or_reply!(reply, self.open_fid(base, oflags));
        let fh = self.insert_handle(fid, ino, pipelined);
        reply.opened(fh, 0);
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        let fid = or_reply!(reply, self.handle(fh)).fid;
        self.settle_writes(Some(ino));
        let offset = or_reply!(reply, file_offset(offset));
        let size = size.min(self.io_chunk());
        let data = read_full(&self.client, fid, offset, size);
        let data = or_reply!(reply, self.rt.block_on(data));
        reply.data(&data);
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyWrite,
    ) {
        let offset = or_reply!(reply, file_offset(offset));
        let len = or_reply!(reply, u32::try_from(data.len()).map_err(|_| libc::EINVAL));
        let h = or_reply!(reply, self.handle(fh));
        let (fid, ino, err) = (h.fid, h.ino, h.write_error.clone());
        match (err, self.writes.get(&ino).cloned()) {
            (Some(err), Some(pipeline)) => {
                let w = Write {
                    fid,
                    off: offset,
                    data: data.to_vec(),
                    err,
                };
                self.rt.block_on(pipeline.write(w));
            }
            _ => {
                // After the pipelined writes to the same file.
                self.settle_writes(Some(ino));
                let chunk = self.io_chunk() as usize;
                let written = write_all(&self.client, fid, offset, data, chunk);
                or_reply!(reply, self.rt.block_on(written));
            }
        }
        reply.written(len);
    }

    fn flush(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, _lock: u64, reply: ReplyEmpty) {
        // Called on every close(2), which is where a write error should show up.
        match self.handles.get(&fh).and_then(|h| self.take_write_error(h)) {
            Some(e) => reply.error(e),
            None => reply.ok(),
        }
    }

    fn fsync(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        let Ok(h) = self.handle(fh) else {
            return reply.ok();
        };
        let fid = h.fid;
        if let Some(e) = self.take_write_error(h) {
            return reply.error(e);
        }
        or_reply!(reply, self.rt.block_on(self.client.fsync(fid)));
        reply.ok();
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        match self.close_handle(fh) {
            Some(e) => reply.error(e),
            None => reply.ok(),
        }
        self.count_handles();
    }

    fn create(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let parent_fid = or_reply!(reply, self.fid_of(parent));
        let name = name.to_string_lossy();
        let (oflags, pipelined) = self.open_flags(flags);
        // Creating through a copy of the parent's fid leaves that fid open on the new file. The
        // inode gets its own unopened fid, as from a lookup.
        let created = self.walk(parent_fid, &[]).and_then(|(open_fid, _)| {
            let create = self
                .client
                .lcreate(open_fid, &name, oflags, mode & 0o7777, req.gid());
            let entry = self
                .rt
                .block_on(create)
                .and_then(|_| self.walk_attr(parent_fid, &name))
                .inspect_err(|_| self.clunk(open_fid))?;
            Ok((open_fid, entry))
        });
        let (open_fid, (fid, attr)) = or_reply!(reply, created);
        let (attr, generation) = self.add_entry(parent, &name, fid, &attr);
        let fh = self.insert_handle(open_fid, attr.ino, pipelined);
        reply.created(&self.tuning.entry_ttl, &attr, generation, fh, 0);
    }

    fn opendir(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        let base = or_reply!(reply, self.fid_of(ino));
        let fid = or_reply!(reply, self.open_fid(base, libc::O_RDONLY as u32));
        let fh = self.insert_handle(fid, ino, false);
        reply.opened(fh, 0);
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let fid = or_reply!(reply, self.handle(fh)).fid;
        let entries = self
            .client
            .readdir(fid, offset.cast_unsigned(), READDIR_BYTES);
        for e in or_reply!(reply, self.rt.block_on(entries)) {
            // An entry's offset is where to continue after it. `add` is true once the buffer is full.
            if reply.add(
                self.ino(&e.qid),
                e.offset.cast_signed(),
                kind_from_qid(e.qid.typ),
                &e.name,
            ) {
                break;
            }
        }
        reply.ok();
    }

    /// `readdir` that also returns each entry's attributes. Only used with `Tuning::readdirplus`.
    fn readdirplus(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        mut reply: ReplyDirectoryPlus,
    ) {
        let open_fid = or_reply!(reply, self.handle(fh)).fid;
        let dir_fid = or_reply!(reply, self.fid_of(ino));
        let entries = self
            .client
            .readdir(open_fid, offset.cast_unsigned(), READDIR_BYTES);
        let entries = or_reply!(reply, self.rt.block_on(entries));
        // The sizes must include writes we have acknowledged but not sent yet.
        self.settle_writes(None);
        let client = &self.client;
        let walks = entries.iter().map(|e| async move {
            if is_dot(&e.name) {
                None
            } else {
                walk_attr(client, dir_fid, &e.name).await
            }
        });
        let found = self.rt.block_on(futures_util::future::join_all(walks));

        let mut full = false;
        let ttl = self.tuning.entry_ttl;
        for (e, found) in entries.iter().zip(found) {
            // `add` is true once the buffer is full; the kernel only takes a lookup reference to
            // entries that fit. From "." and ".." it takes only the inode number and type, so
            // they aren't walked.
            if is_dot(&e.name) {
                let ino = self.ino(&e.qid);
                let attr = dirent_attr(ino, kind_from_qid(e.qid.typ));
                full = full || reply.add(ino, e.offset.cast_signed(), &e.name, &ttl, &attr, 0);
                continue;
            }
            let Some((fid, attr)) = found else {
                continue;
            };
            if full {
                self.clunk(fid);
                continue;
            }
            let entry_ino = self.ino(&attr.qid);
            let attr = to_fileattr(entry_ino, &attr);
            let generation = self.add_lookup(ino, &e.name, entry_ino, fid);
            full = reply.add(
                entry_ino,
                e.offset.cast_signed(),
                &e.name,
                &ttl,
                &attr,
                generation,
            );
            if full {
                self.forget_lookups(entry_ino, 1);
            }
        }
        reply.ok();
    }

    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        self.close_handle(fh);
        reply.ok();
        self.count_handles();
    }

    fn mkdir(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let parent_fid = or_reply!(reply, self.fid_of(parent));
        let name = name.to_string_lossy();
        let made = self
            .client
            .mkdir(parent_fid, &name, mode & 0o7777, req.gid());
        or_reply!(reply, self.rt.block_on(made));
        self.reply_new_entry(parent, parent_fid, &name, reply);
    }

    fn symlink(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let parent_fid = or_reply!(reply, self.fid_of(parent));
        let name = name.to_string_lossy();
        let target = target.to_string_lossy();
        let made = self.client.symlink(parent_fid, &name, &target, req.gid());
        or_reply!(reply, self.rt.block_on(made));
        self.reply_new_entry(parent, parent_fid, &name, reply);
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let fid = or_reply!(reply, self.fid_of(ino));
        let target = or_reply!(reply, self.rt.block_on(self.client.readlink(fid)));
        reply.data(target.as_bytes());
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        self.remove(parent, name, 0, reply);
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        self.remove(parent, name, libc::AT_REMOVEDIR as u32, reply);
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let from = or_reply!(reply, self.fid_of(parent));
        let to = or_reply!(reply, self.fid_of(newparent));
        let (name, newname) = (name.to_string_lossy(), newname.to_string_lossy());
        let renamed = self.client.renameat(from, &name, to, &newname);
        or_reply!(reply, self.rt.block_on(renamed));

        // diod ties a fid to a path, so the moved file's fid now fails with ENOENT, and the kernel
        // goes on using the inode without looking it up again. Give it a fid at the new path.
        if let Ok((fresh, qids)) = self.walk(to, &[&newname]) {
            match qids.last().map(|qid| self.ino(qid)) {
                Some(ino) => self.replace_fid(ino, fresh, newparent, &newname),
                None => self.clunk(fresh),
            }
        }
        reply.ok();
    }

    fn statfs(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyStatfs) {
        let fid = self.fid_of(ino).unwrap_or(self.client.root_fid);
        let stats = or_reply!(reply, self.rt.block_on(self.client.statfs(fid)));
        let (bsize, blocks, bfree, bavail, files, ffree, namelen) = stats;
        reply.statfs(blocks, bfree, bavail, files, ffree, bsize, namelen, bsize);
    }
}

impl Fuse9p {
    /// Record an entry the kernel now holds a lookup reference to, reached through `fid` as `name`
    /// in directory `parent`: its attributes and the generation to report with them.
    fn add_entry(&mut self, parent: u64, name: &str, fid: u32, attr: &Attr) -> (FileAttr, u64) {
        let ino = self.ino(&attr.qid);
        let generation = self.add_lookup(parent, name, ino, fid);
        (to_fileattr(ino, attr), generation)
    }

    /// Answer a mkdir or symlink with the entry it just made in `parent`.
    fn reply_new_entry(&mut self, parent: u64, parent_fid: u32, name: &str, reply: ReplyEntry) {
        let (fid, attr) = or_reply!(reply, self.walk_attr(parent_fid, name));
        let (attr, generation) = self.add_entry(parent, name, fid, &attr);
        reply.entry(&self.tuning.entry_ttl, &attr, generation);
    }

    fn remove(&mut self, parent: u64, name: &OsStr, flags: u32, reply: ReplyEmpty) {
        let parent_fid = or_reply!(reply, self.fid_of(parent));
        let name = name.to_string_lossy();
        let removed = self.client.unlinkat(parent_fid, &name, flags);
        or_reply!(reply, self.rt.block_on(removed));
        reply.ok();
    }
}

/// Whether a directory entry is "." or "..".
fn is_dot(name: &str) -> bool {
    name == "." || name == ".."
}

/// Walk a new fid to entry `name` of `dir` and get its attributes.
async fn walk_attr(client: &NineClient, dir: u32, name: &str) -> Option<(u32, Attr)> {
    let fid = client.alloc_fid();
    client.walk(dir, fid, &[name]).await.ok()?;
    match client.getattr(fid).await {
        Ok(attr) => Some((fid, attr)),
        Err(_) => {
            let _ = client.clunk(fid).await;
            None
        }
    }
}

/// Read up to `size` bytes at `off`. A server may return fewer bytes than asked for before the end
/// of the file; only an empty reply means the end. Passing a short reply on would look like a short
/// file to the application (SQLite then fails with "disk I/O error"), so keep reading.
async fn read_full(client: &NineClient, fid: u32, off: u64, size: u32) -> Result<Vec<u8>, i32> {
    let mut out = Vec::new();
    let mut remaining = size;
    while remaining > 0 {
        let chunk = client.read(fid, off + out.len() as u64, remaining).await?;
        if chunk.is_empty() {
            break;
        }
        let n = u32::try_from(chunk.len()).map_err(|_| libc::EIO)?;
        remaining = remaining.checked_sub(n).ok_or(libc::EIO)?;
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// A read or write offset from the kernel, which never sends a negative one.
fn file_offset(offset: i64) -> Result<u64, i32> {
    u64::try_from(offset).map_err(|_| libc::EINVAL)
}
