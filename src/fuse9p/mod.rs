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
//! - `unmount`: ending the session once unmounted from our namespace.
//! - `attr`: converting 9p attributes to FUSE ones.

mod attr;
mod filesystem;
mod invalidate;
mod mount;
mod tuning;
mod unmount;
mod write_pipeline;
mod writes;

pub use tuning::Tuning;

use crate::client::NineClient;
use crate::ninep::{Attr, Qid};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::runtime::Handle;
use tokio::sync::watch;
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
    /// The number of entries in `handles`, for the task that waits for them to close on unmount.
    open_handles: watch::Sender<usize>,
    next_fh: u64,
    /// The write pipeline of each inode open through a pipelined handle.
    writes: HashMap<u64, Arc<InodeWrites>>,
}

struct Inode {
    /// A fid walked to the file but not opened, used for getattr/setattr and to walk or open from.
    fid: u32,
    lookups: u64,
    /// Where `fid` was walked to: the directory inode and the name in it. diod ties a fid to its
    /// path, so this is what `fid` really names.
    parent: u64,
    name: Box<str>,
    /// Told to the kernel with the inode number; changes when the number is found to have passed to
    /// another file, so the kernel drops the inode it holds instead of merging the two files.
    generation: u64,
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

fn is_dir(qid: &Qid) -> bool {
    qid.typ & 0x80 != 0
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

    /// Count a lookup reference the kernel now holds to `ino`, reached through `fid` as `name` in
    /// directory `parent`, and return the generation to report with it.
    ///
    /// A known inode takes `fid` when it was found by the path its own fid was walked by: diod ties
    /// a fid to the whole path, so a rename above the file has left that one naming nothing, and the
    /// new fid is as good otherwise. Found by another path, the inode keeps its fid while that still
    /// names the same file, as with a hard link (asking the server); if not, the file was moved or
    /// deleted outside the mount and `fid` takes over. A deleted file's number may already be this
    /// new file's, which the kernel can't tell from the file it holds unless the generation
    /// changes. They can only be the same file if we have it open, since the server's open
    /// descriptor then keeps the number from being reused; a file moved outside the mount while
    /// not open gets a new generation too, which only costs the kernel its caches for it. A
    /// directory keeps its generation: the kernel caches no data for one, so merging two is only a
    /// stale listing until the entry expires, while a new generation fails every process whose
    /// working directory is inside with EIO, and a directory renamed outside the mount is the
    /// likelier case.
    ///
    /// Not told apart: a file replaced at the same path by one of the same type with the same number
    /// (diod reports no generation of its own; the kernel sees the attributes change), and a
    /// hard-linked file's fid still breaks when the name it was walked by is removed.
    fn add_lookup(&mut self, parent: u64, name: &str, qid: &Qid, fid: u32) -> u64 {
        let ino = self.ino(qid);
        let Some(inode) = self.inodes.get_mut(&ino) else {
            let inode = Inode {
                fid,
                lookups: 1,
                parent,
                name: name.into(),
                generation: 0,
            };
            self.inodes.insert(ino, inode);
            return 0;
        };
        inode.lookups += 1;
        let (old_fid, mut generation) = (inode.fid, inode.generation);
        let same_path = inode.parent == parent && *inode.name == *name;
        // The root keeps its attach fid, which the invalidator walks from.
        if ino == ROOT_INO {
            self.clunk(fid);
            return generation;
        }
        if !same_path {
            if self.names(old_fid, ino) {
                self.clunk(fid);
                return generation;
            }
            if !is_dir(qid) && !self.handles.values().any(|h| h.ino == ino) {
                generation += 1;
                self.inodes.get_mut(&ino).expect("checked above").generation = generation;
            }
        }
        self.replace_fid(ino, fid, parent, name);
        generation
    }

    /// Whether `fid` still names the file with inode number `ino`.
    fn names(&self, fid: u32, ino: u64) -> bool {
        self.rt
            .block_on(self.client.getattr(fid))
            .is_ok_and(|attr| self.ino(&attr.qid) == ino)
    }

    /// Make `fid`, walked to `name` in directory `parent`, the fid of `ino` and release the one it
    /// had. `fid` is released instead if the kernel doesn't hold `ino`.
    fn replace_fid(&mut self, ino: u64, fid: u32, parent: u64, name: &str) {
        let stale = match self.inodes.get_mut(&ino) {
            Some(inode) => {
                inode.parent = parent;
                inode.name = name.into();
                std::mem::replace(&mut inode.fid, fid)
            }
            None => fid,
        };
        self.clunk(stale);
    }

    /// Drop `n` of the kernel's lookup references to `ino`, releasing its fid once none are left.
    fn forget_lookups(&mut self, ino: u64, n: u64) {
        if let Some(inode) = self.inodes.get_mut(&ino) {
            inode.lookups = inode.lookups.saturating_sub(n);
            if inode.lookups == 0 {
                let fid = inode.fid;
                self.inodes.remove(&ino);
                self.clunk(fid);
            }
        }
    }
}
