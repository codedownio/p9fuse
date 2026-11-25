//! Converting between 9p and FUSE attributes.

use crate::ninep::Attr;
use fuser::{FileAttr, FileType, TimeOrNow};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(super) fn to_fileattr(ino: u64, a: &Attr) -> FileAttr {
    FileAttr {
        ino,
        size: a.size,
        blocks: a.blocks,
        atime: unixtime(a.atime),
        mtime: unixtime(a.mtime),
        ctime: unixtime(a.ctime),
        crtime: UNIX_EPOCH,
        kind: kind_from_mode(a.mode),
        perm: (a.mode & 0o7777) as u16,
        nlink: u32::try_from(a.nlink.max(1)).unwrap_or(u32::MAX),
        uid: a.uid,
        gid: a.gid,
        // The low 32 bits of a glibc dev_t are the kernel's encoding for devices with major
        // numbers below 4096, which covers real devices.
        #[allow(clippy::cast_possible_truncation)]
        rdev: a.rdev as u32,
        blksize: u32::try_from(a.blksize.max(512)).unwrap_or(u32::MAX),
        flags: 0,
    }
}

/// The attributes of a cached failed lookup: FUSE reads inode 0 as "no such entry".
pub(super) fn negative_attr() -> FileAttr {
    FileAttr {
        ino: 0,
        size: 0,
        blocks: 0,
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind: FileType::RegularFile,
        perm: 0,
        nlink: 0,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 512,
        flags: 0,
    }
}

/// Attributes for a readdirplus entry the kernel takes nothing from but the inode number and type:
/// "." and "..".
pub(super) fn dirent_attr(ino: u64, kind: FileType) -> FileAttr {
    FileAttr {
        ino,
        kind,
        ..negative_attr()
    }
}

/// The file type from a qid's type bits.
pub(super) fn kind_from_qid(typ: u8) -> FileType {
    if typ & 0x80 != 0 {
        FileType::Directory
    } else if typ & 0x02 != 0 {
        FileType::Symlink
    } else {
        FileType::RegularFile
    }
}

/// A setattr time as 9p's (seconds, nanoseconds).
pub(super) fn time_or_now(t: TimeOrNow) -> (u64, u64) {
    let t = match t {
        TimeOrNow::SpecificTime(t) => t,
        TimeOrNow::Now => SystemTime::now(),
    };
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    (d.as_secs(), d.subsec_nanos() as u64)
}

fn unixtime((sec, nsec): (u64, u64)) -> SystemTime {
    let nsec = u32::try_from(nsec.min(999_999_999)).unwrap_or(0);
    UNIX_EPOCH + Duration::new(sec, nsec)
}

fn kind_from_mode(mode: u32) -> FileType {
    match mode & libc::S_IFMT {
        libc::S_IFDIR => FileType::Directory,
        libc::S_IFLNK => FileType::Symlink,
        _ => FileType::RegularFile,
    }
}
