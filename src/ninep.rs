//! Minimal 9p2000.L wire protocol: message type constants, a little-endian writer/reader, the `Qid`,
//! and typed encoders/decoders for the subset of messages the FUSE bridge needs. 9p is little-endian
//! throughout. Strings are `len[2] bytes`. A full message on the wire is
//! `size[4] type[1] tag[2] body...`, where `size` counts itself. This module only deals with the
//! `body`; framing (size/type/tag) lives in `client`.

#![allow(dead_code)]

// 9p2000.L message types (odd = response of the preceding even, except version/attach).
pub const TLERROR: u8 = 6;
pub const RLERROR: u8 = 7;
pub const TSTATFS: u8 = 8;
pub const RSTATFS: u8 = 9;
pub const TLOPEN: u8 = 12;
pub const RLOPEN: u8 = 13;
pub const TLCREATE: u8 = 14;
pub const RLCREATE: u8 = 15;
pub const TSYMLINK: u8 = 16;
pub const RSYMLINK: u8 = 17;
pub const TREADLINK: u8 = 22;
pub const RREADLINK: u8 = 23;
pub const TGETATTR: u8 = 24;
pub const RGETATTR: u8 = 25;
pub const TSETATTR: u8 = 26;
pub const RSETATTR: u8 = 27;
pub const TREADDIR: u8 = 40;
pub const RREADDIR: u8 = 41;
pub const TFSYNC: u8 = 50;
pub const RFSYNC: u8 = 51;
pub const TMKDIR: u8 = 72;
pub const RMKDIR: u8 = 73;
pub const TRENAMEAT: u8 = 74;
pub const RRENAMEAT: u8 = 75;
pub const TUNLINKAT: u8 = 76;
pub const RUNLINKAT: u8 = 77;
pub const TVERSION: u8 = 100;
pub const RVERSION: u8 = 101;
pub const TATTACH: u8 = 104;
pub const RATTACH: u8 = 105;
pub const TWALK: u8 = 110;
pub const RWALK: u8 = 111;
pub const TREAD: u8 = 116;
pub const RREAD: u8 = 117;
pub const TWRITE: u8 = 118;
pub const RWRITE: u8 = 119;
pub const TCLUNK: u8 = 120;
pub const RCLUNK: u8 = 121;

// Tsetattr `valid` bitmask.
pub const SETATTR_MODE: u32 = 0x0001;
pub const SETATTR_UID: u32 = 0x0002;
pub const SETATTR_GID: u32 = 0x0004;
pub const SETATTR_SIZE: u32 = 0x0008;
pub const SETATTR_ATIME: u32 = 0x0010;
pub const SETATTR_MTIME: u32 = 0x0020;
pub const SETATTR_ATIME_SET: u32 = 0x0080;
pub const SETATTR_MTIME_SET: u32 = 0x0100;

// Tgetattr request mask: everything.
pub const GETATTR_ALL: u64 = 0x0000_3fff;

// Sentinel fids/tags.
pub const NOFID: u32 = 0xffff_ffff;

/// A 9p unique file id: 13 bytes on the wire. `path` is unique per file and we reuse it as the FUSE
/// inode number (with the attach root remapped to 1).
#[derive(Clone, Copy, Debug)]
pub struct Qid {
    pub typ: u8,
    pub version: u32,
    pub path: u64,
}

/// Decoded Rgetattr (Linux stat-like attributes). We only keep the fields FUSE needs.
#[derive(Clone, Copy, Debug)]
pub struct Attr {
    pub qid: Qid,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
    pub rdev: u64,
    pub size: u64,
    pub blksize: u64,
    pub blocks: u64,
    pub atime: (u64, u64),
    pub mtime: (u64, u64),
    pub ctime: (u64, u64),
}

/// One Rreaddir entry.
#[derive(Clone, Debug)]
pub struct DirEntry {
    pub qid: Qid,
    pub offset: u64,
    pub typ: u8,
    pub name: String,
}

/// Little-endian writer for building a message body.
#[derive(Default)]
pub struct W {
    pub buf: Vec<u8>,
}

impl W {
    pub fn new() -> Self {
        W { buf: Vec::new() }
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn str(&mut self, s: &str) -> &mut Self {
        self.u16(s.len() as u16);
        self.buf.extend_from_slice(s.as_bytes());
        self
    }
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }
}

/// Little-endian reader over a message body. All getters saturate/`None` on short reads via `ok()`.
pub struct R<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> R<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        R { b, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.pos)
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.b.len() {
            return None;
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    pub fn u16(&mut self) -> Option<u16> {
        self.take(2)
            .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
    }
    pub fn str(&mut self) -> Option<String> {
        let n = self.u16()? as usize;
        let s = self.take(n)?;
        Some(String::from_utf8_lossy(s).into_owned())
    }
    pub fn qid(&mut self) -> Option<Qid> {
        Some(Qid {
            typ: self.u8()?,
            version: self.u32()?,
            path: self.u64()?,
        })
    }
}

/// Parse an Rgetattr body. Layout: valid[8] qid[13] mode[4] uid[4] gid[4] nlink[8] rdev[8] size[8]
/// blksize[8] blocks[8] atime(sec,nsec) mtime(sec,nsec) ctime(sec,nsec) btime(sec,nsec) gen[8]
/// data_version[8]. We stop after ctime since that's all FUSE consumes.
pub fn parse_getattr(body: &[u8]) -> Option<Attr> {
    let mut r = R::new(body);
    let _valid = r.u64()?;
    let qid = r.qid()?;
    let mode = r.u32()?;
    let uid = r.u32()?;
    let gid = r.u32()?;
    let nlink = r.u64()?;
    let rdev = r.u64()?;
    let size = r.u64()?;
    let blksize = r.u64()?;
    let blocks = r.u64()?;
    let atime = (r.u64()?, r.u64()?);
    let mtime = (r.u64()?, r.u64()?);
    let ctime = (r.u64()?, r.u64()?);
    Some(Attr {
        qid,
        mode,
        uid,
        gid,
        nlink,
        rdev,
        size,
        blksize,
        blocks,
        atime,
        mtime,
        ctime,
    })
}

/// Parse the packed Rreaddir data blob into entries. Each entry: qid[13] offset[8] type[1] name[s].
pub fn parse_readdir(data: &[u8]) -> Vec<DirEntry> {
    let mut r = R::new(data);
    let mut out = Vec::new();
    while let Some(qid) = r.qid() {
        let (offset, typ, name) = match (r.u64(), r.u8(), r.str()) {
            (Some(o), Some(t), Some(n)) => (o, t, n),
            _ => break,
        };
        out.push(DirEntry {
            qid,
            offset,
            typ,
            name,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives_roundtrip_little_endian() {
        let mut w = W::new();
        w.u8(0xAB)
            .u16(0x1234)
            .u32(0xDEAD_BEEF)
            .u64(0x0102_0304_0506_0708)
            .str("héllo")
            .bytes(&[1, 2, 3]);
        // u16 is little-endian on the wire.
        assert_eq!(&w.buf[1..3], &[0x34, 0x12]);

        let mut r = R::new(&w.buf);
        assert_eq!(r.u8(), Some(0xAB));
        assert_eq!(r.u16(), Some(0x1234));
        assert_eq!(r.u32(), Some(0xDEAD_BEEF));
        assert_eq!(r.u64(), Some(0x0102_0304_0506_0708));
        assert_eq!(r.str().as_deref(), Some("héllo"));
        assert_eq!(r.remaining(), 3); // the trailing raw bytes
    }

    #[test]
    fn short_reads_return_none() {
        let mut r = R::new(&[0x01, 0x02]);
        assert_eq!(r.u16(), Some(0x0201));
        assert_eq!(r.u8(), None); // exhausted
        assert_eq!(R::new(&[0x01]).u32(), None);
        // str with a length header longer than the remaining bytes.
        assert_eq!(R::new(&[0x03, 0x00, b'a']).str(), None);
    }

    #[test]
    fn str_empty_and_multibyte() {
        let mut w = W::new();
        w.str("");
        assert_eq!(R::new(&w.buf).str().as_deref(), Some(""));

        let mut w2 = W::new();
        w2.str("naïve → 世界");
        assert_eq!(R::new(&w2.buf).str().as_deref(), Some("naïve → 世界"));
    }

    #[test]
    fn qid_roundtrip_is_13_bytes() {
        let mut w = W::new();
        w.u8(0x80).u32(7).u64(0xCAFE_F00D_1234);
        assert_eq!(w.buf.len(), 13);
        let q = R::new(&w.buf).qid().unwrap();
        assert_eq!((q.typ, q.version, q.path), (0x80, 7, 0xCAFE_F00D_1234));
    }

    // A well-formed Rgetattr body, plus the trailing btime/gen/data_version fields the parser ignores.
    fn getattr_body(mode: u32, size: u64, qid_path: u64) -> Vec<u8> {
        let mut w = W::new();
        w.u64(GETATTR_ALL);
        w.u8(0).u32(3).u64(qid_path); // qid
        w.u32(mode).u32(1000).u32(1001); // mode, uid, gid
        w.u64(2) // nlink
            .u64(0) // rdev
            .u64(size)
            .u64(4096) // blksize
            .u64(size.div_ceil(512)); // blocks
        w.u64(11).u64(0); // atime
        w.u64(22).u64(0); // mtime
        w.u64(33).u64(0); // ctime
        w.u64(44).u64(0).u64(0); // btime, gen, data_version (ignored)
        w.buf
    }

    #[test]
    fn parse_getattr_reads_fields_and_ignores_trailing() {
        let a = parse_getattr(&getattr_body(0o100_644, 4242, 99)).unwrap();
        assert_eq!(a.mode, 0o100_644);
        assert_eq!(a.uid, 1000);
        assert_eq!(a.gid, 1001);
        assert_eq!(a.size, 4242);
        assert_eq!(a.qid.path, 99);
        assert_eq!(a.mtime, (22, 0));
        assert_eq!(a.ctime, (33, 0));
    }

    #[test]
    fn parse_getattr_truncated_is_none() {
        let mut body = getattr_body(0o100_644, 1, 0);
        body.truncate(20); // cut mid-structure
        assert!(parse_getattr(&body).is_none());
    }

    fn push_dirent(w: &mut W, qid_path: u64, off: u64, typ: u8, name: &str) {
        w.u8(0).u32(0).u64(qid_path); // qid
        w.u64(off).u8(typ).str(name);
    }

    #[test]
    fn parse_readdir_multiple_entries() {
        let mut w = W::new();
        push_dirent(&mut w, 10, 1, 0x80, ".");
        push_dirent(&mut w, 11, 2, 0x80, "..");
        push_dirent(&mut w, 12, 3, 0, "file.txt");
        let ents = parse_readdir(&w.buf);
        assert_eq!(ents.len(), 3);
        assert_eq!(ents[0].qid.path, 10);
        assert_eq!(ents[2].name, "file.txt");
        assert_eq!(ents[2].offset, 3);
    }

    #[test]
    fn parse_readdir_stops_on_truncated_tail() {
        let mut w = W::new();
        push_dirent(&mut w, 10, 1, 0x80, "ok");
        push_dirent(&mut w, 11, 2, 0, "partial");
        w.buf.truncate(w.buf.len() - 4); // chop the last entry's name
        let ents = parse_readdir(&w.buf);
        assert_eq!(ents.len(), 1);
        assert_eq!(ents[0].name, "ok");
    }

    #[test]
    fn parse_readdir_empty() {
        assert!(parse_readdir(&[]).is_empty());
    }
}
