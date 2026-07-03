//! Async 9p2000.L client multiplexed over a [`NineTransport`]. A single background task owns the
//! read half, reassembles 9p frames (`size[4] type[1] tag[2] body`) across arbitrary chunk
//! boundaries, and dispatches each response to the waiting request by `tag`. Request methods are
//! `async` and may be called concurrently; tags are allocated per in-flight request.
//!
//! This is the engine behind the FUSE bridge: instead of `mount(2)` (which needs CAP_SYS_ADMIN),
//! the bridge drives these methods, so a 9p export can be mounted unprivileged via FUSE while still
//! speaking full 9p2000.L (complete chmod/metadata fidelity).

use crate::ninep::*;
use crate::transport::{ByteSink, NineTransport};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

const NOTAG: u16 = 0xffff;
const ROOT_FID: u32 = 1;

/// A decoded response frame: message type plus the body after the 7-byte header.
struct Frame {
    typ: u8,
    body: Vec<u8>,
}

pub struct NineClient {
    sink: tokio::sync::Mutex<ByteSink>,
    pending: Mutex<HashMap<u16, oneshot::Sender<Frame>>>,
    next_tag: AtomicU16,
    next_fid: AtomicU32,
    pub msize: u32,
    pub root_fid: u32,
}

fn to_io<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

impl NineClient {
    /// Split the transport, start the read pump, negotiate version, and attach to `aname` as
    /// `n_uname`. Returns the ready client plus the root qid.
    pub async fn connect(
        transport: Box<dyn NineTransport>,
        msize: u32,
        n_uname: u32,
        aname: &str,
    ) -> Result<(Arc<NineClient>, Qid), Box<dyn std::error::Error>> {
        let (sink, mut stream) = transport.split();

        let client = Arc::new(NineClient {
            sink: tokio::sync::Mutex::new(sink),
            pending: Mutex::new(HashMap::new()),
            next_tag: AtomicU16::new(0),
            next_fid: AtomicU32::new(ROOT_FID + 1),
            msize,
            root_fid: ROOT_FID,
        });

        // Read pump: reassemble frames and route to waiters by tag.
        let pump = client.clone();
        tokio::spawn(async move {
            let mut acc: Vec<u8> = Vec::with_capacity(1 << 16);
            while let Some(item) = stream.next().await {
                match item {
                    Ok(chunk) => {
                        acc.extend_from_slice(&chunk);
                        while let Some(frame) = take_frame(&mut acc) {
                            pump.dispatch(frame);
                        }
                    }
                    // Transport error: stop pumping; the cleanup below fails all waiters.
                    Err(_) => break,
                }
            }
            // Transport gone: drop all waiters so their requests fail instead of hanging.
            pump.pending.lock().unwrap().clear();
        });

        // Version handshake (tag NOTAG), then attach.
        let negotiated = client.version(msize).await?;
        // Re-stamp msize is immutable on the struct; we only ever send <= negotiated, and our reads
        // request `negotiated`. Keep it simple: assert we can proceed with what we asked for.
        if negotiated < 4096 {
            return Err(format!("server negotiated tiny msize {negotiated}").into());
        }
        let root_qid = client.attach(ROOT_FID, "user", aname, n_uname).await?;
        Ok((client, root_qid))
    }

    fn dispatch(&self, frame: Frame) {
        // tag lives in the body? No: take_frame strips size/type but keeps tag at body[0..2].
        let tag = u16::from_le_bytes([frame.body[0], frame.body[1]]);
        let payload = Frame {
            typ: frame.typ,
            body: frame.body[2..].to_vec(),
        };
        if let Some(tx) = self.pending.lock().unwrap().remove(&tag) {
            let _ = tx.send(payload);
        }
    }

    fn alloc_tag(&self) -> u16 {
        loop {
            let t = self.next_tag.fetch_add(1, Ordering::Relaxed);
            if t != NOTAG {
                return t;
            }
        }
    }

    pub fn alloc_fid(&self) -> u32 {
        self.next_fid.fetch_add(1, Ordering::Relaxed)
    }

    /// Send a T-message body and await the matching response. Returns Err(errno) on Rlerror or a
    /// transport/protocol failure (mapped to EIO).
    async fn transact(&self, mtype: u8, tag: u16, body: &[u8]) -> Result<Frame, i32> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(tag, tx);

        let size = (4 + 1 + 2 + body.len()) as u32;
        let mut frame = Vec::with_capacity(size as usize);
        frame.extend_from_slice(&size.to_le_bytes());
        frame.push(mtype);
        frame.extend_from_slice(&tag.to_le_bytes());
        frame.extend_from_slice(body);

        {
            let mut sink = self.sink.lock().await;
            if sink.send(frame).await.is_err() {
                self.pending.lock().unwrap().remove(&tag);
                return Err(libc::EIO);
            }
        }

        match rx.await {
            Ok(resp) => {
                if resp.typ == RLERROR {
                    let ecode = R::new(&resp.body).u32().unwrap_or(libc::EIO as u32);
                    Err(ecode as i32)
                } else {
                    Ok(resp)
                }
            }
            Err(_) => Err(libc::EIO), // transport dropped the waiter
        }
    }

    /// Like `transact` but checks the response type and returns just the body.
    async fn req(&self, mtype: u8, expect: u8, body: &[u8]) -> Result<Vec<u8>, i32> {
        let tag = self.alloc_tag();
        let r = self.transact(mtype, tag, body).await?;
        if r.typ != expect {
            tracing::warn!(got = r.typ, want = expect, "9p: unexpected response type");
            return Err(libc::EIO);
        }
        Ok(r.body)
    }

    async fn version(&self, msize: u32) -> Result<u32, Box<dyn std::error::Error>> {
        let mut w = W::new();
        w.u32(msize).str("9P2000.L");
        // Version uses NOTAG.
        let r = self
            .transact(TVERSION, NOTAG, &w.buf)
            .await
            .map_err(|e| to_io(format!("Tversion failed: errno {e}")))?;
        if r.typ != RVERSION {
            return Err("server did not answer Tversion".into());
        }
        let mut rr = R::new(&r.body);
        let neg = rr.u32().ok_or_else(|| to_io("short Rversion"))?;
        let ver = rr.str().ok_or_else(|| to_io("short Rversion"))?;
        if ver != "9P2000.L" {
            return Err(format!("server speaks {ver}, not 9P2000.L").into());
        }
        Ok(neg)
    }

    async fn attach(
        &self,
        fid: u32,
        uname: &str,
        aname: &str,
        n_uname: u32,
    ) -> Result<Qid, Box<dyn std::error::Error>> {
        let mut w = W::new();
        w.u32(fid).u32(NOFID).str(uname).str(aname).u32(n_uname);
        let body = self
            .req(TATTACH, RATTACH, &w.buf)
            .await
            .map_err(|e| to_io(format!("Tattach failed: errno {e}")))?;
        R::new(&body)
            .qid()
            .ok_or_else(|| to_io("short Rattach").into())
    }

    /// Walk `names` from `fid` into the fresh `newfid`. `names` empty clones the fid (newfid points
    /// at the same file). Returns the walked qids (one per name).
    pub async fn walk(&self, fid: u32, newfid: u32, names: &[&str]) -> Result<Vec<Qid>, i32> {
        let mut w = W::new();
        w.u32(fid).u32(newfid).u16(names.len() as u16);
        for n in names {
            w.str(n);
        }
        let body = self.req(TWALK, RWALK, &w.buf).await?;
        let mut r = R::new(&body);
        let nq = r.u16().ok_or(libc::EIO)? as usize;
        let mut out = Vec::with_capacity(nq);
        for _ in 0..nq {
            out.push(r.qid().ok_or(libc::EIO)?);
        }
        Ok(out)
    }

    pub async fn getattr(&self, fid: u32) -> Result<Attr, i32> {
        let mut w = W::new();
        w.u32(fid).u64(GETATTR_ALL);
        let body = self.req(TGETATTR, RGETATTR, &w.buf).await?;
        parse_getattr(&body).ok_or(libc::EIO)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn setattr(
        &self,
        fid: u32,
        valid: u32,
        mode: u32,
        uid: u32,
        gid: u32,
        size: u64,
        atime: (u64, u64),
        mtime: (u64, u64),
    ) -> Result<(), i32> {
        let mut w = W::new();
        w.u32(fid)
            .u32(valid)
            .u32(mode)
            .u32(uid)
            .u32(gid)
            .u64(size)
            .u64(atime.0)
            .u64(atime.1)
            .u64(mtime.0)
            .u64(mtime.1);
        self.req(TSETATTR, RSETATTR, &w.buf).await.map(|_| ())
    }

    /// Open an existing fid for I/O. Returns (qid, iounit).
    pub async fn lopen(&self, fid: u32, flags: u32) -> Result<(Qid, u32), i32> {
        let mut w = W::new();
        w.u32(fid).u32(flags);
        let body = self.req(TLOPEN, RLOPEN, &w.buf).await?;
        let mut r = R::new(&body);
        let qid = r.qid().ok_or(libc::EIO)?;
        let iounit = r.u32().ok_or(libc::EIO)?;
        Ok((qid, iounit))
    }

    /// Create a file in the directory `dfid` and leave `dfid` opened on the new file.
    pub async fn lcreate(
        &self,
        dfid: u32,
        name: &str,
        flags: u32,
        mode: u32,
        gid: u32,
    ) -> Result<(Qid, u32), i32> {
        let mut w = W::new();
        w.u32(dfid).str(name).u32(flags).u32(mode).u32(gid);
        let body = self.req(TLCREATE, RLCREATE, &w.buf).await?;
        let mut r = R::new(&body);
        let qid = r.qid().ok_or(libc::EIO)?;
        let iounit = r.u32().ok_or(libc::EIO)?;
        Ok((qid, iounit))
    }

    pub async fn mkdir(&self, dfid: u32, name: &str, mode: u32, gid: u32) -> Result<Qid, i32> {
        let mut w = W::new();
        w.u32(dfid).str(name).u32(mode).u32(gid);
        let body = self.req(TMKDIR, RMKDIR, &w.buf).await?;
        R::new(&body).qid().ok_or(libc::EIO)
    }

    pub async fn readdir(&self, fid: u32, offset: u64, count: u32) -> Result<Vec<DirEntry>, i32> {
        let mut w = W::new();
        w.u32(fid).u64(offset).u32(count);
        let body = self.req(TREADDIR, RREADDIR, &w.buf).await?;
        let mut r = R::new(&body);
        let n = r.u32().ok_or(libc::EIO)? as usize;
        let data = &body[4..4 + n.min(body.len() - 4)];
        Ok(parse_readdir(data))
    }

    pub async fn read(&self, fid: u32, offset: u64, count: u32) -> Result<Vec<u8>, i32> {
        let mut w = W::new();
        w.u32(fid).u64(offset).u32(count);
        let body = self.req(TREAD, RREAD, &w.buf).await?;
        let mut r = R::new(&body);
        let n = r.u32().ok_or(libc::EIO)? as usize;
        Ok(body[4..4 + n.min(body.len() - 4)].to_vec())
    }

    pub async fn write(&self, fid: u32, offset: u64, data: &[u8]) -> Result<u32, i32> {
        let mut w = W::new();
        w.u32(fid).u64(offset).u32(data.len() as u32).bytes(data);
        let body = self.req(TWRITE, RWRITE, &w.buf).await?;
        R::new(&body).u32().ok_or(libc::EIO)
    }

    pub async fn clunk(&self, fid: u32) -> Result<(), i32> {
        let mut w = W::new();
        w.u32(fid);
        self.req(TCLUNK, RCLUNK, &w.buf).await.map(|_| ())
    }

    /// `flags` = 0 to unlink a file, `AT_REMOVEDIR` (0x200) to remove a directory.
    pub async fn unlinkat(&self, dfid: u32, name: &str, flags: u32) -> Result<(), i32> {
        let mut w = W::new();
        w.u32(dfid).str(name).u32(flags);
        self.req(TUNLINKAT, RUNLINKAT, &w.buf).await.map(|_| ())
    }

    pub async fn fsync(&self, fid: u32) -> Result<(), i32> {
        let mut w = W::new();
        w.u32(fid).u32(0);
        self.req(TFSYNC, RFSYNC, &w.buf).await.map(|_| ())
    }

    pub async fn renameat(
        &self,
        olddfid: u32,
        oldname: &str,
        newdfid: u32,
        newname: &str,
    ) -> Result<(), i32> {
        let mut w = W::new();
        w.u32(olddfid).str(oldname).u32(newdfid).str(newname);
        self.req(TRENAMEAT, RRENAMEAT, &w.buf).await.map(|_| ())
    }

    /// Create symlink `name` -> `target` in directory `dfid`. Returns the new link's qid.
    pub async fn symlink(&self, dfid: u32, name: &str, target: &str, gid: u32) -> Result<Qid, i32> {
        let mut w = W::new();
        w.u32(dfid).str(name).str(target).u32(gid);
        let body = self.req(TSYMLINK, RSYMLINK, &w.buf).await?;
        R::new(&body).qid().ok_or(libc::EIO)
    }

    pub async fn readlink(&self, fid: u32) -> Result<String, i32> {
        let mut w = W::new();
        w.u32(fid);
        let body = self.req(TREADLINK, RREADLINK, &w.buf).await?;
        R::new(&body).str().ok_or(libc::EIO)
    }

    /// Returns (bsize, blocks, bfree, bavail, files, ffree, namelen).
    pub async fn statfs(&self, fid: u32) -> Result<(u32, u64, u64, u64, u64, u64, u32), i32> {
        let mut w = W::new();
        w.u32(fid);
        let body = self.req(TSTATFS, RSTATFS, &w.buf).await?;
        let mut r = R::new(&body);
        let _typ = r.u32().ok_or(libc::EIO)?;
        let bsize = r.u32().ok_or(libc::EIO)?;
        let blocks = r.u64().ok_or(libc::EIO)?;
        let bfree = r.u64().ok_or(libc::EIO)?;
        let bavail = r.u64().ok_or(libc::EIO)?;
        let files = r.u64().ok_or(libc::EIO)?;
        let ffree = r.u64().ok_or(libc::EIO)?;
        let _fsid = r.u64().ok_or(libc::EIO)?;
        let namelen = r.u32().ok_or(libc::EIO)?;
        Ok((bsize, blocks, bfree, bavail, files, ffree, namelen))
    }
}

/// Pull one complete 9p frame out of `acc` if present. A frame is `size[4] type[1] tag[2] body`,
/// where `size` counts the whole frame. Returns the frame with `body` = `tag[2] ++ rest` (the caller
/// reads the tag back off the front); leaves any trailing partial bytes in `acc`.
fn take_frame(acc: &mut Vec<u8>) -> Option<Frame> {
    if acc.len() < 7 {
        return None;
    }
    let size = u32::from_le_bytes([acc[0], acc[1], acc[2], acc[3]]) as usize;
    if size < 7 || acc.len() < size {
        return None;
    }
    let typ = acc[4];
    // body = tag(2) + payload; drain the whole frame from acc.
    let body = acc[5..size].to_vec();
    acc.drain(0..size);
    Some(Frame { typ, body })
}
