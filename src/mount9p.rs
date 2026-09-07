//! `mount9p` subcommand: mount the kernel's in-tree 9p2000.L client (v9fs) over a [`NineTransport`],
//! bridged to a remote 9p server. This is the privileged alternative to the FUSE bridge: the Linux
//! kernel speaks 9p2000.L directly and we are just a dumb byte pipe between the kernel's transport
//! fd and the transport.
//!
//! How it works: we create a `socketpair`; one end is handed to the v9fs client via
//! `mount -t 9p -o trans=fd,rfdno=,wfdno=`, and we pump raw bytes between the other end and the
//! transport. 9p frames itself (4-byte size prefix), so the transport only needs to deliver bytes
//! in order -- arbitrary chunking is fine.
//!
//! Requirements: `CAP_SYS_ADMIN` (the `mount(2)` syscall -- unlike FUSE, 9p has no setuid mount
//! helper and is not user-namespace mountable) and the `9p`/`9pnet`/`9pnet_fd` kernel modules loaded
//! on the node. When those aren't available, use the FUSE bridge (`mount9p-fuse`) instead.

use crate::ninep::{tmsg_name, TFLUSH};
use crate::transport::NineTransport;
use futures_util::{SinkExt, StreamExt};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn to_io<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// Requests we've forwarded to the server and not yet seen a response for: tag -> (T-type, sent).
type Outstanding = Arc<Mutex<HashMap<u16, (u8, Instant)>>>;

/// Incremental scan of a 9p byte stream, reporting each frame's header without buffering payloads.
/// A frame is `size[4] type[1] tag[2] body...`; for `Tflush` the first body field is `oldtag[2]`,
/// so we capture up to 9 bytes per frame and skip the rest.
struct FrameScanner {
    header: [u8; 9],
    have: usize,
    skip: usize,
}

impl FrameScanner {
    fn new() -> Self {
        FrameScanner {
            header: [0; 9],
            have: 0,
            skip: 0,
        }
    }

    /// Feed a chunk, invoking `on_frame(type, tag, oldtag)` once per frame. `oldtag` is only
    /// meaningful for `Tflush`; for frames shorter than 9 bytes it is 0.
    fn feed(&mut self, mut b: &[u8], mut on_frame: impl FnMut(u8, u16, u16)) {
        while !b.is_empty() {
            if self.skip > 0 {
                let n = self.skip.min(b.len());
                self.skip -= n;
                b = &b[n..];
                continue;
            }
            let target = if self.have < 4 {
                4
            } else {
                let size = u32::from_le_bytes(self.header[0..4].try_into().unwrap()) as usize;
                if size < 7 {
                    // Not legal 9p; resync as best we can by skipping the remainder.
                    tracing::warn!(size, "9p frame scanner: undersized frame");
                    self.skip = size.saturating_sub(self.have);
                    self.have = 0;
                    continue;
                }
                size.min(9)
            };
            let n = (target - self.have).min(b.len());
            self.header[self.have..self.have + n].copy_from_slice(&b[..n]);
            self.have += n;
            b = &b[n..];
            if self.have < target || self.have < 7 {
                continue;
            }
            let size = u32::from_le_bytes(self.header[0..4].try_into().unwrap()) as usize;
            let typ = self.header[4];
            let tag = u16::from_le_bytes(self.header[5..7].try_into().unwrap());
            let oldtag = match self.have {
                9 => u16::from_le_bytes(self.header[7..9].try_into().unwrap()),
                _ => 0,
            };
            on_frame(typ, tag, oldtag);
            self.skip = size - self.have;
            self.have = 0;
        }
    }
}

/// Resolves with an error once the oldest outstanding request has gone unanswered for
/// `timeout` (never, when `timeout` is zero). The kernel v9fs client waits forever for a reply,
/// so a server that stops answering -- a silently dead tunnel, or a server wedged on its backing
/// store -- hangs every process touching the mount until we tear it down.
async fn stall_watchdog(outstanding: Outstanding, timeout: Duration) -> io::Error {
    if timeout.is_zero() {
        return std::future::pending().await;
    }
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    loop {
        ticker.tick().await;
        let oldest = {
            let map = outstanding.lock().unwrap();
            map.iter()
                .map(|(tag, (typ, at))| (*tag, *typ, at.elapsed()))
                .max_by_key(|(_, _, age)| *age)
        };
        if let Some((tag, typ, age)) = oldest {
            if age > timeout {
                let n = outstanding.lock().unwrap().len();
                return io::Error::other(format!(
                    "9p request stalled: {} (tag {tag}) unanswered for {}s, {n} outstanding",
                    tmsg_name(typ),
                    age.as_secs()
                ));
            }
        }
    }
}

/// Split `transport`, mount the v9fs client at `mountpoint`, and bridge bytes until either side
/// closes. Best-effort unmount on exit. `aname` is fixed to `/export` in the mount options below.
///
/// `cache` is v9fs's cache mode, passed through as-is (`none`, `readahead`, `mmap`, `loose`,
/// `fscache`); see the note on the mount options below for how to pick one.
pub async fn mount9p(
    transport: Box<dyn NineTransport>,
    mountpoint: &Path,
    msize: usize,
    cache: &str,
    stall_timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Split the transport into its 9p byte sink/stream.
    let (mut sink, mut stream) = transport.split();

    // 2. socketpair: sock_kernel is handed to the v9fs client; sock_bridge is our pump end.
    let (sock_kernel, sock_bridge) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::empty(),
    )?;

    // 3. Turn the bridge end into a tokio stream. We must start pumping BEFORE mount(2) returns:
    // the kernel performs the 9p version/attach handshake synchronously inside mount(), so if the
    // bridge weren't already forwarding, mount() would block forever waiting for the server.
    let bridge_std =
        unsafe { std::os::unix::net::UnixStream::from_raw_fd(sock_bridge.into_raw_fd()) };
    bridge_std.set_nonblocking(true)?;
    let bridge = tokio::net::UnixStream::from_std(bridge_std)?;
    let (mut bridge_rd, mut bridge_wr) = tokio::io::split(bridge);

    let outstanding: Outstanding = Arc::new(Mutex::new(HashMap::new()));

    // sock -> transport: forward the kernel's 9p requests, recording each one's tag.
    let req_tags = outstanding.clone();
    let sock_to_transport = async move {
        let mut buf = vec![0u8; 1 << 17];
        let mut scan = FrameScanner::new();
        loop {
            let n = bridge_rd.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            scan.feed(&buf[..n], |typ, tag, oldtag| {
                let mut map = req_tags.lock().unwrap();
                // A Tflush abandons oldtag: the kernel no longer expects its answer.
                if typ == TFLUSH {
                    map.remove(&oldtag);
                }
                map.insert(tag, (typ, Instant::now()));
            });
            sink.send(buf[..n].to_vec()).await?;
        }
        Ok::<(), io::Error>(())
    };

    // transport -> sock: forward the server's 9p responses, resolving their tags.
    let resp_tags = outstanding.clone();
    let transport_to_sock = async move {
        let mut scan = FrameScanner::new();
        while let Some(item) = stream.next().await {
            match item {
                Ok(chunk) => {
                    scan.feed(&chunk, |_typ, tag, _oldtag| {
                        resp_tags.lock().unwrap().remove(&tag);
                    });
                    bridge_wr.write_all(&chunk).await?
                }
                Err(e) => return Err(e),
            }
        }
        Ok::<(), io::Error>(())
    };

    let watchdog = stall_watchdog(outstanding, stall_timeout);

    // 4. Perform mount(2) on a blocking thread while the pumps run on the async runtime. The
    // v9fs fd transport fget()s the fd and keeps its own reference, so once mount() returns we can
    // drop our copy of sock_kernel.
    let fd = sock_kernel.as_raw_fd();
    // `aname=/export`: a server like diod (`diod -e /export`) only honors attaches whose aname names
    // an exported path. A multiuser server running as root setfsuids per attach (root at mount, the
    // attaching uid for file ops), so no client `access=`/uid option is needed and file ownership
    // follows the accessing uid.
    //
    // The cache mode is the caller's call, because it decides correctness, not just speed. Under
    // `cache=loose`, v9fs_vfs_getattr answers from the cached inode and never asks the server, and
    // nothing can drop that -- the kernel client has no equivalent of the FUSE bridge's notify path.
    // A file rewritten on the server then keeps its old size and contents for this client forever,
    // so `loose` is only safe when nothing else writes to the export. `mmap` (the default) still
    // caches pages, so files can be mapped and executed out of the mount, but revalidates against
    // the server so out-of-band writes show up.
    let data = format!(
        "trans=fd,rfdno={fd},wfdno={fd},version=9p2000.L,msize={msize},cache={cache},aname=/export"
    );
    let mp = mountpoint.to_path_buf();
    tracing::info!(?mp, %data, "mount9p: mounting v9fs");
    let mount_task = tokio::task::spawn_blocking(move || {
        let r = mount(
            Some("9p"),
            mp.as_path(),
            Some("9p"),
            MsFlags::empty(),
            Some(data.as_str()),
        );
        drop(sock_kernel); // kernel holds its own ref now
        r
    });

    tokio::pin!(sock_to_transport);
    tokio::pin!(transport_to_sock);
    tokio::pin!(watchdog);

    let result: Result<(), Box<dyn std::error::Error>> = async {
        // mount() completes only after the handshake, which needs the pumps running concurrently.
        tokio::select! {
            m = mount_task => {
                let mount_result = m?;            // join error (panic in the blocking task)
                if let Err(e) = mount_result {
                    // Dump the privilege context so we can see WHY mount(2) was refused: is this
                    // process actually root (setuid took effect)? does it have CAP_SYS_ADMIN? is it
                    // inside a user namespace (where 9p, lacking FS_USERNS_MOUNT, can't be mounted)?
                    eprintln!("mount9p: mount(2) failed: {e}");
                    eprintln!("mount9p: euid={} uid={}", nix::unistd::geteuid(), nix::unistd::getuid());
                    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
                        for line in s.lines() {
                            if line.starts_with("Cap") || line.starts_with("NoNewPrivs") {
                                eprintln!("mount9p: {line}");
                            }
                        }
                    }
                    if let Ok(s) = std::fs::read_to_string("/proc/self/uid_map") {
                        eprintln!("mount9p: uid_map: {}", s.trim());
                    }
                    return Err(e.into());
                }
            }
            r = &mut sock_to_transport => { r.map_err(to_io)?; return Err("9p transport closed before mount completed".into()); }
            r = &mut transport_to_sock => { r.map_err(to_io)?; return Err("9p transport closed before mount completed".into()); }
            e = &mut watchdog => { tracing::error!(%e, "mount9p: exiting so the mount detaches and the supervisor remounts"); return Err(e.into()); }
        }
        tracing::info!(?mountpoint, "mount9p: mounted; bridging");
        // Keep pumping for the life of the mount.
        tokio::select! {
            r = &mut sock_to_transport => r.map_err(to_io)?,
            r = &mut transport_to_sock => r.map_err(to_io)?,
            e = &mut watchdog => { tracing::error!(%e, "mount9p: exiting so the mount detaches and the supervisor remounts"); return Err(e.into()); }
        }
        Ok(())
    }
    .await;

    // 5. Best-effort detach-unmount on exit so a dead transport doesn't leave a wedged mount.
    let _ = umount2(mountpoint, MntFlags::MNT_DETACH);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a frame: size[4] type[1] tag[2] + body.
    fn frame(typ: u8, tag: u16, body: &[u8]) -> Vec<u8> {
        let size = (7 + body.len()) as u32;
        let mut f = size.to_le_bytes().to_vec();
        f.push(typ);
        f.extend_from_slice(&tag.to_le_bytes());
        f.extend_from_slice(body);
        f
    }

    fn scan_all(scan: &mut FrameScanner, bytes: &[u8], chunk: usize) -> Vec<(u8, u16, u16)> {
        let mut seen = Vec::new();
        for c in bytes.chunks(chunk.max(1)) {
            scan.feed(c, |typ, tag, oldtag| seen.push((typ, tag, oldtag)));
        }
        seen
    }

    #[test]
    fn parses_frames_at_every_chunking() {
        let mut bytes = frame(crate::ninep::TGETATTR, 1, &[0u8; 20]);
        bytes.extend(frame(TFLUSH, 2, &1u16.to_le_bytes())); // Tflush oldtag=1
        bytes.extend(frame(crate::ninep::RCLUNK, 3, &[])); // 7-byte frame, no body
        bytes.extend(frame(crate::ninep::TWRITE, 4, &[0u8; 300]));
        for chunk in 1..=bytes.len() {
            let mut scan = FrameScanner::new();
            let seen = scan_all(&mut scan, &bytes, chunk);
            assert_eq!(
                seen,
                vec![
                    (crate::ninep::TGETATTR, 1, 0),
                    (TFLUSH, 2, 1),
                    (crate::ninep::RCLUNK, 3, 0),
                    (crate::ninep::TWRITE, 4, 0),
                ],
                "chunk size {chunk}"
            );
        }
    }

    #[test]
    fn oldtag_not_leaked_across_frames() {
        // A 9-byte frame leaves bytes in header[7..9]; the following short frame must not
        // report them as its oldtag.
        let mut bytes = frame(TFLUSH, 1, &7u16.to_le_bytes());
        bytes.extend(frame(crate::ninep::RCLUNK, 2, &[]));
        let mut scan = FrameScanner::new();
        let seen = scan_all(&mut scan, &bytes, bytes.len());
        assert_eq!(seen, vec![(TFLUSH, 1, 7), (crate::ninep::RCLUNK, 2, 0)]);
    }
}
