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

use crate::transport::NineTransport;
use futures_util::{SinkExt, StreamExt};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn to_io<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// Split `transport`, mount the v9fs client at `mountpoint`, and bridge bytes until either side
/// closes. Best-effort unmount on exit. `aname` is fixed to `/export` in the mount options below.
pub async fn mount9p(
    transport: Box<dyn NineTransport>,
    mountpoint: &Path,
    msize: usize,
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

    // sock -> transport: forward the kernel's 9p requests.
    let sock_to_transport = async move {
        let mut buf = vec![0u8; 1 << 17];
        loop {
            let n = bridge_rd.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            sink.send(buf[..n].to_vec()).await?;
        }
        Ok::<(), io::Error>(())
    };

    // transport -> sock: forward the server's 9p responses.
    let transport_to_sock = async move {
        while let Some(item) = stream.next().await {
            match item {
                Ok(chunk) => bridge_wr.write_all(&chunk).await?,
                Err(e) => return Err(e),
            }
        }
        Ok::<(), io::Error>(())
    };

    // 4. Perform mount(2) on a blocking thread while the pumps run on the async runtime. The
    // v9fs fd transport fget()s the fd and keeps its own reference, so once mount() returns we can
    // drop our copy of sock_kernel.
    let fd = sock_kernel.as_raw_fd();
    // `aname=/export`: a server like diod (`diod -e /export`) only honors attaches whose aname names
    // an exported path. A multiuser server running as root setfsuids per attach (root at mount, the
    // attaching uid for file ops), so no client `access=`/uid option is needed and file ownership
    // follows the accessing uid. `cache=loose` favors throughput for a single client.
    let data = format!(
        "trans=fd,rfdno={fd},wfdno={fd},version=9p2000.L,msize={msize},cache=loose,aname=/export"
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
        }
        tracing::info!(?mountpoint, "mount9p: mounted; bridging");
        // Keep pumping for the life of the mount.
        tokio::select! {
            r = &mut sock_to_transport => r.map_err(to_io)?,
            r = &mut transport_to_sock => r.map_err(to_io)?,
        }
        Ok(())
    }
    .await;

    // 5. Best-effort detach-unmount on exit so a dead transport doesn't leave a wedged mount.
    let _ = umount2(mountpoint, MntFlags::MNT_DETACH);
    result
}
