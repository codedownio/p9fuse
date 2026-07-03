//! End-to-end integration tests: mount a real `diod` export over FUSE (via the public
//! [`TcpTransport`]) and exercise POSIX semantics + write-back integrity against the underlying
//! export directory.
//!
//! The tests **skip gracefully** (printing why) when `diod`, `/dev/fuse`, or `fusermount3` are
//! unavailable, so `cargo test` is safe to run anywhere. In an environment that has them (e.g. the
//! nix dev shell, or CI with diod on `PATH`) they run for real. Point at a specific server binary
//! with `DIOD_BIN=/path/to/diod`.
//!
//! `diod` is run rootless in TCP-listen mode with `-n` (no auth) and `-N` (no userdb), and the
//! client attaches as the current uid, so `setfsuid` is a no-op and no privilege is required.

use futures_util::{SinkExt, StreamExt};
use p9fuse::{
    mount, NineClient, NineTransport, TcpTransport, Tuning, UnixTransport, WebSocketTransport,
};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const READY: &str = "__ready__";

// ---------------------------------------------------------------------------------------------
// Environment probing / skip support
// ---------------------------------------------------------------------------------------------

fn find_diod() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("DIOD_BIN") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    if let Ok(o) = Command::new("sh").arg("-c").arg("command -v diod").output() {
        if o.status.success() {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if !s.is_empty() {
                return Some(PathBuf::from(s));
            }
        }
    }
    // Fallback: a diod built into the nix store (useful on Nix/NixOS systems).
    if let Ok(rd) = std::fs::read_dir("/nix/store") {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().contains("diod") {
                let cand = e.path().join("bin/diod");
                if cand.exists() {
                    return Some(cand);
                }
            }
        }
    }
    None
}

fn fusermount_bin() -> Option<&'static str> {
    for bin in ["fusermount3", "fusermount", "/run/wrappers/bin/fusermount3"] {
        let ok = Command::new(bin)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return Some(bin);
        }
    }
    None
}

/// Returns the reason to skip, or `None` if the environment can run the test.
fn skip_reason() -> Option<String> {
    if find_diod().is_none() {
        return Some("diod not found (set DIOD_BIN or put diod on PATH)".into());
    }
    if !Path::new("/dev/fuse").exists() {
        return Some("/dev/fuse missing".into());
    }
    if fusermount_bin().is_none() {
        return Some("fusermount3 not available".into());
    }
    None
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A rootless `diod` serving a fresh temp directory over TCP. Killed on drop.
struct Diod {
    child: Child,
    export: TempDir,
    port: u16,
}

impl Diod {
    // The child is reaped in `Drop` (kill + wait); clippy can't see through the struct.
    #[allow(clippy::zombie_processes)]
    fn start() -> Diod {
        let diod = find_diod().expect("diod (checked by skip_reason)");
        let export = tempfile::tempdir().unwrap();
        let port = free_port();
        let child = Command::new(&diod)
            .args([
                "-f", // foreground
                "-n", // no auth
                "-N", // bypass userdb, so a rootless diod needs no passwd/group entry for our uid
                "-L",
                "stderr",
                "-l",
                &format!("127.0.0.1:{port}"),
                "-e",
                export.path().to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn diod");

        // Wait for diod to accept connections before anyone attaches.
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Diod {
                    child,
                    export,
                    port,
                };
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("diod did not start listening on 127.0.0.1:{port}");
    }

    fn export(&self) -> &Path {
        self.export.path()
    }
}

impl Drop for Diod {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn umount(mp: &Path) {
    if let Some(bin) = fusermount_bin() {
        let ok = Command::new(bin)
            .arg("-u")
            .arg(mp)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return;
        }
    }
    let _ = Command::new("umount").arg(mp).status();
}

/// Which transport to reach diod through. Non-TCP transports use a tiny in-test relay that bridges
/// to diod's TCP port, so all three transports exercise the same server.
#[derive(Clone, Copy)]
enum Via {
    Tcp,
    Unix,
    Ws,
}

/// A resolved connect target handed to the mount task.
enum Connect {
    Tcp(String),
    Unix(PathBuf),
    Ws(String),
}

async fn connect_transport(c: Connect) -> Result<Box<dyn NineTransport>, String> {
    Ok(match c {
        Connect::Tcp(a) => Box::new(TcpTransport::connect(&a).await.map_err(|e| e.to_string())?),
        Connect::Unix(p) => Box::new(
            UnixTransport::connect(&p)
                .await
                .map_err(|e| e.to_string())?,
        ),
        Connect::Ws(u) => Box::new(
            WebSocketTransport::connect(&u, &[])
                .await
                .map_err(|e| e.to_string())?,
        ),
    })
}

/// Accept Unix connections at `sock` and splice each to a fresh TCP connection to `tcp_addr`.
async fn spawn_unix_relay(sock: PathBuf, tcp_addr: String) -> tokio::task::JoinHandle<()> {
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let tcp_addr = tcp_addr.clone();
            tokio::spawn(async move {
                if let Ok(mut up) = tokio::net::TcpStream::connect(&tcp_addr).await {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
                }
            });
        }
    })
}

/// A websocket server (ephemeral port) that carries each 9p chunk as a binary frame to/from a TCP
/// connection to `tcp_addr` -- mirrors a real ws-fronted 9p endpoint bridging to its server.
async fn spawn_ws_relay(tcp_addr: String) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let tcp_addr = tcp_addr.clone();
            tokio::spawn(async move {
                let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let Ok(up) = tokio::net::TcpStream::connect(&tcp_addr).await else {
                    return;
                };
                ws_tcp_bridge(ws, up).await;
            });
        }
    });
    (port, handle)
}

async fn ws_tcp_bridge(
    ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    tcp: tokio::net::TcpStream,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::Message;
    let (mut ws_tx, mut ws_rx) = ws.split();
    let (mut rd, mut wr) = tcp.into_split();
    let c2s = async move {
        while let Some(Ok(msg)) = ws_rx.next().await {
            if let Message::Binary(b) = msg {
                if wr.write_all(&b).await.is_err() {
                    break;
                }
            }
        }
    };
    let s2c = async move {
        let mut buf = vec![0u8; 1 << 16];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ws_tx
                        .send(Message::Binary(buf[..n].to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    };
    tokio::select! { _ = c2s => {}, _ = s2c => {} }
}

/// Start diod, reach it via `via`, FUSE-mount the export with `tuning`, wait until the mount is live,
/// run `body` (on a blocking thread, with the mountpoint path), then unmount and tear down. Any panic
/// in `body` propagates to fail the test.
async fn with_mount_via<F>(via: Via, tuning: Tuning, body: F)
where
    F: FnOnce(&Path) + Send + 'static,
{
    let diod = Diod::start();
    // Seed a readiness sentinel in the export; it appears through the mount once FUSE is live.
    std::fs::write(diod.export().join(READY), b"1").unwrap();

    let tcp_addr = format!("127.0.0.1:{}", diod.port);
    let aname = diod.export().to_string_lossy().into_owned();
    let uid = unsafe { libc::geteuid() };

    // Resolve the connect target, starting a relay to diod's TCP port for non-TCP transports.
    let reldir = tempfile::tempdir().unwrap();
    let mut relays: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    let connect = match via {
        Via::Tcp => Connect::Tcp(tcp_addr.clone()),
        Via::Unix => {
            let sock = reldir.path().join("9p.sock");
            relays.push(spawn_unix_relay(sock.clone(), tcp_addr.clone()).await);
            Connect::Unix(sock)
        }
        Via::Ws => {
            let (port, h) = spawn_ws_relay(tcp_addr.clone()).await;
            relays.push(h);
            Connect::Ws(format!("ws://127.0.0.1:{port}"))
        }
    };

    let mountpoint = tempfile::tempdir().unwrap();
    let mp = mountpoint.path().to_path_buf();
    let mp_task = mp.clone();
    // The task output must be Send, and mount()'s Box<dyn Error> isn't -- stringify it.
    let task = tokio::spawn(async move {
        let transport = connect_transport(connect).await?;
        // `mount` blocks until unmounted; the error (if any) surfaces after umount below.
        mount(transport, &mp_task, 512_000, uid, &aname, tuning)
            .await
            .map_err(|e| e.to_string())
    });

    // Wait for the mount to become live (sentinel visible through FUSE).
    let ready_path = mp.join(READY);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if tokio::fs::try_exists(&ready_path).await.unwrap_or(false) {
            break;
        }
        if Instant::now() >= deadline {
            umount(&mp);
            let _ = task.await;
            panic!("mount did not become ready within 15s");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let mp_body = mp.clone();
    let outcome = tokio::task::spawn_blocking(move || body(&mp_body)).await;

    umount(&mp);
    let mount_result = task.await.expect("mount task join");
    for h in relays {
        h.abort();
    }

    // Surface a body panic first (more informative), then any mount error.
    outcome.expect("test body panicked");
    mount_result.expect("mount() returned an error");
    drop(diod);
    drop(reldir);
    drop(mountpoint);
}

/// Convenience: mount over TCP (the common case).
async fn with_mount<F>(tuning: Tuning, body: F)
where
    F: FnOnce(&Path) + Send + 'static,
{
    with_mount_via(Via::Tcp, tuning, body).await;
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

/// Reads, writes, mkdir, symlink/readlink, rename, unlink, and chmod all round-trip between the FUSE
/// mount and the underlying export.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn posix_semantics() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP posix_semantics: {reason}");
        return;
    }

    with_mount(Tuning::default(), move |mp| {
        // 1. read a file that the harness pre-seeds (READY) -- proves reads work.
        assert_eq!(std::fs::read(mp.join(READY)).unwrap(), b"1");

        // 2. write a new file through the mount; read it back through the mount.
        std::fs::write(mp.join("w.txt"), b"written via 9p").unwrap();
        assert_eq!(std::fs::read(mp.join("w.txt")).unwrap(), b"written via 9p");

        // 3. mkdir + nested file.
        std::fs::create_dir(mp.join("d")).unwrap();
        std::fs::write(mp.join("d/n.txt"), b"nested").unwrap();
        assert!(mp.join("d").is_dir());
        assert_eq!(std::fs::read(mp.join("d/n.txt")).unwrap(), b"nested");

        // 4. chmod: set an unusual mode and read it back (full POSIX-mode fidelity over 9p).
        std::fs::set_permissions(mp.join("w.txt"), std::fs::Permissions::from_mode(0o640)).unwrap();
        let mode = std::fs::metadata(mp.join("w.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640, "chmod did not round-trip through 9p");

        // 5. symlink + readlink.
        std::os::unix::fs::symlink("w.txt", mp.join("link")).unwrap();
        assert_eq!(
            std::fs::read_link(mp.join("link")).unwrap(),
            Path::new("w.txt")
        );
        // Following the symlink reads the target's contents.
        assert_eq!(std::fs::read(mp.join("link")).unwrap(), b"written via 9p");

        // 6. rename: reflected in readdir, and the destination reads back (fid-refresh on rename).
        std::fs::rename(mp.join("w.txt"), mp.join("renamed.txt")).unwrap();
        let listing: Vec<String> = std::fs::read_dir(mp)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            listing.contains(&"renamed.txt".to_string()) && !listing.contains(&"w.txt".to_string()),
            "rename not reflected in directory listing: {listing:?}"
        );
        assert!(!mp.join("w.txt").exists());
        assert_eq!(
            std::fs::read(mp.join("renamed.txt")).unwrap(),
            b"written via 9p"
        );

        // 7. unlink + rmdir.
        std::fs::remove_file(mp.join("renamed.txt")).unwrap();
        assert!(!mp.join("renamed.txt").exists());
        std::fs::remove_file(mp.join("link")).unwrap();
        assert!(!mp.join("link").exists());
        std::fs::remove_file(mp.join("d/n.txt")).unwrap();
        std::fs::remove_dir(mp.join("d")).unwrap();
        assert!(!mp.join("d").exists());
    })
    .await;
}

/// A `mv a b; cat b` round-trip. This exercises the rename fid-refresh: diod binds fids to paths, so
/// after a rename the moved inode's persistent fid is stale; the bridge re-walks to the new name and
/// swaps in a fresh fid, so reading the destination back (no fresh lookup -- the kernel reuses the
/// moved dentry) still works.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rename_then_read() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP rename_then_read: {reason}");
        return;
    }
    with_mount(Tuning::default(), move |mp| {
        std::fs::write(mp.join("a.txt"), b"payload").unwrap();
        std::fs::rename(mp.join("a.txt"), mp.join("b.txt")).unwrap();
        assert_eq!(std::fs::read(mp.join("b.txt")).unwrap(), b"payload");
    })
    .await;
}

/// A multi-megabyte write with write-back pipelining round-trips byte-for-byte, and the file's size
/// is correct on the server side.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writeback_large_file() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP writeback_large_file: {reason}");
        return;
    }

    // A deterministic, well-mixed 4 MiB payload (no rng dependency; wrapping avoids debug overflow).
    let payload: Vec<u8> = (0..4u64 * 1024 * 1024)
        .map(|i| i.wrapping_mul(2654435761).rotate_right(13) as u8)
        .collect();
    let expected = payload.clone();

    with_mount(Tuning::default(), move |mp| {
        let path = mp.join("big.bin");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            // Write in odd-sized chunks to exercise the write-back pipeline across offsets.
            for chunk in payload.chunks(7919) {
                f.write_all(chunk).unwrap();
            }
            f.sync_all().unwrap(); // flush the pipeline
        }
        let got = std::fs::read(&path).unwrap();
        assert_eq!(got.len(), expected.len(), "size mismatch after write-back");
        assert!(got == expected, "content mismatch after write-back");
    })
    .await;
}

/// `mv src dst` where `dst` already exists: the overwritten file's inode is discarded and `dst` now
/// serves `src`'s contents through the refreshed fid.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rename_over_existing() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP rename_over_existing: {reason}");
        return;
    }
    with_mount(Tuning::default(), move |mp| {
        std::fs::write(mp.join("src"), b"SRC").unwrap();
        std::fs::write(mp.join("dst"), b"DST-old").unwrap();
        std::fs::rename(mp.join("src"), mp.join("dst")).unwrap();
        assert!(!mp.join("src").exists());
        assert_eq!(std::fs::read(mp.join("dst")).unwrap(), b"SRC");
    })
    .await;
}

/// Protocol-level (no FUSE): isolate whether a rename followed by a walk to the new name works at
/// the raw 9p layer, below the FUSE inode/fid bookkeeping.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_rename_then_walk() {
    if find_diod().is_none() {
        eprintln!("SKIP client_rename_then_walk: diod not found");
        return;
    }
    let diod = Diod::start();
    let addr = format!("127.0.0.1:{}", diod.port);
    let aname = diod.export().to_string_lossy().into_owned();
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };

    let transport = Box::new(TcpTransport::connect(&addr).await.unwrap());
    let (client, _root) = NineClient::connect(transport, 512_000, uid, &aname)
        .await
        .unwrap();
    let root = client.root_fid;

    // Create "a.txt" (lcreate opens `dfid` on the new file, so clone root into a scratch fid first).
    let dfid = client.alloc_fid();
    client.walk(root, dfid, &[]).await.unwrap();
    client
        .lcreate(dfid, "a.txt", libc::O_WRONLY as u32, 0o644, gid)
        .await
        .unwrap();
    client.clunk(dfid).await.unwrap();

    // Sanity: walk to a.txt succeeds before the rename.
    let f1 = client.alloc_fid();
    client
        .walk(root, f1, &["a.txt"])
        .await
        .expect("walk a.txt before rename");
    client.clunk(f1).await.unwrap();

    // Rename a.txt -> b.txt, then walk to b.txt from a fresh clone of root.
    client
        .renameat(root, "a.txt", root, "b.txt")
        .await
        .expect("renameat");
    let f2 = client.alloc_fid();
    let walk_b = client.walk(root, f2, &["b.txt"]).await;
    let _ = client.clunk(f2).await;

    assert!(
        walk_b.is_ok(),
        "walk to renamed file failed at the 9p layer: {walk_b:?}"
    );
}

/// With write-back disabled, each write is a synchronous round-trip -- data must still be intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn synchronous_writes() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP synchronous_writes: {reason}");
        return;
    }
    let tuning = Tuning {
        writeback: false,
        ..Tuning::default()
    };
    with_mount(tuning, move |mp| {
        let path = mp.join("sync.txt");
        std::fs::write(&path, b"no writeback, one Twrite per write").unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"no writeback, one Twrite per write"
        );
    })
    .await;
}

/// The same core ops over the Unix-socket transport (relayed to diod's TCP port).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unix_transport() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP unix_transport: {reason}");
        return;
    }
    with_mount_via(Via::Unix, Tuning::default(), |mp| {
        std::fs::write(mp.join("u.txt"), b"over a unix socket").unwrap();
        assert_eq!(
            std::fs::read(mp.join("u.txt")).unwrap(),
            b"over a unix socket"
        );
        std::fs::create_dir(mp.join("ud")).unwrap();
        assert!(mp.join("ud").is_dir());
    })
    .await;
}

/// Core ops over the WebSocket transport, with a payload big enough to span many binary frames --
/// exercises the ws `Message` <-> byte-chunk mapping and frame reassembly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_transport() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP websocket_transport: {reason}");
        return;
    }
    with_mount_via(Via::Ws, Tuning::default(), |mp| {
        let data = vec![0x5au8; 200_000];
        std::fs::write(mp.join("w.bin"), &data).unwrap();
        assert_eq!(std::fs::read(mp.join("w.bin")).unwrap(), data);
    })
    .await;
}

/// `statfs` (df) reports a non-zero block size and capacity.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn statfs_reports_capacity() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP statfs_reports_capacity: {reason}");
        return;
    }
    with_mount(Tuning::default(), |mp| {
        let cpath = std::ffi::CString::new(mp.to_str().unwrap()).unwrap();
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::statvfs(cpath.as_ptr(), &mut st) }, 0);
        assert!(st.f_bsize > 0, "block size should be non-zero");
        assert!(st.f_blocks > 0, "total blocks should be non-zero");
    })
    .await;
}

/// Truncating (via `setattr` size) shrinks and grows a file; growth zero-fills.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn truncate_grow_and_shrink() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP truncate_grow_and_shrink: {reason}");
        return;
    }
    with_mount(Tuning::default(), |mp| {
        let p = mp.join("t");
        std::fs::write(&p, b"0123456789").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&p)
            .unwrap()
            .set_len(4)
            .unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"0123");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&p)
            .unwrap()
            .set_len(8)
            .unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"0123\0\0\0\0");
    })
    .await;
}

/// Setting mtime (via `setattr`) round-trips.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn set_modified_time() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP set_modified_time: {reason}");
        return;
    }
    with_mount(Tuning::default(), |mp| {
        let p = mp.join("m");
        std::fs::write(&p, b"x").unwrap();
        let t = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(t)
            .unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().modified().unwrap(),
            t,
            "mtime did not round-trip through setattr"
        );
    })
    .await;
}

/// Overwriting at an offset on a *write-only* handle: with the writeback cache on this is a
/// partial-page read-modify-write, so the kernel issues reads on the write-only handle -- which only
/// works because `open` upgrades write-only opens to O_RDWR under writeback (else the server EBADFs).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offset_writes() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP offset_writes: {reason}");
        return;
    }
    with_mount(Tuning::default(), |mp| {
        use std::io::{Seek, SeekFrom, Write};
        let p = mp.join("o");
        std::fs::write(&p, b"hello world").unwrap();
        let mut f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        f.seek(SeekFrom::Start(6)).unwrap();
        f.write_all(b"WORLD").unwrap();
        drop(f);
        assert_eq!(std::fs::read(&p).unwrap(), b"hello WORLD");
    })
    .await;
}

/// Appending (O_APPEND) lands at end-of-file. Tested with write-back off: under the FUSE writeback
/// cache the kernel handles O_APPEND itself, which is not reliable, so append semantics are only
/// well-defined in the synchronous (writeback-off) mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn append_writes() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP append_writes: {reason}");
        return;
    }
    let tuning = Tuning {
        writeback: false,
        ..Tuning::default()
    };
    with_mount(tuning, |mp| {
        use std::io::Write;
        let p = mp.join("a");
        std::fs::write(&p, b"hello").unwrap();
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b" world").unwrap();
        drop(f);
        assert_eq!(std::fs::read(&p).unwrap(), b"hello world");
    })
    .await;
}

/// A directory with enough entries to span multiple `Treaddir` round-trips lists every entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_directory_readdir() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP large_directory_readdir: {reason}");
        return;
    }
    with_mount(Tuning::default(), |mp| {
        let n = 300;
        for i in 0..n {
            std::fs::write(mp.join(format!("f{i:04}")), b"x").unwrap();
        }
        let names: std::collections::HashSet<String> = std::fs::read_dir(mp)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        for i in 0..n {
            assert!(names.contains(&format!("f{i:04}")), "missing f{i:04}");
        }
    })
    .await;
}

/// Error mappings: ENOENT, EEXIST (O_EXCL / mkdir), ENOTEMPTY, ENOTDIR.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn error_paths() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP error_paths: {reason}");
        return;
    }
    with_mount(Tuning::default(), |mp| {
        use std::io::ErrorKind;
        // Missing file.
        assert_eq!(
            std::fs::read(mp.join("nope")).unwrap_err().kind(),
            ErrorKind::NotFound
        );
        // Exclusive create over an existing file.
        std::fs::write(mp.join("e"), b"1").unwrap();
        let excl = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(mp.join("e"))
            .unwrap_err();
        assert_eq!(excl.kind(), ErrorKind::AlreadyExists);
        // mkdir over an existing directory.
        std::fs::create_dir(mp.join("d")).unwrap();
        assert_eq!(
            std::fs::create_dir(mp.join("d")).unwrap_err().kind(),
            ErrorKind::AlreadyExists
        );
        // rmdir on a non-empty directory.
        std::fs::write(mp.join("d/x"), b"1").unwrap();
        assert_eq!(
            std::fs::remove_dir(mp.join("d"))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOTEMPTY)
        );
        // Descend into a non-directory.
        assert_eq!(
            std::fs::create_dir(mp.join("e/sub"))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOTDIR)
        );
    })
    .await;
}
