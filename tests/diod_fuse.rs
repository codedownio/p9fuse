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

// Test data is made by truncating random numbers on purpose.
#![allow(clippy::cast_possible_truncation)]

use futures_util::{SinkExt, StreamExt};
use p9fuse::{
    mount_with_invalidations, NineClient, NineTransport, TcpTransport, Tuning, UnixTransport,
    WebSocketTransport,
};
use std::io::{BufRead, Write};
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
    /// Start diod on a free port. The port is only free when we look: another test may take it
    /// before diod binds it, so wait for diod itself to say it is listening, and try another port
    /// if it couldn't bind.
    fn start() -> Diod {
        let diod = find_diod().expect("diod (checked by skip_reason)");
        let export = tempfile::tempdir().unwrap();
        for _ in 0..20 {
            let port = free_port();
            let mut child = Command::new(&diod)
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
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn diod");
            if diod_listening(&mut child) && accepting(port) {
                return Diod {
                    child,
                    export,
                    port,
                };
            }
            let _ = child.kill();
            let _ = child.wait();
        }
        panic!("diod could not start listening on a free port");
    }

    fn export(&self) -> &Path {
        self.export.path()
    }
}

/// Read diod's log until it says it is listening (true) or exits without doing so (false). The rest
/// of the log is drained in the background so diod never blocks writing it.
fn diod_listening(child: &mut Child) -> bool {
    let stderr = child.stderr.take().expect("diod stderr piped");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut lines = std::io::BufReader::new(stderr).lines();
        for line in lines.by_ref() {
            match line {
                Ok(l) if l.starts_with("Listening on ") => {
                    let _ = tx.send(true);
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let _ = tx.send(false);
        for _ in lines {}
    });
    rx.recv_timeout(Duration::from_secs(10)).unwrap_or(false)
}

/// Wait until a connection to `port` succeeds. diod logs that it is listening once it has bound the
/// port but before it calls listen(), so a connection made right then can be refused.
fn accepting(port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

impl Drop for Diod {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Unmount `mp`. Retries for a few seconds first: a desktop service probing new mounts (GNOME's
/// gvfsd-trash looks up a trash folder in each one) holds the mount busy while its lookup is in
/// flight. Then falls back to a lazy unmount, which detaches the mount at once.
fn umount(mp: &Path) {
    let Some(bin) = fusermount_bin() else {
        let _ = Command::new("umount").arg(mp).status();
        return;
    };
    let run = |args: &[&str]| {
        Command::new(bin)
            .args(args)
            .arg(mp)
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if run(&["-u"]) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !run(&["-u", "-z"]) {
        eprintln!("couldn't unmount {}", mp.display());
    }
}

/// Unmount `mp` and wait for its mount task to end, failing instead of hanging if it doesn't.
async fn unmount_and_join(
    mp: &Path,
    task: tokio::task::JoinHandle<Result<(), String>>,
) -> Result<(), String> {
    umount(mp);
    match tokio::time::timeout(Duration::from_secs(30), task).await {
        Ok(joined) => joined.expect("mount task join"),
        Err(_) => panic!(
            "mount of {} still running 30s after unmounting",
            mp.display()
        ),
    }
}

/// Run the binary to mount `diod`'s export at `mp`, keeping its stdin open, and wait until the
/// mount is up.
fn spawn_binary(diod: &Diod, mp: &Path) -> Child {
    std::fs::write(diod.export().join(READY), b"1").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_p9fuse"))
        .arg("mount9p-fuse")
        .arg(format!("--connect=tcp://127.0.0.1:{}", diod.port))
        .arg(format!("--uid={}", nix::unistd::geteuid()))
        .arg("--aname")
        .arg(diod.export())
        .arg(mp)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn p9fuse");
    let deadline = Instant::now() + Duration::from_secs(15);
    while !mp.join(READY).exists() {
        assert!(child.try_wait().unwrap().is_none(), "p9fuse exited early");
        assert!(Instant::now() < deadline, "mount did not become ready");
        std::thread::sleep(Duration::from_millis(50));
    }
    child
}

/// Wait up to `limit` for `child` to exit.
fn wait_exit(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

/// A child process killed when dropped.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
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

/// What a test body gets: the mountpoint, the export directory behind it (to change files from
/// outside the mount), and a socket to send the mount invalidation requests and read their replies.
struct Mounted<'a> {
    mp: &'a Path,
    export: &'a Path,
    inval: std::os::unix::net::UnixStream,
}

/// Start diod, reach it via `via`, FUSE-mount the export with `tuning`, wait until the mount is live,
/// run `body` (on a blocking thread, with the mountpoint path), then unmount and tear down. Any panic
/// in `body` propagates to fail the test.
async fn with_mount_via<F>(via: Via, tuning: Tuning, body: F)
where
    F: FnOnce(&Path) + Send + 'static,
{
    with_mount_full(via, tuning, |m| body(m.mp)).await;
}

/// [`with_mount_via`], but the body also gets the export directory and the invalidation input.
async fn with_mount_full<F>(via: Via, tuning: Tuning, body: F)
where
    F: FnOnce(Mounted<'_>) + Send + 'static,
{
    let diod = Diod::start();
    // Seed a readiness sentinel in the export; it appears through the mount once FUSE is live.
    std::fs::write(diod.export().join(READY), b"1").unwrap();

    let tcp_addr = format!("127.0.0.1:{}", diod.port);
    let aname = diod.export().to_string_lossy().into_owned();
    let uid = nix::unistd::geteuid().as_raw();

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

    let (inval_tx, inval_rx) = std::os::unix::net::UnixStream::pair().unwrap();
    inval_rx.set_nonblocking(true).unwrap();
    let (inval_rx, inval_replies) = tokio::net::UnixStream::from_std(inval_rx)
        .unwrap()
        .into_split();

    let mountpoint = tempfile::tempdir().unwrap();
    let mp = mountpoint.path().to_path_buf();
    let mp_task = mp.clone();
    // The task output must be Send, and mount()'s Box<dyn Error> isn't -- stringify it.
    let task = tokio::spawn(async move {
        let transport = connect_transport(connect).await?;
        // `mount` blocks until unmounted; the error (if any) surfaces after umount below.
        mount_with_invalidations(
            transport,
            &mp_task,
            512_000,
            uid,
            &aname,
            tuning,
            Box::new(inval_rx),
            Box::new(inval_replies),
        )
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
        if task.is_finished() {
            let result = task.await.expect("mount task join");
            panic!("mount ended before it became ready: {result:?}");
        }
        if Instant::now() >= deadline {
            let _ = unmount_and_join(&mp, task).await;
            panic!("mount did not become ready within 15s");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let mp_body = mp.clone();
    let export = diod.export().to_path_buf();
    let outcome = tokio::task::spawn_blocking(move || {
        body(Mounted {
            mp: &mp_body,
            export: &export,
            inval: inval_tx,
        })
    })
    .await;

    let mount_result = unmount_and_join(&mp, task).await;
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
/// is correct on the server side. Run with the kernel writeback cache both off and on.
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
    for writeback_cache in [false, true] {
        let payload = payload.clone();
        let expected = payload.clone();
        let tuning = Tuning {
            writeback_cache,
            ..Tuning::default()
        };
        with_mount(tuning, move |mp| {
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

/// With READDIRPLUS, listing a directory returns its ".." entry, which must not become the parent's
/// fid: diod resolves fids by path, so "child/.." stops working once the child is removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn readdirplus_dotdot_leaves_parent_usable() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP readdirplus_dotdot_leaves_parent_usable: {reason}");
        return;
    }
    let tuning = Tuning {
        readdirplus: true,
        ..Tuning::default()
    };
    with_mount(tuning, move |mp| {
        std::fs::create_dir_all(mp.join("parent/child")).unwrap();
        std::fs::write(mp.join("parent/child/f"), b"x").unwrap();
        // `ls -F` marks directories from the entry type alone, without stat.
        let ls = Command::new("ls")
            .args(["-aF", "--", mp.join("parent/child").to_str().unwrap()])
            .output()
            .unwrap();
        let ls = String::from_utf8(ls.stdout).unwrap();
        assert_eq!(ls.lines().collect::<Vec<_>>(), ["./", "../", "f"]);

        std::fs::remove_file(mp.join("parent/child/f")).unwrap();
        std::fs::remove_dir(mp.join("parent/child")).unwrap();
        std::fs::write(mp.join("parent/g"), b"y").unwrap();
        assert_eq!(std::fs::read(mp.join("parent/g")).unwrap(), b"y");
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
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();

    let transport = Box::new(TcpTransport::connect(&addr).await.unwrap());
    let (client, _root) =
        NineClient::connect(transport, 512_000, uid, &aname, Duration::from_secs(0))
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

/// With the write pipeline off, each write is a synchronous round-trip -- data must still be intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn synchronous_writes() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP synchronous_writes: {reason}");
        return;
    }
    let tuning = Tuning {
        write_pipeline: false,
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

/// A file grown from outside the mount reads back whole once invalidated, even while an open fd keeps
/// its inode cached. Under the FUSE writeback cache the kernel keeps its own stale size for the
/// pinned inode and the read comes back cut to the old length, which is why the cache is off by
/// default.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn external_growth_with_pinned_inode() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP external_growth_with_pinned_inode: {reason}");
        return;
    }
    with_mount_full(Via::Tcp, Tuning::default(), |mut m| {
        let long: &[u8] = b"#let title = \"Changed in the export\"";
        std::fs::write(m.export.join("f"), b"#let title = \"Original\"").unwrap();
        assert_eq!(
            std::fs::read(m.mp.join("f")).unwrap(),
            b"#let title = \"Original\""
        );

        let _pin = std::fs::File::open(m.mp.join("f")).unwrap();
        std::fs::write(m.export.join("f"), long).unwrap();
        writeln!(m.inval, "inval 1 f").unwrap();
        let mut reply = String::new();
        std::io::BufReader::new(&m.inval)
            .read_line(&mut reply)
            .unwrap();
        assert_eq!(reply, "ok 1\n");

        let got = std::fs::read(m.mp.join("f")).unwrap();
        assert_eq!(String::from_utf8_lossy(&got), String::from_utf8_lossy(long));
    })
    .await;
}

/// Invalidating paths deeper than one `Twalk` can carry (16 names), existing or not, works and
/// doesn't break the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalidate_deep_path() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP invalidate_deep_path: {reason}");
        return;
    }
    with_mount_full(Via::Tcp, Tuning::default(), |mut m| {
        let dir = "d/".repeat(20);
        std::fs::create_dir_all(m.export.join(&dir)).unwrap();
        std::fs::write(m.export.join(format!("{dir}f")), b"old").unwrap();
        assert_eq!(std::fs::read(m.mp.join(format!("{dir}f"))).unwrap(), b"old");

        std::fs::write(m.export.join(format!("{dir}f")), b"new").unwrap();
        writeln!(m.inval, "inval 1 {dir}f").unwrap();
        let mut reply = String::new();
        std::io::BufReader::new(&m.inval)
            .read_line(&mut reply)
            .unwrap();
        assert_eq!(reply, "ok 1\n");

        assert_eq!(std::fs::read(m.mp.join(format!("{dir}f"))).unwrap(), b"new");

        // Fails in the second Twalk, after the first has established the fid.
        writeln!(m.inval, "inval 2 {dir}missing/{dir}f").unwrap();
        let mut reply = String::new();
        std::io::BufReader::new(&m.inval)
            .read_line(&mut reply)
            .unwrap();
        assert_eq!(reply, "ok 2\n");
        assert_eq!(std::fs::read(m.mp.join(format!("{dir}f"))).unwrap(), b"new");
    })
    .await;
}

/// `stat` and a read through a second fd see every write made so far on a still-open writer, even
/// though the write pipeline has acknowledged writes the server may not have yet. Without the
/// writeback cache the kernel takes size and data from us, so we have to wait for those writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stat_and_read_see_pipelined_writes() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP stat_and_read_see_pipelined_writes: {reason}");
        return;
    }
    with_mount(Tuning::default(), |mp| {
        const LEN: u64 = 64 * 131072;
        for trial in 0..10 {
            let p = mp.join(format!("t{trial}"));
            let mut w = std::fs::File::create(&p).unwrap();
            for i in 0..64u8 {
                w.write_all(&[b'A' + i % 26; 131072]).unwrap();
            }

            let size = std::fs::metadata(&p).unwrap().len();
            let read = std::fs::read(&p).unwrap().len() as u64;
            assert_eq!(
                (size, read),
                (LEN, LEN),
                "trial {trial}: (stat, read) lengths"
            );
        }
    })
    .await;
}

/// Writes held back for merging still reach the server when the application stops writing and
/// neither closes nor stats the file: the write that was in flight sends them when it finishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn merged_writes_reach_server_without_close() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP merged_writes_reach_server_without_close: {reason}");
        return;
    }
    let tuning = Tuning {
        wb_depth: 1,
        ..Tuning::default()
    };
    with_mount_full(Via::Tcp, tuning, |m| {
        let mut f = std::fs::File::create(m.mp.join("m")).unwrap();
        let mut expected = Vec::new();
        // Small writes, then a large one immediately followed by a small one: the last write
        // arrives while the large one is in flight, so it is held back.
        let mut chunks: Vec<Vec<u8>> = (0..256u32).map(|i| vec![(i % 251) as u8; 1000]).collect();
        chunks.push(vec![b'L'; 400_000]);
        chunks.push(vec![b'E'; 1000]);
        for chunk in chunks {
            f.write_all(&chunk).unwrap();
            expected.extend_from_slice(&chunk);
        }

        // Read the export directly, so nothing on the mount side forces the writes out.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut got = std::fs::read(m.export.join("m")).unwrap();
        while got != expected && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
            got = std::fs::read(m.export.join("m")).unwrap();
        }
        assert_eq!(got.len(), expected.len(), "bytes on the server");
        assert!(got == expected, "contents on the server");
        drop(f);
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
        // SAFETY: statvfs is a plain C struct, for which all zeroes is a valid value.
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: `cpath` is NUL-terminated and `st` is a live statvfs.
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
/// works because `open` upgrades write-only opens to O_RDWR under the cache (else the server EBADFs).
/// Run with the cache both on and off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offset_writes() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP offset_writes: {reason}");
        return;
    }
    for writeback_cache in [false, true] {
        let tuning = Tuning {
            writeback_cache,
            ..Tuning::default()
        };
        with_mount(tuning, |mp| {
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
}

/// The write modes: the default (pipeline, no kernel cache), the same with a pipeline one write
/// deep (so nearly every write arriving while another is in flight is merged), pipeline plus kernel
/// writeback cache, and fully synchronous writes.
fn write_modes() -> [(&'static str, Tuning); 4] {
    [
        ("pipeline", Tuning::default()),
        (
            "pipeline depth 1",
            Tuning {
                wb_depth: 1,
                ..Tuning::default()
            },
        ),
        (
            "pipeline+cache",
            Tuning {
                writeback_cache: true,
                ..Tuning::default()
            },
        ),
        (
            "sync",
            Tuning {
                write_pipeline: false,
                ..Tuning::default()
            },
        ),
    ]
}

/// A small deterministic PRNG (xorshift64*), so the randomized tests need no extra dependency and
/// a failure reproduces.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Many O_APPEND writes land at end-of-file in the order they were made, in every write mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn append_writes() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP append_writes: {reason}");
        return;
    }
    for (mode, tuning) in write_modes() {
        with_mount(tuning, move |mp| {
            use std::io::Write;
            let p = mp.join("a");
            std::fs::write(&p, b"start:").unwrap();
            let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
            let mut expected = b"start:".to_vec();
            for i in 0..64u8 {
                let chunk = [b'A' + i % 26; 8192];
                f.write_all(&chunk).unwrap();
                expected.extend_from_slice(&chunk);
            }
            drop(f);

            let got = std::fs::read(&p).unwrap();
            assert!(got == expected, "{mode}: appends out of order or lost");
        })
        .await;
    }
}

/// Rewriting the same region over and over leaves the last write's data, in every write mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overlapping_writes_keep_order() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP overlapping_writes_keep_order: {reason}");
        return;
    }
    for (mode, tuning) in write_modes() {
        with_mount(tuning, move |mp| {
            use std::os::unix::fs::FileExt;
            for trial in 0..10 {
                let p = mp.join(format!("o{trial}"));
                let f = std::fs::File::create(&p).unwrap();
                for i in 0..64u8 {
                    f.write_all_at(&[i; 262_144], 0).unwrap();
                }
                drop(f);

                let got = std::fs::read(&p).unwrap();
                assert!(
                    got == [63u8; 262_144],
                    "{mode}: trial {trial}: an older write won"
                );
            }
        })
        .await;
    }
}

/// Random writes (small and large, overlapping, through two handles on the same file), truncates
/// and mid-way stat/read checks all agree with an in-memory copy of the file, in every write mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn random_writes_match_model() {
    if let Some(reason) = skip_reason() {
        eprintln!("SKIP random_writes_match_model: {reason}");
        return;
    }
    for (mode, tuning) in write_modes() {
        with_mount(tuning, move |mp| {
            use std::os::unix::fs::FileExt;
            let p = mp.join("r");
            let a = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&p)
                .unwrap();
            let b = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
            let mut model: Vec<u8> = Vec::new();
            let mut rng = Rng(0x9E3779B97F4A7C15);
            for step in 0..3000u32 {
                let f = if rng.below(4) == 0 { &b } else { &a };
                match rng.below(40) {
                    0 => {
                        let len = rng.below(300_000) as usize;
                        f.set_len(len as u64).unwrap();
                        model.resize(len, 0);
                    }
                    1 | 2 => {
                        let size = std::fs::metadata(&p).unwrap().len();
                        let got = std::fs::read(&p).unwrap();
                        assert_eq!(size, model.len() as u64, "{mode}: step {step}: stat size");
                        assert!(got == model, "{mode}: step {step}: contents differ");
                    }
                    _ => {
                        // Mostly runs of small sequential writes, with some big ones and jumps.
                        let off = if rng.below(3) == 0 {
                            rng.below(262_144) as usize
                        } else {
                            model.len().min(262_144)
                        };
                        let len = 1 + if rng.below(5) == 0 {
                            rng.below(131_072)
                        } else {
                            rng.below(4096)
                        } as usize;
                        let data: Vec<u8> = (0..len).map(|i| (step as usize + i) as u8).collect();
                        f.write_all_at(&data, off as u64).unwrap();
                        if model.len() < off + len {
                            model.resize(off + len, 0);
                        }
                        model[off..off + len].copy_from_slice(&data);
                    }
                }
            }
            drop(a);
            drop(b);

            let got = std::fs::read(&p).unwrap();
            assert_eq!(got.len(), model.len(), "{mode}: final size");
            assert!(got == model, "{mode}: final contents differ");
        })
        .await;
    }
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

/// The binary exits once unmounted, even while whoever started it keeps its stdin open.
#[test]
fn binary_exits_after_unmount_with_stdin_open() {
    if let Some(why) = skip_reason() {
        eprintln!("skipping: {why}");
        return;
    }
    let diod = Diod::start();
    let mountpoint = tempfile::tempdir().unwrap();
    let mut child = KillOnDrop(spawn_binary(&diod, mountpoint.path()));

    umount(mountpoint.path());
    let status = wait_exit(&mut child.0, Duration::from_secs(10));
    assert!(
        status.is_some_and(|s| s.success()),
        "p9fuse exited with {status:?}"
    );
}

/// After a lazy unmount the binary keeps serving files that are still open, then exits once they
/// are closed.
#[test]
fn binary_exits_once_files_close_after_lazy_unmount() {
    if let Some(why) = skip_reason() {
        eprintln!("skipping: {why}");
        return;
    }
    let diod = Diod::start();
    let mountpoint = tempfile::tempdir().unwrap();
    let mp = mountpoint.path();
    let mut child = KillOnDrop(spawn_binary(&diod, mp));
    let mut f = std::fs::File::create(mp.join("f")).unwrap();
    f.write_all(b"before ").unwrap();

    let lazy = Command::new(fusermount_bin().unwrap())
        .args(["-u", "-z"])
        .arg(mp)
        .status()
        .unwrap();
    assert!(lazy.success());
    assert!(wait_exit(&mut child.0, Duration::from_secs(1)).is_none());

    f.write_all(b"after").unwrap();
    drop(f);
    let status = wait_exit(&mut child.0, Duration::from_secs(10));
    assert!(
        status.is_some_and(|s| s.success()),
        "p9fuse exited with {status:?}"
    );
    assert_eq!(
        std::fs::read(diod.export().join("f")).unwrap(),
        b"before after"
    );
}

/// The session ends at unmount even while another mount namespace holds a copy of the mount, as a
/// container or build sandbox started during the mount would.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unmount_ends_session_despite_namespace_copy() {
    if let Some(why) = skip_reason() {
        eprintln!("skipping: {why}");
        return;
    }
    let unshare = |args: &[&str]| {
        let mut command = Command::new("unshare");
        command.args(["-U", "-r", "-m"]).args(args);
        command
    };
    if !unshare(&["true"]).status().is_ok_and(|s| s.success()) {
        eprintln!("skipping: unshare can't make a user and mount namespace");
        return;
    }
    let holder = std::sync::Arc::new(std::sync::Mutex::new(None));
    let holder_body = holder.clone();
    // The holder outlives unmount_and_join's timeout, so the test fails if the session waits for it.
    with_mount(Tuning::default(), move |mp| {
        let child = unshare(&["sleep", "120"]).spawn().unwrap();
        let mountinfo = format!("/proc/{}/mountinfo", child.id());
        let mp = mp.to_string_lossy().into_owned();
        *holder_body.lock().unwrap() = Some(KillOnDrop(child));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !std::fs::read_to_string(&mountinfo).is_ok_and(|m| m.contains(&mp)) {
            assert!(Instant::now() < deadline, "the copy never showed up");
            std::thread::sleep(Duration::from_millis(20));
        }
    })
    .await;
    drop(holder);
}
