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

use p9fuse::{mount, NineClient, TcpTransport, Tuning};
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

/// Start diod, FUSE-mount its export with `tuning`, wait until the mount is live, run `body` (on a
/// blocking thread, with the mountpoint path), then unmount and tear everything down. Any panic in
/// `body` propagates to fail the test.
async fn with_mount<F>(tuning: Tuning, body: F)
where
    F: FnOnce(&Path) + Send + 'static,
{
    let diod = Diod::start();
    // Seed a readiness sentinel in the export; it appears through the mount once FUSE is live.
    std::fs::write(diod.export().join(READY), b"1").unwrap();

    let mountpoint = tempfile::tempdir().unwrap();
    let mp = mountpoint.path().to_path_buf();
    let addr = format!("127.0.0.1:{}", diod.port);
    let aname = diod.export().to_string_lossy().into_owned();
    let uid = unsafe { libc::geteuid() };

    let mp_task = mp.clone();
    // The task output must be Send, and mount()'s Box<dyn Error> isn't -- stringify it.
    let task = tokio::spawn(async move {
        let transport = TcpTransport::connect(&addr)
            .await
            .map_err(|e| e.to_string())?;
        // `mount` blocks until unmounted; the error (if any) surfaces after umount below.
        mount(Box::new(transport), &mp_task, 512_000, uid, &aname, tuning)
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

    // Surface a body panic first (more informative), then any mount error.
    outcome.expect("test body panicked");
    mount_result.expect("mount() returned an error");
    drop(diod);
    drop(mountpoint);
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
