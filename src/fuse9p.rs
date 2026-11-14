//! `mount9p-fuse`: a userspace FUSE filesystem that speaks 9p2000.L to a remote server via the
//! [`NineClient`]. This is the unprivileged alternative to the kernel v9fs client: FUSE is
//! user-namespace mountable / has a setuid `fusermount3` helper, so it mounts without CAP_SYS_ADMIN,
//! while 9p2000.L still carries full POSIX metadata so `chmod`/ownership round-trip faithfully.
//!
//! FUSE callbacks are synchronous and serialized (single-threaded session), so the inode/handle
//! tables need no locking; each callback bridges to the async client via `Handle::block_on`.

use crate::client::NineClient;
use crate::ninep::Attr;
use crate::write_pipeline::{write_all, InodeWrites, Write, WriteError};
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::runtime::Handle;

const ROOT_INO: u64 = 1;
const AT_REMOVEDIR: u32 = 0x200;

/// Performance knobs, each independently toggleable from the CLI (see `main.rs`). They trade cache
/// coherence / round-trips for throughput; this is safe when this process is the sole 9p client of
/// the export (the kernel v9fs path makes the same bet with `cache=loose`). Every knob can be turned
/// off to isolate its effect or to fall back to strict, round-trip-per-op behavior.
#[derive(Clone, Debug)]
pub struct Tuning {
    /// How long the kernel may trust a cached `getattr` result before asking us again. Longer = far
    /// fewer `Tgetattr` round-trips on repeated stats; staleness window for out-of-band edits. 0 = no
    /// attr caching (every stat round-trips).
    pub attr_ttl: Duration,
    /// How long the kernel may trust a cached name->inode `lookup`. Same trade-off as `attr_ttl` for
    /// path resolution. 0 = no entry caching.
    pub entry_ttl: Duration,
    /// If set, cache "no such file" lookups for this long (negative-dentry caching), so repeated
    /// probes of non-existent paths (compilers walking include dirs, `$PATH` searches) don't
    /// round-trip. `None` = always round-trip a miss.
    pub negative_ttl: Option<Duration>,
    /// Prefetch each entry's attributes during directory reads (`readdirplus`), so a later `stat` of
    /// a just-listed file is a kernel-cache hit instead of a round-trip -- the big lever for
    /// `ls`/`find`/`git`/build tree-walks. Off = plain `readdir` (kernel stats each entry separately).
    pub readdirplus: bool,
    /// Advertise `FUSE_WRITEBACK_CACHE`: the kernel buffers writes in its page cache and flushes them
    /// in large background batches. Unsafe when the export is also changed from outside the mount:
    /// under this capability the kernel treats its own `i_size` as authoritative, so a file grown
    /// behind the mount reads back truncated to the old size for as long as its inode stays cached,
    /// invalidation notwithstanding. Only turn it on when this mount is the sole writer.
    pub writeback_cache: bool,
    /// Pipeline writes: acknowledge each FUSE `write` at once and send its `Twrite` from a background
    /// task, up to `wb_depth` in flight per file, turning latency-bound sequential writes into
    /// throughput. A write waits for overlapping writes still in flight, and when the pipeline is
    /// full, adjacent small writes are merged into one `Twrite`. Errors surface at
    /// flush/fsync/release. Off = each `write` is one synchronous `Twrite` round-trip. O_APPEND
    /// handles write synchronously unless `writeback_cache` is on.
    pub write_pipeline: bool,
    /// Max concurrent in-flight `Twrite`s per file when `write_pipeline` is on. Bounds memory
    /// (~`wb_depth` * msize) and sets the pipeline depth.
    pub wb_depth: usize,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning {
            attr_ttl: Duration::from_secs(60),
            entry_ttl: Duration::from_secs(60),
            negative_ttl: Some(Duration::from_secs(5)),
            // OFF by default: benchmarking showed it's net-negative. `find -type f` never stats (it
            // uses readdir's d_type), so prefetching attrs is pure overhead; and even for `ls -l` our
            // prefetch does a walk+getattr per entry from the shared parent fid, which diod
            // serializes -- so it isn't actually pipelined and costs more than on-demand getattr +
            // the attr cache. The caching knobs deliver the v9fs-`cache=loose` speed; readdirplus
            // doesn't. Kept as a knob in case a future impl walks per-entry fids concurrently.
            readdirplus: false,
            writeback_cache: false,
            write_pipeline: true,
            wb_depth: 16,
        }
    }
}

// st_mode type bits.
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

/// Per-inode bookkeeping. `fid` is a *base* fid (walked from root, not opened for I/O); it is the
/// handle we getattr/setattr through and clone for child walks and I/O opens.
struct Inode {
    fid: u32,
    lookups: u64,
}

/// An open file/dir handle: the opened 9p fid and its inode, plus, for a handle whose writes go
/// through the inode's write pipeline, the slot for the first error one of them hits.
struct FileHandle {
    fid: u32,
    ino: u64,
    wb: Option<WriteError>,
}

pub struct Fuse9p {
    client: Arc<NineClient>,
    rt: Handle,
    tuning: Tuning,
    inodes: HashMap<u64, Inode>,
    /// The export root's qid.path, which we remap to FUSE_ROOT_ID (1). See `intern`.
    root_qid_path: u64,
    /// Open file/dir handles, keyed by fh.
    handles: HashMap<u64, FileHandle>,
    next_fh: u64,
    /// The write pipeline of each inode with a pipelined handle open, keyed by inode.
    writes: HashMap<u64, Arc<InodeWrites>>,
}

/// Map a 9p qid.path to a FUSE inode number. We use the qid.path directly (it's a stable unique id
/// per file), except the export root, which must be FUSE_ROOT_ID. Using qid.path as the inode means
/// the invalidation task can resolve a path to its inode with a plain 9p walk, no shared inode table.
/// (A non-root file whose qid.path happens to be 1 would collide with root, but that's the underlying
/// fs root inode, which can't appear under the exported subdir.)
fn qid_to_ino(qid_path: u64, root_qid_path: u64) -> u64 {
    if qid_path == root_qid_path {
        ROOT_INO
    } else {
        qid_path
    }
}

impl Fuse9p {
    fn intern(&self, qid_path: u64) -> u64 {
        qid_to_ino(qid_path, self.root_qid_path)
    }

    fn fid_of(&self, ino: u64) -> Option<u32> {
        self.inodes.get(&ino).map(|i| i.fid)
    }

    /// The flags to open a file's fid with for the kernel's `flags`, and whether writes through it
    /// may be pipelined.
    fn open_flags(&self, flags: i32) -> (u32, bool) {
        let mut oflags = (flags as u32) & !(libc::O_CLOEXEC as u32);
        let acc = oflags & libc::O_ACCMODE as u32;
        let append = oflags & libc::O_APPEND as u32 != 0;
        if self.tuning.writeback_cache {
            // With the FUSE writeback cache the kernel issues READs on the handle for partial-page
            // read-modify-write even when the file was opened write-only, which the server would
            // refuse with EBADF on a write-only fid; so open those read-write. The kernel also
            // places O_APPEND writes itself and may write back any dirty page through any of the
            // file's handles, so the server must honour our offsets: drop O_APPEND.
            if acc == libc::O_WRONLY as u32 {
                oflags = (oflags & !(libc::O_ACCMODE as u32)) | libc::O_RDWR as u32;
            }
            oflags &= !(libc::O_APPEND as u32);
        }
        // Without the cache an O_APPEND fid stays O_APPEND, so the server appends at its real end
        // of file -- but then it ignores our offsets, and two appends in flight could land in either
        // order. Those handles write synchronously.
        let writable = acc != libc::O_RDONLY as u32;
        let pipelined =
            writable && self.tuning.write_pipeline && (self.tuning.writeback_cache || !append);
        (oflags, pipelined)
    }

    /// Register an opened fid as a new file/dir handle. A `pipelined` handle sends its writes
    /// through the inode's write pipeline; others write synchronously.
    fn insert_handle(&mut self, fid: u32, ino: u64, pipelined: bool) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        let wb = if pipelined {
            let (client, chunk, depth) = (
                self.client.clone(),
                self.write_chunk(),
                self.tuning.wb_depth,
            );
            self.writes
                .entry(ino)
                .or_insert_with(|| InodeWrites::new(client, chunk, depth));
            Some(WriteError::default())
        } else {
            None
        };
        self.handles.insert(fh, FileHandle { fid, ino, wb });
        fh
    }

    /// The most bytes one `Twrite` carries: the negotiated msize less the header.
    fn write_chunk(&self) -> usize {
        self.client.msize.saturating_sub(24) as usize
    }

    /// Wait for the pipelined writes still unsent or in flight on `ino` (through any handle), or on
    /// every inode when `ino` is `None`, so a server op that reports a file's size or contents sees
    /// them, and a synchronous write or truncate lands after them. Without the writeback cache the
    /// kernel takes size and data from us, and the server does not know about writes we have
    /// acknowledged but not yet sent. Errors stay recorded for that handle's flush/fsync/release.
    fn settle_writes(&self, ino: Option<u64>) {
        let busy: Vec<Arc<InodeWrites>> = match ino {
            Some(ino) => self.writes.get(&ino).cloned().into_iter().collect(),
            None => self.writes.values().cloned().collect(),
        };
        let busy: Vec<Arc<InodeWrites>> = busy.into_iter().filter(|w| w.busy()).collect();
        if busy.is_empty() {
            return;
        }
        self.rt.block_on(async move {
            for w in busy {
                w.settle().await;
            }
        });
    }

    /// Wait for every pipelined write on the handle's inode, returning the first error any write
    /// through this handle hit since the last time it was asked.
    fn drain_writeback(&self, ino: u64, err: &WriteError) -> Option<i32> {
        self.settle_writes(Some(ino));
        err.lock().unwrap().take()
    }
}

/// A zeroed attr (inode 0) used to cache a negative lookup: FUSE reads inode 0 as "no such entry,
/// remember that for the entry TTL."
fn negative_attr() -> FileAttr {
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

/// Read up to `cap` bytes at `off`, reassembling short replies.
///
/// A 9p server may answer a Tread with fewer bytes than asked for even mid-file -- a short `pread`
/// on its backing store is enough -- and only a zero-length reply means end of file. Returning a
/// short reply straight to FUSE would present it to the application as a short file: a reader that
/// treats that as corruption (SQLite raises SQLITE_IOERR_SHORT_READ, surfaced as "disk I/O error")
/// then fails with no error recorded anywhere, because nothing actually failed.
async fn read_full(client: &NineClient, fid: u32, off: u64, cap: u32) -> Result<Vec<u8>, i32> {
    let mut out: Vec<u8> = Vec::new();
    let mut pos = off;
    while (out.len() as u32) < cap {
        let chunk = client.read(fid, pos, cap - out.len() as u32).await?;
        if chunk.is_empty() {
            break; // end of file
        }
        pos += chunk.len() as u64;
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn unixtime((sec, nsec): (u64, u64)) -> SystemTime {
    UNIX_EPOCH + Duration::new(sec, (nsec as u32).min(999_999_999))
}

fn time_or_now(t: TimeOrNow) -> (u64, u64) {
    match t {
        TimeOrNow::SpecificTime(st) => {
            let d = st.duration_since(UNIX_EPOCH).unwrap_or_default();
            (d.as_secs(), d.subsec_nanos() as u64)
        }
        TimeOrNow::Now => {
            let d = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            (d.as_secs(), d.subsec_nanos() as u64)
        }
    }
}

fn kind_from_mode(mode: u32) -> FileType {
    match mode & S_IFMT {
        S_IFDIR => FileType::Directory,
        S_IFLNK => FileType::Symlink,
        _ => FileType::RegularFile,
    }
}

fn kind_from_qid(typ: u8) -> FileType {
    if typ & 0x80 != 0 {
        FileType::Directory
    } else if typ & 0x02 != 0 {
        FileType::Symlink
    } else {
        FileType::RegularFile
    }
}

fn to_fileattr(ino: u64, a: &Attr) -> FileAttr {
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
        nlink: a.nlink.max(1) as u32,
        uid: a.uid,
        gid: a.gid,
        rdev: a.rdev as u32,
        blksize: a.blksize.max(512) as u32,
        flags: 0,
    }
}

impl Fuse9p {
    /// Mount at `mountpoint`, blocking until unmounted. Builds the client, attaches, then runs the
    /// FUSE session on a blocking thread (callbacks bridge back to the runtime via `Handle`).
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        transport: Box<dyn crate::transport::NineTransport>,
        mountpoint: &Path,
        msize: u32,
        uid: u32,
        aname: &str,
        tuning: Tuning,
        // When the 9p transport closes we always exit (so a supervisor can remount). If this is set we
        // also lazily detach the mount first, so the mountpoint reverts to its underlying contents
        // instead of lingering as a dead ENOTCONN mount. Detaching lets a supervisor remount cleanly at
        // the same path (the default); leaving it undetached keeps failed I/O visible as ENOTCONN
        // rather than briefly exposing whatever is underneath.
        detach_on_transport_loss: bool,
        // Whether to mount with `default_permissions`.
        default_permissions: bool,
        // Give up on a 9p request unanswered for this long: the transport is declared dead, the
        // mount exits, and the supervisor remounts. Zero disables the watchdog.
        stall_timeout: std::time::Duration,
        // Where invalidation requests arrive, one per line, and where their replies go (see
        // `invalidation_loop`). The binary passes its stdin and stdout.
        invalidations: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        replies: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!(?tuning, "mount9p-fuse: tuning");
        // Attach as `uid` so the server acts as that user for file ops (a multiuser server like diod
        // setfsuids to it per attach), so files are owned by `uid` and chmod works.
        let (client, root_qid) =
            NineClient::connect(transport, msize, uid, aname, stall_timeout).await?;
        // Watch for the 9p transport closing: if it does, the mount is dead (every op would just
        // return EIO), so we exit below and let whatever supervises this process remount.
        let mut transport_gone = client.transport_gone();

        let mut inodes = HashMap::new();
        inodes.insert(
            ROOT_INO,
            Inode {
                fid: client.root_fid,
                lookups: 1,
            },
        );

        // Kept for the invalidation task (resolves server-pushed paths -> inodes via fresh walks).
        let inval_client = client.clone();
        let root_fid = client.root_fid;
        let root_qid_path = root_qid.path;

        let fs = Fuse9p {
            client,
            rt: Handle::current(),
            tuning,
            inodes,
            root_qid_path,
            handles: HashMap::new(),
            next_fh: 1,
            writes: HashMap::new(),
        };

        // No AutoUnmount: that path wants the libfuse feature we deliberately dropped. The kernel
        // tears the mount down when this process exits.
        let mut options = vec![
            MountOption::FSName("p9fuse".to_string()),
            MountOption::Subtype("9p".to_string()),
        ];
        if default_permissions {
            options.push(MountOption::DefaultPermissions);
        }
        // When mounting as root, the mount is root-owned but processes running as another uid can
        // only traverse it with `allow_other`. Only root may set allow_other without
        // `user_allow_other` in /etc/fuse.conf, so gate it on euid 0 -- an unprivileged mount is
        // same-uid and doesn't need it (and would fail to set it).
        if nix::unistd::geteuid().as_raw() == 0 {
            options.push(MountOption::AllowOther);
        }

        let mp = mountpoint.to_path_buf();
        tracing::info!(?mp, "mount9p-fuse: mounting FUSE filesystem");
        // Use Session (not fuser::mount2) so we can take a Notifier: that's how out-of-band changes
        // (paths fed on stdin by an external change-notification source) reach the kernel's caches --
        // letting us cache aggressively AND stay coherent when the backing store changes underneath.
        let mut session = fuser::Session::new(fs, &mp, &options)?;
        let notifier = session.notifier();
        // Read invalidation paths (one per line) and drop them from the kernel cache.
        tokio::spawn(invalidation_loop(
            invalidations,
            replies,
            notifier,
            inval_client,
            root_fid,
            root_qid_path,
        ));
        // session.run() blocks for the life of the mount; run it off the async executor so the
        // runtime stays free to service the client's (and invalidation task's) requests. Race it
        // against the transport closing: on a dead transport the session would otherwise keep
        // running and answer every op with EIO forever, so exit instead -- the kernel tears down the
        // FUSE mount when we exit, and the supervising mount loop remounts against a fresh transport.
        let session_task = tokio::task::spawn_blocking(move || session.run());
        tokio::select! {
            r = session_task => r?.map_err(|e| e.into()),
            res = transport_gone.wait_for(|&gone| gone) => {
                let _ = res;
                // On daemon exit the kernel leaves the mount in place answering ENOTCONN (it does *not*
                // auto-remove it), which would block a clean remount at the same path. When enabled, a
                // lazy detach reverts the mountpoint immediately (and, since we made it a shared mount,
                // propagates the detach into the sandbox bind) so the supervising mount loop can remount
                // fresh -- mirroring mount9p's umount-on-exit. When disabled we just exit, leaving a
                // dead ENOTCONN mount so I/O fails loudly rather than exposing the underlying dir.
                if detach_on_transport_loss {
                    tracing::error!("mount9p-fuse: 9p transport closed; detaching the mount and exiting so it is remounted");
                    let _ = nix::mount::umount2(mp.as_path(), nix::mount::MntFlags::MNT_DETACH);
                } else {
                    tracing::error!("mount9p-fuse: 9p transport closed; exiting so it is remounted (no detach)");
                }
                std::process::exit(75); // EX_TEMPFAIL; the mount loop that spawned us restarts us
            }
        }
    }
}

/// Reads invalidation paths (one path per line, relative to the mount root) and drops them
/// from the kernel's caches via FUSE notifies. Feed this from whatever knows the backing store changed
/// out-of-band, to keep aggressive caching coherent. Resolving a path to its inode is a plain 9p walk
/// (inode == qid.path), so no shared state with the FUSE filesystem is needed. Best-effort: a path the
/// kernel never cached simply isn't there to drop.
async fn invalidation_loop(
    invalidations: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    replies: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    notifier: fuser::Notifier,
    client: Arc<NineClient>,
    root_fid: u32,
    root_qid_path: u64,
) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    // The notifier calls are synchronous writes to /dev/fuse, and the kernel processes a
    // notify_inval_entry under the parent directory's inode lock -- which an in-flight LOOKUP of
    // that directory holds until WE answer it. Issuing the notify from a runtime worker can
    // therefore deadlock the whole mount (notify blocks the worker -> the 9p reply that would
    // complete the LOOKUP is never processed -> the kernel never releases the lock -> the notify
    // never returns). Run every notify on a blocking thread so the runtime keeps servicing 9p.
    let notifier = std::sync::Arc::new(notifier);
    let mut lines = BufReader::new(invalidations).lines();
    let mut out = replies;
    loop {
        let line = match lines.next_line().await {
            Ok(Some(l)) => l,
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(?e, "mount9p-fuse: error reading invalidations");
                break;
            }
        };
        // "inval <id> <escaped path>", or a bare unescaped path from a client that predates ids.
        // Every request gets exactly one reply, including one whose path resolves to nothing.
        let (reply_id, path) = match line.strip_prefix("inval ") {
            Some(rest) => {
                let (id, escaped) = rest.split_once(' ').unwrap_or((rest, ""));
                match decode_path(escaped) {
                    Ok(p) => (Some(id.to_string()), p),
                    Err(e) => {
                        tracing::warn!(
                            id,
                            escaped,
                            e,
                            "mount9p-fuse: undecodable invalidation path"
                        );
                        reply(&mut *out, &format!("err {id} {e}")).await;
                        continue;
                    }
                }
            }
            None => (None, line.clone()),
        };
        'line: {
            let rel = path.trim().trim_start_matches('/');
            if rel.is_empty() {
                break 'line;
            }
            let comps: Vec<&str> = rel.split('/').filter(|s| !s.is_empty()).collect();
            let (name, parent_comps) = match comps.split_last() {
                Some(x) => x,
                None => break 'line,
            };

            // Parent inode -> drop the dentry for `name` (forces a fresh lookup, picking up creates,
            // deletes and renames).
            let pf = client.alloc_fid();
            let parent_ino = match client.walk(root_fid, pf, parent_comps).await {
                Ok(qids) => {
                    let _ = client.clunk(pf).await;
                    let pqp = qids.last().map(|q| q.path).unwrap_or(root_qid_path);
                    Some(qid_to_ino(pqp, root_qid_path))
                }
                // The walk did not establish pf, so there is nothing to clunk.
                Err(e) => {
                    tracing::warn!(rel, ?e, "mount9p-fuse: invalidation parent walk failed");
                    None
                }
            };
            if let Some(pino) = parent_ino {
                let n = notifier.clone();
                let name_owned = name.to_string();
                let r = tokio::task::spawn_blocking(move || {
                    n.inval_entry(pino, std::ffi::OsStr::new(&name_owned))
                })
                .await;
                tracing::info!(rel, pino, name, result = ?r, "mount9p-fuse: inval_entry");
            }

            // Child inode -> drop cached attrs + data (forces re-read of changed content).
            let cf = client.alloc_fid();
            match client.walk(root_fid, cf, &comps).await {
                Ok(qids) => {
                    let _ = client.clunk(cf).await;
                    if let Some(q) = qids.last() {
                        let ino = qid_to_ino(q.path, root_qid_path);
                        let n = notifier.clone();
                        let r = tokio::task::spawn_blocking(move || n.inval_inode(ino, 0, 0)).await;
                        tracing::info!(rel, ino, result = ?r, "mount9p-fuse: inval_inode");
                    }
                }
                // The walk did not establish cf, so there is nothing to clunk. This is the common case:
                // an invalidation for a deleted or renamed path no longer resolves.
                Err(e) => {
                    tracing::warn!(rel, ?e, "mount9p-fuse: invalidation child walk failed");
                }
            }
        }
        match &reply_id {
            Some(id) => reply(&mut *out, &format!("ok {id}")).await,
            None => reply(&mut *out, &format!("ok {path}")).await,
        }
    }
    tracing::info!("mount9p-fuse: invalidation input closed");
}

/// Percent-decode a request's path. The client percent-encodes it because a filename may contain
/// the newline that ends one request, and may contain the `%` that starts an escape.
fn decode_path(s: &str) -> Result<String, &'static str> {
    percent_encoding::percent_decode_str(s)
        .decode_utf8()
        .map(|p| p.into_owned())
        .map_err(|_| "path wasn't utf-8 once decoded")
}

/// Write one reply line on stdout, once the request it answers has been applied. A client that
/// orders work after an invalidation needs this, since writing to our stdin only says the path was
/// queued. Replies are tagged so a client can tell one from anything else that ever reaches stdout,
/// and match it to the request it answers rather than relying on position.
async fn reply(out: &mut (dyn tokio::io::AsyncWrite + Send + Unpin), line: &str) {
    use tokio::io::AsyncWriteExt;
    let mut buf = String::with_capacity(line.len() + 1);
    buf.push_str(line);
    buf.push('\n');
    if let Err(e) = out.write_all(buf.as_bytes()).await {
        tracing::warn!(?e, "mount9p-fuse: couldn't write an invalidation reply");
        return;
    }
    if let Err(e) = out.flush().await {
        tracing::warn!(?e, "mount9p-fuse: couldn't flush an invalidation reply");
    }
}

impl Filesystem for Fuse9p {
    fn init(
        &mut self,
        _req: &Request,
        config: &mut fuser::KernelConfig,
    ) -> Result<(), libc::c_int> {
        // Match the FUSE max write/read to the 9p msize so big-file I/O isn't capped at the 128 KiB
        // default -- each FUSE op is one synchronous 9p round-trip, so larger ops mean far fewer of
        // them. Leave headroom for the 9p Twrite/Tread headers.
        let want = self.client.msize.saturating_sub(64).max(8192);
        let _ = config.set_max_write(want);
        let _ = config.set_max_readahead(want);
        // Capability flags (not re-exported by fuser::consts):
        const FUSE_WRITEBACK_CACHE: u32 = 1 << 16; // kernel buffers + async-flushes writes
        const FUSE_DO_READDIRPLUS: u32 = 1 << 13; // kernel issues READDIRPLUS (readdir+lookup) ops
        const FUSE_READDIRPLUS_AUTO: u32 = 1 << 14; // ...adaptively, only when it pays off
        if self.tuning.writeback_cache {
            // Writeback caching lets the kernel buffer the app's writes and flush them async,
            // coalesced and several in flight (max_background, default 16) -- which, with our async
            // write-back handler, turns the latency-bound write path into a pipelined one.
            let _ = config.add_capabilities(FUSE_WRITEBACK_CACHE);
        }
        if self.tuning.readdirplus {
            // Ask the kernel to use READDIRPLUS so directory reads prefetch+cache each entry's attrs.
            let _ = config.add_capabilities(FUSE_DO_READDIRPLUS | FUSE_READDIRPLUS_AUTO);
        }
        Ok(())
    }

    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let parent_fid = match self.fid_of(parent) {
            Some(f) => f,
            None => return reply.error(libc::ENOENT),
        };
        let name = name.to_string_lossy().to_string();
        let newfid = self.client.alloc_fid();
        let client = self.client.clone();
        // Walk first, and only own (and so only clunk) newfid once the walk has established it.
        let walked = self
            .rt
            .block_on(async move { client.walk(parent_fid, newfid, &[&name]).await });
        if let Ok(Some(q)) = walked.as_ref().map(|qids| qids.last()) {
            self.settle_writes(Some(self.intern(q.path)));
        }
        let client = self.client.clone();
        let res = self.rt.block_on(async move {
            walked?;
            match client.getattr(newfid).await {
                Ok(a) => Ok(a),
                // The fid exists but we are not returning it, so release it.
                Err(e) => {
                    let _ = client.clunk(newfid).await;
                    Err(e)
                }
            }
        });
        match res {
            Err(e) => {
                // Negative-dentry caching: tell the kernel to remember this miss for a while so
                // repeated probes of the same absent path don't each round-trip.
                match (e, self.tuning.negative_ttl) {
                    (libc::ENOENT, Some(ttl)) => reply.entry(&ttl, &negative_attr(), 0),
                    _ => reply.error(e),
                }
            }
            Ok(attr) => {
                let ino = self.intern(attr.qid.path);
                if let Some(existing) = self.inodes.get_mut(&ino) {
                    existing.lookups += 1;
                    let c = self.client.clone();
                    let _ = self.rt.block_on(async move { c.clunk(newfid).await });
                } else {
                    self.inodes.insert(
                        ino,
                        Inode {
                            fid: newfid,
                            lookups: 1,
                        },
                    );
                }
                reply.entry(&self.tuning.entry_ttl, &to_fileattr(ino, &attr), 0);
            }
        }
    }

    fn forget(&mut self, _req: &Request, ino: u64, nlookup: u64) {
        if ino == ROOT_INO {
            return;
        }
        if let Some(inode) = self.inodes.get_mut(&ino) {
            inode.lookups = inode.lookups.saturating_sub(nlookup);
            if inode.lookups == 0 {
                let fid = inode.fid;
                self.inodes.remove(&ino);
                let c = self.client.clone();
                let _ = self.rt.block_on(async move { c.clunk(fid).await });
            }
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        let fid = match self.fid_of(ino) {
            Some(f) => f,
            None => return reply.error(libc::ENOENT),
        };
        self.settle_writes(Some(ino));
        let client = self.client.clone();
        match self.rt.block_on(async move { client.getattr(fid).await }) {
            Ok(a) => reply.attr(&self.tuning.attr_ttl, &to_fileattr(ino, &a)),
            Err(e) => reply.error(e),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &mut self,
        _req: &Request,
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
        use crate::ninep::*;
        let fid = match self.fid_of(ino) {
            Some(f) => f,
            None => return reply.error(libc::ENOENT),
        };
        let mut valid = 0u32;
        let mut p9mode = 0u32;
        let mut p9uid = 0u32;
        let mut p9gid = 0u32;
        let mut p9size = 0u64;
        let mut p9atime = (0u64, 0u64);
        let mut p9mtime = (0u64, 0u64);
        if let Some(m) = mode {
            valid |= SETATTR_MODE;
            p9mode = m & 0o7777;
        }
        if let Some(u) = uid {
            valid |= SETATTR_UID;
            p9uid = u;
        }
        if let Some(g) = gid {
            valid |= SETATTR_GID;
            p9gid = g;
        }
        if let Some(s) = size {
            valid |= SETATTR_SIZE;
            p9size = s;
        }
        if let Some(t) = atime {
            valid |= SETATTR_ATIME;
            if let TimeOrNow::SpecificTime(_) = t {
                valid |= SETATTR_ATIME_SET;
            }
            p9atime = time_or_now(t);
        }
        if let Some(t) = mtime {
            valid |= SETATTR_MTIME;
            if let TimeOrNow::SpecificTime(_) = t {
                valid |= SETATTR_MTIME_SET;
            }
            p9mtime = time_or_now(t);
        }
        // A truncate must land after the writes that came before it, and the size we report back
        // has to include them.
        self.settle_writes(Some(ino));
        let client = self.client.clone();
        let res = self.rt.block_on(async move {
            client
                .setattr(fid, valid, p9mode, p9uid, p9gid, p9size, p9atime, p9mtime)
                .await?;
            client.getattr(fid).await
        });
        match res {
            Ok(a) => reply.attr(&self.tuning.attr_ttl, &to_fileattr(ino, &a)),
            Err(e) => reply.error(e),
        }
    }

    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        let base = match self.fid_of(ino) {
            Some(f) => f,
            None => return reply.error(libc::ENOENT),
        };
        let newfid = self.client.alloc_fid();
        let (oflags, pipelined) = self.open_flags(flags);
        if oflags & libc::O_TRUNC as u32 != 0 {
            // The server truncates at open; that must land after writes already queued.
            self.settle_writes(Some(ino));
        }
        let client = self.client.clone();
        let res = self.rt.block_on(async move {
            // Clone the base fid. newfid exists only once this succeeds, so the open failing below
            // is the only case that has to release it.
            client.walk(base, newfid, &[]).await?;
            match client.lopen(newfid, oflags).await {
                Ok(_) => Ok::<(), i32>(()),
                Err(e) => {
                    let _ = client.clunk(newfid).await;
                    Err(e)
                }
            }
        });
        match res {
            Ok(()) => {
                let fh = self.insert_handle(newfid, ino, pipelined);
                reply.opened(fh, 0);
            }
            Err(e) => reply.error(e),
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        let fid = match self.handles.get(&fh) {
            Some(h) => h.fid,
            None => return reply.error(libc::EBADF),
        };
        self.settle_writes(Some(ino));
        let client = self.client.clone();
        let cap = size.min(self.client.msize.saturating_sub(24));
        match self
            .rt
            .block_on(async move { read_full(&client, fid, offset as u64, cap).await })
        {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(e),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyWrite,
    ) {
        let (fid, ino, wb) = match self.handles.get(&fh) {
            Some(h) => (h.fid, h.ino, h.wb.clone()),
            None => return reply.error(libc::EBADF),
        };
        let data = data.to_vec();
        let len = data.len() as u32;
        let off = offset as u64;

        match (wb, self.writes.get(&ino).cloned()) {
            // Pipelined handle: queue the write and acknowledge the bytes at once. An error is
            // recorded and surfaced at flush/fsync/release -- standard write-back semantics.
            (Some(err), Some(pipeline)) => {
                let w = Write {
                    fid,
                    off,
                    data,
                    err,
                };
                self.rt.block_on(async move { pipeline.write(w).await });
                reply.written(len);
            }
            // Synchronous handle: one round-trip, after any pipelined writes to the same file.
            _ => {
                self.settle_writes(Some(ino));
                let client = self.client.clone();
                let chunk = self.write_chunk();
                let res = self
                    .rt
                    .block_on(async move { write_all(&client, fid, off, &data, chunk).await });
                match res {
                    Ok(()) => reply.written(len),
                    Err(e) => reply.error(e),
                }
            }
        }
    }

    fn release(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        if let Some(h) = self.handles.remove(&fh) {
            // Finish any deferred writes before clunking the fid (and surface a write error here if
            // the app never called fsync/flush).
            let err = h.wb.as_ref().and_then(|wb| self.drain_writeback(h.ino, wb));
            let fid = h.fid;
            let c = self.client.clone();
            let _ = self.rt.block_on(async move { c.clunk(fid).await });
            // Drop the inode's pipeline with its last pipelined handle; it is idle after the drain.
            if h.wb.is_some()
                && !self
                    .handles
                    .values()
                    .any(|o| o.ino == h.ino && o.wb.is_some())
            {
                self.writes.remove(&h.ino);
            }
            if let Some(e) = err {
                return reply.error(e);
            }
        }
        reply.ok();
    }

    fn opendir(&mut self, _req: &Request, ino: u64, _flags: i32, reply: ReplyOpen) {
        let base = match self.fid_of(ino) {
            Some(f) => f,
            None => return reply.error(libc::ENOENT),
        };
        let newfid = self.client.alloc_fid();
        let client = self.client.clone();
        let res = self.rt.block_on(async move {
            // Clone the base fid. newfid exists only once this succeeds, so the open failing below
            // is the only case that has to release it.
            client.walk(base, newfid, &[]).await?;
            // O_RDONLY; diod allows readdir on it.
            match client.lopen(newfid, 0).await {
                Ok(_) => Ok::<(), i32>(()),
                Err(e) => {
                    let _ = client.clunk(newfid).await;
                    Err(e)
                }
            }
        });
        match res {
            Ok(()) => {
                let fh = self.insert_handle(newfid, ino, false);
                reply.opened(fh, 0);
            }
            Err(e) => reply.error(e),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let fid = match self.handles.get(&fh) {
            Some(h) => h.fid,
            None => return reply.error(libc::EBADF),
        };
        let client = self.client.clone();
        let entries = match self
            .rt
            .block_on(async move { client.readdir(fid, offset as u64, 8192).await })
        {
            Ok(e) => e,
            Err(e) => return reply.error(e),
        };
        for e in entries {
            let kind = kind_from_qid(e.qid.typ);
            let child_ino = self.intern(e.qid.path);
            // 9p's entry.offset is the cookie to resume *after* this entry.
            if reply.add(child_ino, e.offset as i64, kind, &e.name) {
                break;
            }
        }
        reply.ok();
    }

    /// Like `readdir`, but prefetches each entry's attributes (one walk+getattr per entry, all
    /// pipelined over the ws) and hands them to the kernel with the entry/attr TTL, so a subsequent
    /// `stat` of any listed file is a cache hit instead of a round-trip. The kernel only calls this
    /// (instead of `readdir`) when the `readdirplus` knob enabled the capability in `init`.
    fn readdirplus(
        &mut self,
        _req: &Request,
        ino: u64,
        fh: u64,
        offset: i64,
        mut reply: ReplyDirectoryPlus,
    ) {
        let fid = match self.handles.get(&fh) {
            Some(h) => h.fid,
            None => return reply.error(libc::EBADF),
        };
        // Children are walked from the directory's *base* fid (not the opened readdir fid).
        let parent = match self.fid_of(ino) {
            Some(f) => f,
            None => return reply.error(libc::ENOENT),
        };
        let client = self.client.clone();
        let entries = match self
            .rt
            .block_on(async move { client.readdir(fid, offset as u64, 8192).await })
        {
            Ok(e) => e,
            Err(e) => return reply.error(e),
        };

        // The prefetched attrs include sizes, so they must not miss our own pending writes.
        self.settle_writes(None);
        // One fid per entry; walk+getattr them all concurrently (the client multiplexes by tag).
        let fids: Vec<u32> = entries.iter().map(|_| self.client.alloc_fid()).collect();
        let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
        let client = self.client.clone();
        let jobs: Vec<(String, u32)> = names.into_iter().zip(fids.iter().copied()).collect();
        let attrs: Vec<Option<Attr>> = self.rt.block_on(async move {
            let futs = jobs.into_iter().map(|(name, nf)| {
                let c = client.clone();
                async move {
                    // "." clones the dir fid; other names (incl "..") walk by name.
                    let walked = if name == "." {
                        c.walk(parent, nf, &[]).await
                    } else {
                        c.walk(parent, nf, &[name.as_str()]).await
                    };
                    match walked {
                        // walk failed: nf was never created on the server, nothing to clunk.
                        Err(_) => None,
                        Ok(_) => match c.getattr(nf).await {
                            Ok(a) => Some(a),
                            Err(_) => {
                                let _ = c.clunk(nf).await;
                                None
                            }
                        },
                    }
                }
            });
            futures_util::future::join_all(futs).await
        });

        let mut full = false;
        for (i, e) in entries.iter().enumerate() {
            let nf = fids[i];
            let attr = match attrs[i] {
                Some(a) => a,
                None => continue, // failed/cleaned-up entry; skip it
            };
            if full {
                // Buffer filled earlier; we won't emit this one, so drop its prefetched fid.
                let c = self.client.clone();
                let _ = self.rt.block_on(async move { c.clunk(nf).await });
                continue;
            }
            let child_ino = self.intern(attr.qid.path);
            let fa = to_fileattr(child_ino, &attr);
            // add() returns true when the entry did NOT fit -- so only commit the lookup reference
            // (bump count / keep the fid) when it WAS accepted, else clunk and stop.
            if reply.add(
                child_ino,
                e.offset as i64,
                &e.name,
                &self.tuning.entry_ttl,
                &fa,
                0,
            ) {
                full = true;
                let c = self.client.clone();
                let _ = self.rt.block_on(async move { c.clunk(nf).await });
            } else if let Some(existing) = self.inodes.get_mut(&child_ino) {
                existing.lookups += 1;
                let c = self.client.clone();
                let _ = self.rt.block_on(async move { c.clunk(nf).await }); // dup of an existing fid
            } else {
                self.inodes.insert(
                    child_ino,
                    Inode {
                        fid: nf,
                        lookups: 1,
                    },
                );
            }
        }
        reply.ok();
    }

    fn releasedir(&mut self, _req: &Request, _ino: u64, fh: u64, _flags: i32, reply: ReplyEmpty) {
        if let Some(h) = self.handles.remove(&fh) {
            let fid = h.fid;
            let c = self.client.clone();
            let _ = self.rt.block_on(async move { c.clunk(fid).await });
        }
        reply.ok();
    }

    fn create(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let parent_fid = match self.fid_of(parent) {
            Some(f) => f,
            None => return reply.error(libc::ENOENT),
        };
        let name = name.to_string_lossy().to_string();
        let gid = req.gid();
        let openfid = self.client.alloc_fid();
        let basefid = self.client.alloc_fid();
        let (oflags, pipelined) = self.open_flags(flags);
        let client = self.client.clone();
        let res = self.rt.block_on(async move {
            // Clone the parent into openfid and create+open the new file through it. Each step
            // releases only the fids the server has actually established by that point.
            client.walk(parent_fid, openfid, &[]).await?;
            if let Err(e) = client
                .lcreate(openfid, &name, oflags, mode & 0o7777, gid)
                .await
            {
                let _ = client.clunk(openfid).await;
                return Err(e);
            }
            // Separately walk a base fid to the new entry for the inode table + attrs.
            if let Err(e) = client.walk(parent_fid, basefid, &[&name]).await {
                let _ = client.clunk(openfid).await;
                return Err(e);
            }
            match client.getattr(basefid).await {
                Ok(a) => Ok(a),
                Err(e) => {
                    let _ = client.clunk(openfid).await;
                    let _ = client.clunk(basefid).await;
                    Err(e)
                }
            }
        });
        match res {
            Ok(attr) => {
                let ino = self.intern(attr.qid.path);
                self.inodes.insert(
                    ino,
                    Inode {
                        fid: basefid,
                        lookups: 1,
                    },
                );
                let fh = self.insert_handle(openfid, ino, pipelined);
                reply.created(&self.tuning.entry_ttl, &to_fileattr(ino, &attr), 0, fh, 0);
            }
            Err(e) => reply.error(e),
        }
    }

    fn mkdir(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let parent_fid = match self.fid_of(parent) {
            Some(f) => f,
            None => return reply.error(libc::ENOENT),
        };
        let name = name.to_string_lossy().to_string();
        let gid = req.gid();
        let basefid = self.client.alloc_fid();
        let client = self.client.clone();
        let res = self.rt.block_on(async move {
            client.mkdir(parent_fid, &name, mode & 0o7777, gid).await?;
            client.walk(parent_fid, basefid, &[&name]).await?;
            // basefid exists from here on; release it if the getattr fails.
            match client.getattr(basefid).await {
                Ok(a) => Ok::<Attr, i32>(a),
                Err(e) => {
                    let _ = client.clunk(basefid).await;
                    Err(e)
                }
            }
        });
        match res {
            Ok(attr) => {
                let ino = self.intern(attr.qid.path);
                self.inodes.insert(
                    ino,
                    Inode {
                        fid: basefid,
                        lookups: 1,
                    },
                );
                reply.entry(&self.tuning.entry_ttl, &to_fileattr(ino, &attr), 0);
            }
            Err(e) => reply.error(e),
        }
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        self.do_unlink(parent, name, 0, reply);
    }

    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        self.do_unlink(parent, name, AT_REMOVEDIR, reply);
    }

    fn flush(&mut self, _req: &Request, _ino: u64, fh: u64, _lock: u64, reply: ReplyEmpty) {
        // flush() runs on every close(2). Drain deferred writes so an error reaches the app's
        // close() return, matching POSIX write-back expectations.
        if let Some((ino, wb)) = self
            .handles
            .get(&fh)
            .and_then(|h| h.wb.clone().map(|wb| (h.ino, wb)))
        {
            if let Some(e) = self.drain_writeback(ino, &wb) {
                return reply.error(e);
            }
        }
        reply.ok();
    }

    fn fsync(&mut self, _req: &Request, _ino: u64, fh: u64, _datasync: bool, reply: ReplyEmpty) {
        let (fid, ino, wb) = match self.handles.get(&fh) {
            Some(h) => (h.fid, h.ino, h.wb.clone()),
            None => return reply.ok(),
        };
        // Make deferred writes durable: first drain our in-flight Twrites, then Tfsync on the server.
        if let Some(wb) = wb {
            if let Some(e) = self.drain_writeback(ino, &wb) {
                return reply.error(e);
            }
        }
        let c = self.client.clone();
        match self.rt.block_on(async move { c.fsync(fid).await }) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }

    fn rename(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let (pfid, npfid) = match (self.fid_of(parent), self.fid_of(newparent)) {
            (Some(a), Some(b)) => (a, b),
            _ => return reply.error(libc::ENOENT),
        };
        let name = name.to_string_lossy().to_string();
        let newname = newname.to_string_lossy().to_string();

        // 1. Perform the rename on the server.
        let client = self.client.clone();
        let (n1, nn1) = (name.clone(), newname.clone());
        if let Err(e) = self
            .rt
            .block_on(async move { client.renameat(pfid, &n1, npfid, &nn1).await })
        {
            return reply.error(e);
        }

        // 2. Refresh the moved inode's fid. diod binds each fid to a pathname, so the file's
        //    persistent per-inode fid (walked to the *old* name) is now stale -- every later
        //    getattr/open on that inode would return ENOENT, and the kernel reuses the moved dentry
        //    without a fresh lookup, so nothing else repairs it. Re-walk to the new name for a fresh
        //    fid (and the file's qid) and swap it into the inode table, clunking the stale one.
        //    Best-effort: the rename already succeeded, so we reply ok regardless.
        let freshfid = self.client.alloc_fid();
        let client = self.client.clone();
        let walked = self.rt.block_on(async move {
            let qids = client.walk(npfid, freshfid, &[&newname]).await?;
            // The walk established freshfid; release it if the reply carried no qid to use.
            match qids.last().map(|q| q.path) {
                Some(p) => Ok(p),
                None => {
                    let _ = client.clunk(freshfid).await;
                    Err(libc::EIO)
                }
            }
        });
        // A failed walk did not establish freshfid, so that case has nothing to clunk.
        if let Ok(qid_path) = walked {
            let ino = self.intern(qid_path);
            if let Some(inode) = self.inodes.get_mut(&ino) {
                let stale = std::mem::replace(&mut inode.fid, freshfid);
                let c = self.client.clone();
                let _ = self.rt.block_on(async move { c.clunk(stale).await });
            } else {
                // Not tracked (never looked up / already forgotten): nothing to repair.
                let c = self.client.clone();
                let _ = self.rt.block_on(async move { c.clunk(freshfid).await });
            }
        }
        reply.ok();
    }

    fn symlink(
        &mut self,
        req: &Request,
        parent: u64,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let parent_fid = match self.fid_of(parent) {
            Some(f) => f,
            None => return reply.error(libc::ENOENT),
        };
        let name = link_name.to_string_lossy().to_string();
        let target = target.to_string_lossy().to_string();
        let gid = req.gid();
        let basefid = self.client.alloc_fid();
        let client = self.client.clone();
        let res = self.rt.block_on(async move {
            client.symlink(parent_fid, &name, &target, gid).await?;
            client.walk(parent_fid, basefid, &[&name]).await?;
            // basefid exists from here on; release it if the getattr fails.
            match client.getattr(basefid).await {
                Ok(a) => Ok::<Attr, i32>(a),
                Err(e) => {
                    let _ = client.clunk(basefid).await;
                    Err(e)
                }
            }
        });
        match res {
            Ok(attr) => {
                let ino = self.intern(attr.qid.path);
                self.inodes.insert(
                    ino,
                    Inode {
                        fid: basefid,
                        lookups: 1,
                    },
                );
                reply.entry(&self.tuning.entry_ttl, &to_fileattr(ino, &attr), 0);
            }
            Err(e) => reply.error(e),
        }
    }

    fn readlink(&mut self, _req: &Request, ino: u64, reply: ReplyData) {
        let fid = match self.fid_of(ino) {
            Some(f) => f,
            None => return reply.error(libc::ENOENT),
        };
        let client = self.client.clone();
        match self.rt.block_on(async move { client.readlink(fid).await }) {
            Ok(t) => reply.data(t.as_bytes()),
            Err(e) => reply.error(e),
        }
    }

    fn statfs(&mut self, _req: &Request, ino: u64, reply: fuser::ReplyStatfs) {
        let fid = self.fid_of(ino).unwrap_or(self.client.root_fid);
        let client = self.client.clone();
        match self.rt.block_on(async move { client.statfs(fid).await }) {
            Ok((bsize, blocks, bfree, bavail, files, ffree, namelen)) => {
                reply.statfs(blocks, bfree, bavail, files, ffree, bsize, namelen, bsize)
            }
            Err(e) => reply.error(e),
        }
    }
}

impl Fuse9p {
    fn do_unlink(&mut self, parent: u64, name: &OsStr, flags: u32, reply: ReplyEmpty) {
        let parent_fid = match self.fid_of(parent) {
            Some(f) => f,
            None => return reply.error(libc::ENOENT),
        };
        let name = name.to_string_lossy().to_string();
        let client = self.client.clone();
        match self
            .rt
            .block_on(async move { client.unlinkat(parent_fid, &name, flags).await })
        {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::decode_path;

    // The forms the client is expected to send. These pin the agreement between its encoder and
    // this decoder, which are separate libraries in separate languages.
    #[test]
    fn decodes_what_the_client_encodes() {
        assert_eq!(decode_path("foo.typ"), Ok("foo.typ".to_string()));
        assert_eq!(decode_path("."), Ok(".".to_string()));
        assert_eq!(decode_path(""), Ok("".to_string()));
        assert_eq!(
            decode_path("inc%2Fheader.typ"),
            Ok("inc/header.typ".to_string())
        );
        assert_eq!(decode_path("we%0Aird.typ"), Ok("we\nird.typ".to_string()));
        assert_eq!(decode_path("we%0Dird.typ"), Ok("we\rird.typ".to_string()));
        assert_eq!(decode_path("a%25b.typ"), Ok("a%b.typ".to_string()));
        assert_eq!(decode_path("a%20b.typ"), Ok("a b.typ".to_string()));
        assert_eq!(decode_path("h%C3%A9ader.typ"), Ok("héader.typ".to_string()));
    }

    #[test]
    fn refuses_bytes_that_are_not_utf8_once_decoded() {
        assert_eq!(decode_path("%FF%FE"), Err("path wasn't utf-8 once decoded"));
    }
}
