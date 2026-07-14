//! `mount9p-fuse`: a userspace FUSE filesystem that speaks 9p2000.L to a remote server via the
//! [`NineClient`]. This is the unprivileged alternative to the kernel v9fs client: FUSE is
//! user-namespace mountable / has a setuid `fusermount3` helper, so it mounts without CAP_SYS_ADMIN,
//! while 9p2000.L still carries full POSIX metadata so `chmod`/ownership round-trip faithfully.
//!
//! FUSE callbacks are synchronous and serialized (single-threaded session), so the inode/handle
//! tables need no locking; each callback bridges to the async client via `Handle::block_on`.

use crate::client::NineClient;
use crate::ninep::Attr;
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::runtime::Handle;
use tokio::sync::Semaphore;

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
    /// Pipeline writes: defer each `Twrite` to a background task (depth `wb_depth`) and let the kernel
    /// buffer/flush via FUSE writeback cache, turning latency-bound sequential writes into throughput.
    /// Off = each `write` is one synchronous `Twrite` round-trip (the original behavior).
    pub writeback: bool,
    /// Max concurrent in-flight `Twrite`s per open file when `writeback` is on. Bounds memory
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
            writeback: true,
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

/// Write-back state for one open writable file: a semaphore bounding in-flight `Twrite`s (the
/// pipeline depth) and the first error seen by any background write, surfaced at flush/fsync/release.
struct WriteBack {
    sem: Arc<Semaphore>,
    depth: usize,
    err: Mutex<Option<i32>>,
}

/// An open file/dir handle: the opened 9p fid, plus (for writable files) the write-back tracker.
struct FileHandle {
    fid: u32,
    wb: Option<Arc<WriteBack>>,
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

    /// Register an opened fid as a new file/dir handle. Writable file handles get a write-back
    /// tracker (when the `writeback` knob is on) so their writes can pipeline; read-only/dir handles
    /// and the writeback-off case don't, so writes fall back to synchronous round-trips.
    fn insert_handle(&mut self, fid: u32, writable: bool) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        let wb = if writable && self.tuning.writeback {
            let depth = self.tuning.wb_depth.max(1);
            Some(Arc::new(WriteBack {
                sem: Arc::new(Semaphore::new(depth)),
                depth,
                err: Mutex::new(None),
            }))
        } else {
            None
        };
        self.handles.insert(fh, FileHandle { fid, wb });
        fh
    }

    /// Block until every in-flight write-back task for `wb` has completed, returning the first error
    /// any of them hit. Acquiring all `depth` permits is only possible once all outstanding writes
    /// have released theirs.
    fn drain_writeback(&self, wb: Arc<WriteBack>) -> Option<i32> {
        let depth = wb.depth as u32;
        self.rt.block_on(async move {
            let _all = wb
                .sem
                .acquire_many(depth)
                .await
                .expect("write-back semaphore closed");
            wb.err.lock().unwrap().take()
        })
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

/// Write `data` to `fid` starting at byte `off`, split into `chunk`-sized `Twrite`s. A short write of
/// 0 is treated as an error so callers don't spin.
async fn write_all(
    client: &NineClient,
    fid: u32,
    off: u64,
    data: &[u8],
    chunk: usize,
) -> Result<(), i32> {
    let mut pos = 0usize;
    let mut o = off;
    while pos < data.len() {
        let end = (pos + chunk.max(1)).min(data.len());
        let n = client.write(fid, o, &data[pos..end]).await?;
        if n == 0 {
            return Err(libc::EIO);
        }
        pos += n as usize;
        o += n as u64;
    }
    Ok(())
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
    pub async fn run(
        transport: Box<dyn crate::transport::NineTransport>,
        mountpoint: &Path,
        msize: u32,
        uid: u32,
        aname: &str,
        tuning: Tuning,
    ) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!(?tuning, "mount9p-fuse: tuning");
        // Attach as `uid` so the server acts as that user for file ops (a multiuser server like diod
        // setfsuids to it per attach), so files are owned by `uid` and chmod works.
        let (client, root_qid) = NineClient::connect(transport, msize, uid, aname).await?;

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
        };

        // No AutoUnmount: that path wants the libfuse feature we deliberately dropped. The kernel
        // tears the mount down when this process exits.
        let mut options = vec![
            MountOption::FSName("p9fuse".to_string()),
            MountOption::Subtype("9p".to_string()),
            MountOption::DefaultPermissions,
        ];
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
        // Read invalidation paths (one per line) from stdin and drop them from the kernel cache.
        tokio::spawn(invalidation_loop(
            notifier,
            inval_client,
            root_fid,
            root_qid_path,
        ));
        // session.run() blocks for the life of the mount; run it off the async executor so the
        // runtime stays free to service the client's (and invalidation task's) requests.
        tokio::task::spawn_blocking(move || session.run())
            .await?
            .map_err(|e| e.into())
    }
}

/// Reads invalidation paths from stdin (one path per line, relative to the mount root) and drops them
/// from the kernel's caches via FUSE notifies. Feed this from whatever knows the backing store changed
/// out-of-band, to keep aggressive caching coherent. Resolving a path to its inode is a plain 9p walk
/// (inode == qid.path), so no shared state with the FUSE filesystem is needed. Best-effort: a path the
/// kernel never cached simply isn't there to drop.
async fn invalidation_loop(
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
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    loop {
        let line = match lines.next_line().await {
            Ok(Some(l)) => l,
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(?e, "mount9p-fuse: error reading invalidation stdin");
                break;
            }
        };
        let rel = line.trim().trim_start_matches('/');
        if rel.is_empty() {
            continue;
        }
        let comps: Vec<&str> = rel.split('/').filter(|s| !s.is_empty()).collect();
        let (name, parent_comps) = match comps.split_last() {
            Some(x) => x,
            None => continue,
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
            Err(e) => {
                let _ = client.clunk(pf).await;
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
            Err(e) => {
                let _ = client.clunk(cf).await;
                tracing::warn!(rel, ?e, "mount9p-fuse: invalidation child walk failed");
            }
        }
    }
    tracing::info!("mount9p-fuse: invalidation stdin closed");
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
        if self.tuning.writeback {
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
        let res = self.rt.block_on(async move {
            client.walk(parent_fid, newfid, &[&name]).await?;
            let a = client.getattr(newfid).await?;
            Ok::<Attr, i32>(a)
        });
        match res {
            Err(e) => {
                // The walk may have partially succeeded then failed; clunk defensively.
                let c = self.client.clone();
                let _ = self.rt.block_on(async move { c.clunk(newfid).await });
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
        let mut oflags = (flags as u32) & !(libc::O_CLOEXEC as u32);
        // With the FUSE writeback cache the kernel issues READs on the handle for partial-page
        // read-modify-write even when the file was opened write-only; the server would then answer
        // those reads with EBADF on a write-only fid. Upgrade write-only opens to O_RDWR so the
        // kernel's RMW reads succeed. (Harmless when off, but only needed with writeback on.)
        if self.tuning.writeback && (oflags & libc::O_ACCMODE as u32) == libc::O_WRONLY as u32 {
            oflags = (oflags & !(libc::O_ACCMODE as u32)) | libc::O_RDWR as u32;
        }
        let client = self.client.clone();
        let res = self.rt.block_on(async move {
            client.walk(base, newfid, &[]).await?; // clone the base fid
            client.lopen(newfid, oflags).await?;
            Ok::<(), i32>(())
        });
        match res {
            Ok(()) => {
                // Give writable opens a write-back tracker so writes can pipeline.
                let writable = (oflags & libc::O_ACCMODE as u32) != libc::O_RDONLY as u32;
                let fh = self.insert_handle(newfid, writable);
                reply.opened(fh, 0);
            }
            Err(e) => {
                let c = self.client.clone();
                let _ = self.rt.block_on(async move { c.clunk(newfid).await });
                reply.error(e);
            }
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        _ino: u64,
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
        let client = self.client.clone();
        let cap = size.min(self.client.msize.saturating_sub(24));
        match self
            .rt
            .block_on(async move { client.read(fid, offset as u64, cap).await })
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
        let (fid, wb) = match self.handles.get(&fh) {
            Some(h) => (h.fid, h.wb.clone()),
            None => return reply.error(libc::EBADF),
        };
        // Chunk to the negotiated msize (leave headroom for the Twrite header).
        let chunk = self.client.msize.saturating_sub(24) as usize;
        let client = self.client.clone();
        let data = data.to_vec();
        let len = data.len() as u32;
        let off = offset as u64;

        let wb = match wb {
            // Writable handle: defer the Twrite(s) to a background task so successive writes pipeline
            // over the ws (depth-bounded by the semaphore). Ack the bytes optimistically; any error
            // is recorded and surfaced at flush/fsync/release -- standard write-back semantics.
            Some(wb) => wb,
            // Read-only handle being written (shouldn't happen): fall back to a synchronous write.
            None => {
                let res = self
                    .rt
                    .block_on(async move { write_all(&client, fid, off, &data, chunk).await });
                return match res {
                    Ok(()) => reply.written(len),
                    Err(e) => reply.error(e),
                };
            }
        };

        self.rt.block_on(async {
            // Backpressure: block here once wb_depth writes are already in flight.
            let permit = wb
                .sem
                .clone()
                .acquire_owned()
                .await
                .expect("write-back semaphore closed");
            let wb2 = wb.clone();
            tokio::spawn(async move {
                let _permit = permit; // released (slot freed) when this write finishes
                if let Err(e) = write_all(&client, fid, off, &data, chunk).await {
                    let mut g = wb2.err.lock().unwrap();
                    if g.is_none() {
                        *g = Some(e);
                    }
                }
            });
        });
        reply.written(len);
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
            let err = h.wb.and_then(|wb| self.drain_writeback(wb));
            let fid = h.fid;
            let c = self.client.clone();
            let _ = self.rt.block_on(async move { c.clunk(fid).await });
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
            client.walk(base, newfid, &[]).await?; // clone
            client.lopen(newfid, 0).await?; // O_RDONLY; diod allows readdir on it
            Ok::<(), i32>(())
        });
        match res {
            Ok(()) => {
                let fh = self.insert_handle(newfid, false);
                reply.opened(fh, 0);
            }
            Err(e) => {
                let c = self.client.clone();
                let _ = self.rt.block_on(async move { c.clunk(newfid).await });
                reply.error(e);
            }
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
        let oflags = (flags as u32) & !(libc::O_CLOEXEC as u32);
        let client = self.client.clone();
        let res = self.rt.block_on(async move {
            // Clone the parent into openfid and create+open the new file through it.
            client.walk(parent_fid, openfid, &[]).await?;
            client
                .lcreate(openfid, &name, oflags, mode & 0o7777, gid)
                .await?;
            // Separately walk a base fid to the new entry for the inode table + attrs.
            client.walk(parent_fid, basefid, &[&name]).await?;
            let a = client.getattr(basefid).await?;
            Ok::<Attr, i32>(a)
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
                // The created file is opened for writing -> give it a write-back tracker.
                let fh = self.insert_handle(openfid, true);
                reply.created(&self.tuning.entry_ttl, &to_fileattr(ino, &attr), 0, fh, 0);
            }
            Err(e) => {
                let c = self.client.clone();
                self.rt.block_on(async move {
                    let _ = c.clunk(openfid).await;
                    let _ = c.clunk(basefid).await;
                });
                reply.error(e);
            }
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
            let a = client.getattr(basefid).await?;
            Ok::<Attr, i32>(a)
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
            Err(e) => {
                let c = self.client.clone();
                let _ = self.rt.block_on(async move { c.clunk(basefid).await });
                reply.error(e);
            }
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
        if let Some(wb) = self.handles.get(&fh).and_then(|h| h.wb.clone()) {
            if let Some(e) = self.drain_writeback(wb) {
                return reply.error(e);
            }
        }
        reply.ok();
    }

    fn fsync(&mut self, _req: &Request, _ino: u64, fh: u64, _datasync: bool, reply: ReplyEmpty) {
        let (fid, wb) = match self.handles.get(&fh) {
            Some(h) => (h.fid, h.wb.clone()),
            None => return reply.ok(),
        };
        // Make deferred writes durable: first drain our in-flight Twrites, then Tfsync on the server.
        if let Some(wb) = wb {
            if let Some(e) = self.drain_writeback(wb) {
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
            qids.last().map(|q| q.path).ok_or(libc::EIO)
        });
        match walked {
            Ok(qid_path) => {
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
            Err(_) => {
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
            let a = client.getattr(basefid).await?;
            Ok::<Attr, i32>(a)
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
            Err(e) => {
                let c = self.client.clone();
                let _ = self.rt.block_on(async move { c.clunk(basefid).await });
                reply.error(e);
            }
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
