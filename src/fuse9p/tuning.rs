use std::time::Duration;

/// Caching and write knobs, each settable from the CLI. The caches assume this mount is the main
/// way the export changes; paths changed from outside are dropped from them by invalidations.
#[derive(Clone, Debug)]
pub struct Tuning {
    /// How long the kernel may reuse a file's attributes before asking again. 0 = ask every time.
    pub attr_ttl: Duration,
    /// How long the kernel may reuse a name -> inode lookup. 0 = look up every time.
    pub entry_ttl: Duration,
    /// How long the kernel may remember that a name doesn't exist, so repeated probes of missing
    /// paths (include dirs, `$PATH`) don't each go to the server. `None` = don't remember.
    pub negative_ttl: Option<Duration>,
    /// Fetch each entry's attributes while reading a directory (READDIRPLUS). Off by default: it
    /// costs a walk and getattr per entry, which measured slower than fetching attributes on demand.
    pub readdirplus: bool,
    /// Let the kernel buffer writes in its page cache (FUSE_WRITEBACK_CACHE). The kernel then trusts
    /// its own file sizes, so a file grown from outside the mount reads back truncated while its
    /// inode is cached, even after an invalidation. Only safe when nothing else writes the export.
    pub writeback_cache: bool,
    /// Acknowledge writes at once and send them from background tasks, up to `wb_depth` per file.
    /// Errors are reported at flush/fsync/close. Off = one synchronous round trip per write.
    pub write_pipeline: bool,
    /// The most writes in flight per file when `write_pipeline` is on.
    pub wb_depth: usize,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning {
            attr_ttl: Duration::from_secs(60),
            entry_ttl: Duration::from_secs(60),
            negative_ttl: Some(Duration::from_secs(5)),
            readdirplus: false,
            writeback_cache: false,
            write_pipeline: true,
            wb_depth: 16,
        }
    }
}
