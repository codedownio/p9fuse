//! `p9fuse` binary: a general-purpose 9p2000.L mounter built on the `p9fuse` library crate. Two
//! subcommands mount a remote 9p server -- `mount9p` via the kernel v9fs client (needs
//! CAP_SYS_ADMIN) and `mount9p-fuse` via an unprivileged userspace FUSE bridge. The server is
//! selected by `--connect`'s URL scheme: `tcp://host:port`, `unix:///path`, or `ws://` / `wss://`.

use clap::{Parser, Subcommand};
use p9fuse::transport::{NineTransport, TcpTransport, UnixTransport, WebSocketTransport};
use p9fuse::{fuse9p, mount9p};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "p9fuse",
    about = "Mount a remote 9p2000.L server over TCP/Unix/websocket"
)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Mount a remote 9p2000.L server via the kernel v9fs client (needs CAP_SYS_ADMIN + the 9p
    /// kernel modules). Prefer `mount9p-fuse` where privilege isn't available.
    #[command(name = "mount9p")]
    Mount9p {
        /// Server URL: tcp://host:port, unix:///path, or ws://.../wss://... (`--connect-ws` alias).
        #[arg(long, alias = "connect-ws")]
        connect: String,
        /// Extra websocket handshake header(s), "Name: Value" (e.g. an auth token). Repeatable.
        #[arg(long = "header")]
        headers: Vec<String>,
        /// 9p msize (max message size) in bytes.
        #[arg(long, default_value_t = 512000)]
        msize: usize,
        mountpoint: PathBuf,
    },

    /// Mount a userspace FUSE filesystem that speaks 9p2000.L to the server. Unlike `mount9p`, this
    /// needs no CAP_SYS_ADMIN (FUSE mounts unprivileged), while still carrying full POSIX metadata so
    /// `chmod` works.
    #[command(name = "mount9p-fuse")]
    Mount9pFuse {
        /// Server URL: tcp://host:port, unix:///path, or ws://.../wss://... (`--connect-ws` alias).
        #[arg(long, alias = "connect-ws")]
        connect: String,
        /// Extra websocket handshake header(s), "Name: Value" (e.g. an auth token). Repeatable.
        #[arg(long = "header")]
        headers: Vec<String>,
        /// 9p msize (max message size) in bytes.
        #[arg(long, default_value_t = 512000)]
        msize: usize,
        /// Attach (n_uname) as this uid -- the user the server should act as for file ops.
        #[arg(long, default_value_t = 1000)]
        uid: u32,
        /// Export name to attach (must match the server's export, e.g. diod's `-e`).
        #[arg(long, default_value = "/export")]
        aname: String,

        // ---- Performance knobs (each independently on/off; see p9fuse::Tuning). Defaults favour
        //      throughput, trading cache coherence for fewer round-trips -- safe when the client is
        //      the sole 9p client of its export. Set a TTL to 0 / a bool to false to disable that
        //      optimization and measure or fall back to strict per-op behavior. ----
        /// Seconds the kernel may cache a file's attributes (getattr). 0 disables attr caching.
        #[arg(long, default_value_t = 60)]
        attr_ttl: u64,
        /// Seconds the kernel may cache a name->inode lookup. 0 disables entry caching.
        #[arg(long, default_value_t = 60)]
        entry_ttl: u64,
        /// Seconds to cache a "no such file" lookup (negative-dentry caching). 0 disables it.
        #[arg(long, default_value_t = 5)]
        negative_ttl: u64,
        /// Prefetch every directory entry's attrs on readdir (readdirplus). OFF by default: it's
        /// net-negative (find never stats; our per-entry walk+getattr isn't pipelined). Pass true to
        /// experiment. Metadata speed comes from the attr/entry caches above, not this.
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
        readdirplus: bool,
        /// Pipeline writes (async write-back + kernel writeback cache). Pass false for a synchronous
        /// round-trip per write (the un-tuned baseline).
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        writeback: bool,
        /// Max concurrent in-flight Twrites per file when writeback is on (pipeline depth).
        #[arg(long, default_value_t = 16)]
        wb_depth: usize,

        /// On 9p transport loss the daemon always exits (so a supervisor can remount). When true it
        /// also lazily detaches the mount first, so the mountpoint reverts to its underlying contents
        /// and a supervisor can remount cleanly at the same path. Pass false to leave the dead mount in
        /// place (I/O then fails with ENOTCONN rather than briefly exposing what's underneath).
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        detach_on_transport_loss: bool,

        mountpoint: PathBuf,
    },

    /// Make a directory a shared mount point: bind it onto itself, detach it to MS_PRIVATE, then
    /// mark it MS_SHARED. A filesystem mounted on it *afterwards* then propagates into existing bind
    /// mounts of it. Needs CAP_SYS_ADMIN, so run this as root or via a setuid-root install.
    #[command(name = "make-shared")]
    MakeShared { path: PathBuf },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Log to stderr: stdin/stdout are protocol channels (invalidation paths arrive on stdin), so
    // stdout must stay clean.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    match Args::parse().cmd {
        Cmd::Mount9p {
            connect,
            headers,
            msize,
            mountpoint,
        } => {
            let transport = build_transport(&connect, &parse_headers(&headers)?).await?;
            mount9p::mount9p(transport, &mountpoint, msize).await
        }
        Cmd::Mount9pFuse {
            connect,
            headers,
            msize,
            uid,
            aname,
            attr_ttl,
            entry_ttl,
            negative_ttl,
            readdirplus,
            writeback,
            wb_depth,
            detach_on_transport_loss,
            mountpoint,
        } => {
            let transport = build_transport(&connect, &parse_headers(&headers)?).await?;
            let tuning = fuse9p::Tuning {
                attr_ttl: std::time::Duration::from_secs(attr_ttl),
                entry_ttl: std::time::Duration::from_secs(entry_ttl),
                negative_ttl: (negative_ttl > 0)
                    .then(|| std::time::Duration::from_secs(negative_ttl)),
                readdirplus,
                writeback,
                wb_depth,
            };
            fuse9p::Fuse9p::run(
                transport,
                &mountpoint,
                msize as u32,
                uid,
                &aname,
                tuning,
                detach_on_transport_loss,
            )
            .await
        }
        Cmd::MakeShared { path } => make_shared(&path),
    }
}

/// Make `path` a shared mount point. Bind it onto itself so it becomes a mount, detach it from any
/// inherited master (you can't make a *slave* mount shared -- EINVAL, which is the state mounts are
/// in inside a container/kata), then mark it MS_SHARED so a later mount on it propagates into bind
/// mounts of it. Requires CAP_SYS_ADMIN (this binary is setuid-root).
fn make_shared(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use nix::mount::{mount, MsFlags};
    let none = None::<&str>;
    mount(Some(path), path, none, MsFlags::MS_BIND, none)?;
    mount(none, path, none, MsFlags::MS_PRIVATE, none)?;
    mount(none, path, none, MsFlags::MS_SHARED, none)?;
    Ok(())
}

/// How long `build_transport` retries a local endpoint that isn't accepting connections yet.
const CONNECT_RETRY: std::time::Duration = std::time::Duration::from_secs(30);

/// Retry `attempt` while it fails with "connection refused" / "not found", up to `CONNECT_RETRY`.
/// A freshly-started server may not be listening (or its unix socket may not exist) the instant we
/// dial it; riding out that brief window here avoids failing the whole mount over a startup race.
async fn retry_connect<T, Fut>(mut attempt: impl FnMut() -> Fut) -> std::io::Result<T>
where
    Fut: std::future::Future<Output = std::io::Result<T>>,
{
    let deadline = tokio::time::Instant::now() + CONNECT_RETRY;
    loop {
        match attempt().await {
            Ok(t) => return Ok(t),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                ) && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Build a transport from a `--connect` URL. `headers` apply only to the websocket handshake.
async fn build_transport(
    connect: &str,
    headers: &[(String, String)],
) -> Result<Box<dyn NineTransport>, Box<dyn std::error::Error>> {
    if let Some(addr) = connect.strip_prefix("tcp://") {
        Ok(Box::new(retry_connect(|| TcpTransport::connect(addr)).await?))
    } else if let Some(path) = connect.strip_prefix("unix://") {
        let path = Path::new(path);
        Ok(Box::new(retry_connect(|| UnixTransport::connect(path)).await?))
    } else if connect.starts_with("ws://") || connect.starts_with("wss://") {
        Ok(Box::new(
            WebSocketTransport::connect(connect, headers).await?,
        ))
    } else {
        Err(format!(
            "unsupported --connect {connect:?}: use tcp://host:port, unix:///path, or ws://.../wss://..."
        )
        .into())
    }
}

fn parse_headers(raw: &[String]) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    raw.iter()
        .map(|h| match h.split_once(':') {
            Some((k, v)) => Ok((k.trim().to_string(), v.trim().to_string())),
            None => Err(format!("--header must be 'Name: Value', got {h:?}").into()),
        })
        .collect()
}
