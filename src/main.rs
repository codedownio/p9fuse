//! `p9fuse` binary: a general-purpose 9p2000.L mounter built on the `p9fuse` library crate. Two
//! subcommands mount a remote 9p server -- `mount9p` via the kernel v9fs client (needs
//! CAP_SYS_ADMIN) and `mount9p-fuse` via an unprivileged userspace FUSE bridge. The server is
//! selected by `--connect`'s URL scheme: `tcp://host:port`, `unix:///path`, or `ws://` / `wss://`.

use clap::{Parser, Subcommand};
use p9fuse::transport::{NineTransport, TcpTransport, UnixTransport, WebSocketTransport};
use p9fuse::{fuse9p, mount9p};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(name = "p9fuse", about = "Mount a remote 9p2000.L server over TCP/Unix/websocket")]
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

        mountpoint: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    match Args::parse().cmd {
        Cmd::Mount9p { connect, headers, msize, mountpoint } => {
            let transport = build_transport(&connect, &parse_headers(&headers)?).await?;
            mount9p::mount9p(transport, &mountpoint, msize).await
        }
        Cmd::Mount9pFuse {
            connect, headers, msize, uid, aname,
            attr_ttl, entry_ttl, negative_ttl, readdirplus, writeback, wb_depth,
            mountpoint,
        } => {
            let transport = build_transport(&connect, &parse_headers(&headers)?).await?;
            let tuning = fuse9p::Tuning {
                attr_ttl: std::time::Duration::from_secs(attr_ttl),
                entry_ttl: std::time::Duration::from_secs(entry_ttl),
                negative_ttl: (negative_ttl > 0).then(|| std::time::Duration::from_secs(negative_ttl)),
                readdirplus,
                writeback,
                wb_depth,
            };
            fuse9p::Fuse9p::run(transport, &mountpoint, msize as u32, uid, &aname, tuning).await
        }
    }
}

/// Build a transport from a `--connect` URL. `headers` apply only to the websocket handshake.
async fn build_transport(
    connect: &str,
    headers: &[(String, String)],
) -> Result<Box<dyn NineTransport>, Box<dyn std::error::Error>> {
    if let Some(addr) = connect.strip_prefix("tcp://") {
        Ok(Box::new(TcpTransport::connect(addr).await?))
    } else if let Some(path) = connect.strip_prefix("unix://") {
        Ok(Box::new(UnixTransport::connect(Path::new(path)).await?))
    } else if connect.starts_with("ws://") || connect.starts_with("wss://") {
        Ok(Box::new(WebSocketTransport::connect(connect, headers).await?))
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
