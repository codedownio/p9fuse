//! A userspace **9p2000.L client and FUSE bridge**: mount a remote 9p filesystem locally, over any
//! transport, without CAP_SYS_ADMIN.
//!
//! Unlike the Linux kernel's in-tree v9fs client (which needs privilege to `mount(2)`), this mounts
//! through FUSE's unprivileged `fusermount3` helper while still speaking full 9p2000.L -- so POSIX
//! metadata (`chmod`, ownership, symlinks) round-trips faithfully. It carries attribute/entry/
//! negative-lookup caching and write-back pipelining so it stays fast over a network link.
//!
//! ```no_run
//! # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! use std::path::Path;
//! use p9fuse::{mount, Tuning, TcpTransport};
//!
//! // Mount a diod export (`diod -e /export -l 0.0.0.0:564`) at /mnt/home.
//! let transport = Box::new(TcpTransport::connect("127.0.0.1:564").await?);
//! mount(transport, Path::new("/mnt/home"), 512_000, 1000, "/export", Tuning::default()).await?;
//! # Ok(()) }
//! ```
//!
//! The pieces are usable independently: [`NineClient`] is a standalone async 9p2000.L client, and
//! [`NineTransport`] lets you plug in any byte-stream transport ([`TcpTransport`], [`UnixTransport`],
//! [`WebSocketTransport`], or your own).

pub mod client;
pub mod fuse9p;
pub mod mount9p;
pub mod ninep;
pub mod transport;

pub use client::NineClient;
pub use fuse9p::{Fuse9p, Tuning};
pub use transport::{
    ByteSink, ByteStream, NineTransport, TcpTransport, UnixTransport, WebSocketTransport,
};

use std::path::Path;

/// Mount the 9p2000.L server reachable via `transport` as a FUSE filesystem at `mountpoint`,
/// blocking until it is unmounted.
///
/// - `msize` is the 9p max message size to negotiate (e.g. `512_000`).
/// - `uid` is the identity to attach as (`n_uname`); the server acts as this user for file ops.
/// - `aname` is the export name to attach (must match the server's export, e.g. `"/export"`).
/// - `tuning` controls the caching / write-back knobs (see [`Tuning`]).
///
/// Invalidation requests are read from the process's stdin and answered on its stdout; use
/// [`mount_with_invalidations`] to use other streams.
pub async fn mount(
    transport: Box<dyn NineTransport>,
    mountpoint: &Path,
    msize: u32,
    uid: u32,
    aname: &str,
    tuning: Tuning,
) -> Result<(), Box<dyn std::error::Error>> {
    mount_with_invalidations(
        transport,
        mountpoint,
        msize,
        uid,
        aname,
        tuning,
        Box::new(tokio::io::stdin()),
        Box::new(tokio::io::stdout()),
    )
    .await
}

/// Like [`mount`], but reads invalidation requests from `invalidations` and writes their replies to
/// `replies`. Each request names a path relative to the mount root and drops its cached entry,
/// attributes and data from the kernel, so the next access sees changes made to the export from
/// outside the mount; its reply is written once that is done.
#[allow(clippy::too_many_arguments)]
pub async fn mount_with_invalidations(
    transport: Box<dyn NineTransport>,
    mountpoint: &Path,
    msize: u32,
    uid: u32,
    aname: &str,
    tuning: Tuning,
    invalidations: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    replies: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
) -> Result<(), Box<dyn std::error::Error>> {
    Fuse9p::run(
        transport,
        mountpoint,
        msize,
        uid,
        aname,
        tuning,
        true,
        true,
        std::time::Duration::from_secs(30),
        invalidations,
        replies,
    )
    .await
}
