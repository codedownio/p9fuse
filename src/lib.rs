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
/// On 9p transport loss this exits and detaches the mount so a supervisor can remount cleanly (the
/// default). Call [`Fuse9p::run`] directly to control that with `detach_on_transport_loss`.
pub async fn mount(
    transport: Box<dyn NineTransport>,
    mountpoint: &Path,
    msize: u32,
    uid: u32,
    aname: &str,
    tuning: Tuning,
) -> Result<(), Box<dyn std::error::Error>> {
    Fuse9p::run(transport, mountpoint, msize, uid, aname, tuning, true).await
}
