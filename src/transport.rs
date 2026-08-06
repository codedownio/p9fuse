//! Pluggable transports for the 9p client.
//!
//! A transport is nothing more than an ordered, reliable, bidirectional stream of **byte chunks**.
//! 9p2000.L is self-framing -- every message begins with a 4-byte little-endian `size` -- and
//! [`crate::client`] reassembles frames across arbitrary chunk boundaries, so a transport never has
//! to preserve message framing. That means a raw TCP/Unix socket read, a websocket binary message,
//! or anything else that delivers bytes in order works identically.
//!
//! Three transports ship here:
//! - [`TcpTransport`] / [`UnixTransport`] -- the standard 9p transports (connect straight to a
//!   `diod`, `nfs-ganesha`, QEMU virtfs, or any 9p2000.L server).
//! - [`WebSocketTransport`] -- 9p tunnelled over a websocket, for reaching a server that is only
//!   exposed via an HTTP endpoint (and can carry auth headers on the handshake).

use bytes::Bytes;
use futures_util::{future, Sink, SinkExt, Stream, StreamExt};
use std::io;
use std::path::Path;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};
use tokio_util::codec::{BytesCodec, FramedRead, FramedWrite};

/// The write half of a transport: an ordered sink of 9p byte chunks.
pub type ByteSink = Pin<Box<dyn Sink<Vec<u8>, Error = io::Error> + Send>>;
/// The read half of a transport: an ordered stream of 9p byte chunks (or an I/O error).
pub type ByteStream = Pin<Box<dyn Stream<Item = io::Result<Vec<u8>>> + Send>>;

/// A connected transport that can be split into its write and read halves. Implementors box their
/// halves so [`crate::client::NineClient`] stays transport-agnostic (and non-generic).
pub trait NineTransport: Send + 'static {
    fn split(self: Box<Self>) -> (ByteSink, ByteStream);
}

fn to_io<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// Wrap a raw byte-stream socket (TCP or Unix) as a `(ByteSink, ByteStream)` pair. `BytesCodec`
/// hands us whatever bytes are available per read as one chunk and writes chunks straight through --
/// exactly the "framing doesn't matter" contract 9p relies on.
fn framed<R, W>(rd: R, wr: W) -> (ByteSink, ByteStream)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let stream = FramedRead::new(rd, BytesCodec::new()).map(|r| r.map(|b| b.to_vec()));
    let sink = FramedWrite::new(wr, BytesCodec::new())
        .with(|v: Vec<u8>| future::ready(Ok::<Bytes, io::Error>(Bytes::from(v))));
    (Box::pin(sink), Box::pin(stream))
}

/// 9p over a plain TCP socket -- the usual way to reach a `diod`/`unpfs`/virtfs server.
pub struct TcpTransport(pub TcpStream);

impl TcpTransport {
    pub async fn connect(addr: &str) -> io::Result<Self> {
        Ok(Self(TcpStream::connect(addr).await?))
    }
}

impl NineTransport for TcpTransport {
    fn split(self: Box<Self>) -> (ByteSink, ByteStream) {
        let (rd, wr) = self.0.into_split();
        framed(rd, wr)
    }
}

/// 9p over a socket someone else already connected and passed to us on a file descriptor.
///
/// For the case where this process cannot do the connecting: the peer dials *in*, and whoever
/// accepted the connection hands the socket over (as stdin, say) rather than relaying its bytes.
/// That keeps every byte on a direct kernel path between the 9p server and this process.
///
/// Takes ownership of `fd`, and works for either an AF_INET/AF_INET6 or an AF_UNIX socket --
/// whoever accepted it decides which, so ask the kernel rather than assume.
pub struct FdTransport(FdInner);

enum FdInner {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl FdTransport {
    /// # Safety
    /// `fd` must be a connected socket that nothing else owns or reads/writes concurrently.
    pub unsafe fn from_raw_fd(fd: std::os::unix::io::RawFd) -> io::Result<Self> {
        use std::os::unix::io::FromRawFd;

        // tokio requires a nonblocking fd; an inherited one usually isn't.
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut domain: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_DOMAIN,
            &mut domain as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        match domain {
            libc::AF_UNIX => Ok(Self(FdInner::Unix(UnixStream::from_std(
                std::os::unix::net::UnixStream::from_raw_fd(fd),
            )?))),
            libc::AF_INET | libc::AF_INET6 => Ok(Self(FdInner::Tcp(TcpStream::from_std(
                std::net::TcpStream::from_raw_fd(fd),
            )?))),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("fd {fd} is a socket of unsupported domain {other}"),
            )),
        }
    }
}

impl NineTransport for FdTransport {
    fn split(self: Box<Self>) -> (ByteSink, ByteStream) {
        match self.0 {
            FdInner::Tcp(s) => {
                let (rd, wr) = s.into_split();
                framed(rd, wr)
            }
            FdInner::Unix(s) => {
                let (rd, wr) = s.into_split();
                framed(rd, wr)
            }
        }
    }
}

/// 9p over a Unix-domain socket -- for a server on the same host (rootless diod, a local export).
pub struct UnixTransport(pub UnixStream);

impl UnixTransport {
    pub async fn connect(path: &Path) -> io::Result<Self> {
        Ok(Self(UnixStream::connect(path).await?))
    }
}

impl NineTransport for UnixTransport {
    fn split(self: Box<Self>) -> (ByteSink, ByteStream) {
        let (rd, wr) = self.0.into_split();
        framed(rd, wr)
    }
}

type WsStream = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

/// 9p tunnelled over a websocket. Each 9p chunk is carried as one binary message; control frames
/// (ping/pong/text) are ignored and a close ends the stream. Useful when the 9p server is only
/// reachable behind an HTTP endpoint that can also carry auth headers on the handshake.
pub struct WebSocketTransport(WsStream);

impl WebSocketTransport {
    /// Open the websocket at `url` (`ws://` or `wss://`), attaching each `"Name: Value"` pair in
    /// `headers` to the handshake request (e.g. an auth token).
    pub async fn connect(
        url: &str,
        headers: &[(String, String)],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};

        let mut req = url.into_client_request().map_err(to_io)?;
        {
            let hs = req.headers_mut();
            for (k, v) in headers {
                let name = HeaderName::from_bytes(k.as_bytes()).map_err(to_io)?;
                let val = HeaderValue::from_str(v).map_err(to_io)?;
                hs.insert(name, val);
            }
        }
        let (ws, _resp) = tokio_tungstenite::connect_async(req).await.map_err(to_io)?;
        tracing::info!(%url, "websocket transport connected");
        Ok(Self(ws))
    }
}

impl NineTransport for WebSocketTransport {
    fn split(self: Box<Self>) -> (ByteSink, ByteStream) {
        use tokio_tungstenite::tungstenite::Message;

        let (sink, stream) = self.0.split();
        let sink = sink
            .sink_map_err(to_io)
            .with(|v: Vec<u8>| future::ready(Ok::<Message, io::Error>(Message::Binary(v))));
        let stream = stream.filter_map(|msg| async move {
            match msg {
                Ok(Message::Binary(b)) => Some(Ok(b)),
                Ok(Message::Close(_)) => None,
                // ping/pong/text: not 9p payload -- skip without ending the stream.
                Ok(_) => None,
                Err(e) => Some(Err(to_io(e))),
            }
        });
        (Box::pin(sink), Box::pin(stream))
    }
}
