//! Dropping paths changed outside the mount from the kernel's caches.
//!
//! Requests arrive one per line as `inval <id> <percent-encoded path>`, or as a bare path from older
//! clients, relative to the mount root. Each gets exactly one reply line once it has been applied:
//! `ok <id>` (or `ok <path>`), or `err <id> <reason>` if the path can't be decoded.

use super::qid_to_ino;
use crate::client::NineClient;
use fuser::Notifier;
use std::ffi::OsStr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

/// The longest file name Linux allows.
const NAME_MAX: usize = 255;

pub(super) struct Invalidator {
    pub notifier: Notifier,
    pub client: Arc<NineClient>,
    pub root_fid: u32,
    pub root_qid_path: u64,
}

impl Invalidator {
    pub(super) async fn run(
        self,
        requests: Box<dyn AsyncRead + Send + Unpin>,
        mut replies: Box<dyn AsyncWrite + Send + Unpin>,
    ) {
        let this = Arc::new(self);
        let mut lines = BufReader::new(requests).lines();
        loop {
            let line = match lines.next_line().await {
                Ok(Some(line)) => line,
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!(?e, "mount9p-fuse: error reading invalidations");
                    break;
                }
            };
            let answer = match line.strip_prefix("inval ") {
                Some(rest) => {
                    let (id, escaped) = rest.split_once(' ').unwrap_or((rest, ""));
                    match decode_path(escaped) {
                        Ok(path) => {
                            this.invalidate(&path).await;
                            format!("ok {id}")
                        }
                        Err(e) => {
                            tracing::warn!(id, escaped, e, "mount9p-fuse: bad invalidation path");
                            format!("err {id} {e}")
                        }
                    }
                }
                None => {
                    this.invalidate(&line).await;
                    format!("ok {line}")
                }
            };
            reply(&mut *replies, &answer).await;
        }
        tracing::info!("mount9p-fuse: invalidation input closed");
    }

    /// Drop the dentry for `path` (so the next access looks it up again) and its inode's cached
    /// attributes and data. A path that doesn't resolve any more (deleted or renamed) only has its
    /// dentry dropped.
    async fn invalidate(self: &Arc<Self>, path: &str) {
        let comps: Vec<&str> = path.trim().split('/').filter(|s| !s.is_empty()).collect();
        let Some((name, parent)) = comps.split_last() else {
            return;
        };
        // No file has a longer name, and 9p can't send one over 65535 bytes.
        if comps.iter().any(|c| c.len() > NAME_MAX) {
            return;
        }
        match self.resolve(parent).await {
            Ok(parent_ino) => {
                let name = name.to_string();
                let r = self
                    .notify(move |n| n.inval_entry(parent_ino, OsStr::new(&name)))
                    .await;
                tracing::info!(path, parent_ino, result = ?r, "mount9p-fuse: inval_entry");
            }
            Err(e) => tracing::warn!(path, e, "mount9p-fuse: invalidation parent walk failed"),
        }
        match self.resolve(&comps).await {
            Ok(ino) => {
                let r = self.notify(move |n| n.inval_inode(ino, 0, 0)).await;
                tracing::info!(path, ino, result = ?r, "mount9p-fuse: inval_inode");
            }
            Err(e) => tracing::warn!(path, e, "mount9p-fuse: invalidation walk failed"),
        }
    }

    /// The inode at `comps` below the root, found with a fresh walk (inode numbers are qid paths).
    async fn resolve(&self, comps: &[&str]) -> Result<u64, i32> {
        let fid = self.client.alloc_fid();
        let qids = self.client.walk(self.root_fid, fid, comps).await?;
        let _ = self.client.clunk(fid).await;
        let qid_path = qids.last().map_or(self.root_qid_path, |q| q.path);
        Ok(qid_to_ino(qid_path, self.root_qid_path))
    }

    /// Run a notify on a blocking thread. The kernel handles an entry notify under the parent
    /// directory's lock, which a LOOKUP in progress holds until we answer it; blocking a runtime
    /// worker here could stop that answer from ever being sent.
    async fn notify(
        self: &Arc<Self>,
        f: impl FnOnce(&Notifier) -> std::io::Result<()> + Send + 'static,
    ) -> Result<std::io::Result<()>, tokio::task::JoinError> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || f(&this.notifier)).await
    }
}

/// Percent-decode a request's path. Clients encode it because a filename may contain a newline.
fn decode_path(s: &str) -> Result<String, &'static str> {
    percent_encoding::percent_decode_str(s)
        .decode_utf8()
        .map(|p| p.into_owned())
        .map_err(|_| "path wasn't utf-8 once decoded")
}

async fn reply(out: &mut (dyn AsyncWrite + Send + Unpin), line: &str) {
    let line = format!("{line}\n");
    if let Err(e) = out.write_all(line.as_bytes()).await {
        tracing::warn!(?e, "mount9p-fuse: couldn't write an invalidation reply");
    } else if let Err(e) = out.flush().await {
        tracing::warn!(?e, "mount9p-fuse: couldn't flush an invalidation reply");
    }
}

#[cfg(test)]
mod tests {
    use super::decode_path;

    // What clients send. The encoder lives in a separate library in another language, so these pin
    // the format both sides agree on.
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
