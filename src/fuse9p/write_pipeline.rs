//! Pipelined writes for one inode. A FUSE `write` is acknowledged as soon as it is queued here; the
//! `Twrite`s go out from background tasks, up to `depth` at a time. Two rules keep the file's
//! contents what the application wrote:
//!
//! - A write never overtakes an earlier write it overlaps. The server may apply concurrent `Twrite`s
//!   in any order, so a write waits for every overlapping write still in flight before it is sent.
//! - When every slot is busy, a write that continues exactly where the previous one ended is merged
//!   into a single pending buffer (up to one `Twrite`'s worth) instead of waiting for a slot, and the
//!   first write to finish sends it. Runs of small sequential writes over a slow link then go out
//!   as a few large `Twrite`s; on an idle pipeline nothing is held back.
//!
//! The FUSE session calls `write` and `settle` from one thread at a time, so only the background
//! tasks run concurrently with them.

use crate::client::NineClient;
use std::sync::{Arc, Mutex};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};

/// The first error hit by a background write through one handle, reported at its next
/// flush/fsync/release.
pub(crate) type WriteError = Arc<Mutex<Option<i32>>>;

/// One application write: the bytes, where they go, and the fid and error slot of its handle.
pub(crate) struct Write {
    pub fid: u32,
    pub off: u64,
    pub data: Vec<u8>,
    pub err: WriteError,
}

impl Write {
    fn end(&self) -> u64 {
        self.off + self.data.len() as u64
    }
}

/// The write pipeline of one inode, shared by all its open handles.
pub(crate) struct InodeWrites {
    client: Arc<NineClient>,
    /// The most bytes one `Twrite` carries; also the cap on a merged pending buffer.
    chunk: usize,
    /// One permit per `Twrite` in flight. Every held permit belongs to a running task, which is
    /// what guarantees a pending buffer is eventually sent.
    slots: Arc<Semaphore>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// Writes handed to a task and not yet finished, oldest first.
    inflight: Vec<InFlight>,
    /// Newer than everything in `inflight`; sent by the next task to finish, or by the next write
    /// or settle that cannot merge into it.
    pending: Option<Write>,
    next_id: u64,
}

struct InFlight {
    id: u64,
    start: u64,
    end: u64,
    /// Its sender is dropped when the write finishes, which wakes everything waiting on it.
    done: watch::Receiver<()>,
}

impl InodeWrites {
    pub(crate) fn new(client: Arc<NineClient>, chunk: usize, depth: usize) -> Arc<Self> {
        Arc::new(InodeWrites {
            client,
            chunk: chunk.max(1),
            slots: Arc::new(Semaphore::new(depth.max(1))),
            state: Mutex::new(State::default()),
        })
    }

    /// Whether any write is still unsent or in flight.
    pub(crate) fn busy(&self) -> bool {
        let st = self.state.lock().unwrap();
        st.pending.is_some() || !st.inflight.is_empty()
    }

    /// Queue `w`. Returns once it is merged into the pending buffer or handed to a background task;
    /// blocks only while every slot is busy and `w` cannot be merged.
    pub(crate) async fn write(self: &Arc<Self>, w: Write) {
        let earlier = {
            let mut st = self.state.lock().unwrap();
            if let Some(p) = st.pending.as_mut() {
                if p.fid == w.fid && p.end() == w.off && p.data.len() + w.data.len() <= self.chunk {
                    p.data.extend_from_slice(&w.data);
                    return;
                }
            }
            st.pending.take()
        };
        // The pending buffer is older than `w`, so it goes out first.
        if let Some(p) = earlier {
            let permit = self.acquire().await;
            self.start(permit, p);
        }
        let permit = {
            let mut st = self.state.lock().unwrap();
            // Checked under the lock that tasks release their permits under: if this fails, some
            // task still holds a slot and will see the pending buffer when it finishes.
            match self.slots.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) if w.data.len() < self.chunk => {
                    st.pending = Some(w);
                    return;
                }
                Err(_) => None,
            }
        };
        let permit = match permit {
            Some(permit) => permit,
            None => self.acquire().await,
        };
        self.start(permit, w);
    }

    /// Send the pending buffer and wait until every write on this inode has finished.
    pub(crate) async fn settle(self: &Arc<Self>) {
        let earlier = self.state.lock().unwrap().pending.take();
        if let Some(p) = earlier {
            let permit = self.acquire().await;
            self.start(permit, p);
        }
        let waits: Vec<watch::Receiver<()>> = {
            let st = self.state.lock().unwrap();
            st.inflight.iter().map(|f| f.done.clone()).collect()
        };
        for mut done in waits {
            let _ = done.changed().await;
        }
    }

    async fn acquire(&self) -> OwnedSemaphorePermit {
        self.slots
            .clone()
            .acquire_owned()
            .await
            .expect("write slots semaphore closed")
    }

    fn start(self: &Arc<Self>, permit: OwnedSemaphorePermit, w: Write) {
        let started = {
            let mut st = self.state.lock().unwrap();
            register(&mut st, &w)
        };
        tokio::spawn(self.clone().run(permit, w, started));
    }

    /// Send `w` once the writes it overlaps have finished, then keep the slot for the pending buffer
    /// if there is one.
    async fn run(
        self: Arc<Self>,
        permit: OwnedSemaphorePermit,
        mut w: Write,
        mut started: Started,
    ) {
        loop {
            for mut done in std::mem::take(&mut started.waits) {
                let _ = done.changed().await;
            }
            if let Err(e) = write_all(&self.client, w.fid, w.off, &w.data, self.chunk).await {
                w.err.lock().unwrap().get_or_insert(e);
            }
            let mut st = self.state.lock().unwrap();
            st.inflight.retain(|f| f.id != started.id);
            match st.pending.take() {
                Some(next) => {
                    started = register(&mut st, &next);
                    w = next;
                }
                None => {
                    // Released under the lock; see `write`.
                    drop(permit);
                    return;
                }
            }
        }
    }
}

/// A write just added to `inflight`: its id, the overlapping writes it must wait for, and the
/// sender whose drop marks it finished.
struct Started {
    id: u64,
    waits: Vec<watch::Receiver<()>>,
    _done: watch::Sender<()>,
}

fn register(st: &mut State, w: &Write) -> Started {
    let waits = st
        .inflight
        .iter()
        .filter(|f| f.start < w.end() && w.off < f.end)
        .map(|f| f.done.clone())
        .collect();
    let (tx, rx) = watch::channel(());
    let id = st.next_id;
    st.next_id += 1;
    st.inflight.push(InFlight {
        id,
        start: w.off,
        end: w.end(),
        done: rx,
    });
    Started {
        id,
        waits,
        _done: tx,
    }
}

/// Write `data` to `fid` starting at byte `off`, split into `chunk`-sized `Twrite`s. A short write of
/// 0 is treated as an error so callers don't spin.
pub(crate) async fn write_all(
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
