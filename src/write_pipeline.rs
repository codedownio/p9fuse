//! Pipelined writes for one inode. A FUSE `write` is acknowledged as soon as it is queued here; the
//! `Twrite`s go out from background tasks, up to `depth` at a time.
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

/// The write pipeline of one inode, shared by all its open handles.
pub(crate) struct InodeWrites {
    client: Arc<NineClient>,
    /// The most bytes one `Twrite` carries.
    chunk: usize,
    /// One permit per write in flight.
    slots: Arc<Semaphore>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// Writes handed to a task and not yet finished, oldest first.
    inflight: Vec<InFlight>,
    next_id: u64,
}

struct InFlight {
    id: u64,
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
        !st.inflight.is_empty()
    }

    /// Queue `w`. Returns once it is handed to a background task; blocks while every slot is busy.
    pub(crate) async fn write(self: &Arc<Self>, w: Write) {
        let permit = self.acquire().await;
        self.start(permit, w);
    }

    /// Wait until every write on this inode has finished.
    pub(crate) async fn settle(&self) {
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
            register(&mut st)
        };
        tokio::spawn(self.clone().run(permit, w, started));
    }

    async fn run(self: Arc<Self>, permit: OwnedSemaphorePermit, w: Write, started: Started) {
        if let Err(e) = write_all(&self.client, w.fid, w.off, &w.data, self.chunk).await {
            w.err.lock().unwrap().get_or_insert(e);
        }
        self.state
            .lock()
            .unwrap()
            .inflight
            .retain(|f| f.id != started.id);
        drop(permit);
    }
}

/// A write just added to `inflight`: its id and the sender whose drop marks it finished.
struct Started {
    id: u64,
    _done: watch::Sender<()>,
}

fn register(st: &mut State) -> Started {
    let (tx, rx) = watch::channel(());
    let id = st.next_id;
    st.next_id += 1;
    st.inflight.push(InFlight { id, done: rx });
    Started { id, _done: tx }
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
