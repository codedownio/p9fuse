//! Connecting to the server and running the FUSE session.

use super::invalidate::Invalidator;
use super::{unmount, Fuse9p, Inode, Tuning, ROOT_INO};
use crate::client::NineClient;
use crate::transport::NineTransport;
use fuser::MountOption;
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::runtime::Handle;
use tokio::sync::watch;

impl Fuse9p {
    /// Attach to the server as `uid` and serve it at `mountpoint` until unmounted. That means
    /// unmounted from this process's mount namespace with no files left open, even if a copy of
    /// the mount in another namespace would keep the filesystem alive.
    ///
    /// - `detach_on_transport_loss`: when the 9p transport closes, the process exits so a
    ///   supervisor can remount. With this set it lazily unmounts first, so the mountpoint shows its
    ///   underlying directory instead of failing with ENOTCONN until the remount.
    /// - `stall_timeout`: treat the transport as dead when a request goes unanswered this long
    ///   (zero = never).
    /// - `invalidations` / `replies`: where invalidation requests come from and their replies go
    ///   (see the `invalidate` module); the binary uses stdin and stdout.
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        transport: Box<dyn NineTransport>,
        mountpoint: &Path,
        msize: u32,
        uid: u32,
        aname: &str,
        tuning: Tuning,
        detach_on_transport_loss: bool,
        default_permissions: bool,
        stall_timeout: Duration,
        invalidations: Box<dyn AsyncRead + Send + Unpin>,
        replies: Box<dyn AsyncWrite + Send + Unpin>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!(?tuning, "mount9p-fuse: tuning");
        let (client, root_qid) =
            NineClient::connect(transport, msize, uid, aname, stall_timeout).await?;
        let mut transport_gone = client.transport_gone();
        let root_fid = client.root_fid;
        let invalidations_client = client.clone();

        // As the mount table will show it. Once mounted, resolving it would ask us for the root's
        // attributes before we serve requests.
        let mountpoint = &std::fs::canonicalize(mountpoint)?;
        let (open_handles, open_handles_rx) = watch::channel(0);
        let root = Inode {
            fid: root_fid,
            lookups: 1,
            parent: ROOT_INO,
            name: "".into(),
            generation: 0,
        };
        let fs = Fuse9p {
            client,
            rt: Handle::current(),
            tuning,
            inodes: HashMap::from([(ROOT_INO, root)]),
            root_qid_path: root_qid.path,
            handles: HashMap::new(),
            open_handles,
            next_fh: 1,
            writes: HashMap::new(),
        };

        let mut options = vec![
            MountOption::FSName("p9fuse".to_string()),
            MountOption::Subtype("9p".to_string()),
        ];
        if default_permissions {
            options.push(MountOption::DefaultPermissions);
        }
        // A mount made by root is only usable by other users with allow_other, which only root
        // may set without user_allow_other in /etc/fuse.conf.
        if nix::unistd::geteuid().is_root() {
            options.push(MountOption::AllowOther);
        }

        tracing::info!(?mountpoint, "mount9p-fuse: mounting FUSE filesystem");
        let mut session = fuser::Session::new(fs, mountpoint, &options)?;
        let invalidator = Invalidator {
            notifier: session.notifier(),
            client: invalidations_client,
            root_fid,
            root_qid_path: root_qid.path,
        };
        tokio::spawn(invalidator.run(invalidations, replies));

        let device = unmount::mount_device(mountpoint);
        if device.is_none() {
            tracing::warn!(?mountpoint, "mount9p-fuse: mount not in the mount table; won't notice an unmount that leaves copies of it elsewhere");
        }
        // Open it now, while the device number is certainly ours: the kernel reuses it once our
        // filesystem is destroyed.
        let abort = device.as_deref().map(unmount::open_abort);
        let unmounted = async {
            match &device {
                Some(device) => unmount::unmounted(device, open_handles_rx).await,
                None => std::future::pending().await,
            }
        };

        // The session blocks for the life of the mount, so it gets its own thread.
        let mut session_task = tokio::task::spawn_blocking(move || session.run());
        tokio::select! {
            r = &mut session_task => r?.map_err(|e| e.into()),
            r = unmounted => {
                if let Err(e) = r {
                    tracing::warn!(error = %e, "mount9p-fuse: can't watch the mount table");
                    return session_task.await?.map_err(|e| e.into());
                }
                // Gone from our namespace, though a copy of the mount in another namespace can keep
                // the filesystem alive. If the kernel already ended the connection, this does
                // nothing.
                tracing::info!("mount9p-fuse: unmounted from our namespace; ending the session");
                if let Some(Err(e)) = abort.map(|f| f.and_then(|mut f| f.write_all(b"1"))) {
                    // Closing /dev/fuse when the process exits ends the connection instead.
                    tracing::warn!(error = %e, "mount9p-fuse: couldn't end the FUSE connection");
                    return Ok(());
                }
                session_task.await?.map_err(|e| e.into())
            }
            _ = async { transport_gone.wait_for(|&gone| gone).await.map(|_| ()) } => {
                // Every operation would fail from now on. Exit so a supervisor remounts.
                if detach_on_transport_loss {
                    tracing::error!("mount9p-fuse: 9p transport closed; detaching the mount and exiting so it is remounted");
                    let _ = nix::mount::umount2(mountpoint, nix::mount::MntFlags::MNT_DETACH);
                } else {
                    tracing::error!("mount9p-fuse: 9p transport closed; exiting so it is remounted (no detach)");
                }
                std::process::exit(75); // EX_TEMPFAIL
            }
        }
    }
}
