//! Connecting to the server and running the FUSE session.

use super::invalidate::Invalidator;
use super::{Fuse9p, Inode, Tuning, ROOT_INO};
use crate::client::NineClient;
use crate::transport::NineTransport;
use fuser::MountOption;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::runtime::Handle;

impl Fuse9p {
    /// Attach to the server as `uid` and serve it at `mountpoint` until unmounted.
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

        let root = Inode {
            fid: root_fid,
            lookups: 1,
        };
        let fs = Fuse9p {
            client,
            rt: Handle::current(),
            tuning,
            inodes: HashMap::from([(ROOT_INO, root)]),
            root_qid_path: root_qid.path,
            handles: HashMap::new(),
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

        // The session blocks for the life of the mount, so it gets its own thread.
        let session_task = tokio::task::spawn_blocking(move || session.run());
        tokio::select! {
            r = session_task => r?.map_err(|e| e.into()),
            _ = transport_gone.wait_for(|&gone| gone) => {
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
