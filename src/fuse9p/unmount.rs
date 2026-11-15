//! Noticing that the filesystem was unmounted from our mount namespace.
//!
//! The session normally ends when the kernel tears the filesystem down. But a process that copies
//! the mount namespace while we're mounted (a container, a nix build sandbox, `unshare -m`) keeps
//! its copy of the mount, and so the filesystem, alive after the user unmounts ours. So we also
//! end the session once the filesystem is gone from our own namespace and nothing has a file open.

use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::watch;

/// The device (`major:minor`) of the filesystem mounted at `mountpoint`, from our mount table.
/// `mountpoint` must be absolute with no symlinks, as the mount table shows it.
pub(super) fn mount_device(mountpoint: &Path) -> Option<String> {
    let table = std::fs::read("/proc/self/mountinfo").ok()?;
    let target = escape(mountpoint);
    // The last entry wins: it is the mount on top.
    let device = table.rsplit(|&b| b == b'\n').find_map(|line| {
        let mut fields = line.split(|&b| b == b' ');
        let device = fields.nth(2)?;
        let point = fields.nth(1)?;
        (point == target.as_slice()).then_some(device)
    })?;
    String::from_utf8(device.to_vec()).ok()
}

/// Return once `device` is mounted nowhere in our namespace and `open_handles` is zero. The kernel
/// wakes pollers of the mount table whenever it changes.
pub(super) async fn unmounted(
    device: &str,
    mut open_handles: watch::Receiver<usize>,
) -> io::Result<()> {
    let file = File::open("/proc/self/mountinfo")?;
    // SAFETY: the `File` owns its fd and keeps it open, unchanged, until the `AsyncFd` drops it.
    let table = unsafe { AsyncFd::register_with_interest(file, Interest::PRIORITY) }
        .map_err(io::Error::from)?;
    while mounted(device)? {
        table.ready(Interest::PRIORITY).await?.clear_ready();
    }
    // After a lazy unmount, files opened through the mount can still be in use.
    let _ = open_handles.wait_for(|&n| n == 0).await;
    Ok(())
}

/// Open the control file that ends the FUSE connection behind `device` when written to. The file
/// stays tied to the connection it was opened on: once that connection is gone, writing to it does
/// nothing, even if a new connection has taken the same device number.
pub(super) fn open_abort(device: &str) -> io::Result<File> {
    match device.split_once(':') {
        Some(("0", minor)) => std::fs::OpenOptions::new()
            .write(true)
            .open(format!("/sys/fs/fuse/connections/{minor}/abort")),
        _ => Err(io::ErrorKind::InvalidData.into()),
    }
}

fn mounted(device: &str) -> io::Result<bool> {
    let table = std::fs::read("/proc/self/mountinfo")?;
    Ok(table
        .split(|&b| b == b'\n')
        .any(|line| line.split(|&b| b == b' ').nth(2) == Some(device.as_bytes())))
}

/// A path as the mount table writes it: space, tab, newline and backslash as octal escapes.
fn escape(path: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    for &b in path.as_os_str().as_bytes() {
        match b {
            b' ' | b'\t' | b'\n' | b'\\' => out.extend(format!("\\{b:03o}").bytes()),
            _ => out.push(b),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_like_the_mount_table() {
        assert_eq!(escape(Path::new("/tmp/a b\\c")), b"/tmp/a\\040b\\134c");
    }

    #[test]
    fn finds_the_root_mount() {
        assert!(mount_device(Path::new("/")).is_some());
        assert!(mounted(&mount_device(Path::new("/")).unwrap()).unwrap());
    }
}
