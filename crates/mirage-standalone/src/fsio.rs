//! Atomic, private file writes.
//!
//! Every file this crate persists is written the same way: into a temporary
//! file **in the same directory**, flushed, given mode 0600 (Unix only), and
//! only then renamed over the target. A crash mid-write therefore leaves the
//! previous file intact rather than a half-written one, and a reader never
//! observes a partial file.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Write `bytes` to `path` atomically.
///
/// The temporary file lives in the target's own directory so the final
/// `rename` stays within one filesystem — a cross-device rename is not
/// atomic and would fail outright.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    fs::create_dir_all(dir)?;

    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target path has no file name"))?;
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));

    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    set_private_mode(&tmp)?;

    match fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(source) => {
            // The rename failed: drop the temporary file so a later run does
            // not find a stale one. The original error is what matters.
            let _ = fs::remove_file(&tmp);
            Err(source)
        }
    }
}

/// Give `path` mode 0600 — owner read/write only.
///
/// On Unix a freshly created file inherits the process umask, which is often
/// `022` — world-readable. These files hold private keys, so the mode is set
/// explicitly. On Windows the ACL model is different and this is a no-op.
#[cfg(unix)]
fn set_private_mode(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

/// Windows has no Unix mode bits — the file inherits the directory's ACL.
#[cfg(not(unix))]
fn set_private_mode(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Join a directory with a file name, for callers that build paths.
pub(crate) fn path_in(dir: &Path, name: &str) -> PathBuf {
    dir.join(name)
}
