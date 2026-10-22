//! Who on this machine may read the data directory.
//!
//! The directory and everything in it is for the server's own account:
//! 0700 for folders and 0600 for files. Windows keeps its own access lists,
//! which a mode cannot express, so nothing here runs there.

use std::path::{Path, PathBuf};

/// Creates `dir` and any missing parents; the folders it makes are 0700.
pub(crate) fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Writes `bytes` to `path` as a file only the owner can read.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        // A file that already existed keeps its old mode through `open`.
        set_mode(path, 0o600)?;
        f.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

/// Makes sure `path` exists as an empty file only the owner can read, so
/// SQLite, which copies that mode to its side files, never makes it wider.
pub(crate) fn touch_private(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Narrows the data directory and everything under it to the owner, and
/// returns what it had to change. Folders from earlier releases and
/// hand-made ones start open.
pub(crate) fn tighten(data_dir: &Path) -> Vec<PathBuf> {
    #[cfg(unix)]
    {
        let mut changed = Vec::new();
        walk(data_dir, &mut changed);
        changed
    }
    #[cfg(not(unix))]
    {
        let _ = data_dir;
        Vec::new()
    }
}

#[cfg(unix)]
fn walk(path: &Path, changed: &mut Vec<PathBuf>) {
    use std::os::unix::fs::PermissionsExt;
    // Links are left alone: a mode set through one would change its target.
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.file_type().is_symlink() {
        return;
    }
    let want = if meta.is_dir() { 0o700 } else { 0o600 };
    if meta.permissions().mode() & 0o777 != want && set_mode(path, want).is_ok() {
        changed.push(path.to_path_buf());
    }
    if meta.is_dir() {
        if let Ok(rd) = std::fs::read_dir(path) {
            for e in rd.flatten() {
                walk(&e.path(), changed);
            }
        }
    }
}
