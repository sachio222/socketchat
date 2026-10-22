//! Who on this machine may read a profile.
//!
//! On Unix the profile folder is 0700 and its files 0600, so another
//! account cannot copy the database and salt file and guess the passphrase
//! offline. A folder another account owns is refused: that account could
//! read or swap the files. A folder reached through a link is checked where
//! the link points. Making a folder or file private is best effort: some
//! file systems (FAT, exFAT, some network shares) cannot change a mode, and
//! a profile there still opens, with a warning. Windows keeps each person's
//! AppData folder private with access lists, which a mode cannot express,
//! so these checks do nothing there.

use std::path::{Path, PathBuf};

use crate::CoreError;

/// What making a profile private changed, and what it could not change.
#[derive(Default)]
pub(crate) struct Report {
    notes: Vec<String>,
    changed: Vec<PathBuf>,
    failed: Vec<(PathBuf, std::io::Error)>,
}

impl Report {
    /// Adds a line for the person about something else done to the folder.
    pub(crate) fn note(&mut self, line: String) {
        self.notes.push(line);
    }

    /// Plain lines for the person: the notes, one line naming everything
    /// made private, then one for each folder or file that could not be.
    pub(crate) fn lines(&self, dir: &Path) -> Vec<String> {
        let mut out = self.notes.clone();
        if !self.changed.is_empty() {
            let names: Vec<String> = self
                .changed
                .iter()
                .map(|p| match p.strip_prefix(dir) {
                    Ok(name) if !name.as_os_str().is_empty() => name.display().to_string(),
                    _ => p.display().to_string(),
                })
                .collect();
            out.push(format!(
                "Socketchat made these private to your account, since other accounts on this computer could open them: {}.",
                names.join(", ")
            ));
        }
        for (p, e) in &self.failed {
            out.push(format!(
                "Socketchat could not make {} private to your account ({e}), so other accounts on this computer may be able to read it.",
                p.display()
            ));
        }
        out
    }
}

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

/// Refuses a profile folder that another account owns, and narrows one
/// that other accounts can open to 0700. A link is followed, and the
/// folder it points to is the one checked.
pub(crate) fn guard_dir(dir: &Path, report: &mut Report) -> Result<(), CoreError> {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        guard_dir_as(dir, unsafe { libc::geteuid() }, report)
    }
    #[cfg(not(unix))]
    {
        let _ = (dir, report);
        Ok(())
    }
}

/// [`guard_dir`] for the account `uid`.
#[cfg(unix)]
pub(crate) fn guard_dir_as(dir: &Path, uid: u32, report: &mut Report) -> Result<(), CoreError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    // The owner check and the mode change go through one open handle, so
    // they apply to the same folder.
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(dir)?;
    let meta = f.metadata()?;
    if meta.uid() != uid {
        return Err(CoreError::Other(format!(
            "The profile folder {} belongs to another user account, so Socketchat will not open it. Use a profile folder your own account owns.",
            dir.display()
        )));
    }
    if meta.mode() & 0o077 != 0 {
        match f.set_permissions(std::fs::Permissions::from_mode(0o700)) {
            Ok(()) => report.changed.push(dir.to_path_buf()),
            Err(e) => report.failed.push((dir.to_path_buf(), e)),
        }
    }
    Ok(())
}

/// Options that create a file only the owner can read and write.
pub(crate) fn private_options() -> std::fs::OpenOptions {
    #[allow(unused_mut)]
    let mut o = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o
}

/// Writes `bytes` to a new file at `path` that only the owner can read,
/// never through a link, and waits until they are on disk.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut o = private_options();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = o.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Waits until the names in the folder `dir`, such as a file just renamed
/// there, are on disk. Best effort: some file systems refuse this for a
/// folder, and nothing depends on it beyond surviving a power cut.
pub(crate) fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(f) = std::fs::File::open(dir) {
        let _ = f.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Makes sure `path` exists as a file only the owner can read, so SQLite,
/// which gives its side files the database file's mode, never makes them
/// wider.
pub(crate) fn touch_private(path: &Path, report: &mut Report) -> std::io::Result<()> {
    private_options()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    narrow_file(path, report);
    Ok(())
}

/// Reads the file at `path`, at most `max` bytes of it. A link is not
/// followed (see [`is_link`]), and anything other than a plain file is
/// refused, so a changed profile cannot make the app read forever.
pub(crate) fn read_bounded(path: &Path, max: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    #[allow(unused_mut)]
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let f = o.open(path)?;
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a plain file",
        ));
    }
    let mut out = Vec::new();
    f.take(max as u64).read_to_end(&mut out)?;
    Ok(out)
}

/// Whether `e` came from opening a link with [`read_bounded`].
pub(crate) fn is_link(e: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        e.raw_os_error() == Some(libc::ELOOP)
    }
    #[cfg(not(unix))]
    {
        let _ = e;
        false
    }
}

/// Narrows the file at `path` to 0600 when other accounts can open it.
/// A missing file is fine; a link is left alone, since a mode set through
/// it would change the file it points to.
pub(crate) fn narrow_file(path: &Path, report: &mut Report) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path);
        let f = match f {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound || is_link(&e) => return,
            Err(e) => return report.failed.push((path.to_path_buf(), e)),
        };
        let meta = match f.metadata() {
            Ok(m) => m,
            Err(e) => return report.failed.push((path.to_path_buf(), e)),
        };
        if meta.is_file() && meta.mode() & 0o077 != 0 {
            match f.set_permissions(std::fs::Permissions::from_mode(0o600)) {
                Ok(()) => report.changed.push(path.to_path_buf()),
                Err(e) => report.failed.push((path.to_path_buf(), e)),
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, report);
    }
}

/// The database, the files SQLite keeps beside it, the salt file and the
/// lock file.
pub(crate) fn profile_file_names() -> [String; 6] {
    use crate::store::{DB_FILE, LOCK_FILE, SALT_FILE};
    [
        DB_FILE.to_string(),
        format!("{DB_FILE}-wal"),
        format!("{DB_FILE}-shm"),
        format!("{DB_FILE}-journal"),
        SALT_FILE.to_string(),
        LOCK_FILE.to_string(),
    ]
}

/// Narrows every file of the profile in the folder `dir`.
pub(crate) fn narrow_profile_files(dir: &Path, report: &mut Report) {
    for name in profile_file_names() {
        narrow_file(&dir.join(name), report);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::store::{Store, DB_FILE, LOCK_FILE, SALT_FILE};
    use std::os::unix::fs::PermissionsExt;

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    fn set_mode(p: &Path, m: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    }

    /// The database and the files SQLite keeps beside it, the salt file
    /// and the lock file: whichever exist.
    fn profile_files(dir: &Path) -> Vec<std::path::PathBuf> {
        let db = DB_FILE;
        [
            db.to_string(),
            format!("{db}-wal"),
            format!("{db}-shm"),
            SALT_FILE.to_string(),
            LOCK_FILE.to_string(),
        ]
        .iter()
        .map(|f| dir.join(f))
        .filter(|p| p.exists())
        .collect()
    }

    #[test]
    fn a_new_profile_is_for_its_owner_only() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("profile");
        let (s, _p) = Store::create(&dir, "k").unwrap();
        s.conn()
            .execute_batch("CREATE TABLE IF NOT EXISTS t (x); INSERT INTO t VALUES (1);")
            .unwrap();
        assert_eq!(mode(&dir), 0o700, "folder");
        let files = profile_files(&dir);
        for f in [DB_FILE, SALT_FILE, LOCK_FILE] {
            assert!(files.contains(&dir.join(f)), "{f} missing");
        }
        for f in files {
            assert_eq!(mode(&f) & 0o077, 0, "{}: {:o}", f.display(), mode(&f));
        }
    }

    #[test]
    fn opening_a_profile_narrows_a_folder_and_files_others_can_read() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("profile");
        {
            let (s, _p) = Store::create(&dir, "k").unwrap();
            s.conn()
                .execute_batch("CREATE TABLE IF NOT EXISTS t (x); INSERT INTO t VALUES (1);")
                .unwrap();
        }
        set_mode(&dir, 0o755);
        for f in profile_files(&dir) {
            set_mode(&f, 0o644);
        }
        {
            let (s, _p) = Store::open(&dir, "k").unwrap();
            assert_eq!(mode(&dir), 0o700, "folder");
            for f in profile_files(&dir) {
                assert_eq!(mode(&f) & 0o077, 0, "{}: {:o}", f.display(), mode(&f));
            }
            // One plain line says what changed.
            assert_eq!(s.notes().len(), 1, "{:?}", s.notes());
            let line = &s.notes()[0];
            assert!(line.contains("private to your account"), "{line}");
            assert!(line.contains(&dir.display().to_string()), "{line}");
            assert!(line.contains(DB_FILE) && line.contains(SALT_FILE), "{line}");
        }
        let (s, _p) = Store::open(&dir, "k").unwrap();
        assert!(s.notes().is_empty(), "{:?}", s.notes());
    }

    /// Some file systems (FAT, exFAT, some network shares) cannot change a
    /// mode. Narrowing there is a warning, never a profile that will not
    /// open. A locked file stands in for one here.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_mode_that_cannot_change_is_a_warning() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("profile");
        drop(Store::create(&dir, "k").unwrap());
        let salt = dir.join(SALT_FILE);
        set_mode(&salt, 0o644);
        // chflags is called directly: a child process started while other
        // tests hold profile locks would hold copies of them for a moment.
        let c = std::ffi::CString::new(salt.as_os_str().as_encoded_bytes()).unwrap();
        let flag = |f: libc::c_uint| {
            // SAFETY: `c` is a valid NUL-terminated path for the call.
            assert_eq!(unsafe { libc::chflags(c.as_ptr(), f) }, 0);
        };
        flag(libc::UF_IMMUTABLE);
        let opened = Store::open(&dir, "k");
        flag(0);
        let (s, _p) = opened.unwrap();
        assert!(
            s.notes()
                .iter()
                .any(|l| l.contains("could not make") && l.contains(SALT_FILE)),
            "{:?}",
            s.notes()
        );
    }

    /// A profile folder reached through a link works when the folder it
    /// points to is this account's, and the checks apply to that folder.
    #[test]
    fn a_profile_folder_through_a_link_is_checked_where_it_points() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        std::fs::create_dir(&real).unwrap();
        set_mode(&real, 0o755);
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        drop(Store::create(&link, "k").unwrap());
        assert_eq!(mode(&real), 0o700, "the folder the link points to");
        set_mode(&real, 0o755);
        assert!(Store::open(&link, "k").is_ok());
        assert_eq!(mode(&real), 0o700, "the folder the link points to");

        // SAFETY: geteuid has no preconditions and cannot fail.
        let me = unsafe { libc::geteuid() };
        let mut report = Report::default();
        let err = guard_dir_as(&link, me.wrapping_add(1), &mut report).unwrap_err();
        assert!(
            err.to_string().contains("belongs to another user account"),
            "{err}"
        );
    }

    #[test]
    fn a_profile_folder_another_account_owns_is_refused() {
        let d = tempfile::tempdir().unwrap();
        // SAFETY: geteuid has no preconditions and cannot fail.
        let me = unsafe { libc::geteuid() };
        let mut report = Report::default();
        assert!(guard_dir_as(d.path(), me, &mut report).is_ok());
        let err = guard_dir_as(d.path(), me.wrapping_add(1), &mut report).unwrap_err();
        assert!(
            err.to_string().contains("belongs to another user account"),
            "{err}"
        );
    }

    /// A link inside the folder is left as it is, and so is its target.
    #[test]
    fn narrowing_leaves_links_alone() {
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("elsewhere");
        std::fs::write(&target, b"x").unwrap();
        set_mode(&target, 0o644);
        let link = d.path().join("socketchat.db-wal");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let mut report = Report::default();
        narrow_profile_files(d.path(), &mut report);
        assert_eq!(mode(&target), 0o644);
        assert!(report.lines(d.path()).is_empty());
    }
}
