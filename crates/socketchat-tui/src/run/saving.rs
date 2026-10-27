//! Saving the files people send: to the Downloads folder unless the
//! person names another, under a name that never replaces a file there.

use std::path::{Path, PathBuf};

use socketchat_core::client::SharedFile;
use socketchat_proto::msg::{FileId, GroupId};

use super::{local_time, Screen};

/// Where `/save` and a click put files, and how a file line names that
/// folder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SaveDir {
    pub path: PathBuf,
    /// "Downloads", or where the folder is when it is not in the home
    /// folder.
    pub label: String,
}

impl SaveDir {
    /// This system's Downloads folder; with none, the folder Socketchat
    /// started in.
    pub(crate) fn system() -> SaveDir {
        let path = directories::UserDirs::new()
            .and_then(|u| u.download_dir().map(PathBuf::from))
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        SaveDir::at(path, home().as_deref())
    }

    /// `path`, named by its own name when it sits right in the home
    /// folder, as `Downloads` does, and by where it is otherwise.
    pub(crate) fn at(path: PathBuf, home: Option<&Path>) -> SaveDir {
        let in_home = home.is_some_and(|h| path.parent() == Some(h));
        let label = match path.file_name() {
            Some(n) if in_home => n.to_string_lossy().into_owned(),
            _ => shown_path(&path, home),
        };
        SaveDir { path, label }
    }
}

/// The person's home folder.
pub(crate) fn home() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf())
}

/// `path` as a line shows it: with `~` for the home folder.
pub(crate) fn shown_path(path: &Path, home: Option<&Path>) -> String {
    match home.and_then(|h| path.strip_prefix(h).ok()) {
        Some(rest) if rest.as_os_str().is_empty() => "~".into(),
        Some(rest) => format!("~{}{}", std::path::MAIN_SEPARATOR, rest.display()),
        None => path.display().to_string(),
    }
}

/// The file `/save` with no name saves: the newest one someone else
/// sent. When there is none, what the bottom line says.
pub(crate) fn newest_from_others(files: &[SharedFile]) -> Result<&SharedFile, String> {
    match files.iter().rev().find(|f| !f.mine) {
        Some(f) => Ok(f),
        None if files.is_empty() => Err("No one has sent a file in this chat yet.".into()),
        None => Err("No one else has sent a file in this chat yet.".into()),
    }
}

impl Screen {
    /// `/save`: the file named, or with no name the newest file someone
    /// else sent, saved in `dir` or the default folder.
    pub(super) async fn save_command(
        &mut self,
        g: GroupId,
        file: Option<String>,
        dir: Option<PathBuf>,
    ) -> Result<(), String> {
        let files = self.client.shared_files(g);
        let picked = match &file {
            Some(want) => crate::commands::pick_file(&files, want, local_time)?,
            None => newest_from_others(&files)?,
        };
        let id = picked.offer.id;
        self.save_to(g, id, dir).await
    }

    /// A click on the line that says someone sent a file: it saves that
    /// file in the default folder, once. A second click says where it
    /// went, while the file is still there.
    pub(super) async fn click_save(&mut self, g: GroupId, id: FileId) -> Result<(), String> {
        if let Some(p) = self.saved.get(&id).filter(|p| p.is_file()) {
            self.app.status = Some(format!(
                "Already saved to {}.",
                shown_path(p, home().as_deref())
            ));
            return Ok(());
        }
        self.save_to(g, id, None).await
    }

    /// Saves file `id` in `dir`, or the default folder, under a name that
    /// replaces nothing, and puts a line in the room, on this computer
    /// only, that says where.
    async fn save_to(
        &mut self,
        g: GroupId,
        id: FileId,
        dir: Option<PathBuf>,
    ) -> Result<(), String> {
        let name = self
            .client
            .shared_files(g)
            .into_iter()
            .find(|f| f.offer.id == id)
            .map(|f| f.offer.name)
            .ok_or_else(|| "That file is no longer in this chat.".to_string())?;
        let dir = dir.unwrap_or_else(|| self.save_dir.path.clone());
        let saved = self
            .client
            .save_file(g, id, &dir)
            .await
            .map_err(|e| e.to_string())?;
        let said = format!("Saved {name} to {}.", shown_path(&saved, home().as_deref()));
        self.saved.insert(id, saved);
        self.client
            .add_local_notice(g, &said)
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{newest_from_others, shown_path, SaveDir};
    use std::path::{Path, PathBuf, MAIN_SEPARATOR};

    fn home() -> PathBuf {
        Path::new(MAIN_SEPARATOR.to_string().as_str())
            .join("home")
            .join("ada")
    }

    #[test]
    fn paths_show_the_home_folder_as_a_tilde() {
        let h = home();
        let file = h.join("Downloads").join("report (1).pdf");
        let want = format!(
            "~{MAIN_SEPARATOR}{}",
            Path::new("Downloads").join("report (1).pdf").display()
        );
        assert_eq!(shown_path(&file, Some(&h)), want);
        assert_eq!(shown_path(&h, Some(&h)), "~");
        let elsewhere = Path::new(MAIN_SEPARATOR.to_string().as_str())
            .join("srv")
            .join("a.txt");
        assert_eq!(
            shown_path(&elsewhere, Some(&h)),
            elsewhere.display().to_string()
        );
        assert_eq!(shown_path(&file, None), file.display().to_string());
    }

    #[test]
    fn the_default_folder_goes_by_its_name_in_the_home_folder() {
        let h = home();
        assert_eq!(
            SaveDir::at(h.join("Downloads"), Some(&h)).label,
            "Downloads"
        );
        let deep = h.join("work").join("in");
        assert_eq!(
            SaveDir::at(deep.clone(), Some(&h)).label,
            shown_path(&deep, Some(&h))
        );
    }

    #[test]
    fn save_alone_takes_the_newest_file_someone_else_sent() {
        use socketchat_core::client::SharedFile;
        let file = |id: u8, mine: bool| SharedFile {
            offer: socketchat_core::files::FileOffer {
                id: socketchat_proto::msg::FileId([id; 16]),
                name: format!("f{id}.txt"),
                size: 1,
                mime: "text/plain".into(),
                sha256: [0; 32],
                key: [0; 32],
                nonce_prefix: [0; 19],
            },
            from: "Ada".into(),
            mine,
            sent_unix: 0,
        };
        let files = [file(1, false), file(2, false), file(3, true)];
        assert_eq!(newest_from_others(&files).unwrap().offer.name, "f2.txt");
        assert_eq!(
            newest_from_others(&files[2..]).unwrap_err(),
            "No one else has sent a file in this chat yet."
        );
        assert_eq!(
            newest_from_others(&[]).unwrap_err(),
            "No one has sent a file in this chat yet."
        );
    }
}
