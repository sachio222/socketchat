//! Files dropped on the window. A terminal pastes a dropped file's path as
//! text, wherever on the window the file lands. A paste that holds nothing
//! but paths to things that exist is a drop: its files become attachments,
//! shown in the message box as `[Photo 1]`, `[Video 1]` or `[File 1]`, and
//! Enter sends them as `/send` does. The paths stay here, never in the
//! message box.

use std::path::{Path, PathBuf};

use socketchat_core::client::human_size;
use socketchat_core::files::{fill, safe_name, sniff, Kind};
use socketchat_core::sanitize::MAX_TEXT_BYTES;

use super::{ended_hint, Action, App, Focus};
use crate::ui::ViewModel;

/// What `/send` makes of a file, as its placeholder names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropKind {
    Photo,
    Video,
    File,
}

impl DropKind {
    fn word(self) -> &'static str {
        match self {
            DropKind::Photo => "Photo",
            DropKind::Video => "Video",
            DropKind::File => "File",
        }
    }

    /// Read from the file's first bytes, as `/send` reads it.
    fn of(path: &Path) -> DropKind {
        let mut head = [0u8; 16];
        let n = std::fs::File::open(path)
            .and_then(|mut f| fill(&mut f, &mut head))
            .unwrap_or(0);
        match sniff(&head[..n]) {
            Kind::Video => DropKind::Video,
            Kind::Other => DropKind::File,
            _ => DropKind::Photo,
        }
    }
}

/// A dropped file waiting in the message box for Enter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    pub kind: DropKind,
    /// Its number among the draft's files of its kind, from 1.
    pub number: usize,
    /// The file's name as the room will see it.
    pub name: String,
    /// Its size when it was dropped.
    pub size: u64,
    pub(crate) path: PathBuf,
    /// Where its placeholder starts in the message box, in bytes.
    at: usize,
    /// The person said yes to sending it as it is: a video, or a photo
    /// Socketchat cannot clean.
    pub(crate) as_is: bool,
}

impl Attachment {
    /// The placeholder in the message box, such as `[Photo 1]`.
    pub fn label(&self) -> String {
        format!("[{}]", self.title())
    }

    /// How the bottom line names it, such as `Photo 1`.
    pub fn title(&self) -> String {
        format!("{} {}", self.kind.word(), self.number)
    }

    /// Its placeholder is still where it was put in `input`.
    fn shows_in(&self, input: &str) -> bool {
        input.get(self.at..self.at + self.label().len()) == Some(self.label().as_str())
    }
}

/// Why something dropped cannot be sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unsendable {
    Gone,
    Folder,
    NotAFile,
    Unreadable,
}

impl Unsendable {
    /// What follows the name, as in "Trip is a folder, and only files can
    /// be sent".
    fn says(self) -> &'static str {
        match self {
            Unsendable::Gone => "is no longer there",
            Unsendable::Folder => "is a folder, and only files can be sent",
            Unsendable::NotAFile => "is not a file, and only files can be sent",
            Unsendable::Unreadable => "cannot be read. Check that you have permission to open it",
        }
    }
}

/// The file's size, or why it cannot be sent.
pub(crate) fn sendable(path: &Path) -> Result<u64, Unsendable> {
    let m = std::fs::metadata(path).map_err(|_| Unsendable::Gone)?;
    if m.is_dir() {
        return Err(Unsendable::Folder);
    }
    if !m.is_file() {
        return Err(Unsendable::NotAFile);
    }
    std::fs::File::open(path).map_err(|_| Unsendable::Unreadable)?;
    Ok(m.len())
}

/// A name as the room would see it.
fn name_of(path: &Path) -> String {
    safe_name(
        &path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
    )
}

/// What the bottom line says when an attachment cannot go at Enter.
pub(crate) fn not_sent(a: &Attachment, why: Unsendable) -> String {
    format!(
        "{}, {}, {}. Nothing was sent.",
        a.title(),
        a.name,
        why.says()
    )
}

/// The paths a paste names, when the whole paste is one or more absolute
/// paths to things that exist. `None` means the paste is text.
pub fn dropped_paths(text: &str) -> Option<Vec<PathBuf>> {
    let home = directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf());
    parse(text, home.as_deref())
}

/// Terminals paste a drop in different ways: with a backslash before each
/// space (Terminal.app, iTerm2, Ghostty, WezTerm), in single or double
/// quotes (VS Code, WezTerm's other modes, Windows Terminal), as
/// `file://` links (kitty and some Linux terminals), or as they are, one
/// per line. The paste is read as shell words first, then one path per
/// line.
fn parse(text: &str, home: Option<&Path>) -> Option<Vec<PathBuf>> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let lines: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();
    [words(text), Some(lines)]
        .into_iter()
        .flatten()
        .find_map(|ws| {
            ws.iter()
                .map(|w| path_of(w, home))
                .collect::<Option<Vec<_>>>()
                .filter(|ps| !ps.is_empty())
        })
}

/// `text` split as a shell splits words: backslashes and quotes come off.
/// `None` when a quote is left open or a backslash ends the text.
fn words(text: &str) -> Option<Vec<String>> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut in_word = false;
    let mut cs = text.chars();
    while let Some(c) = cs.next() {
        match c {
            '\\' => {
                let n = cs.next()?;
                if n != '\n' {
                    cur.push(n);
                }
                in_word = true;
            }
            '\'' => {
                loop {
                    match cs.next()? {
                        '\'' => break,
                        c => cur.push(c),
                    }
                }
                in_word = true;
            }
            '"' => {
                loop {
                    match cs.next()? {
                        '"' => break,
                        '\\' => {
                            let n = cs.next()?;
                            if !matches!(n, '"' | '\\' | '$' | '`' | '\n') {
                                cur.push('\\');
                            }
                            if n != '\n' {
                                cur.push(n);
                            }
                        }
                        c => cur.push(c),
                    }
                }
                in_word = true;
            }
            c if c.is_whitespace() => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            c => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    Some(out)
}

/// The absolute path a word names, when something is there.
fn path_of(word: &str, home: Option<&Path>) -> Option<PathBuf> {
    let p = if let Some(rest) = word.strip_prefix("file://") {
        let rest = rest.strip_prefix("localhost").unwrap_or(rest);
        let decoded = percent_decoded(rest)?;
        // `file:///C:/Users/...` on Windows.
        let b = decoded.as_bytes();
        if cfg!(windows) && b.len() > 2 && b[0] == b'/' && b[2] == b':' {
            PathBuf::from(&decoded[1..])
        } else {
            PathBuf::from(decoded)
        }
    } else if let Some(rest) = word.strip_prefix("~/") {
        home?.join(rest)
    } else {
        PathBuf::from(word)
    };
    (p.is_absolute() && std::fs::metadata(&p).is_ok()).then_some(p)
}

/// `%20` and the like turned back into the characters they stand for.
fn percent_decoded(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// "a", "a and b", "a, b and c".
fn listed(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

impl App {
    /// The files waiting in the message box, in the order their
    /// placeholders show.
    pub fn attachments(&self) -> Vec<Attachment> {
        self.attachments
            .iter()
            .filter(|a| a.shows_in(&self.input))
            .cloned()
            .collect()
    }

    /// Before each key or paste: forgets files whose placeholder is no
    /// longer in the message box. While Up and Down show an earlier line,
    /// the draft's files wait with the draft for Down to bring it back;
    /// `ends_recall` means this key or paste ends that, and the draft goes.
    pub(super) fn tidy_attachments(&mut self, ends_recall: bool) {
        if self.recalling() {
            if ends_recall {
                self.attachments.clear();
            }
            return;
        }
        let input = &self.input;
        self.attachments.retain(|a| a.shows_in(input));
    }

    /// A paste that names files: in the message box they become
    /// placeholders, and the bottom line names each. `None` leaves the
    /// paste to go in as text.
    pub(super) fn paste_files(&mut self, text: &str) -> Option<Vec<Action>> {
        if self.input.starts_with('/') {
            // `/send ` and one dropped file: the plain path, ready to run.
            if self.switcher.is_none() && self.input.trim_end() == "/send" {
                if let Some([one]) = dropped_paths(text).as_deref() {
                    self.modal = None;
                    self.focus = Focus::Input;
                    self.input = format!("/send {}", one.display());
                    return Some(vec![]);
                }
            }
            return None;
        }
        let paths = dropped_paths(text)?;
        self.switcher = None;
        self.modal = None;
        self.focus = Focus::Input;
        let mut added: Vec<Attachment> = vec![];
        let mut said: Vec<String> = vec![];
        for path in paths {
            let name = name_of(&path);
            let size = match sendable(&path) {
                Ok(size) => size,
                Err(why) => {
                    said.push(format!("{name} {}.", why.says()));
                    continue;
                }
            };
            let kind = DropKind::of(&path);
            let number = self
                .attachments
                .iter()
                .filter(|a| a.kind == kind)
                .map(|a| a.number)
                .max()
                .unwrap_or(0)
                + 1;
            let mut a = Attachment {
                kind,
                number,
                name,
                size,
                path,
                at: 0,
                as_is: false,
            };
            let gap = if self.input.is_empty() || self.input.ends_with(char::is_whitespace) {
                ""
            } else {
                " "
            };
            let label = a.label();
            if self.input.len() + gap.len() + label.len() + 1 > MAX_TEXT_BYTES {
                said.push("The message box is full at 16 KB, the most one message holds.".into());
                break;
            }
            self.input.push_str(gap);
            a.at = self.input.len();
            self.input.push_str(&label);
            self.input.push(' ');
            self.attachments.push(a.clone());
            added.push(a);
        }
        let named = match added.as_slice() {
            [] => None,
            [a] => Some(format!(
                "{} is {}, {}. Enter sends it.",
                a.title(),
                a.name,
                human_size(a.size)
            )),
            many => Some(format!(
                "{}. Enter sends them.",
                many.iter()
                    .map(|a| format!("{} is {}", a.title(), a.name))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        };
        let line: Vec<String> = named.into_iter().chain(said).collect();
        self.status = (!line.is_empty()).then(|| line.join(" "));
        Some(vec![])
    }

    /// Backspace at the end of a placeholder removes it whole, and its
    /// file. Whether it did.
    pub(super) fn backspace_attachment(&mut self) -> bool {
        let end = self.input.len();
        let Some(i) = self
            .attachments
            .iter()
            .position(|a| a.shows_in(&self.input) && a.at + a.label().len() == end)
        else {
            return false;
        };
        let a = self.attachments.remove(i);
        self.input.truncate(a.at);
        true
    }

    /// Enter with files in the message box sends them, then the words.
    /// The draft stays in the box until each part has gone.
    pub(super) fn enter_attachments(&mut self, vm: &ViewModel) -> Option<Vec<Action>> {
        self.tidy_attachments(true);
        if self.attachments.is_empty() {
            return None;
        }
        let ended = vm
            .groups
            .iter()
            .find(|g| Some(g.id) == self.selected)
            .and_then(|g| g.ended);
        if let Some(why) = ended {
            self.status = Some(ended_hint(why).into());
            return Some(vec![]);
        }
        let Some(g) = self.selected else {
            self.status = Some("Pick a chat first, or start one with /new <name>.".into());
            return Some(vec![]);
        };
        self.scroll = 0;
        Some(vec![Action::SendDrop(g)])
    }

    /// The first file in the message box went: its placeholder and the
    /// space after it leave the box.
    pub(crate) fn first_attachment_sent(&mut self) {
        let input = &self.input;
        self.attachments.retain(|a| a.shows_in(input));
        if self.attachments.is_empty() {
            return;
        }
        let a = self.attachments.remove(0);
        let mut end = a.at + a.label().len();
        if self.input[end..].starts_with(' ') {
            end += 1;
        }
        self.input.replace_range(a.at..end, "");
        let gone = end - a.at;
        for b in &mut self.attachments {
            b.at -= gone;
        }
    }

    /// Yes to the question about a dropped video or photo at `path`: it
    /// may go as it is. Whether the question was about a dropped file.
    pub(crate) fn confirm_dropped(&mut self, path: &str) -> bool {
        match self
            .attachments
            .iter_mut()
            .find(|a| !a.as_is && a.path == Path::new(path))
        {
            Some(a) => {
                a.as_is = true;
                true
            }
            None => false,
        }
    }

    /// Once every file has gone: the words left in the box, which leave
    /// it. Up and Down keep them, never the placeholders.
    pub(crate) fn take_dropped_text(&mut self) -> String {
        self.attachments.clear();
        let text = std::mem::take(&mut self.input).trim().to_string();
        if !text.is_empty() {
            self.remember(&text);
        }
        text
    }
}

/// The status after dropped files went: photos say they were cleaned.
pub(crate) fn cleaned_status(names: &[String]) -> Option<String> {
    match names {
        [] => None,
        [one] => Some(format!(
            "Sent {one} with its location and device data removed."
        )),
        many => Some(format!(
            "Sent {} with their location and device data removed.",
            listed(many)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse, sendable, Unsendable};
    use std::path::{Path, PathBuf};

    /// A folder with these files in it, each holding a few bytes.
    fn files(names: &[&str]) -> (tempfile::TempDir, Vec<PathBuf>) {
        let d = tempfile::tempdir().unwrap();
        let paths = names
            .iter()
            .map(|n| {
                let p = d.path().join(n);
                std::fs::write(&p, b"some bytes").unwrap();
                p
            })
            .collect();
        (d, paths)
    }

    fn s(p: &Path) -> String {
        p.display().to_string()
    }

    /// `p` with a backslash before each character a shell would split
    /// on, as Terminal.app, iTerm2, Ghostty and WezTerm paste a drop.
    fn escaped(p: &Path) -> String {
        let mut out = String::new();
        for c in s(p).chars() {
            if " '\"()&;$`!*?[]{}<>|#~\\".contains(c) {
                out.push('\\');
            }
            out.push(c);
        }
        out
    }

    fn percent(p: &Path) -> String {
        s(p).replace('%', "%25")
            .replace(' ', "%20")
            .replace('\'', "%27")
    }

    #[test]
    fn a_plain_absolute_path_is_a_drop() {
        let (_d, p) = files(&["beach.jpg"]);
        assert_eq!(parse(&s(&p[0]), None), Some(p.clone()));
        // Terminals add a space or a line break after the path.
        assert_eq!(parse(&format!("{} ", s(&p[0])), None), Some(p.clone()));
        assert_eq!(parse(&format!("{}\n", s(&p[0])), None), Some(p));
    }

    /// Terminal.app, iTerm2, Ghostty and WezTerm put a backslash before a
    /// space and other characters a shell reads, and a space after.
    #[test]
    fn backslash_escapes_come_off() {
        let (_d, p) = files(&["My Photo (1).jpg", "Bo's & Cy's #2.png"]);
        for one in &p {
            assert_eq!(
                parse(&format!("{} ", escaped(one)), None),
                Some(vec![one.clone()])
            );
        }
        let both = format!("{} {} ", escaped(&p[0]), escaped(&p[1]));
        assert_eq!(parse(&both, None), Some(p));
    }

    /// VS Code's terminal and WezTerm's Posix mode quote with single
    /// quotes; Windows Terminal and WezTerm's Windows mode with double.
    #[test]
    fn quoted_paths_lose_their_quotes() {
        let (_d, p) = files(&["My Photo.jpg", "Bo's.png", "say \"hi\".txt"]);
        assert_eq!(
            parse(&format!("'{}'", s(&p[0])), None),
            Some(vec![p[0].clone()])
        );
        assert_eq!(
            parse(&format!("\"{}\"", s(&p[0])), None),
            Some(vec![p[0].clone()])
        );
        // A single quote inside single quotes, as a shell writes it.
        let bo = s(&p[1]).replace('\'', "'\\''");
        assert_eq!(parse(&format!("'{bo}'"), None), Some(vec![p[1].clone()]));
        let hi = s(&p[2]).replace('"', "\\\"");
        assert_eq!(parse(&format!("\"{hi}\""), None), Some(vec![p[2].clone()]));
        let all = format!("'{}' '{bo}' \"{hi}\"", s(&p[0]));
        assert_eq!(parse(&all, None), Some(p));
    }

    /// kitty and some Linux terminals paste `file://` links, one per line,
    /// with spaces and other characters written as `%20` and so on.
    #[test]
    fn file_links_are_decoded() {
        let (_d, p) = files(&["My Photo.jpg", "Bo's 100%.png"]);
        let one = format!("file://{}", percent(&p[0]));
        assert_eq!(parse(&one, None), Some(vec![p[0].clone()]));
        let host = format!("file://localhost{}", percent(&p[1]));
        assert_eq!(parse(&host, None), Some(vec![p[1].clone()]));
        let lines = format!("file://{}\r\nfile://{}\r\n", percent(&p[0]), percent(&p[1]));
        assert_eq!(parse(&lines, None), Some(p));
        assert_eq!(parse("file:///no/such%2", None), None, "a broken escape");
    }

    /// A terminal that pastes a path as it is, spaces and all, one path
    /// per line.
    #[test]
    fn unescaped_paths_one_per_line() {
        let (_d, p) = files(&["My Photo.jpg", "Our trip 2.mov"]);
        assert_eq!(parse(&s(&p[0]), None), Some(vec![p[0].clone()]));
        let lines = format!("{}\n{}\n", s(&p[0]), s(&p[1]));
        assert_eq!(parse(&lines, None), Some(p));
    }

    #[test]
    fn a_path_from_home() {
        let (d, p) = files(&["beach.jpg"]);
        assert_eq!(parse("~/beach.jpg", Some(d.path())), Some(p.clone()));
        assert_eq!(parse("'~/beach.jpg'", Some(d.path())), Some(p.clone()));
        assert_eq!(parse("~/beach.jpg", None), None, "no home folder");
    }

    #[test]
    fn several_paths_on_several_lines() {
        let (_d, p) = files(&["a.jpg", "b c.png", "d.txt"]);
        let text = format!("{}\n{}\n{}", escaped(&p[0]), escaped(&p[1]), escaped(&p[2]));
        assert_eq!(parse(&text, None), Some(p));
    }

    /// A folder is a drop too, so the person hears why it cannot go.
    #[test]
    fn a_folder_is_a_drop_that_cannot_go() {
        let (d, p) = files(&["beach.jpg"]);
        assert_eq!(
            parse(&s(d.path()), None),
            Some(vec![d.path().to_path_buf()])
        );
        assert_eq!(sendable(d.path()), Err(Unsendable::Folder));
        assert_eq!(sendable(&p[0]), Ok(10));
        assert_eq!(sendable(&d.path().join("gone")), Err(Unsendable::Gone));
    }

    #[cfg(unix)]
    #[test]
    fn a_file_nobody_may_read_cannot_go() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, p) = files(&["secret.pdf"]);
        std::fs::set_permissions(&p[0], std::fs::Permissions::from_mode(0o000)).unwrap();
        // Someone with every permission still reads it.
        if std::fs::File::open(&p[0]).is_err() {
            assert_eq!(sendable(&p[0]), Err(Unsendable::Unreadable));
        }
        assert_eq!(parse(&s(&p[0]), None), Some(p));
    }

    /// Anything else stays text: a missing file, a path among other
    /// words, a path that is not absolute, an open quote.
    #[test]
    fn anything_else_is_text() {
        let (d, p) = files(&["beach.jpg"]);
        let gone = d.path().join("gone.jpg");
        for text in [
            String::new(),
            "   \n".to_string(),
            "hello".to_string(),
            s(&gone),
            format!("look at {}", s(&p[0])),
            format!("{} is the one", s(&p[0])),
            format!("{} {}", s(&p[0]), s(&gone)),
            "beach.jpg".to_string(),
            "./beach.jpg".to_string(),
            format!("'{}", s(&p[0])),
            format!("{}\\", s(&p[0])),
            format!("file://{}?x", s(&p[0])),
        ] {
            assert_eq!(parse(&text, None), None, "{text:?}");
        }
    }
}
