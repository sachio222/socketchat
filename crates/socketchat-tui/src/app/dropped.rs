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

use super::{ended_hint, word_matches, Action, App, Focus};
use crate::commands::parse_command;
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
    parse(text, home.as_deref(), Platform::HOST, &|p| {
        std::fs::metadata(p).is_ok()
    })
}

/// Whose rules a terminal pastes a dropped path by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Platform {
    Unix,
    Windows,
}

impl Platform {
    /// The system Socketchat runs on.
    const HOST: Platform = if cfg!(windows) {
        Platform::Windows
    } else {
        Platform::Unix
    };

    /// Whether `p` names a place from the top of a disk: on Unix it
    /// starts with `/`; on Windows with a drive, as `C:\` or `C:/`, or a
    /// network share, as `\\server\share`.
    fn is_absolute(self, p: &str) -> bool {
        match self {
            Platform::Unix => p.starts_with('/'),
            Platform::Windows => {
                let b = p.as_bytes();
                p.starts_with(r"\\")
                    || (b.len() > 2
                        && b[0].is_ascii_alphabetic()
                        && b[1] == b':'
                        && matches!(b[2], b'\\' | b'/'))
            }
        }
    }
}

/// Terminals paste a drop in different ways. On Unix: with a backslash
/// before each space (Terminal.app, iTerm2, Ghostty, WezTerm), in single
/// or double quotes (VS Code, WezTerm's other modes), or as `file://`
/// links (kitty and some Linux terminals). On Windows, where a backslash
/// separates folders: as the plain path, in double quotes when it has
/// spaces (Windows Terminal, the console, VS Code). Anywhere, as they
/// are, one per line. The paste is read as words first, then one path per
/// line, and only paths that exist count.
fn parse(
    text: &str,
    home: Option<&Path>,
    platform: Platform,
    exists: &dyn Fn(&Path) -> bool,
) -> Option<Vec<PathBuf>> {
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
    let words = match platform {
        Platform::Unix => shell_words(text),
        Platform::Windows => quoted_words(text),
    };
    [words, Some(lines)].into_iter().flatten().find_map(|ws| {
        ws.iter()
            .map(|w| path_of(w, home, platform, exists))
            .collect::<Option<Vec<_>>>()
            .filter(|ps| !ps.is_empty())
    })
}

/// `text` split as a Unix shell splits words: backslashes and quotes come
/// off. `None` when a quote is left open or a backslash ends the text.
fn shell_words(text: &str) -> Option<Vec<String>> {
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

/// `text` split at spaces outside double quotes, which come off, as
/// Windows terminals write several paths. A backslash is a folder
/// separator, never an escape. `None` when a quote is left open.
fn quoted_words(text: &str) -> Option<Vec<String>> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut in_word = false;
    let mut quoted = false;
    for c in text.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                in_word = true;
            }
            c if c.is_whitespace() && !quoted => {
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
    if quoted {
        return None;
    }
    if in_word {
        out.push(cur);
    }
    Some(out)
}

/// The absolute path a word names, when something is there.
fn path_of(
    word: &str,
    home: Option<&Path>,
    platform: Platform,
    exists: &dyn Fn(&Path) -> bool,
) -> Option<PathBuf> {
    let p = if let Some(rest) = word.strip_prefix("file://") {
        PathBuf::from(link_path(rest, platform)?)
    } else if let Some(rest) = word.strip_prefix("~/") {
        // Joined with the platform's separator rather than the host's, so
        // each platform's rules give the same path on any machine.
        let home = home?;
        let sep = match platform {
            Platform::Unix => "/",
            Platform::Windows => "\\",
        };
        let mut p = home.as_os_str().to_os_string();
        if !home.to_string_lossy().ends_with(sep) {
            p.push(sep);
        }
        p.push(rest);
        PathBuf::from(p)
    } else if platform.is_absolute(word) {
        PathBuf::from(word)
    } else {
        return None;
    };
    exists(&p).then_some(p)
}

/// The path a `file://` link names, from what follows `file://`: on
/// Windows `file:///C:/Users/...` is `C:\Users\...` and
/// `file://server/share/...` is `\\server\share\...`.
fn link_path(rest: &str, platform: Platform) -> Option<String> {
    let rest = rest.strip_prefix("localhost").unwrap_or(rest);
    let decoded = percent_decoded(rest)?;
    let path = match platform {
        Platform::Unix => decoded,
        Platform::Windows => match decoded.strip_prefix('/') {
            Some(local) => local.replace('/', "\\"),
            None => format!(r"\\{}", decoded.replace('/', "\\")),
        },
    };
    platform.is_absolute(&path).then_some(path)
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

    /// Enter on words that are nothing but paths to things on this
    /// computer, as a terminal that types a drop instead of pasting it
    /// leaves them: the paths never go to the room. Their files become
    /// placeholders, as a drop makes them, and the bottom line says so,
    /// so the next Enter sends the files. `None` leaves Enter to send or
    /// run what the box holds: a message that mentions a path among other
    /// words, or a command.
    pub(super) fn enter_paths(&mut self) -> Option<Vec<Action>> {
        let shown = self.attachments();
        // The words after the placeholders; before and between them, only
        // spaces.
        let end = shown
            .iter()
            .map(|a| a.at + a.label().len())
            .max()
            .unwrap_or(0);
        let mut head = self.input[..end].to_string();
        for a in &shown {
            head = head.replacen(&a.label(), "", 1);
        }
        let text = self.input[end..].trim().to_string();
        if !head.trim().is_empty() || text.is_empty() {
            return None;
        }
        let paths = dropped_paths(&text)?;
        // A Unix path starts as a command does: only a file, and only when
        // no command has that name, counts as a path.
        if text.starts_with('/') {
            let command = match parse_command(&text) {
                Ok(_) => true,
                Err(e) => !e.starts_with("There is no") || word_matches("", &text).len() == 1,
            };
            if command || !paths.iter().all(|p| p.is_file()) {
                return None;
            }
        }
        self.input.truncate(end);
        self.paste_files(&text)?;
        let stays = match paths.len() {
            1 => "The path stays on this computer.",
            _ => "The paths stay on this computer.",
        };
        self.status = Some(match self.status.take() {
            Some(said) => format!("{stays} {said}"),
            None => stays.to_string(),
        });
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
    use super::{parse, sendable, Platform, Unsendable};
    use std::path::{Path, PathBuf};

    /// Parses `text` by `platform`'s rules against a made-up disk that
    /// holds exactly `disk`, so both systems' forms run on every system.
    /// The disk matches a path letter for letter: comparing `Path`s would
    /// use the host's rules, and on Windows `/u/a/beach.jpg\` is the same
    /// path as `/u/a/beach.jpg`.
    fn on(platform: Platform, disk: &[&str], text: &str) -> Option<Vec<PathBuf>> {
        parse(text, Some(Path::new("/u/a")), platform, &|p| {
            disk.iter()
                .any(|d| p.as_os_str() == std::ffi::OsStr::new(d))
        })
    }

    fn paths(ps: &[&str]) -> Option<Vec<PathBuf>> {
        Some(ps.iter().map(PathBuf::from).collect())
    }

    mod unix {
        use super::{on, paths};
        use crate::app::dropped::Platform::Unix;

        const DISK: &[&str] = &[
            "/u/a/beach.jpg",
            "/u/a/My Photo (1).jpg",
            "/u/a/Bo's & Cy's #2.png",
            "/u/a/Bo's.png",
            "/u/a/say \"hi\".txt",
            "/u/a/Bo's 100%.png",
            "/u/a/Our trip 2.mov",
            r"C:\u\beach.jpg",
        ];

        fn find(text: &str) -> Option<Vec<std::path::PathBuf>> {
            on(Unix, DISK, text)
        }

        #[test]
        fn a_plain_path_with_what_terminals_add_after_it() {
            for text in ["/u/a/beach.jpg", "/u/a/beach.jpg ", "/u/a/beach.jpg\n"] {
                assert_eq!(find(text), paths(&["/u/a/beach.jpg"]), "{text:?}");
            }
        }

        /// Terminal.app, iTerm2, Ghostty and WezTerm put a backslash
        /// before a space and other characters a shell reads.
        #[test]
        fn backslash_escapes_come_off() {
            let photo = r"/u/a/My\ Photo\ \(1\).jpg";
            let bo = r"/u/a/Bo\'s\ \&\ Cy\'s\ \#2.png";
            assert_eq!(
                find(&format!("{photo} ")),
                paths(&["/u/a/My Photo (1).jpg"])
            );
            assert_eq!(find(&format!("{bo} ")), paths(&["/u/a/Bo's & Cy's #2.png"]));
            assert_eq!(
                find(&format!("{photo} {bo} ")),
                paths(&["/u/a/My Photo (1).jpg", "/u/a/Bo's & Cy's #2.png"])
            );
        }

        /// VS Code's terminal and WezTerm's Posix mode quote with single
        /// quotes, writing a single quote inside as `'\''`.
        #[test]
        fn quoted_paths_lose_their_quotes() {
            assert_eq!(
                find("'/u/a/My Photo (1).jpg'"),
                paths(&["/u/a/My Photo (1).jpg"])
            );
            assert_eq!(
                find("\"/u/a/My Photo (1).jpg\""),
                paths(&["/u/a/My Photo (1).jpg"])
            );
            assert_eq!(find(r"'/u/a/Bo'\''s.png'"), paths(&["/u/a/Bo's.png"]));
            assert_eq!(
                find(r#""/u/a/say \"hi\".txt""#),
                paths(&["/u/a/say \"hi\".txt"])
            );
            assert_eq!(
                find(r#"'/u/a/Bo'\''s.png' "/u/a/say \"hi\".txt" /u/a/beach.jpg"#),
                paths(&["/u/a/Bo's.png", "/u/a/say \"hi\".txt", "/u/a/beach.jpg"])
            );
        }

        /// kitty and some Linux terminals paste `file://` links, one per
        /// line.
        #[test]
        fn file_links_are_decoded() {
            assert_eq!(
                find("file:///u/a/My%20Photo%20(1).jpg"),
                paths(&["/u/a/My Photo (1).jpg"])
            );
            assert_eq!(
                find("file://localhost/u/a/Bo%27s%20100%25.png"),
                paths(&["/u/a/Bo's 100%.png"])
            );
            assert_eq!(
                find("file:///u/a/beach.jpg\r\nfile:///u/a/Bo%27s.png\r\n"),
                paths(&["/u/a/beach.jpg", "/u/a/Bo's.png"])
            );
            assert_eq!(find("file:///u/a/beach%2"), None, "a broken escape");
            assert_eq!(
                find("file://server/u/a/beach.jpg"),
                None,
                "another computer"
            );
        }

        /// A terminal that pastes paths as they are, one per line.
        #[test]
        fn unescaped_paths_one_per_line() {
            assert_eq!(
                find("/u/a/My Photo (1).jpg"),
                paths(&["/u/a/My Photo (1).jpg"])
            );
            assert_eq!(
                find("/u/a/My Photo (1).jpg\n/u/a/Our trip 2.mov\n"),
                paths(&["/u/a/My Photo (1).jpg", "/u/a/Our trip 2.mov"])
            );
            assert_eq!(
                find("/u/a/beach.jpg\n/u/a/Bo\\'s.png"),
                paths(&["/u/a/beach.jpg", "/u/a/Bo's.png"])
            );
        }

        /// Other forms a macOS terminal may write a drop in: a link from
        /// `localhost`, quoted paths one per line, and a path with only a
        /// line break after it.
        #[test]
        fn more_forms_macos_terminals_may_write() {
            assert_eq!(
                find("file://localhost/u/a/beach.jpg"),
                paths(&["/u/a/beach.jpg"])
            );
            assert_eq!(
                find("file:///u/a/My Photo (1).jpg\n"),
                paths(&["/u/a/My Photo (1).jpg"])
            );
            assert_eq!(
                find("'/u/a/My Photo (1).jpg'\n'/u/a/Bo'\\''s.png'\n"),
                paths(&["/u/a/My Photo (1).jpg", "/u/a/Bo's.png"])
            );
            assert_eq!(
                find("/u/a/My\\ Photo\\ \\(1\\).jpg\r\n/u/a/beach.jpg\r\n"),
                paths(&["/u/a/My Photo (1).jpg", "/u/a/beach.jpg"])
            );
            assert_eq!(find("\n/u/a/beach.jpg\n"), paths(&["/u/a/beach.jpg"]));
        }

        #[test]
        fn a_path_from_home() {
            assert_eq!(find("~/beach.jpg"), paths(&["/u/a/beach.jpg"]));
            assert_eq!(find("'~/beach.jpg'"), paths(&["/u/a/beach.jpg"]));
        }

        #[test]
        fn anything_else_is_text() {
            for text in [
                "",
                "   \n",
                "hello",
                "/u/a/gone.jpg",
                "look at /u/a/beach.jpg",
                "/u/a/beach.jpg is the one",
                "/u/a/beach.jpg /u/a/gone.jpg",
                "beach.jpg",
                "./beach.jpg",
                "'/u/a/beach.jpg",
                "/u/a/beach.jpg\\",
                "file:///u/a/beach.jpg?x",
                r"C:\u\beach.jpg",
            ] {
                assert_eq!(find(text), None, "{text:?}");
            }
        }
    }

    mod windows {
        use super::{on, paths};
        use crate::app::dropped::Platform::Windows;

        const DISK: &[&str] = &[
            r"C:\Users\a\beach.jpg",
            r"C:\Users\a\My Photo (1).jpg",
            r"C:\Users\a\Bo's & Cy's #2.png",
            r"D:\Trip 2\clip.mp4",
            "C:/Users/a/beach.jpg",
            r"\\server\share\Our trip.jpg",
            r"\\server\share\beach.jpg",
            r"C:\Users\a\Bo's 100%.png",
            "/u/a/beach.jpg",
        ];

        fn find(text: &str) -> Option<Vec<std::path::PathBuf>> {
            on(Windows, DISK, text)
        }

        #[test]
        fn a_plain_path_with_what_terminals_add_after_it() {
            for text in [
                r"C:\Users\a\beach.jpg",
                r"C:\Users\a\beach.jpg ",
                "C:\\Users\\a\\beach.jpg\r\n",
            ] {
                assert_eq!(find(text), paths(&[r"C:\Users\a\beach.jpg"]), "{text:?}");
            }
            assert_eq!(
                find("C:/Users/a/beach.jpg"),
                paths(&["C:/Users/a/beach.jpg"])
            );
        }

        /// Windows Terminal, the console and VS Code wrap a path with
        /// spaces in double quotes, and put a space between files.
        #[test]
        fn double_quotes_come_off() {
            assert_eq!(
                find(r#""C:\Users\a\My Photo (1).jpg""#),
                paths(&[r"C:\Users\a\My Photo (1).jpg"])
            );
            assert_eq!(
                find(r#""C:\Users\a\My Photo (1).jpg" C:\Users\a\beach.jpg "D:\Trip 2\clip.mp4" "#),
                paths(&[
                    r"C:\Users\a\My Photo (1).jpg",
                    r"C:\Users\a\beach.jpg",
                    r"D:\Trip 2\clip.mp4"
                ])
            );
        }

        /// A backslash is a folder separator, and a single quote is part
        /// of the name.
        #[test]
        fn backslashes_and_single_quotes_stay() {
            assert_eq!(
                find(r#""C:\Users\a\Bo's & Cy's #2.png""#),
                paths(&[r"C:\Users\a\Bo's & Cy's #2.png"])
            );
            assert_eq!(
                find(r"C:\Users\a\My\ Photo\ (1).jpg"),
                None,
                "escapes are Unix"
            );
        }

        #[test]
        fn network_shares() {
            assert_eq!(
                find(r#""\\server\share\Our trip.jpg""#),
                paths(&[r"\\server\share\Our trip.jpg"])
            );
            assert_eq!(
                find(r"\\server\share\beach.jpg"),
                paths(&[r"\\server\share\beach.jpg"])
            );
        }

        #[test]
        fn file_links_are_decoded() {
            assert_eq!(
                find("file:///C:/Users/a/My%20Photo%20(1).jpg"),
                paths(&[r"C:\Users\a\My Photo (1).jpg"])
            );
            assert_eq!(
                find("file://localhost/C:/Users/a/Bo%27s%20100%25.png"),
                paths(&[r"C:\Users\a\Bo's 100%.png"])
            );
            assert_eq!(
                find("file://server/share/beach.jpg"),
                paths(&[r"\\server\share\beach.jpg"])
            );
            assert_eq!(
                find("file:///C:/Users/a/beach.jpg\r\nfile:///D:/Trip%202/clip.mp4\r\n"),
                paths(&[r"C:\Users\a\beach.jpg", r"D:\Trip 2\clip.mp4"])
            );
            assert_eq!(find("file:///C:/Users/a/beach%2"), None, "a broken escape");
        }

        #[test]
        fn unquoted_paths_one_per_line() {
            assert_eq!(
                find(r"C:\Users\a\My Photo (1).jpg"),
                paths(&[r"C:\Users\a\My Photo (1).jpg"])
            );
            assert_eq!(
                find("C:\\Users\\a\\My Photo (1).jpg\r\nD:\\Trip 2\\clip.mp4\r\n"),
                paths(&[r"C:\Users\a\My Photo (1).jpg", r"D:\Trip 2\clip.mp4"])
            );
        }

        #[test]
        fn anything_else_is_text() {
            for text in [
                "",
                "hello",
                r"C:\Users\a\gone.jpg",
                r"look at C:\Users\a\beach.jpg",
                r"C:\Users\a\beach.jpg C:\Users\a\gone.jpg",
                r"Users\a\beach.jpg",
                r"\Users\a\beach.jpg",
                "C:beach.jpg",
                r#""C:\Users\a\beach.jpg"#,
                "/u/a/beach.jpg",
                "file:///u/a/beach.jpg",
            ] {
                assert_eq!(find(text), None, "{text:?}");
            }
        }
    }

    /// Real files, pasted as this system's terminals paste them.
    mod on_this_system {
        use super::{parse, sendable, Platform, Unsendable};
        use std::path::{Path, PathBuf};

        /// A folder with these files in it, each holding a few bytes.
        /// Every name is one both systems allow.
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

        fn find(text: &str) -> Option<Vec<PathBuf>> {
            parse(text, None, Platform::HOST, &|p| {
                std::fs::metadata(p).is_ok()
            })
        }

        /// As this system's terminals paste a drop: a backslash before
        /// each space on Unix, double quotes around a path with spaces on
        /// Windows, a space after each.
        fn pasted(ps: &[PathBuf]) -> String {
            ps.iter()
                .map(|p| {
                    let s = p.display().to_string();
                    match Platform::HOST {
                        Platform::Windows if s.contains(' ') => format!("\"{s}\" "),
                        Platform::Windows => format!("{s} "),
                        Platform::Unix => {
                            let mut out = String::new();
                            for c in s.chars() {
                                if " '\"()&;$`!*?[]{}<>|#~\\".contains(c) {
                                    out.push('\\');
                                }
                                out.push(c);
                            }
                            out + " "
                        }
                    }
                })
                .collect()
        }

        /// A `file://` link to `p`, as kitty pastes one on Unix.
        fn link(p: &Path) -> String {
            let s = p.display().to_string();
            let s = match Platform::HOST {
                Platform::Windows => format!("/{}", s.replace('\\', "/")),
                Platform::Unix => s,
            };
            format!(
                "file://{}",
                s.replace('%', "%25")
                    .replace(' ', "%20")
                    .replace('\'', "%27")
            )
        }

        #[test]
        fn a_drop_of_real_files_finds_them() {
            let (_d, p) = files(&["beach.jpg", "My Photo (1).jpg", "Bo's & Cy's #2.png"]);
            for one in &p {
                assert_eq!(
                    find(&pasted(std::slice::from_ref(one))),
                    Some(vec![one.clone()])
                );
                assert_eq!(find(&link(one)), Some(vec![one.clone()]));
            }
            assert_eq!(find(&pasted(&p)), Some(p.clone()));
            let lines: Vec<String> = p.iter().map(|x| x.display().to_string()).collect();
            assert_eq!(find(&lines.join("\n")), Some(p));
        }

        #[test]
        fn a_missing_file_or_other_words_are_text() {
            let (d, p) = files(&["beach.jpg"]);
            let gone = d.path().join("gone.jpg");
            assert_eq!(find(&pasted(std::slice::from_ref(&gone))), None);
            assert_eq!(find(&format!("look at {}", pasted(&p))), None);
            assert_eq!(find("beach.jpg"), None);
        }

        /// A folder is a drop too, so the person hears why it cannot go.
        #[test]
        fn a_folder_is_a_drop_that_cannot_go() {
            let (d, p) = files(&["beach.jpg"]);
            let dir = d.path().to_path_buf();
            assert_eq!(
                find(&pasted(std::slice::from_ref(&dir))),
                Some(vec![dir.clone()])
            );
            assert_eq!(sendable(&dir), Err(Unsendable::Folder));
            assert_eq!(sendable(&p[0]), Ok(10));
            assert_eq!(sendable(&dir.join("gone")), Err(Unsendable::Gone));
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
            assert_eq!(find(&pasted(&p)), Some(p));
        }
    }
}
