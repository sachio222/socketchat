//! Files dropped on the window: a terminal pastes their paths, and the
//! message box shows a placeholder for each.

use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use socketchat_core::client::Ended;
use socketchat_proto::msg::GroupId;
use socketchat_tui::app::{Action, App, DropKind, Focus, Modal};
use socketchat_tui::commands::{Command, HELP};
use socketchat_tui::ui::{GroupView, ViewModel};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn g(n: u8) -> GroupId {
    GroupId([n; 16])
}

fn vm() -> ViewModel {
    ViewModel {
        me: "Ada".into(),
        groups: vec![
            GroupView {
                id: g(1),
                name: "Book club".into(),
                unread: 0,
                is_dm: false,
                muted: false,
                ended: None,
            },
            GroupView {
                id: g(2),
                name: "Old".into(),
                unread: 0,
                is_dm: false,
                muted: false,
                ended: Some(Ended::Closed),
            },
        ],
        lines: vec![],
        members: vec![],
        connected: true,
        server: None,
        topic: None,
        invite_names: vec![],
        join_rooms: vec![],
    }
}

/// An app with Book club open.
fn book_club() -> App {
    let mut a = App::new();
    a.selected = Some(g(1));
    a
}

const JPEG: &[u8] = b"\xff\xd8\xff\xe0 a photo";
const MP4: &[u8] = b"\0\0\0\x18ftypisom a video";
const TEXT: &[u8] = b"some notes";

/// A folder holding these files, each starting with the given bytes.
fn files(made: &[(&str, &[u8])]) -> (tempfile::TempDir, Vec<PathBuf>) {
    let d = tempfile::tempdir().unwrap();
    let paths = made
        .iter()
        .map(|(n, bytes)| {
            let p = d.path().join(n);
            std::fs::write(&p, bytes).unwrap();
            p
        })
        .collect();
    (d, paths)
}

/// As Terminal.app pastes a drop: spaces escaped, a space after each.
fn dropped(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|p| format!("{} ", p.display().to_string().replace(' ', "\\ ")))
        .collect()
}

fn type_text(app: &mut App, text: &str) {
    for c in text.chars() {
        app.handle_key(key(KeyCode::Char(c)), &vm());
    }
}

fn no_path(app: &App, p: &Path) {
    let dir = p.parent().unwrap().display().to_string();
    assert!(!app.input.contains(&dir), "{}", app.input);
    assert!(!app.status.clone().unwrap_or_default().contains(&dir));
}

#[test]
fn a_dropped_photo_shows_as_a_placeholder_and_the_bottom_line_names_it() {
    let (_d, p) = files(&[("My beach.jpg", JPEG)]);
    std::fs::write(&p[0], [JPEG, &vec![0u8; 2_100_000]].concat()).unwrap();
    let mut app = book_club();
    assert!(app.handle_paste(&dropped(&p)).is_empty());
    assert_eq!(app.input, "[Photo 1] ");
    assert_eq!(
        app.status.as_deref(),
        Some("Photo 1 is My beach.jpg, 2.1 MB. Enter sends it.")
    );
    assert_eq!(app.attachments().len(), 1);
    assert_eq!(app.attachments()[0].kind, DropKind::Photo);
    no_path(&app, &p[0]);
}

/// Photos, videos and other files are told apart as `/send` tells them
/// apart, and each kind counts from 1 in the draft.
#[test]
fn photos_videos_and_files_count_up_on_their_own() {
    let (_d, p) = files(&[
        ("a.jpg", JPEG),
        ("b.mp4", MP4),
        ("c.txt", TEXT),
        ("d.png", JPEG),
    ]);
    let mut app = book_club();
    app.handle_paste(&dropped(&p));
    assert_eq!(app.input, "[Photo 1] [Video 1] [File 1] [Photo 2] ");
    assert_eq!(
        app.status.as_deref(),
        Some("Photo 1 is a.jpg, Video 1 is b.mp4, File 1 is c.txt, Photo 2 is d.png. Enter sends them.")
    );
    for x in &p {
        no_path(&app, x);
    }
}

#[test]
fn words_go_before_and_after_a_placeholder() {
    let (_d, p) = files(&[("a.jpg", JPEG), ("b.jpg", JPEG)]);
    let mut app = book_club();
    type_text(&mut app, "look");
    app.handle_paste(&dropped(&p[..1]));
    type_text(&mut app, "nice");
    assert_eq!(app.input, "look [Photo 1] nice");
    app.handle_paste(&dropped(&p[1..]));
    assert_eq!(app.input, "look [Photo 1] nice [Photo 2] ");
}

/// A drop lands wherever the window has focus, and over a box: the box
/// closes as it does for a paste, a question counting as answered no.
#[test]
fn a_drop_anywhere_on_the_window_goes_in_the_message_box() {
    let (_d, p) = files(&[("a.jpg", JPEG)]);
    for focus in [Focus::Groups, Focus::Messages, Focus::Members, Focus::Input] {
        let mut app = book_club();
        app.focus = focus;
        app.handle_paste(&dropped(&p));
        assert_eq!(app.focus, Focus::Input, "{focus:?}");
        assert_eq!(app.input, "[Photo 1] ", "{focus:?}");
    }
    for modal in [
        Modal::Help { offset: 0, pick: 0 },
        Modal::ConfirmVideo {
            group: g(1),
            path: "/x/v.mp4".into(),
        },
        Modal::Details {
            lines: vec!["a".into()],
            offset: 0,
        },
    ] {
        let mut app = book_club();
        app.modal = Some(modal.clone());
        assert!(app.handle_paste(&dropped(&p)).is_empty(), "{modal:?}");
        assert!(app.modal.is_none(), "{modal:?}");
        assert_eq!(app.input, "[Photo 1] ", "{modal:?}");
    }
    let mut app = book_club();
    app.switcher = Some("bo".into());
    app.handle_paste(&dropped(&p));
    assert!(app.switcher.is_none());
    assert_eq!(app.input, "[Photo 1] ");
}

/// A box that starts with `/` takes the paste as text, so a path can
/// follow a command. After `/send ` it goes in plain, ready to run.
#[test]
fn after_a_slash_the_path_is_text() {
    let (_d, p) = files(&[("My beach.jpg", JPEG)]);
    let paste = dropped(&p);
    let mut app = book_club();
    type_text(&mut app, "/kick ");
    app.handle_paste(&paste);
    assert_eq!(app.input, format!("/kick {paste}"));
    assert!(app.attachments().is_empty());

    let mut app = book_club();
    type_text(&mut app, "/send ");
    app.handle_paste(&paste);
    let plain = p[0].display().to_string();
    assert_eq!(app.input, format!("/send {plain}"));
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm()),
        vec![Action::Command(Command::Send(plain))]
    );
}

#[test]
fn text_that_is_not_only_files_pastes_as_before() {
    let (d, p) = files(&[("a.jpg", JPEG)]);
    let gone = d.path().join("gone.jpg").display().to_string();
    for text in [
        format!("see {}", p[0].display()),
        gone.clone(),
        "hello".to_string(),
    ] {
        let mut app = book_club();
        app.handle_paste(&text);
        assert_eq!(app.input, text);
        assert!(app.attachments().is_empty());
        assert_eq!(app.status, None);
    }
}

/// Typed keys never attach: only a paste does.
#[test]
fn typing_a_path_attaches_nothing() {
    let (_d, p) = files(&[("a.jpg", JPEG)]);
    let mut app = book_club();
    let path = p[0].display().to_string();
    type_text(&mut app, &path);
    assert_eq!(app.input, path);
    assert!(app.attachments().is_empty());
}

/// Backspace removes a placeholder whole, and its file with it.
#[test]
fn backspace_removes_a_placeholder_whole() {
    let (_d, p) = files(&[("a.jpg", JPEG), ("b.mp4", MP4)]);
    let mut app = book_club();
    type_text(&mut app, "hi ");
    app.handle_paste(&dropped(&p));
    assert_eq!(app.input, "hi [Photo 1] [Video 1] ");
    let mut seen = vec![];
    for _ in 0..6 {
        app.handle_key(key(KeyCode::Backspace), &vm());
        seen.push((app.input.clone(), app.attachments().len()));
    }
    assert_eq!(
        seen,
        vec![
            ("hi [Photo 1] [Video 1]".to_string(), 2),
            ("hi [Photo 1] ".to_string(), 1),
            ("hi [Photo 1]".to_string(), 1),
            ("hi ".to_string(), 0),
            ("hi".to_string(), 0),
            ("h".to_string(), 0),
        ]
    );
}

/// Esc empties the box and drops the files; typing a placeholder's text
/// afterwards is only text.
#[test]
fn clearing_the_box_drops_the_files() {
    let (_d, p) = files(&[("a.jpg", JPEG)]);
    let mut app = book_club();
    app.handle_paste(&dropped(&p));
    app.handle_key(key(KeyCode::Esc), &vm());
    assert_eq!(app.input, "");
    assert!(app.attachments().is_empty());
    type_text(&mut app, "[Photo 1] ");
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm()),
        vec![Action::Send(g(1), "[Photo 1]".into())]
    );
}

/// Enter sends the files; the draft stays in the box until they go.
#[test]
fn enter_sends_the_drop_to_the_open_room() {
    let (_d, p) = files(&[("a.jpg", JPEG)]);
    let mut app = book_club();
    app.handle_paste(&dropped(&p));
    type_text(&mut app, "from the beach");
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm()),
        vec![Action::SendDrop(g(1))]
    );
    assert_eq!(app.input, "[Photo 1] from the beach");

    let mut app = App::new();
    app.handle_paste(&dropped(&p));
    assert!(app.handle_key(key(KeyCode::Enter), &vm()).is_empty());
    assert_eq!(
        app.status.as_deref(),
        Some("Pick a chat first, or start one with /new <name>.")
    );
    assert_eq!(app.input, "[Photo 1] ");

    let mut app = App::new();
    app.selected = Some(g(2));
    app.handle_paste(&dropped(&p));
    assert!(app.handle_key(key(KeyCode::Enter), &vm()).is_empty());
    assert_eq!(app.input, "[Photo 1] ", "an ended room keeps the draft");
}

/// Up keeps the draft and its files while it shows earlier lines; Down
/// past the newest brings both back. Enter on an earlier line sends that
/// line, and the draft goes as it does for text.
#[test]
fn up_and_down_keep_the_files_with_the_draft() {
    let (_d, p) = files(&[("a.jpg", JPEG)]);
    let mut app = book_club();
    type_text(&mut app, "hello");
    app.handle_key(key(KeyCode::Enter), &vm());
    app.handle_paste(&dropped(&p));
    app.handle_key(key(KeyCode::Up), &vm());
    assert_eq!(app.input, "hello");
    app.handle_key(key(KeyCode::Down), &vm());
    assert_eq!(app.input, "[Photo 1] ");
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm()),
        vec![Action::SendDrop(g(1))]
    );
    app.handle_key(key(KeyCode::Up), &vm());
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm()),
        vec![Action::Send(g(1), "hello".into())]
    );
    assert!(app.attachments().is_empty());
}

/// A folder, or a file Socketchat cannot read, is named on the bottom
/// line with why, and gets no placeholder; files dropped with it do.
#[test]
fn a_drop_that_cannot_go_says_why() {
    let (d, p) = files(&[("a.jpg", JPEG)]);
    let trip = d.path().join("Trip");
    std::fs::create_dir(&trip).unwrap();
    let mut app = book_club();
    app.handle_paste(&dropped(std::slice::from_ref(&trip)));
    assert_eq!(app.input, "");
    assert!(app.attachments().is_empty());
    assert_eq!(
        app.status.as_deref(),
        Some("Trip is a folder, and only files can be sent.")
    );

    let mut app = book_club();
    app.handle_paste(&dropped(&[p[0].clone(), trip.clone()]));
    assert_eq!(app.input, "[Photo 1] ");
    assert_eq!(
        app.status.as_deref(),
        Some("Photo 1 is a.jpg, 12 bytes. Enter sends it. Trip is a folder, and only files can be sent.")
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let secret = d.path().join("secret.pdf");
        std::fs::write(&secret, TEXT).unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(&secret).is_err() {
            let mut app = book_club();
            app.handle_paste(&dropped(&[secret]));
            assert_eq!(app.input, "");
            assert_eq!(
                app.status.as_deref(),
                Some("secret.pdf cannot be read. Check that you have permission to open it.")
            );
        }
    }
}

#[test]
fn a_full_message_box_takes_no_more_files() {
    let (_d, p) = files(&[("a.jpg", JPEG)]);
    let mut app = book_club();
    app.input = "x".repeat(socketchat_core::sanitize::MAX_TEXT_BYTES - 5);
    app.handle_paste(&dropped(&p));
    assert!(app.attachments().is_empty());
    assert_eq!(
        app.status.as_deref(),
        Some("The message box is full at 16 KB, the most one message holds.")
    );
}

#[test]
fn help_says_a_file_can_be_dropped() {
    let send = HELP.iter().find(|(c, _)| *c == "/send <path>").unwrap();
    assert_eq!(
        send.1,
        "send a file, photo or video, or drag one onto the window"
    );
}
