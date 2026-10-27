//! Files dropped on the window go to the room as `/send` sends them.

use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::path::PathBuf;

/// Presses `code` on the screen and carries out what it asks.
async fn press(s: &mut Screen, code: KeyCode) {
    let vm = s.view();
    for a in s
        .app
        .handle_key(KeyEvent::new(code, KeyModifiers::NONE), &vm)
    {
        s.act(a).await;
    }
}

async fn paste(s: &mut Screen, text: &str) {
    for a in s.app.handle_paste(text) {
        s.act(a).await;
    }
}

async fn type_text(s: &mut Screen, text: &str) {
    for c in text.chars() {
        press(s, KeyCode::Char(c)).await;
    }
}

/// A folder holding these files.
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

/// As this system's terminals paste a drop: Terminal.app and the like
/// put a backslash before each space; Windows Terminal, the console and
/// VS Code put double quotes around a path with spaces. A space follows
/// each.
fn dropped(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|p| {
            let s = p.display().to_string();
            if cfg!(windows) {
                if s.contains(' ') {
                    format!("\"{s}\" ")
                } else {
                    format!("{s} ")
                }
            } else {
                format!("{} ", s.replace(' ', "\\ "))
            }
        })
        .collect()
}

fn sent_names(s: &Screen, g: GroupId) -> Vec<String> {
    s.client
        .shared_files(g)
        .into_iter()
        .map(|f| f.offer.name)
        .collect()
}

const MP4: &[u8] = b"\0\0\0\x18ftypisom a video";

/// Enter sends each file in the order its placeholder shows, then the
/// words as a message. Up brings back the words, never a placeholder.
#[tokio::test]
async fn files_go_in_order_then_the_words() {
    let srv = TestServer::start().await;
    let (g, _a, mut bo, _dir) = room_with_bo(&srv).await;
    bo.act(Action::Select(g)).await;
    let (d, p) = files(&[("notes one.txt", b"one"), ("list.csv", b"a,b")]);
    paste(&mut bo, &dropped(&p)).await;
    type_text(&mut bo, "both here").await;
    assert_eq!(bo.app.input, "[File 1] [File 2] both here");
    press(&mut bo, KeyCode::Enter).await;
    assert_eq!(sent_names(&bo, g), vec!["notes one.txt", "list.csv"]);
    let lines: Vec<String> = bo
        .client
        .messages(g, 10)
        .into_iter()
        .map(|l| l.text)
        .collect();
    let n = lines.len();
    assert_eq!(
        lines[n - 3..],
        [
            "You sent notes one.txt (3 bytes)".to_string(),
            "You sent list.csv (3 bytes)".to_string(),
            "both here".to_string()
        ]
    );
    let dir = d.path().display().to_string();
    assert!(
        !lines.iter().any(|l| l.contains(&dir)),
        "no path reaches the room"
    );
    assert_eq!(bo.app.input, "");
    assert!(bo.app.attachments().is_empty());
    assert_eq!(bo.app.status, None, "{:?}", bo.app.status);
    press(&mut bo, KeyCode::Up).await;
    assert_eq!(bo.app.input, "both here");
}

/// A file moved, deleted, swapped for a folder or locked since the drop
/// is named on the bottom line, and nothing goes: the draft waits.
#[tokio::test]
async fn a_file_that_changed_since_the_drop_sends_nothing() {
    let srv = TestServer::start().await;
    let (g, _a, mut bo, _dir) = room_with_bo(&srv).await;
    bo.act(Action::Select(g)).await;
    let (_d, p) = files(&[("a.txt", b"one"), ("b.txt", b"two")]);
    paste(&mut bo, &dropped(&p)).await;
    let draft = bo.app.input.clone();

    std::fs::remove_file(&p[1]).unwrap();
    press(&mut bo, KeyCode::Enter).await;
    assert_eq!(
        bo.app.status.as_deref(),
        Some("File 2, b.txt, is no longer there. Nothing was sent.")
    );

    std::fs::create_dir(&p[1]).unwrap();
    press(&mut bo, KeyCode::Enter).await;
    assert_eq!(
        bo.app.status.as_deref(),
        Some("File 2, b.txt, is a folder, and only files can be sent. Nothing was sent.")
    );
    std::fs::remove_dir(&p[1]).unwrap();
    std::fs::write(&p[1], b"two").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p[1], std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(&p[1]).is_err() {
            press(&mut bo, KeyCode::Enter).await;
            assert_eq!(
                bo.app.status.as_deref(),
                Some("File 2, b.txt, cannot be read. Check that you have permission to open it. Nothing was sent.")
            );
        }
        std::fs::set_permissions(&p[1], std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    assert!(sent_names(&bo, g).is_empty());
    assert_eq!(bo.app.input, draft, "the draft waits");
    assert_eq!(bo.app.attachments().len(), 2);

    press(&mut bo, KeyCode::Enter).await;
    assert_eq!(sent_names(&bo, g), vec!["a.txt", "b.txt"]);
}

/// A file over the server's limit says so in `/send`'s words, at Enter:
/// the app learns the limit only from the server. One that grew past it
/// since the drop says the same.
#[tokio::test]
async fn a_file_too_big_for_the_server_says_so() {
    let srv = TestServer::start_with(|c| c.max_file_mb = 1).await;
    let (g, _a, mut bo, _dir) = room_with_bo(&srv).await;
    bo.act(Action::Select(g)).await;
    let big = vec![b'x'; 1_500_000];
    let (_d, p) = files(&[("big.bin", &big), ("small.txt", b"hi")]);
    paste(&mut bo, &dropped(&p[..1])).await;
    press(&mut bo, KeyCode::Enter).await;
    assert_eq!(
        bo.app.status.as_deref(),
        Some("File 1, big.bin, was not sent: this file is larger than this server's limit of 1 MB")
    );
    assert_eq!(bo.app.input, "[File 1] ", "the draft waits");
    assert!(sent_names(&bo, g).is_empty());

    press(&mut bo, KeyCode::Esc).await;
    paste(&mut bo, &dropped(&p[1..])).await;
    std::fs::write(&p[1], &big).unwrap();
    press(&mut bo, KeyCode::Enter).await;
    assert_eq!(
        bo.app.status.as_deref(),
        Some(
            "File 1, small.txt, was not sent: this file is larger than this server's limit of 1 MB"
        )
    );
    assert!(sent_names(&bo, g).is_empty());
}

/// A video waits for the same yes `/send` asks for, before anything
/// goes; no keeps the draft.
#[tokio::test]
async fn a_dropped_video_asks_first() {
    let srv = TestServer::start().await;
    let (g, _a, mut bo, _dir) = room_with_bo(&srv).await;
    bo.act(Action::Select(g)).await;
    let (_d, p) = files(&[("a.txt", b"one"), ("trip.mp4", MP4)]);
    paste(&mut bo, &dropped(&p)).await;
    type_text(&mut bo, "hi").await;
    press(&mut bo, KeyCode::Enter).await;
    let path = p[1].display().to_string();
    assert_eq!(bo.app.modal, Some(Modal::ConfirmVideo { group: g, path }));
    assert!(sent_names(&bo, g).is_empty(), "nothing before the yes");
    press(&mut bo, KeyCode::Char('n')).await;
    assert_eq!(bo.app.input, "[File 1] [Video 1] hi");

    press(&mut bo, KeyCode::Enter).await;
    assert!(bo.app.modal.is_some());
    press(&mut bo, KeyCode::Char('y')).await;
    assert_eq!(sent_names(&bo, g), vec!["a.txt", "trip.mp4"]);
    assert_eq!(bo.app.input, "");
    assert_eq!(
        bo.client.messages(g, 1).last().map(|l| l.text.clone()),
        Some("hi".into())
    );
}
