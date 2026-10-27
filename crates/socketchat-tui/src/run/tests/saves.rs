//! Saving files people send: the line that says how, `/save` alone, Tab
//! after `/save `, a click, and names that never replace a file.

use super::*;
use std::path::Path;

/// Ada sends each of `files`, a name and its bytes, to room `g`, and Bo's
/// screen reads them.
async fn ada_sends(a: &mut TestClient, bo: &mut Screen, g: GroupId, files: &[(&str, &[u8])]) {
    let d = tempfile::tempdir().unwrap();
    for (name, bytes) in files {
        let p = d.path().join(name);
        std::fs::write(&p, bytes).unwrap();
        a.send_file(g, &p, false).await.unwrap();
    }
    for _ in 0..3 {
        bo.sync().await;
    }
}

/// The lines on Bo's screen that name a file, with the command each
/// marks.
fn file_lines(bo: &Screen) -> Vec<(String, Option<String>)> {
    bo.view()
        .lines
        .into_iter()
        .filter(|l| l.text.contains(" sent "))
        .map(|l| {
            let cmd = l.command.clone().map(|at| l.text[at].to_string());
            (l.text, cmd)
        })
        .collect()
}

fn downloads(bo: &Screen) -> &Path {
    &bo.save_dir.path
}

#[tokio::test]
async fn a_file_line_says_how_to_save_it_and_the_command_saves_that_file() {
    let srv = TestServer::start().await;
    let (g, mut a, mut bo, _dir) = room_with_bo(&srv).await;
    bo.act(Action::Select(g)).await;
    ada_sends(&mut a, &mut bo, g, &[("report.pdf", b"first")]).await;
    assert_eq!(
        file_lines(&bo),
        [(
            "Ada sent report.pdf (5 bytes). Type /save report.pdf to save it to Downloads."
                .to_string(),
            Some("/save report.pdf".to_string())
        )]
    );
    // A second file of that name, and one with a space: each line names
    // the one file it means.
    ada_sends(
        &mut a,
        &mut bo,
        g,
        &[("report.pdf", b"second"), ("my plan.txt", b"plan")],
    )
    .await;
    let lines = file_lines(&bo);
    let cmds: Vec<&str> = lines.iter().filter_map(|(_, c)| c.as_deref()).collect();
    assert_eq!(
        cmds,
        [
            "/save report.pdf:1",
            "/save report.pdf:2",
            "/save \"my plan.txt\""
        ]
    );
    assert_eq!(
        lines[2].0,
        "Ada sent my plan.txt (4 bytes). Type /save \"my plan.txt\" to save it to Downloads."
    );
    // Each command, typed as the line shows it, saves that line's file.
    for (cmd, want) in [
        ("/save report.pdf:2", "second"),
        ("/save \"my plan.txt\"", "plan"),
    ] {
        let c = crate::commands::parse_command(cmd).unwrap();
        bo.command(c).await.unwrap();
        let saved = std::fs::read_dir(downloads(&bo))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| std::fs::read(p).unwrap() == want.as_bytes());
        assert!(saved.is_some(), "{cmd} saved {want}");
    }
}

#[tokio::test]
async fn your_own_file_line_has_no_save_hint_and_no_click() {
    let srv = TestServer::start().await;
    let (g, _a, mut bo, _dir) = room_with_bo(&srv).await;
    bo.act(Action::Select(g)).await;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("mine.txt");
    std::fs::write(&p, b"mine").unwrap();
    bo.client.send_file(g, &p, false).await.unwrap();
    let line = bo
        .view()
        .lines
        .into_iter()
        .find(|l| l.text.starts_with("You sent mine.txt"))
        .unwrap();
    assert_eq!(line.text, "You sent mine.txt (4 bytes)");
    assert_eq!((line.command, line.file), (None, None));
}

#[tokio::test]
async fn save_alone_saves_the_newest_file_someone_else_sent() {
    let srv = TestServer::start().await;
    let (g, mut a, mut bo, _dir) = room_with_bo(&srv).await;
    bo.act(Action::Select(g)).await;
    let none = Command::Save {
        file: None,
        dir: None,
    };
    assert_eq!(
        bo.command(none.clone()).await.unwrap_err(),
        "No one has sent a file in this chat yet."
    );
    ada_sends(&mut a, &mut bo, g, &[("a.txt", b"a"), ("b.txt", b"b")]).await;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("c.txt");
    std::fs::write(&p, b"c").unwrap();
    bo.client.send_file(g, &p, false).await.unwrap();
    bo.app.status = None;
    bo.command(none).await.unwrap();
    let saved = downloads(&bo).join("b.txt");
    assert_eq!(std::fs::read(&saved).unwrap(), b"b");
    assert_eq!(last_line(&bo, g), saved_line("b.txt", &saved));
    assert_eq!(bo.app.status, None, "the line in the room says it");
    let names: Vec<_> = std::fs::read_dir(downloads(&bo))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["b.txt"]);
}

#[tokio::test]
async fn saving_never_replaces_a_file_already_in_the_folder() {
    let srv = TestServer::start().await;
    let (g, mut a, mut bo, _dir) = room_with_bo(&srv).await;
    bo.act(Action::Select(g)).await;
    ada_sends(&mut a, &mut bo, g, &[("report.pdf", b"new")]).await;
    std::fs::create_dir_all(downloads(&bo)).unwrap();
    std::fs::write(downloads(&bo).join("report.pdf"), b"keep").unwrap();
    std::fs::write(downloads(&bo).join("report (1).pdf"), b"keep 1").unwrap();
    let c = crate::commands::parse_command("/save report.pdf").unwrap();
    bo.command(c).await.unwrap();
    let saved = downloads(&bo).join("report (2).pdf");
    assert_eq!(std::fs::read(&saved).unwrap(), b"new");
    assert_eq!(
        std::fs::read(downloads(&bo).join("report.pdf")).unwrap(),
        b"keep"
    );
    assert_eq!(last_line(&bo, g), saved_line("report.pdf", &saved));
}

#[tokio::test]
async fn a_click_saves_the_file_once_then_says_where_it_is() {
    let srv = TestServer::start().await;
    let (g, mut a, mut bo, _dir) = room_with_bo(&srv).await;
    bo.act(Action::Select(g)).await;
    ada_sends(&mut a, &mut bo, g, &[("a.txt", b"one"), ("a.txt", b"two")]).await;
    let ids: Vec<_> = bo.view().lines.iter().filter_map(|l| l.file).collect();
    assert_eq!(ids.len(), 2);
    // The older of two files with one name: the click goes by the file,
    // never by its name.
    bo.act(Action::SaveFile(g, ids[0])).await;
    let saved = downloads(&bo).join("a.txt");
    assert_eq!(std::fs::read(&saved).unwrap(), b"one");
    assert_eq!(last_line(&bo, g), saved_line("a.txt", &saved));
    bo.act(Action::SaveFile(g, ids[0])).await;
    assert_eq!(
        bo.app.status,
        Some(format!(
            "Already saved to {}.",
            super::super::saving::shown_path(&saved, super::super::saving::home().as_deref())
        ))
    );
    assert_eq!(std::fs::read_dir(downloads(&bo)).unwrap().count(), 1);
    bo.act(Action::SaveFile(g, ids[1])).await;
    assert_eq!(
        std::fs::read(downloads(&bo).join("a (1).txt")).unwrap(),
        b"two"
    );
    // Gone from the folder, a click fetches it again, which works while
    // the server still holds it: here everyone has it, so the server let
    // it go.
    std::fs::remove_file(&saved).unwrap();
    bo.act(Action::SaveFile(g, ids[0])).await;
    assert!(!saved.exists());
    assert_eq!(
        bo.app.status.as_deref(),
        Some("this file is no longer on the server")
    );
}

#[tokio::test]
async fn tab_after_save_offers_the_rooms_files_newest_first() {
    let srv = TestServer::start().await;
    let (g, mut a, mut bo, _dir) = room_with_bo(&srv).await;
    bo.act(Action::Select(g)).await;
    ada_sends(
        &mut a,
        &mut bo,
        g,
        &[
            ("report.pdf", b"1"),
            ("report.pdf", b"2"),
            ("my plan.txt", b"3"),
        ],
    )
    .await;
    assert!(bo.view().save_files.is_empty(), "read only for /save");
    bo.app.input = "/save ".into();
    assert_eq!(
        bo.view().save_files,
        ["\"my plan.txt\"", "report.pdf:2", "report.pdf:1"]
    );
}
