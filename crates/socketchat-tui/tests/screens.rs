use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::style::{Color, Modifier};
use ratatui::Terminal;
use socketchat_core::keys::Key;
use socketchat_proto::msg::GroupId;
use socketchat_tui::app::{sent_file_status, Action, App, Focus, Modal};
use socketchat_tui::commands::{parse_command, Command};
use socketchat_tui::ui::{draw, GroupView, LineView, MemberLine, ViewModel};

fn render(app: &App, vm: &ViewModel, w: u16, h: u16) -> String {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    t.draw(|f| draw(f, app, vm)).unwrap();
    let buf = t.backend().buffer().clone();
    let mut out = String::new();
    for y in 0..h {
        let mut line = String::new();
        for x in 0..w {
            line.push_str(buf[(x, y)].symbol());
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn ctrl(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
}

fn g(n: u8) -> GroupId {
    GroupId([n; 16])
}

fn k(n: u8) -> Key {
    Key([n; 32])
}

fn crew() -> ViewModel {
    ViewModel {
        me: "Ada".into(),
        groups: vec![
            GroupView { id: g(1), name: "Book club".into(), unread: 0, is_dm: false },
            GroupView { id: g(2), name: "Bo".into(), unread: 3, is_dm: true },
            GroupView { id: g(3), name: "Climbing Saturdays".into(), unread: 12, is_dm: false },
        ],
        lines: vec![
            LineView { time: "09:14:05".into(), sender: "Ada".into(), text: "Who is bringing the book list?".into(), notice: false, mine: true },
            LineView { time: "09:15:12".into(), sender: "Bo".into(), text: "Me. Sending it now.".into(), notice: false, mine: false },
            LineView { time: "09:15:40".into(), sender: String::new(), text: "Bo sent books.pdf (84 KB)".into(), notice: true, mine: false },
            LineView { time: "09:16:58".into(), sender: "Cy".into(), text: "Got it, thanks. Saturday still works for me, and I can bring snacks for everyone.".into(), notice: false, mine: false },
        ],
        members: vec![
            MemberLine { key: k(1), name: "Ada".into(), verified: true, admin: true, me: true },
            MemberLine { key: k(2), name: "Bo".into(), verified: true, admin: false, me: false },
            MemberLine { key: k(3), name: "Cy".into(), verified: false, admin: false, me: false },
        ],
        connected: true,
    }
}

#[test]
fn parse_every_command() {
    let cases = [
        ("/invite", Command::Invite { dm: false }),
        ("/invite --dm", Command::Invite { dm: true }),
        (
            "/join socketchat://h:1/j/x#y",
            Command::Join("socketchat://h:1/j/x#y".into()),
        ),
        ("/new Book club", Command::New("Book club".into())),
        ("/dm Bo", Command::Dm("Bo".into())),
        ("/send ~/photo.jpg", Command::Send("~/photo.jpg".into())),
        (
            "/save books.pdf",
            Command::Save {
                file: "books.pdf".into(),
                dir: None,
            },
        ),
        (
            "/save books.pdf ~/Desktop",
            Command::Save {
                file: "books.pdf".into(),
                dir: Some("~/Desktop".into()),
            },
        ),
        ("/verify Bo", Command::Verify("Bo".into())),
        (
            "/rename Bo Bo from work",
            Command::Rename {
                name: "Bo".into(),
                new: "Bo from work".into(),
            },
        ),
        ("/name Ada L.", Command::Name("Ada L.".into())),
        ("/kick Cy", Command::Kick("Cy".into())),
        ("/admin Cy", Command::Admin("Cy".into())),
        ("/leave", Command::Leave),
        ("/help", Command::Help),
        ("/quit", Command::Quit),
    ];
    for (s, want) in cases {
        assert_eq!(parse_command(s), Ok(want), "{s}");
    }
}

#[test]
fn parse_rejects_unknown_command_with_help_hint() {
    let e = parse_command("/frobnicate").unwrap_err();
    assert!(e.contains("/help"), "{e}");
    assert!(parse_command("/dm").unwrap_err().contains("/dm <name>"));
    assert!(parse_command("/rename Bo").is_err());
}

#[test]
fn screen_empty_first_run() {
    let vm = ViewModel {
        me: "Ada".into(),
        groups: vec![],
        lines: vec![],
        members: vec![],
        connected: true,
    };
    insta::assert_snapshot!(render(&App::new(), &vm, 80, 24));
}

#[test]
fn screen_group_chat_three_members_one_verified() {
    let mut app = App::new();
    app.selected = Some(g(1));
    insta::assert_snapshot!(render(&app, &crew(), 80, 24));
}

#[test]
fn wrapped_lines_sit_clear_of_the_time() {
    let mut app = App::new();
    app.selected = Some(g(1));
    let s = render(&app, &crew(), 80, 24);
    let rows: Vec<&str> = s.lines().collect();
    let first = rows
        .iter()
        .position(|r| r.contains("09:16:58 Cy:"))
        .expect("Cy's line is on screen");
    let col = rows[first].find("09:16:58").unwrap();
    let next = &rows[first + 1][col..];
    let indent = next.chars().take_while(|c| *c == ' ').count();
    assert_eq!(
        indent,
        "09:16:58 ".len(),
        "continuation line: {next:?}\n{s}"
    );
}

#[test]
fn screen_unverified_join_warning() {
    let mut app = App::new();
    app.selected = Some(g(1));
    app.warning = Some("You joined, but the invite could not be checked: the invite was signed by someone other than the person in the link. Compare safety numbers with /verify.".into());
    insta::assert_snapshot!(render(&app, &crew(), 80, 24));
}

#[test]
fn screen_invite_modal_with_qr() {
    let link = "socketchat://chat.example.com:7444/j/AAECAwQFBgcICQoLDA0ODw#3q2-7wABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhs.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8.ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";
    let mut app = App::new();
    app.selected = Some(g(1));
    app.modal = Some(Modal::Invite {
        link: link.into(),
        hours: 2,
    });
    let small = render(&app, &crew(), 80, 24);
    assert!(small.contains("expires in 2 hours."), "{small}");
    insta::assert_snapshot!("invite_80x24", small);
    insta::assert_snapshot!("invite_100x50", render(&app, &crew(), 100, 50));
    app.modal = Some(Modal::Invite {
        link: link.into(),
        hours: 1,
    });
    let one = render(&app, &crew(), 100, 50);
    assert!(one.contains("expires in 1 hour."), "{one}");
    assert_eq!(
        app.handle_key(key(KeyCode::Char('c')), &crew()),
        vec![Action::Copy(link.into())]
    );
    assert!(app.modal.is_some(), "copying keeps the link on screen");
}

#[test]
fn invite_qr_is_true_black_on_white() {
    // Named colors follow the terminal theme (gray on gray in some), so the
    // QR must use exact RGB values for a camera to read it.
    let link = "socketchat://chat.example.com:7444/j/AAECAwQFBgcICQoLDA0ODw#3q2-7wABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhs.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8.ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";
    let mut app = App::new();
    app.selected = Some(g(1));
    app.modal = Some(Modal::Invite {
        link: link.into(),
        hours: 24,
    });
    let mut t = Terminal::new(TestBackend::new(100, 50)).unwrap();
    t.draw(|f| draw(f, &app, &crew())).unwrap();
    let buf = t.backend().buffer().clone();
    let mut qr_cells = 0;
    for y in 0..50 {
        for x in 0..100 {
            let cell = &buf[(x, y)];
            if ["\u{2580}", "\u{2584}", "\u{2588}"].contains(&cell.symbol()) {
                qr_cells += 1;
                assert_eq!(cell.fg, Color::Rgb(0, 0, 0), "QR ink at ({x}, {y})");
                assert_eq!(cell.bg, Color::Rgb(255, 255, 255), "QR paper at ({x}, {y})");
            }
        }
    }
    assert!(
        qr_cells > 100,
        "expected a QR code on screen, found {qr_cells} cells"
    );
}

#[test]
fn screen_verify_modal() {
    let mut app = App::new();
    app.selected = Some(g(1));
    app.modal = Some(Modal::Verify {
        name: "Bo".into(),
        key: k(2),
        number: "12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890".into(),
    });
    insta::assert_snapshot!(render(&app, &crew(), 80, 24));
}

#[test]
fn screen_switcher_open() {
    let mut app = App::new();
    app.selected = Some(g(1));
    app.handle_key(ctrl('k'), &crew());
    for c in "clim".chars() {
        app.handle_key(key(KeyCode::Char(c)), &crew());
    }
    insta::assert_snapshot!(render(&app, &crew(), 80, 24));
    let acts = app.handle_key(key(KeyCode::Enter), &crew());
    assert_eq!(acts, vec![Action::Select(g(3))]);
}

#[test]
fn screen_narrow_80x24_long_names_truncated() {
    let mut vm = crew();
    vm.groups[0].name = "An extremely long group name that never ends".into();
    vm.members[2].name = "Cyrus Alexander Montgomery-Featherstonehaugh".into();
    vm.lines[1].sender = "Bo\u{1b}[31m".replace('\u{1b}', "");
    let mut app = App::new();
    app.selected = Some(g(1));
    let s = render(&app, &vm, 80, 24);
    assert!(s.contains('…'), "long names end in an ellipsis");
    assert!(!s.contains('\u{1b}'));
    insta::assert_snapshot!(s);
}

#[test]
fn tab_cycles_focus_and_help_bar_changes() {
    let mut app = App::new();
    app.selected = Some(g(1));
    let vm = crew();
    assert_eq!(app.focus, Focus::Input);
    let mut bars = vec![];
    for _ in 0..4 {
        let s = render(&app, &vm, 80, 24);
        bars.push(s.lines().nth(23).unwrap().to_string());
        app.handle_key(key(KeyCode::Tab), &vm);
    }
    assert_eq!(app.focus, Focus::Input, "four tabs come back around");
    bars.dedup();
    assert_eq!(bars.len(), 4, "each area has its own help line: {bars:?}");
}

#[test]
fn typing_and_enter_sends_or_runs_a_command() {
    let mut app = App::new();
    app.selected = Some(g(1));
    let vm = crew();
    for c in "hello".chars() {
        app.handle_key(key(KeyCode::Char(c)), &vm);
    }
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Send(g(1), "hello".into())]
    );
    assert_eq!(app.input, "");
    for c in "/leave".chars() {
        app.handle_key(key(KeyCode::Char(c)), &vm);
    }
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Command(Command::Leave)]
    );
    assert_eq!(app.handle_key(ctrl('c'), &vm), vec![Action::Quit]);
}

#[test]
fn groups_focus_arrows_change_selection() {
    let mut app = App::new();
    app.selected = Some(g(1));
    let vm = crew();
    app.focus = Focus::Groups;
    assert_eq!(
        app.handle_key(key(KeyCode::Down), &vm),
        vec![Action::Select(g(2))]
    );
}

fn offer(name: &str, mime: &str) -> socketchat_core::files::FileOffer {
    socketchat_core::files::FileOffer {
        id: socketchat_proto::msg::FileId([0; 16]),
        name: name.into(),
        size: 1000,
        mime: mime.into(),
        sha256: [0; 32],
        key: [0; 32],
        nonce_prefix: [0; 19],
    }
}

#[test]
fn status_after_sending_a_photo_says_it_was_cleaned() {
    for (name, mime) in [
        ("beach.jpg", "image/jpeg"),
        ("map.png", "image/png"),
        ("cat.webp", "image/webp"),
    ] {
        assert_eq!(
            sent_file_status(&offer(name, mime)),
            Some(format!(
                "Sent {name} with its location and device data removed."
            ))
        );
    }
    assert_eq!(
        sent_file_status(&offer("books.pdf", "application/octet-stream")),
        None
    );
    assert_eq!(sent_file_status(&offer("clip.mp4", "video")), None);
}

fn buffer(app: &App, vm: &ViewModel, w: u16, h: u16) -> ratatui::buffer::Buffer {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    t.draw(|f| draw(f, app, vm)).unwrap();
    t.backend().buffer().clone()
}

/// The text of row `y`, and the column where `needle` starts in it.
fn find_in_row(buf: &ratatui::buffer::Buffer, y: u16, needle: &str) -> Option<u16> {
    let row: Vec<&str> = (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect();
    let text: String = row.concat();
    let byte = text.find(needle)?;
    Some(text[..byte].chars().count() as u16)
}

#[test]
fn message_box_is_framed_and_names_the_group() {
    let mut app = App::new();
    app.selected = Some(g(1));
    let buf = buffer(&app, &crew(), 80, 24);
    let s = render(&app, &crew(), 80, 24);
    let rows: Vec<&str> = s.lines().collect();
    // Three rows of box across the full width, then the help line.
    assert!(rows[20].starts_with('┌') && rows[20].ends_with('┐'), "{s}");
    assert!(rows[22].starts_with('└') && rows[22].ends_with('┘'), "{s}");
    assert!(rows[21].contains("What's on your mind, Book club?"), "{s}");
    assert!(rows[21].contains("/ for commands"), "{s}");
    // The box has focus by default, so its border uses the focused style.
    let corner = &buf[(0, 20)];
    assert_eq!(corner.fg, Color::Cyan);
    assert!(corner.modifier.contains(Modifier::BOLD));
    // The room's name stands out; the rest of the hint is dim.
    let name_at = find_in_row(&buf, 21, "Book club").unwrap();
    for x in name_at..name_at + "Book club".len() as u16 {
        let c = &buf[(x, 21)];
        assert_eq!(c.fg, Color::Cyan, "name cell {x}");
        assert!(c.modifier.contains(Modifier::BOLD), "name cell {x}");
    }
    let what_at = find_in_row(&buf, 21, "What's").unwrap();
    assert_eq!(buf[(what_at, 21)].fg, Color::DarkGray);
    let cmd_at = find_in_row(&buf, 21, "/ for commands").unwrap();
    assert_eq!(buf[(cmd_at, 21)].fg, Color::DarkGray);
    insta::assert_snapshot!("message_box_group_hint", s);
}

#[test]
fn empty_message_box_cursor_leaves_the_hint_readable() {
    let mut app = App::new();
    app.selected = Some(g(1));
    let mut t = Terminal::new(TestBackend::new(80, 24)).unwrap();
    t.draw(|f| draw(f, &app, &crew())).unwrap();
    let pos = t.get_cursor_position().unwrap();
    let buf = t.backend().buffer().clone();
    let hint_at = find_in_row(&buf, 21, "What's").unwrap();
    assert_eq!(pos.y, 21);
    assert!(
        pos.x < hint_at,
        "cursor at {} covers the hint at {hint_at}",
        pos.x
    );
    assert_eq!(buf[(pos.x, pos.y)].symbol(), " ");
}

#[test]
fn message_box_says_hi_in_a_direct_chat() {
    let mut app = App::new();
    app.selected = Some(g(2));
    let buf = buffer(&app, &crew(), 80, 24);
    let s = render(&app, &crew(), 80, 24);
    let rows: Vec<&str> = s.lines().collect();
    assert!(rows[21].contains("Say hi to Bo"), "{s}");
    let bo = find_in_row(&buf, 21, "Bo").unwrap();
    assert_eq!(buf[(bo, 21)].fg, Color::Cyan);
    assert!(buf[(bo, 21)].modifier.contains(Modifier::BOLD));
    insta::assert_snapshot!("message_box_dm_hint", s);
}

#[test]
fn message_box_with_no_chat_open() {
    let app = App::new();
    let s = render(&app, &crew(), 80, 24);
    let rows: Vec<&str> = s.lines().collect();
    assert!(
        rows[21].contains("Start a chat with /new <name>, or paste an invite with /join <link>"),
        "{s}"
    );
    insta::assert_snapshot!("message_box_no_chat_hint", s);
}

#[test]
fn message_box_shows_typing_with_the_cursor_after_it() {
    let mut app = App::new();
    app.selected = Some(g(1));
    for c in "hello".chars() {
        app.handle_key(key(KeyCode::Char(c)), &crew());
    }
    let mut t = Terminal::new(TestBackend::new(80, 24)).unwrap();
    t.draw(|f| draw(f, &app, &crew())).unwrap();
    let s = render(&app, &crew(), 80, 24);
    let rows: Vec<&str> = s.lines().collect();
    assert!(rows[21].starts_with("│› hello"), "{s}");
    assert!(!rows[21].contains("What's on your mind"), "{s}");
    let pos = t.get_cursor_position().unwrap();
    assert_eq!((pos.x, pos.y), (1 + 2 + 5, 21));
    insta::assert_snapshot!("message_box_typing", s);
}

#[test]
fn status_shows_on_the_help_line_until_the_next_key() {
    let mut app = App::new();
    app.selected = Some(g(1));
    app.status = Some("Saved to ~/Downloads/books.pdf".into());
    let buf = buffer(&app, &crew(), 80, 24);
    let s = render(&app, &crew(), 80, 24);
    let rows: Vec<&str> = s.lines().collect();
    assert_eq!(rows[23], "Saved to ~/Downloads/books.pdf", "{s}");
    assert_eq!(buf[(0, 23)].fg, Color::Yellow);
    assert!(rows[21].contains("What's on your mind, Book club?"), "{s}");
    insta::assert_snapshot!("message_box_status_on_help_line", s);
    app.handle_key(key(KeyCode::Char('o')), &crew());
    assert_eq!(app.status, None);
    let after = render(&app, &crew(), 80, 24);
    assert!(
        after.lines().nth(23).unwrap().starts_with("Enter send"),
        "{after}"
    );
}
