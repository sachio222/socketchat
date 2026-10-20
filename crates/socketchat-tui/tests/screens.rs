use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
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
            LineView { time: "09:14".into(), sender: "Ada".into(), text: "Who is bringing the book list?".into(), notice: false, mine: true },
            LineView { time: "09:15".into(), sender: "Bo".into(), text: "Me. Sending it now.".into(), notice: false, mine: false },
            LineView { time: "09:15".into(), sender: String::new(), text: "Bo sent books.pdf (84 KB)".into(), notice: true, mine: false },
            LineView { time: "09:16".into(), sender: "Cy".into(), text: "Got it, thanks. Saturday still works for me, and I can bring snacks for everyone.".into(), notice: false, mine: false },
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
