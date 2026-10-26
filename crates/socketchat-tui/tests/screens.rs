use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::style::{Color, Modifier};
use ratatui::Terminal;
use socketchat_core::client::{Ended, RoomDetails};
use socketchat_core::close::CloseView;
use socketchat_core::keys::Key;
use socketchat_core::settings::{WhoCanInvite, WhoCanSetTopic};
use socketchat_core::topic::TopicView;
use socketchat_proto::msg::GroupId;
use socketchat_tui::app::{
    about_lines, details_lines, invite_row, join_choices, leave_step, sent_file_status,
    status_lines, update_status, Action, App, AppStatus, Focus, LeaveStep, Modal,
};
use socketchat_tui::commands::{parse_command, Command, HELP};
use socketchat_tui::theme::{ColorSupport, Theme};
use socketchat_tui::ui::{draw, qr_choices, GroupView, LineView, MemberLine, ViewModel};

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
            GroupView { id: g(1), name: "Book club".into(), unread: 0, is_dm: false, muted: false, ended: None },
            GroupView { id: g(2), name: "Bo".into(), unread: 3, is_dm: true, muted: false, ended: None },
            GroupView { id: g(3), name: "Climbing Saturdays".into(), unread: 12, is_dm: false, muted: false, ended: None },
        ],
        lines: vec![
            LineView { time: "09:14:05".into(), sender: "Ada".into(), text: "Who is bringing the book list?".into(), notice: false, mine: true, topic: false, command: None  },
            LineView { time: "09:15:12".into(), sender: "Bo".into(), text: "Me. Sending it now.".into(), notice: false, mine: false, topic: false, command: None  },
            LineView { time: "09:15:40".into(), sender: String::new(), text: "Bo sent books.pdf (84 KB)".into(), notice: true, mine: false, topic: false, command: None  },
            LineView { time: "09:16:58".into(), sender: "Cy".into(), text: "Got it, thanks. Saturday still works for me, and I can bring snacks for everyone.".into(), notice: false, mine: false, topic: false, command: None  },
        ],
        members: vec![
            MemberLine { key: k(1), name: "Ada".into(), verified: true, admin: true, me: true, changed_key: false },
            MemberLine { key: k(2), name: "Bo".into(), verified: true, admin: false, me: false, changed_key: false },
            MemberLine { key: k(3), name: "Cy".into(), verified: false, admin: false, me: false, changed_key: false },
        ],
        connected: true,
        server: None,
        topic: None,
        invite_names: vec![],
        join_rooms: vec![],
    }
}

#[test]
fn parse_every_command() {
    let cases = [
        ("/invite", Command::Invite { dm: false }),
        ("/invite --dm", Command::Invite { dm: true }),
        (
            "/join socketchat://h:1/j/x#y",
            Command::Join(Some("socketchat://h:1/j/x#y".into())),
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
        ("/switch", Command::Switch(None)),
        (
            "/switch Book club",
            Command::Switch(Some("Book club".into())),
        ),
        ("/title Book club", Command::Title("Book club".into())),
        ("/close", Command::Close),
        ("/keep", Command::Keep),
        ("/invites", Command::Invites),
        ("/cancel 2", Command::Cancel(2)),
        ("/mute", Command::Mute),
        ("/unmute", Command::Unmute),
        ("/details", Command::Details),
        ("/status", Command::Status),
        ("/clear", Command::Clear),
        ("/about", Command::About),
        ("/updates", Command::Updates(None)),
        ("/updates off", Command::Updates(Some(false))),
        ("/updates on", Command::Updates(Some(true))),
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
    assert_eq!(
        parse_command("/cancel x"),
        Err("Usage: /cancel <number>".into())
    );
    assert_eq!(
        parse_command("/cancel"),
        Err("Usage: /cancel <number>".into())
    );
    assert_eq!(parse_command("/title"), Err("Usage: /title <name>".into()));
    assert_eq!(
        parse_command("/updates maybe"),
        Err("Usage: /updates on, or /updates off".into())
    );
}

#[test]
fn screen_empty_first_run() {
    let vm = ViewModel {
        me: "Ada".into(),
        groups: vec![],
        lines: vec![],
        members: vec![],
        connected: true,
        server: None,
        topic: None,
        invite_names: vec![],
        join_rooms: vec![],
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
        copied: true,
    });
    let small = render(&app, &crew(), 80, 24);
    assert!(small.contains("expires in 2 hours."), "{small}");
    insta::assert_snapshot!("invite_80x24", small);
    insta::assert_snapshot!("invite_100x50", render(&app, &crew(), 100, 50));
    app.modal = Some(Modal::Invite {
        link: link.into(),
        hours: 1,
        copied: true,
    });
    let one = render(&app, &crew(), 100, 50);
    assert!(one.contains("expires in 1 hour."), "{one}");
    assert_eq!(
        app.handle_key(key(KeyCode::Char('c')), &crew()),
        vec![Action::Copy(format!(
            "Join me on Socketchat, an encrypted chat.\n1. Install it on your computer from https://socketchat.org\n2. Then run: socketchat join \"{link}\""
        ))]
    );
    assert!(app.modal.is_some(), "copying keeps the link on screen");
}

const LONG_LINK: &str = "socketchat://chat.example.com:7444/j/AAECAwQFBgcICQoLDA0ODw#3q2-7wABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhs.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8.ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";

fn invite_app(link: &str) -> App {
    let mut app = App::new();
    app.selected = Some(g(1));
    app.modal = Some(Modal::Invite {
        link: link.into(),
        hours: 2,
        copied: true,
    });
    app
}

/// The QR code on screen, row by row with its white border, read from the
/// cells drawn black on white. Empty when there is none.
fn qr_on_screen(app: &App, w: u16, h: u16) -> Vec<String> {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    t.draw(|f| draw(f, app, &crew())).unwrap();
    let buf = t.backend().buffer().clone();
    (0..h)
        .map(|y| {
            (0..w)
                .map(|x| &buf[(x, y)])
                .filter(|c| c.bg == Color::Rgb(255, 255, 255))
                .map(|c| c.symbol())
                .collect::<String>()
        })
        .filter(|row| !row.is_empty())
        .collect()
}

#[test]
fn invite_qr_holds_the_web_link() {
    // A phone camera opens the web address; it has no app for socketchat://.
    let app = invite_app(LONG_LINK);
    let web = socketchat_proto::to_web_link(LONG_LINK).unwrap();
    assert_eq!(web, format!("https://socketchat.org/join#{LONG_LINK}"));
    let shown = qr_on_screen(&app, 100, 50);
    assert!(!shown.is_empty(), "no QR code at 100x50");
    assert!(
        qr_choices(&web).contains(&shown),
        "the QR code does not hold {web}"
    );
    assert!(!qr_choices(LONG_LINK).contains(&shown));
    // The text under the box stays the link to paste into a terminal.
    let text = render(&app, &crew(), 100, 50);
    assert!(
        text.contains("│socketchat://chat.example.com:7444/j/"),
        "{text}"
    );
    assert!(!text.contains("https://socketchat.org/join"), "{text}");
}

#[test]
fn invite_qr_is_whole_or_absent_at_every_size() {
    // A QR code with rows cut off cannot be read, so the box shows all of
    // it or a note.
    let app = invite_app(LONG_LINK);
    let web = socketchat_proto::to_web_link(LONG_LINK).unwrap();
    let choices = qr_choices(&web);
    for w in [80, 90, 100, 120] {
        for h in 24..=60 {
            let shown = qr_on_screen(&app, w, h);
            if shown.is_empty() {
                let text = render(&app, &crew(), w, h);
                assert!(
                    text.contains("Make the window larger to show a QR code."),
                    "{w}x{h}: {text}"
                );
            } else {
                assert!(choices.contains(&shown), "{w}x{h}: QR code cut short");
            }
        }
    }
}

#[test]
fn invite_qr_takes_the_smaller_code_when_only_that_fits() {
    let app = invite_app(LONG_LINK);
    let choices = qr_choices(&socketchat_proto::to_web_link(LONG_LINK).unwrap());
    assert!(choices[1].len() < choices[0].len(), "level L is smaller");
    assert_eq!(qr_on_screen(&app, 100, 50), choices[0], "level M at 100x50");
    let small = qr_on_screen(&app, 100, 45);
    if std::env::var_os("SHOW_QR").is_some() {
        println!("{}", render(&app, &crew(), 100, 45));
    }
    assert_eq!(small, choices[1], "level L at 100x45");
}

#[test]
fn invite_qr_shows_at_100x50_with_a_long_server_name() {
    let link = LONG_LINK.replace(
        "chat.example.com",
        "socketchat-server.home.example-family.net",
    );
    let shown = qr_on_screen(&invite_app(&link), 100, 50);
    assert!(!shown.is_empty(), "no QR code at 100x50 for {link}");
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
        copied: true,
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
    assert!(app.handle_key(ctrl('c'), &vm).is_empty());
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
    // These check the classic colors.
    app.theme = Theme::classic(ColorSupport::Indexed256);
    app.selected = Some(g(1));
    let buf = buffer(&app, &crew(), 80, 24);
    let s = render(&app, &crew(), 80, 24);
    let rows: Vec<&str> = s.lines().collect();
    // Three rows of box across the full width, then the help line.
    assert!(rows[20].starts_with('┌') && rows[20].ends_with('┐'), "{s}");
    assert!(rows[22].starts_with('└') && rows[22].ends_with('┘'), "{s}");
    assert!(rows[21].contains("What's on your mind? #Book club"), "{s}");
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
    // These check the classic colors.
    app.theme = Theme::classic(ColorSupport::Indexed256);
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
    // These check the classic colors.
    app.theme = Theme::classic(ColorSupport::Indexed256);
    app.selected = Some(g(1));
    app.status = Some("Saved to ~/Downloads/books.pdf".into());
    let buf = buffer(&app, &crew(), 80, 24);
    let s = render(&app, &crew(), 80, 24);
    let rows: Vec<&str> = s.lines().collect();
    assert!(
        rows[23].starts_with("Saved to ~/Downloads/books.pdf"),
        "{s}"
    );
    assert_eq!(buf[(0, 23)].fg, Color::Yellow);
    assert!(rows[21].contains("What's on your mind? #Book club"), "{s}");
    insta::assert_snapshot!("message_box_status_on_help_line", s);
    app.handle_key(key(KeyCode::Char('o')), &crew());
    assert_eq!(app.status, None);
    let after = render(&app, &crew(), 80, 24);
    assert!(
        after.lines().nth(23).unwrap().starts_with("Enter send"),
        "{after}"
    );
}

fn new_certificate_modal() -> Modal {
    Modal::NewCertificate {
        link: "socketchat://chat.example.com:7444/j/abc#def".into(),
        host: "chat.example.com".into(),
        pinned: "9f2c 41d0 77aa 0b13 5e6f 8812 c3d4 e5f6 0718 293a 4b5c 6d7e 8f90 a1b2 c3d4 e5f6"
            .into(),
        offered: "0707 0707 0707 0707 0707 0707 0707 0707 0707 0707 0707 0707 0707 0707 0707 0707"
            .into(),
    }
}

#[test]
fn screen_new_certificate_modal() {
    let mut app = App::new();
    app.selected = Some(g(1));
    app.modal = Some(new_certificate_modal());
    insta::assert_snapshot!(render(&app, &crew(), 80, 24));
}

#[test]
fn new_certificate_modal_y_trusts_it_and_n_keeps_the_old_one() {
    let mut app = App::new();
    app.modal = Some(new_certificate_modal());
    assert_eq!(
        app.handle_key(key(KeyCode::Char('y')), &crew()),
        vec![Action::AcceptCertificate(
            "socketchat://chat.example.com:7444/j/abc#def".into()
        )]
    );
    assert!(app.modal.is_none());
    app.modal = Some(new_certificate_modal());
    assert!(app.handle_key(key(KeyCode::Char('n')), &crew()).is_empty());
    assert!(app.modal.is_none());
}

fn type_text(app: &mut App, vm: &ViewModel, text: &str) {
    for c in text.chars() {
        app.handle_key(key(KeyCode::Char(c)), vm);
    }
}

fn room(n: u8, name: &str) -> GroupView {
    GroupView {
        id: g(n),
        name: name.into(),
        unread: 0,
        is_dm: false,
        muted: false,
        ended: None,
    }
}

#[test]
fn tab_completes_switch_from_first_letters() {
    let mut app = App::new();
    let vm = crew();
    type_text(&mut app, &vm, "/switch cl");
    assert!(app.handle_key(key(KeyCode::Tab), &vm).is_empty());
    assert_eq!(app.input, "/switch Climbing Saturdays");
    assert_eq!(app.focus, Focus::Input, "Tab completed instead of moving");
}

#[test]
fn tab_completes_help_from_its_first_letter() {
    let mut app = App::new();
    let vm = crew();
    type_text(&mut app, &vm, "/h");
    app.handle_key(key(KeyCode::Tab), &vm);
    assert_eq!(app.input, "/help ");
}

#[test]
fn tab_completes_every_command_the_box_runs() {
    // The command words the parser matches, read from its source, so a new
    // command that Tab can't complete fails here.
    let src = include_str!("../src/commands.rs");
    let words: Vec<&str> = src
        .lines()
        .filter_map(|l| l.trim().strip_prefix('"'))
        .filter_map(|l| l.split_once("\" =>").map(|(w, _)| w))
        .filter(|w| w.starts_with('/') && !w.contains(' '))
        .collect();
    assert!(words.len() > 20, "found the command words: {words:?}");
    let vm = crew();
    for w in words {
        let mut app = App::new();
        type_text(&mut app, &vm, w);
        app.handle_key(key(KeyCode::Tab), &vm);
        assert!(
            app.input.starts_with(w) && app.status.is_none(),
            "Tab after {w} gave {:?} and {:?}",
            app.input,
            app.status
        );
    }
}

#[test]
fn tab_with_nothing_typed_takes_first_room() {
    let mut app = App::new();
    let vm = crew();
    type_text(&mut app, &vm, "/switch ");
    app.handle_key(key(KeyCode::Tab), &vm);
    assert_eq!(app.input, "/switch Book club");
}

#[test]
fn tab_cycles_prefix_matches_in_list_order() {
    let mut vm = crew();
    vm.groups = vec![
        room(1, "Book club"),
        room(2, "Bo"),
        room(3, "Books 2"),
        room(4, "Hobo"),
    ];
    let mut app = App::new();
    type_text(&mut app, &vm, "/switch bo");
    let mut seen = vec![];
    for _ in 0..5 {
        app.handle_key(key(KeyCode::Tab), &vm);
        seen.push(app.input.clone());
    }
    // The room named exactly what was typed comes first, as Enter opens it.
    assert_eq!(
        seen,
        vec![
            "/switch Bo",
            "/switch Book club",
            "/switch Books 2",
            "/switch Bo",
            "/switch Book club"
        ]
    );
    // Any other key ends the cycle: Tab then completes the new text.
    app.handle_key(key(KeyCode::Backspace), &vm);
    assert_eq!(app.input, "/switch Book clu");
    app.handle_key(key(KeyCode::Tab), &vm);
    assert_eq!(app.input, "/switch Book club");
    app.handle_key(key(KeyCode::Tab), &vm);
    assert_eq!(app.input, "/switch Book club", "one match stays put");
    // With no name starting with the text, a name containing it matches.
    app.input = "/switch ob".into();
    app.completion = None;
    app.handle_key(key(KeyCode::Tab), &vm);
    assert_eq!(app.input, "/switch Hobo");
}

/// The grey suggestion after `/switch` names the room Enter opens: the
/// room whose name is the text comes before longer names that start
/// with it.
#[test]
fn switch_ghost_names_the_room_enter_opens() {
    let mut vm = crew();
    vm.groups = vec![room(1, "Book club"), room(2, "Bo")];
    let mut app = App::new();
    type_text(&mut app, &vm, "/switch bo");
    assert_eq!(app.ghost(&vm), None, "Enter opens Bo, so nothing to add");
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Select(g(2))]
    );
    let mut app = App::new();
    type_text(&mut app, &vm, "/switch boo");
    assert_eq!(app.ghost(&vm).as_deref(), Some("k club"));
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Select(g(1))]
    );
}

/// A room name kept with a wide space or two spaces in a row, as an
/// earlier release kept it, opens with the name typed with one space, and
/// Tab writes it with one space so the command runs.
#[test]
fn switch_finds_a_room_whose_name_has_odd_spacing() {
    let mut vm = crew();
    vm.groups = vec![
        room(1, "Chess"),
        room(2, "Book\u{3000}club"),
        room(3, "Bird  watch"),
    ];
    for (typed, want) in [("book club", g(2)), ("bird watch", g(3))] {
        let mut app = App::new();
        type_text(&mut app, &vm, &format!("/switch {typed}"));
        assert_eq!(
            app.handle_key(key(KeyCode::Enter), &vm),
            vec![Action::Select(want)],
            "{typed}: {:?}",
            app.status
        );
    }
    let mut app = App::new();
    type_text(&mut app, &vm, "/switch boo");
    app.handle_key(key(KeyCode::Tab), &vm);
    assert_eq!(app.input, "/switch Book club");
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Select(g(2))],
        "{:?}",
        app.status
    );
    let mut app = App::new();
    app.switcher = Some("bird w".into());
    assert_eq!(app.switcher_pick(&vm), Some(g(3)));
    assert_eq!(app.switcher_matches(&vm).len(), 1);
}

#[test]
fn switch_enter_opens_first_match() {
    let mut vm = crew();
    vm.groups = vec![room(1, "Book club"), room(2, "Bo"), room(3, "Books 2")];
    let mut app = App::new();
    type_text(&mut app, &vm, "/switch book");
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Select(g(1))]
    );
    // An exact name wins over an earlier name that starts with it.
    type_text(&mut app, &vm, "/switch BO");
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Select(g(2))]
    );
    type_text(&mut app, &vm, "/switch 2");
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Select(g(3))]
    );
    type_text(&mut app, &vm, "/switch chess");
    assert!(app.handle_key(key(KeyCode::Enter), &vm).is_empty());
    assert_eq!(
        app.status.as_deref(),
        Some("No room called chess. Type /switch to see them all.")
    );
    app.input.clear();
    type_text(&mut app, &vm, "/switch");
    assert!(app.handle_key(key(KeyCode::Enter), &vm).is_empty());
    assert_eq!(
        app.switcher.as_deref(),
        Some(""),
        "/switch alone opens the switcher"
    );
}

#[test]
fn tab_outside_switch_still_moves_focus() {
    let mut app = App::new();
    let vm = crew();
    type_text(&mut app, &vm, "hello");
    app.handle_key(key(KeyCode::Tab), &vm);
    assert_eq!(app.focus, Focus::Groups);
    assert_eq!(app.input, "hello");
}

#[test]
fn tab_completes_in_ctrl_k_switcher() {
    let mut vm = crew();
    vm.groups = vec![
        room(1, "Book club"),
        room(2, "Bo"),
        room(3, "Climbing Saturdays"),
    ];
    let mut app = App::new();
    app.handle_key(ctrl('k'), &vm);
    type_text(&mut app, &vm, "cl");
    app.handle_key(key(KeyCode::Tab), &vm);
    assert_eq!(app.switcher.as_deref(), Some("Climbing Saturdays"));
    app.handle_key(key(KeyCode::Esc), &vm);
    app.handle_key(ctrl('k'), &vm);
    type_text(&mut app, &vm, "bo");
    app.handle_key(key(KeyCode::Tab), &vm);
    assert_eq!(app.switcher.as_deref(), Some("Bo"));
    // Enter opens the room Tab picked, not the first that contains it.
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Select(g(2))]
    );
}

#[test]
fn leave_step_shows_unseen_first() {
    assert_eq!(leave_step(3, false), LeaveStep::ShowUnseen(3));
    assert_eq!(leave_step(3, true), LeaveStep::Confirm);
    assert_eq!(leave_step(0, false), LeaveStep::Confirm);
}

fn confirm_leave() -> Modal {
    Modal::Confirm {
        question: "Leave Book club? Its messages and files list are deleted from this computer. Press y to leave or n to stay.".into(),
        yes: Box::new(Action::LeaveRoom(g(1))),
    }
}

#[test]
fn confirm_y_returns_its_action_and_n_cancels() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    app.modal = Some(confirm_leave());
    let s = render(&app, &vm, 80, 24);
    assert!(s.contains("Press y to leave or n to stay."), "{s}");
    assert_eq!(
        app.handle_key(key(KeyCode::Char('y')), &vm),
        vec![Action::LeaveRoom(g(1))]
    );
    assert!(app.modal.is_none());
    for no in [KeyCode::Char('n'), KeyCode::Esc] {
        app.modal = Some(confirm_leave());
        assert!(app.handle_key(key(no), &vm).is_empty());
        assert!(app.modal.is_none());
    }
}

#[test]
fn invite_rows_word_hours_like_the_invite_box() {
    assert_eq!(
        invite_row(1, "Book club", 23),
        "1. Book club: expires in 23 hours"
    );
    assert_eq!(
        invite_row(2, "Server invite", 1),
        "2. Server invite: expires in 1 hour"
    );
}

#[test]
fn screen_invites_modal() {
    let mut app = App::new();
    app.selected = Some(g(1));
    app.modal = Some(Modal::Invites {
        rows: vec![
            invite_row(1, "Book club", 1),
            invite_row(2, "Climbing Saturdays", 23),
            invite_row(3, "Server invite", 24),
        ],
        offset: 0,
    });
    let s = render(&app, &crew(), 80, 24);
    assert!(s.contains(" Open invite links "), "{s}");
    assert!(
        s.contains("2. Climbing Saturdays: expires in 23 hours"),
        "{s}"
    );
    assert!(s
        .lines()
        .nth(23)
        .unwrap()
        .starts_with("/cancel <number> stops a link · Esc close"));
    insta::assert_snapshot!(s);
    app.modal = Some(Modal::Invites {
        rows: vec!["You have no open invite links.".into()],
        offset: 0,
    });
    let empty = render(&app, &crew(), 80, 24);
    assert!(empty.contains("You have no open invite links."), "{empty}");
    // Typing a command closes the box and goes into the message box.
    let vm = crew();
    app.handle_key(key(KeyCode::Char('/')), &vm);
    assert!(app.modal.is_none());
    assert_eq!(app.input, "/");
}

fn details() -> RoomDetails {
    RoomDetails {
        name: "Book club".into(),
        server: "chat.socketchat.org".into(),
        admins: vec!["Ada".into(), "Bo".into()],
        size: 3,
        // 2026-03-02 and 2026-10-19, at noon UTC.
        created_unix: Some(1_772_452_800),
        joined_unix: 1_792_411_200,
        muted: false,
        close: Some(CloseView {
            close_id: [1; 16],
            asked_by: "Bo".into(),
            yes: 1,
            no: 0,
            needed: 2,
            admins: 2,
            my_vote: None,
            kept: false,
        }),
        invite: WhoCanInvite::Admins,
        slow_secs: 30,
        server_enforces: Some(true),
        server_members_invite: Some(true),
        topic_who: WhoCanSetTopic::Admins,
        topic: Some(TopicView {
            text: "Piranesi, chapters 1 to 5".into(),
            by: "Bo".into(),
            by_key: k(2),
            verified: true,
            mine: false,
            set_unix: 1_792_411_200,
        }),
        post_quantum: true,
    }
}

fn utc_date(unix: u64) -> String {
    chrono::DateTime::from_timestamp(unix as i64, 0)
        .unwrap()
        .format("%Y-%m-%d")
        .to_string()
}

#[test]
fn details_lines_say_each_fact() {
    let d = details();
    assert_eq!(
        details_lines(&d, "Book club", true, &utc_date),
        vec![
            "Name: Book club",
            "Server: chat.socketchat.org",
            "Topic: Piranesi, chapters 1 to 5 (set by Bo, verified, 2026-10-19)",
            "Admins: Ada, Bo",
            "Members: 3",
            "Created: 2026-03-02",
            "You joined: 2026-10-19",
            "Muted: no",
            "Who can invite: admins only",
            "Slow mode: one message every 30 seconds for each member who isn't an admin",
            "Who can set the topic: admins only",
            "Closing: 1 of 2 admins agree",
            "",
            "Encryption: end-to-end, MLS (RFC 9420)",
            "Post-quantum: yes for messages and files (ML-KEM-768 + X25519). Signatures and the link to the server are not post-quantum yet.",
            "The server cannot see: messages, files, names, room name, topic.",
            "The server sees: when messages move, message sizes in 256-byte blocks, file sizes, IP addresses, a random key for each member, which of them are admins, and the room's settings.",
        ]
    );
    // No topic, and a room that lets anyone set it.
    let mut open_topic = d.clone();
    open_topic.topic = None;
    open_topic.topic_who = WhoCanSetTopic::Anyone;
    let lines = details_lines(&open_topic, "Book club", true, &utc_date);
    assert_eq!(lines[2], "Topic: none");
    assert!(
        lines.contains(&"Who can set the topic: anyone in the room".into()),
        "{lines:?}"
    );
    let mut open = d.clone();
    open.invite = WhoCanInvite::Anyone;
    open.slow_secs = 0;
    let lines = details_lines(&open, "Book club", true, &utc_date);
    assert!(
        lines.contains(&"Who can invite: anyone in the room".into()),
        "{lines:?}"
    );
    assert!(lines.contains(&"Slow mode: off".into()), "{lines:?}");
    assert!(
        !lines.iter().any(|l| l.contains("older version")),
        "{lines:?}"
    );
    // A server from before 0.5.2 cannot enforce them, and the box says so.
    let mut old_server = d.clone();
    old_server.server_enforces = Some(false);
    let lines = details_lines(&old_server, "Book club", true, &utc_date);
    assert!(
        lines.contains(&"This server runs an older version of Socketchat, so it can't enforce who can invite or slow mode.".into()),
        "{lines:?}"
    );
    // The server lets only admins invite, stricter than the room: the line
    // says whose rule it is.
    let mut floor = d.clone();
    floor.invite = WhoCanInvite::Anyone;
    floor.server_members_invite = Some(false);
    let lines = details_lines(&floor, "Book club", true, &utc_date);
    assert!(
        lines.contains(
            &"Who can invite: admins only, because this server lets only admins invite people"
                .into()
        ),
        "{lines:?}"
    );
    // A room already admins-only needs no note.
    let mut both = floor.clone();
    both.invite = WhoCanInvite::Admins;
    let lines = details_lines(&both, "Book club", true, &utc_date);
    assert!(
        lines.contains(&"Who can invite: admins only".into()),
        "{lines:?}"
    );
    // Not reached: nothing said either way.
    let mut offline = d.clone();
    offline.server_enforces = None;
    let lines = details_lines(&offline, "Book club", true, &utc_date);
    assert!(!lines.iter().any(|l| l.contains("enforce")), "{lines:?}");
    let mut old = d.clone();
    old.created_unix = None;
    old.muted = true;
    old.close = None;
    let lines = details_lines(&old, "Book club", false, &utc_date);
    assert!(lines.contains(&"Created: not known (this server runs an older version)".into()));
    assert!(lines.contains(&"Muted: yes".into()));
    assert!(!lines.iter().any(|l| l.starts_with("Closing")));
    // A kept request is no longer open.
    let mut kept = d.clone();
    kept.close.as_mut().unwrap().kept = true;
    let lines = details_lines(&kept, "Book club", true, &utc_date);
    assert!(!lines.iter().any(|l| l.starts_with("Closing")), "{lines:?}");
}

#[test]
fn settings_commands_parse() {
    use socketchat_tui::commands::Setting;
    for (s, want) in [
        ("/settings", Command::Settings(None)),
        (
            "/settings invite admins",
            Command::Settings(Some(Setting::Invite(WhoCanInvite::Admins))),
        ),
        (
            "/settings invite anyone",
            Command::Settings(Some(Setting::Invite(WhoCanInvite::Anyone))),
        ),
        (
            "/settings slow 30",
            Command::Settings(Some(Setting::Slow(30))),
        ),
        (
            "/settings slow off",
            Command::Settings(Some(Setting::Slow(0))),
        ),
        (
            "/settings  slow   0",
            Command::Settings(Some(Setting::Slow(0))),
        ),
        (
            "/settings topic admins",
            Command::Settings(Some(Setting::Topic(WhoCanSetTopic::Admins))),
        ),
        (
            "/settings topic anyone",
            Command::Settings(Some(Setting::Topic(WhoCanSetTopic::Anyone))),
        ),
    ] {
        assert_eq!(parse_command(s), Ok(want), "{s}");
    }
    let usage = "Usage: /settings, /settings invite admins, /settings invite anyone, /settings slow <seconds>, /settings slow off, /settings topic admins, or /settings topic anyone";
    for bad in [
        "/settings invite",
        "/settings invite everyone",
        "/settings slow",
        "/settings slow fast",
        "/settings slow -3",
        "/settings topic",
        "/settings topic members",
        "/settings slow 30 40",
    ] {
        assert_eq!(parse_command(bad), Err(usage.to_string()), "{bad}");
    }
    assert!(HELP.iter().any(|(c, _)| *c == "/settings"));
}

#[test]
fn held_message_line_says_when_it_goes() {
    use socketchat_tui::app::held_line;
    assert_eq!(
        held_line(4),
        "This room limits fast posting; sending in 4 seconds."
    );
    assert_eq!(
        held_line(1),
        "This room limits fast posting; sending in 1 second."
    );
}

#[test]
fn screen_details_modal() {
    let mut app = App::new();
    app.selected = Some(g(1));
    app.modal = Some(Modal::Details {
        lines: details_lines(&details(), "Book club", true, &utc_date),
        offset: 0,
    });
    let s = render(&app, &crew(), 80, 24);
    assert!(s.contains(" Room details "), "{s}");
    assert!(s.contains("Closing: 1 of 2 admins agree"), "{s}");
    assert!(s.contains("Who can invite: admins only"), "{s}");
    insta::assert_snapshot!(s);
}

fn ended_crew(why: Ended) -> ViewModel {
    let mut vm = crew();
    // Open, so read: an ended room stays listed until another opens.
    vm.groups[0].ended = Some(why);
    vm
}

#[test]
fn screen_ended_room_hint() {
    let mut app = App::new();
    app.selected = Some(g(1));
    for (why, hint) in [
        (Ended::Closed, "This room was closed. Its messages leave this computer when you open another room."),
        (Ended::Removed, "You are no longer in this room. Its messages leave this computer when you open another room."),
        (Ended::Left, "You left this room. Its messages leave this computer when you open another room."),
    ] {
        let s = render(&app, &ended_crew(why), 80, 24);
        // The hint wraps inside the message box, never cut short.
        let flat: String = s
            .lines()
            // The message box's rows: one frame on each side, nothing else.
            .filter(|l| l.starts_with('│') && l.matches('│').count() == 2)
            .map(|l| l.trim_matches('│').trim().to_string())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(flat.contains(hint), "{why:?}: {flat:?}\n{s}");
        assert!(!s.contains("What's on your mind"), "{s}");
        if why == Ended::Removed {
            insta::assert_snapshot!(s);
        }
    }
}

#[test]
fn typing_in_an_ended_room_says_why_it_cannot_send() {
    let vm = ended_crew(Ended::Closed);
    let mut app = App::new();
    app.selected = Some(g(1));
    type_text(&mut app, &vm, "hello");
    assert!(app.handle_key(key(KeyCode::Enter), &vm).is_empty());
    assert_eq!(app.input, "hello");
    assert_eq!(
        app.status.as_deref(),
        Some("This room was closed. Its messages leave this computer when you open another room.")
    );
}

#[test]
fn screen_muted_and_ended_rooms_in_list() {
    let mut vm = crew();
    vm.groups[0].muted = true;
    vm.groups[0].unread = 5;
    vm.groups.push(GroupView {
        ended: Some(Ended::Closed),
        unread: 1,
        ..room(4, "Chess")
    });
    vm.groups.push(GroupView {
        ended: Some(Ended::Left),
        unread: 2,
        ..room(5, "Pottery")
    });
    vm.groups.push(GroupView {
        ended: Some(Ended::Removed),
        unread: 4,
        ..room(6, "Art")
    });
    let mut app = App::new();
    // These check the classic colors.
    app.theme = Theme::classic(ColorSupport::Indexed256);
    app.selected = Some(g(3));
    let buf = buffer(&app, &vm, 80, 24);
    let s = render(&app, &vm, 80, 24);
    let rows: Vec<&str> = s.lines().collect();
    assert!(
        rows[1].starts_with("│# Book club       │"),
        "muted shows no count: {s}"
    );
    assert_eq!(buf[(3, 1)].fg, Color::DarkGray, "muted name is dim");
    assert!(rows[4].contains("Chess (closed)"), "{s}");
    assert!(rows[5].contains("Pottery (left)"), "{s}");
    assert!(rows[6].contains("Art (removed)"), "{s}");
    assert!(rows[6].contains(" 4│"), "ended rooms keep their count: {s}");
    insta::assert_snapshot!(s);
}

/// The rows inside a box drawn from column 2 to 77 at 80 wide.
fn modal_text(s: &str) -> Vec<String> {
    s.lines()
        .filter_map(|l| {
            let c: Vec<char> = l.chars().collect();
            (c.len() > 77 && c[2] == '│').then(|| c[3..77].iter().collect::<String>())
        })
        .collect()
}

#[test]
fn help_scrolls_to_every_command_at_80x24() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    app.modal = Some(Modal::Help { offset: 0, pick: 0 });
    let last = HELP.last().unwrap().0;
    let mut shown: Vec<String> = vec![];
    let first = render(&app, &vm, 80, 24);
    assert!(
        modal_text(&first).last().unwrap().contains("↓ more"),
        "{first}"
    );
    assert!(
        first
            .lines()
            .nth(23)
            .unwrap()
            .starts_with("Up/Down pick a command · Enter use it · Esc close"),
        "{first}"
    );
    let mut presses = 0;
    loop {
        let s = render(&app, &vm, 80, 24);
        let inside = modal_text(&s);
        assert!(
            !inside.iter().any(|r| r.contains('…')),
            "a description is cut off:\n{s}"
        );
        shown.extend(inside);
        // The end: the mouse note, under the last command.
        if !s.contains("↓ more") {
            assert!(s.contains("/mouse off."), "the box ends on the note:\n{s}");
            assert!(shown.iter().any(|r| r.starts_with(last)), "{s}");
            break;
        }
        presses += 1;
        assert!(presses < 60, "Down never reached {last}");
        app.handle_key(key(KeyCode::Down), &vm);
    }
    for (cmd, _) in HELP {
        assert!(
            shown.iter().any(|r| r.starts_with(&format!("{cmd} "))),
            "{cmd} never shows"
        );
    }
    // The last command shows the end of the box. Down goes round to the
    // first command at the top, and Up back round to the last at the end.
    let at_end = render(&app, &vm, 80, 24);
    insta::assert_snapshot!("help_80x24_top", first);
    insta::assert_snapshot!("help_80x24_end", at_end);
    app.handle_key(key(KeyCode::Down), &vm);
    assert_eq!(render(&app, &vm, 80, 24), first);
    app.handle_key(key(KeyCode::Up), &vm);
    assert_eq!(render(&app, &vm, 80, 24), at_end);
    // PgUp and PgDn scroll a page and bring the highlight along.
    let top_row = |s: &str| modal_text(s)[0].clone();
    for _ in 0..4 {
        app.handle_key(key(KeyCode::PageUp), &vm);
    }
    assert_eq!(top_row(&render(&app, &vm, 80, 24)), top_row(&first));
    app.handle_key(key(KeyCode::PageDown), &vm);
    assert_ne!(top_row(&render(&app, &vm, 80, 24)), top_row(&first));
    app.handle_key(key(KeyCode::Esc), &vm);
    assert!(app.modal.is_none());
}

#[test]
fn help_lists_the_new_commands_in_order() {
    let names: Vec<&str> = HELP.iter().map(|(c, _)| *c).collect();
    let at = names.iter().position(|c| *c == "/leave").unwrap();
    assert_eq!(
        &names[at..at + 18],
        &[
            "/leave",
            "/switch [room]",
            "/title <name>",
            "/topic [text]",
            "/close",
            "/keep",
            "/invites",
            "/cancel <number>",
            "/servers",
            "/forget <number>",
            "/mute",
            "/unmute",
            "/details",
            "/settings",
            "/settings invite",
            "/settings slow",
            "/settings topic",
            "/clear"
        ]
    );
    assert_eq!(HELP[at].1, "leave this chat and delete its history here");
}

#[test]
fn confirm_ignores_a_stray_y_inside_other_typing() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    app.modal = Some(confirm_leave());
    let mut acts = vec![];
    for c in "okay".chars() {
        acts.extend(app.handle_key(key(KeyCode::Char(c)), &vm));
    }
    assert!(acts.is_empty(), "{acts:?}");
    assert!(app.modal.is_none(), "the first other key says no");
    assert_eq!(app.input, "okay", "the typing goes on in the message box");
    app.input.clear();
    app.modal = Some(confirm_leave());
    assert!(
        app.handle_key(ctrl('y'), &vm).is_empty(),
        "Ctrl+Y is not yes"
    );
    assert!(app.modal.is_none());
    app.modal = Some(confirm_leave());
    let shift_y = KeyEvent::new(KeyCode::Char('Y'), KeyModifiers::SHIFT);
    assert_eq!(
        app.handle_key(shift_y, &vm),
        vec![Action::LeaveRoom(g(1))],
        "a capital Y is yes"
    );
}

#[test]
fn invites_scroll_to_every_link_at_80x24() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    let rows: Vec<String> = (1..=30)
        .map(|n| invite_row(n, &format!("Room {n}"), 24))
        .collect();
    app.modal = Some(Modal::Invites { rows, offset: 0 });
    let first = render(&app, &vm, 80, 24);
    assert!(
        modal_text(&first).last().unwrap().contains("↓ more"),
        "{first}"
    );
    insta::assert_snapshot!("invites_30_links_80x24", first);
    let mut presses = 0;
    while !render(&app, &vm, 80, 24).contains("30. Room 30: expires in 24 hours") {
        presses += 1;
        assert!(presses < 40, "Down never reached link 30");
        app.handle_key(key(KeyCode::Down), &vm);
    }
    let end = render(&app, &vm, 80, 24);
    assert!(!end.contains("↓ more"), "{end}");
    app.handle_key(key(KeyCode::PageUp), &vm);
    app.handle_key(key(KeyCode::PageUp), &vm);
    assert_eq!(render(&app, &vm, 80, 24), first);
    app.handle_key(key(KeyCode::PageDown), &vm);
    assert!(render(&app, &vm, 80, 24).contains("20. Room 20"));
}

#[test]
fn tab_pick_holds_when_two_rooms_share_a_name() {
    let mut vm = crew();
    vm.groups = vec![
        room(1, "Book club"),
        room(2, "Bo"),
        room(3, "Climbing"),
        room(5, "Bo"),
    ];
    let mut app = App::new();
    // Tab goes Bo, Bo, then Book club: the names that are the text first.
    type_text(&mut app, &vm, "/switch bo");
    for _ in 0..2 {
        app.handle_key(key(KeyCode::Tab), &vm);
    }
    assert_eq!(app.input, "/switch Bo");
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Select(g(5))],
        "Enter opens the Bo that Tab showed"
    );
    // Edited after Tab: the text decides again.
    type_text(&mut app, &vm, "/switch bo");
    for _ in 0..2 {
        app.handle_key(key(KeyCode::Tab), &vm);
    }
    app.handle_key(key(KeyCode::Backspace), &vm);
    app.handle_key(key(KeyCode::Char('o')), &vm);
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Select(g(2))]
    );
    // The switcher highlights, and opens, the Bo Tab picked.
    app.handle_key(ctrl('k'), &vm);
    type_text(&mut app, &vm, "bo");
    for _ in 0..2 {
        app.handle_key(key(KeyCode::Tab), &vm);
    }
    assert_eq!(app.switcher.as_deref(), Some("Bo"));
    let buf = buffer(&app, &vm, 80, 24);
    // Box at rows 6..18: "> Bo", then Book club, Bo (g2), Bo (g5).
    assert_eq!(find_in_row(&buf, 9, "Bo"), Some(21));
    assert_eq!(find_in_row(&buf, 10, "Bo"), Some(21));
    let picked = app.theme.selected.bg.unwrap();
    assert_ne!(buf[(21, 9)].bg, picked);
    assert_eq!(buf[(21, 10)].bg, picked);
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Select(g(5))]
    );
}

#[test]
fn help_line_shows_the_version_at_the_right_edge_when_it_fits() {
    let version = format!("socketchat {}", env!("CARGO_PKG_VERSION"));
    let mut app = App::new();
    app.selected = Some(g(1));
    let s = render(&app, &crew(), 100, 24);
    let last = s.lines().nth(23).unwrap();
    assert!(
        last.starts_with("Enter send · /help commands"),
        "the help text stays whole: {last}"
    );
    assert!(last.ends_with(&version), "{last}");
    assert_eq!(last.chars().count(), 100, "right-aligned: {last}");
}

#[test]
fn help_line_drops_the_version_when_it_would_cut_the_help_text() {
    let mut app = App::new();
    app.selected = Some(g(1));
    let s = render(&app, &crew(), 80, 24);
    let last = s.lines().nth(23).unwrap();
    assert_eq!(
        last,
        "Enter send · /help commands · Tab move · Ctrl-K switch chat · Ctrl-C quit"
    );
}

#[test]
fn screen_about_modal() {
    let mut app = App::new();
    app.selected = Some(g(1));
    app.modal = Some(Modal::About);
    let s = render(&app, &crew(), 80, 24);
    assert!(s.contains(" About "), "{s}");
    // The sentence wraps, so check the short lines and the sentence's ends.
    for line in about_lines(&app.updates).iter().filter(|l| l.len() < 70) {
        assert!(s.contains(line), "{line} is missing:\n{s}");
    }
    assert!(s.contains("Socketchat is end-to-end encrypted chat"), "{s}");
    assert!(s.contains("how many people are in each room."), "{s}");
    assert!(about_lines("")[0].ends_with(env!("CARGO_PKG_VERSION")));
    assert!(about_lines("").contains(&"License: MIT or Apache 2.0".to_string()));
    insta::assert_snapshot!(s);
    app.handle_key(key(KeyCode::Esc), &crew());
    assert!(app.modal.is_none());
}

/// Every box that asks a security question: a y typed inside other words
/// must not answer it.
fn security_questions() -> Vec<(Modal, Action)> {
    vec![
        (
            Modal::Verify {
                name: "Bo".into(),
                key: k(2),
                number: "12345 67890".into(),
            },
            Action::MarkVerified(k(2)),
        ),
        (
            Modal::ConfirmVideo {
                group: g(1),
                path: "/tmp/beach.mov".into(),
            },
            Action::ConfirmVideo(g(1), "/tmp/beach.mov".into()),
        ),
        (
            Modal::ConfirmPhoto {
                group: g(1),
                path: "/tmp/beach.heic".into(),
            },
            Action::ConfirmVideo(g(1), "/tmp/beach.heic".into()),
        ),
        (
            new_certificate_modal(),
            Action::AcceptCertificate("socketchat://chat.example.com:7444/j/abc#def".into()),
        ),
    ]
}

#[test]
fn security_questions_ignore_a_y_inside_other_typing() {
    let vm = crew();
    for (modal, _) in security_questions() {
        for word in ["hey", "okay", "1y", " y"] {
            let mut app = App::new();
            app.selected = Some(g(1));
            app.modal = Some(modal.clone());
            let mut acts = vec![];
            for c in word.chars() {
                acts.extend(app.handle_key(key(KeyCode::Char(c)), &vm));
            }
            assert!(acts.is_empty(), "{modal:?} {word:?}: {acts:?}");
            assert!(
                app.modal.is_none(),
                "{modal:?}: the first other key says no"
            );
        }
        for other in [KeyCode::Down, KeyCode::Tab, KeyCode::Left] {
            let mut app = App::new();
            app.modal = Some(modal.clone());
            let mut acts = app.handle_key(key(other), &vm);
            acts.extend(app.handle_key(key(KeyCode::Char('y')), &vm));
            assert!(acts.is_empty(), "{modal:?} {other:?} then y: {acts:?}");
        }
        let mut app = App::new();
        app.modal = Some(modal.clone());
        assert!(
            app.handle_key(ctrl('y'), &vm).is_empty(),
            "Ctrl+Y is not yes"
        );
        assert!(app.modal.is_none());
    }
}

#[test]
fn security_questions_take_a_y_pressed_first() {
    let vm = crew();
    for (modal, yes) in security_questions() {
        let mut app = App::new();
        app.modal = Some(modal.clone());
        assert_eq!(
            app.handle_key(key(KeyCode::Char('y')), &vm),
            vec![yes.clone()]
        );
        assert!(app.modal.is_none());
        let mut app = App::new();
        app.modal = Some(modal.clone());
        let shift_y = KeyEvent::new(KeyCode::Char('Y'), KeyModifiers::SHIFT);
        assert_eq!(app.handle_key(shift_y, &vm), vec![yes]);
        for no in [KeyCode::Char('n'), KeyCode::Esc, KeyCode::Enter] {
            let mut app = App::new();
            app.modal = Some(modal.clone());
            assert!(app.handle_key(key(no), &vm).is_empty(), "{modal:?} {no:?}");
            assert!(app.modal.is_none());
            assert!(app.input.is_empty(), "n, Esc and Enter only answer");
        }
    }
}

/// A paste goes into the message box as text, whatever it holds, and
/// nothing is sent or run until the person presses Enter.
#[test]
fn a_paste_is_text_in_the_message_box_and_runs_nothing() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    assert!(app
        .handle_paste("hello\r\n/kick Bo\n/admin Cy\n")
        .is_empty());
    assert_eq!(app.input, "hello\n/kick Bo\n/admin Cy\n");
    assert_eq!(app.focus, Focus::Input);
    let acts = app.handle_key(key(KeyCode::Enter), &vm);
    assert_eq!(
        acts,
        vec![Action::Send(g(1), "hello\n/kick Bo\n/admin Cy".into())],
        "Enter sends the paste as one message"
    );
    let mut app = App::new();
    app.selected = Some(g(1));
    app.handle_paste("/kick Bo");
    assert_eq!(app.input, "/kick Bo", "a pasted command waits for Enter");
    app.handle_paste("\u{1b}[31m\tx\u{7}");
    assert_eq!(app.input, "/kick Bo[31m x", "control characters stay out");
}

#[test]
fn a_paste_never_answers_a_question() {
    let vm = crew();
    for (modal, _) in security_questions() {
        let mut app = App::new();
        app.selected = Some(g(1));
        app.modal = Some(modal.clone());
        assert!(app.handle_paste("y").is_empty(), "{modal:?}");
        assert!(app.modal.is_none(), "{modal:?}: a paste says no");
        assert_eq!(app.input, "y");
        assert!(app.handle_key(key(KeyCode::Backspace), &vm).is_empty());
    }
    let mut app = App::new();
    app.modal = Some(confirm_leave());
    assert!(app.handle_paste("y").is_empty());
    assert!(app.modal.is_none());
}

#[test]
fn pasted_lines_show_as_return_marks_in_the_message_box() {
    let mut app = App::new();
    app.selected = Some(g(1));
    app.handle_paste("one\ntwo");
    let s = render(&app, &crew(), 80, 24);
    assert!(s.contains("› one↵two"), "{s}");
}

const ONE_LINE: &str = "A command fits on one line. Remove the line breaks to run it.";
const NO_SPACES: &str = "Remove the spaces before the / to run the command.";

/// Text with a line break never runs as a command: a paste that starts
/// with a command and hides more lines below it is refused.
#[test]
fn a_command_with_line_breaks_never_runs() {
    let vm = crew();
    for paste in [
        format!("/send x{}", "\n".repeat(100)),
        "\n\n/kick Bo".to_string(),
        "/kick Bo\nhello".to_string(),
        "/help\n".to_string(),
    ] {
        let mut app = App::new();
        app.selected = Some(g(1));
        app.handle_paste(&paste);
        let acts = app.handle_key(key(KeyCode::Enter), &vm);
        assert!(acts.is_empty(), "{paste:?}: {acts:?}");
        assert_eq!(app.status.as_deref(), Some(ONE_LINE), "{paste:?}");
        assert_eq!(app.input, paste, "the text stays in the box");
    }
}

/// A command runs only from the start of the box, where it shows.
#[test]
fn a_command_after_spaces_never_runs() {
    let vm = crew();
    for text in [
        "   /send x".to_string(),
        format!("{}/kick Bo", " ".repeat(300)),
    ] {
        let mut app = App::new();
        app.selected = Some(g(1));
        app.handle_paste(&text);
        let acts = app.handle_key(key(KeyCode::Enter), &vm);
        assert!(acts.is_empty(), "{text:?}: {acts:?}");
        assert_eq!(app.status.as_deref(), Some(NO_SPACES));
        assert_eq!(app.input, text);
    }
    let mut app = App::new();
    app.selected = Some(g(1));
    for c in "/help".chars() {
        app.handle_key(key(KeyCode::Char(c)), &vm);
    }
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Command(Command::Help)],
        "a typed one-line command still runs"
    );
}

/// While the box holds a command, it shows the command's start, so a long
/// line cannot push the command out of sight.
#[test]
fn the_box_shows_the_start_of_a_command() {
    let mut app = App::new();
    app.selected = Some(g(1));
    app.handle_paste(&format!("/send x{}hello", " ".repeat(200)));
    let s = render(&app, &crew(), 80, 24);
    assert!(s.contains("› /send x"), "{s}");
    let mut app = App::new();
    app.selected = Some(g(1));
    app.handle_paste(&format!("{}the end", "word ".repeat(40)));
    let s = render(&app, &crew(), 80, 24);
    assert!(s.contains("the end"), "plain text shows its end: {s}");
}

/// The box holds at most one message's worth of text; a longer paste is
/// cut on a character boundary and the status line says so.
#[test]
fn a_paste_past_the_message_limit_is_cut_and_says_so() {
    use socketchat_core::sanitize::MAX_TEXT_BYTES;
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    app.handle_key(key(KeyCode::Char('a')), &vm);
    app.handle_paste(&"é".repeat(MAX_TEXT_BYTES));
    assert!(app.input.len() <= MAX_TEXT_BYTES, "{}", app.input.len());
    assert!(app.input.len() > MAX_TEXT_BYTES - 2);
    assert!(app.input[1..].chars().all(|c| c == 'é'));
    assert_eq!(
        app.status.as_deref(),
        Some("The paste was cut to 16 KB, the most one message holds.")
    );
    for _ in 0..3 {
        app.handle_key(key(KeyCode::Char('z')), &vm);
    }
    assert_eq!(app.input.len(), MAX_TEXT_BYTES, "typing fills the box");
    let before = app.input.clone();
    app.handle_key(key(KeyCode::Char('z')), &vm);
    assert_eq!(app.input, before, "typing stops at the limit too");
    let mut app = App::new();
    app.handle_paste("short");
    assert_eq!(app.status, None);
}

/// The box shows what will be sent: direction controls go, as they do
/// from a sent message.
#[test]
fn a_paste_drops_direction_controls() {
    let mut app = App::new();
    app.handle_paste("a\u{202e}b\u{2066}c\u{2069}\u{200f}d");
    assert_eq!(app.input, "abcd");
}

const EXTRA_SPACES: &str = "Remove the extra spaces to run the command.";

/// A command runs only when every space in it shows: runs of spaces and
/// other blank characters could push an argument out of sight.
#[test]
fn a_command_with_hidden_spacing_never_runs() {
    let vm = crew();
    for text in [
        format!("/send{}~/.ssh/id_ed25519", " ".repeat(300)),
        "/send\u{2028}~/.ssh/id_ed25519".to_string(),
        "/send\u{2029}x".to_string(),
        "/send \u{a0}x".to_string(),
        "/kick  Bo".to_string(),
        "/send\u{3000}x".to_string(),
    ] {
        let mut app = App::new();
        app.selected = Some(g(1));
        app.handle_paste(&text);
        let acts = app.handle_key(key(KeyCode::Enter), &vm);
        assert!(acts.is_empty(), "{text:?}: {acts:?}");
        assert_eq!(app.status.as_deref(), Some(EXTRA_SPACES), "{text:?}");
        assert_eq!(app.input, text);
    }
    let mut app = App::new();
    app.selected = Some(g(1));
    app.handle_paste("/send a b  ");
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Command(Command::Send("a b".into()))],
        "single spaces, and spaces at the end, are fine"
    );
}

/// A command too long for the box shows its start and its end.
#[test]
fn a_long_command_shows_its_start_and_its_end() {
    let mut app = App::new();
    app.selected = Some(g(1));
    app.handle_paste(&format!("/send /tmp/{}/end.txt", "a".repeat(200)));
    let s = render(&app, &crew(), 80, 24);
    let row = s.lines().find(|l| l.contains('›')).unwrap();
    assert!(row.contains("› /send /tmp/aaa"), "{row}");
    assert!(row.contains("/end.txt"), "{row}");
}

/// Typing into a full box says why nothing appears.
#[test]
fn typing_into_a_full_box_says_so() {
    use socketchat_core::sanitize::MAX_TEXT_BYTES;
    let vm = crew();
    let mut app = App::new();
    app.handle_paste(&"x".repeat(MAX_TEXT_BYTES));
    assert_eq!(app.status, None);
    app.handle_key(key(KeyCode::Char('z')), &vm);
    assert_eq!(app.input.len(), MAX_TEXT_BYTES);
    assert_eq!(
        app.status.as_deref(),
        Some("The message box is full at 16 KB, the most one message holds.")
    );
}

/// The message box row at 80 columns, wide characters read back without
/// the blank cell each one leaves after itself.
fn box_row(app: &App) -> String {
    let mut t = Terminal::new(TestBackend::new(80, 24)).unwrap();
    t.draw(|f| draw(f, app, &crew())).unwrap();
    let buf = t.backend().buffer().clone();
    let y = (0..24)
        .find(|&y| buf[(1u16, y)].symbol() == "›")
        .expect("a message box row");
    let mut row = String::new();
    let mut x = 0;
    while x < 80 {
        let sym = buf[(x, y)].symbol();
        row.push_str(sym);
        x += if matches!(sym, "文" | "😀") { 2 } else { 1 };
    }
    row
}

/// Wide characters, as in Chinese or emoji, take two columns: a command
/// full of them still shows its end in the box.
#[test]
fn a_command_with_wide_characters_shows_its_end() {
    let mut app = App::new();
    app.selected = Some(g(1));
    app.handle_paste(&format!("/send 😀😀/tmp/{}/end.txt", "文".repeat(60)));
    let row = box_row(&app);
    assert!(row.contains("› /send 😀😀/tmp/文"), "{row}");
    assert!(row.contains("/end.txt"), "{row}");
    assert!(row.contains('…'), "{row}");
}

/// A command that fits by its count of characters but not by its width
/// shows its start and its end.
#[test]
fn a_command_wider_than_the_box_shows_its_start_and_end() {
    let mut app = App::new();
    app.selected = Some(g(1));
    let text = format!("/send {} END", "文".repeat(50));
    assert!(text.chars().count() < 75);
    app.handle_paste(&text);
    let row = box_row(&app);
    assert!(row.contains("› /send 文"), "{row}");
    assert!(row.contains(" END"), "{row}");
    assert!(row.contains('…'), "{row}");
}

/// The cursor sits after wide characters, two columns for each.
#[test]
fn the_cursor_counts_wide_characters_as_two_columns() {
    let mut app = App::new();
    app.selected = Some(g(1));
    app.handle_paste("文文a");
    let mut t = Terminal::new(TestBackend::new(80, 24)).unwrap();
    t.draw(|f| draw(f, &app, &crew())).unwrap();
    let pos = t.get_cursor_position().unwrap();
    // Inside the frame at column 1, after "› " (2 columns) and 5 more.
    assert_eq!(pos.x, 1 + 2 + 5);
}

/// Narrow windows with mixed widths draw without a panic.
#[test]
fn narrow_boxes_with_wide_characters_draw() {
    for w in 8..=11u16 {
        for text in ["/文a😀b文", "文😀", "/s 文", "a😀"] {
            let mut app = App::new();
            app.selected = Some(g(1));
            app.handle_paste(text);
            render(&app, &crew(), w, 24);
        }
    }
}

// ---------- Tab completes slash commands ----------

fn tab(app: &mut App, vm: &ViewModel) {
    app.handle_key(key(KeyCode::Tab), vm);
}

fn back_tab(app: &mut App, vm: &ViewModel) {
    app.handle_key(key(KeyCode::BackTab), vm);
}

fn help_row(app: &App, vm: &ViewModel) -> String {
    render(app, vm, 80, 24).lines().nth(23).unwrap().to_string()
}

#[test]
fn tab_completes_a_unique_command_with_a_space() {
    let (mut app, vm) = (App::new(), crew());
    type_text(&mut app, &vm, "/sw");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/switch ");
    assert_eq!(app.focus, Focus::Input);
}

#[test]
fn tab_fills_the_common_prefix_then_cycles_in_alphabetical_order() {
    let (mut app, vm) = (App::new(), crew());
    type_text(&mut app, &vm, "/in");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/invite", "common prefix first");
    assert!(help_row(&app, &vm).contains("/invite  /invites"));
    let mut seen = vec![];
    for _ in 0..3 {
        tab(&mut app, &vm);
        seen.push(app.input.clone());
    }
    assert_eq!(seen, ["/invite", "/invites", "/invite"]);
}

#[test]
fn shift_tab_cycles_backward() {
    let (mut app, vm) = (App::new(), crew());
    type_text(&mut app, &vm, "/c");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/c", "no prefix to add");
    let mut seen = vec![];
    for _ in 0..3 {
        back_tab(&mut app, &vm);
        seen.push(app.input.clone());
    }
    assert_eq!(seen, ["/close", "/clear", "/cancel"]);
    assert_eq!(app.focus, Focus::Input);
}

#[test]
fn tab_with_no_common_prefix_lists_matches_in_the_dim_help_line() {
    let (mut app, vm) = (App::new(), crew());
    type_text(&mut app, &vm, "/c");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/c");
    assert!(help_row(&app, &vm).contains("/cancel  /clear  /close"));
    let mut seen = vec![];
    for _ in 0..4 {
        tab(&mut app, &vm);
        seen.push(app.input.clone());
    }
    assert_eq!(seen, ["/cancel", "/clear", "/close", "/cancel"]);
}

#[test]
fn any_other_key_ends_cycling() {
    let (mut app, vm) = (App::new(), crew());
    type_text(&mut app, &vm, "/c");
    for _ in 0..3 {
        tab(&mut app, &vm);
    }
    assert_eq!(app.input, "/clear");
    app.handle_key(key(KeyCode::Backspace), &vm);
    tab(&mut app, &vm);
    assert_eq!(app.input, "/clear ", "a fresh Tab, not the next match");
}

#[test]
fn tab_with_no_matching_command_says_so_and_keeps_the_text() {
    let (mut app, vm) = (App::new(), crew());
    type_text(&mut app, &vm, "/xyz");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/xyz");
    assert_eq!(app.status.as_deref(), Some("No command starts with /xyz"));
    assert!(help_row(&app, &vm).contains("No command starts with /xyz"));
    app.handle_key(key(KeyCode::Char('a')), &vm);
    assert!(app.status.is_none());
}

#[test]
fn tab_after_a_lone_slash_lists_commands_and_then_cycles() {
    let (mut app, vm) = (App::new(), crew());
    type_text(&mut app, &vm, "/");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/");
    let row = help_row(&app, &vm);
    assert!(row.contains("/about  /admin  /cancel"), "{row}");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/about");
}

#[test]
fn tab_cycles_theme_names() {
    let (mut app, vm) = (App::new(), crew());
    type_text(&mut app, &vm, "/theme ");
    let mut seen = vec![];
    for _ in 0..3 {
        tab(&mut app, &vm);
        seen.push(app.input.clone());
    }
    assert_eq!(
        seen,
        ["/theme phosphor", "/theme classic", "/theme phosphor"]
    );
    app.input = "/theme cl".into();
    tab(&mut app, &vm);
    assert_eq!(app.input, "/theme classic");
}

#[test]
fn tab_outside_a_command_word_still_moves_focus() {
    let (mut app, vm) = (App::new(), crew());
    tab(&mut app, &vm);
    assert_eq!(app.focus, Focus::Groups);
    let mut app = App::new();
    type_text(&mut app, &vm, "hello");
    tab(&mut app, &vm);
    assert_eq!(app.focus, Focus::Groups);
    assert_eq!(app.input, "hello");
    let mut app = App::new();
    type_text(&mut app, &vm, "/kick Bo");
    tab(&mut app, &vm);
    assert_eq!(app.focus, Focus::Groups);
    assert_eq!(app.input, "/kick Bo");
}

#[test]
fn input_help_line_mentions_tab_completing_only_while_typing_a_command() {
    let (mut app, vm) = (App::new(), crew());
    type_text(&mut app, &vm, "/kick Bo");
    assert!(help_row(&app, &vm).contains("Tab completes"));
    let mut app = App::new();
    assert!(!help_row(&app, &vm).contains("Tab completes"));
    type_text(&mut app, &vm, "/kick Bo");
    let narrow = render(&app, &vm, 30, 24);
    assert!(!narrow.lines().nth(23).unwrap().contains("Tab completes"));
}

// ---------- inline ghost suggestion ----------

fn find_text(buf: &ratatui::buffer::Buffer, w: u16, h: u16, needle: &str) -> Option<(u16, u16)> {
    for y in 0..h {
        let row: Vec<String> = (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect();
        let joined: String = row.concat();
        if let Some(i) = joined.find(needle) {
            return Some((joined[..i].chars().count() as u16, y));
        }
    }
    None
}

#[test]
fn the_rest_of_the_first_match_shows_dim_after_the_cursor() {
    let (mut app, vm) = (App::new(), crew());
    type_text(&mut app, &vm, "/sw");
    let mut t = Terminal::new(TestBackend::new(80, 24)).unwrap();
    t.draw(|f| draw(f, &app, &vm)).unwrap();
    let buf = t.backend().buffer().clone();
    let (x, y) = find_text(&buf, 80, 24, "/switch").expect("ghost drawn");
    assert_eq!(buf[(x + 2, y)].symbol(), "w");
    assert_ne!(buf[(x + 2, y)].fg, app.theme.dim.fg.unwrap());
    for (i, ch) in "itch".chars().enumerate() {
        let cell = &buf[(x + 3 + i as u16, y)];
        assert_eq!(cell.symbol(), ch.to_string());
        assert_eq!(Some(cell.fg), app.theme.dim.fg, "ghost is dim");
    }
    assert_eq!(app.input, "/sw", "display only");
}

#[test]
fn no_ghost_without_a_match_or_a_slash() {
    let vm = crew();
    for text in ["/xyz", "hello", "/kick B"] {
        let mut app = App::new();
        type_text(&mut app, &vm, text);
        assert_eq!(app.ghost(&vm), None, "{text}");
    }
    assert_eq!(App::new().ghost(&vm), None);
}

#[test]
fn ghost_is_what_tab_would_give() {
    let vm = crew();
    let mut app = App::new();
    type_text(&mut app, &vm, "/in");
    assert_eq!(app.ghost(&vm).as_deref(), Some("vite"));
    tab(&mut app, &vm);
    assert_eq!(
        app.ghost(&vm),
        None,
        "/invite is already shown; next is itself"
    );
    let mut app = App::new();
    type_text(&mut app, &vm, "/theme ");
    assert_eq!(app.ghost(&vm).as_deref(), Some("phosphor"));
    let mut app = App::new();
    type_text(&mut app, &vm, "/switch cl");
    assert_eq!(app.ghost(&vm).as_deref(), Some("imbing Saturdays"));
    let mut app = App::new();
    type_text(&mut app, &vm, "/switch ");
    assert_eq!(app.ghost(&vm).as_deref(), Some("Book club"));
}

#[test]
fn right_arrow_accepts_the_ghost() {
    let (mut app, vm) = (App::new(), crew());
    type_text(&mut app, &vm, "/sw");
    app.handle_key(key(KeyCode::Right), &vm);
    assert_eq!(app.input, "/switch ");
    app.handle_key(key(KeyCode::Right), &vm);
    assert_eq!(app.input, "/switch Book club");
    let mut app = App::new();
    type_text(&mut app, &vm, "/theme c");
    app.handle_key(key(KeyCode::Right), &vm);
    assert_eq!(app.input, "/theme classic");
}

#[test]
fn a_sent_message_never_holds_ghost_text() {
    let (mut app, vm) = (App::new(), crew());
    app.selected = Some(g(1));
    type_text(&mut app, &vm, "/sw");
    assert!(app.ghost(&vm).is_some());
    app.input = "hello /sw".into();
    assert_eq!(app.ghost(&vm), None);
    let acts = app.handle_key(key(KeyCode::Enter), &vm);
    assert_eq!(acts, vec![Action::Send(g(1), "hello /sw".into())]);
}

// ---------- Up and Down bring back earlier lines ----------

fn up(app: &mut App, vm: &ViewModel) {
    app.handle_key(key(KeyCode::Up), vm);
}

fn down(app: &mut App, vm: &ViewModel) {
    app.handle_key(key(KeyCode::Down), vm);
}

/// Types `text` in the message box and presses Enter.
fn enter_line(app: &mut App, vm: &ViewModel, text: &str) -> Vec<Action> {
    type_text(app, vm, text);
    app.handle_key(key(KeyCode::Enter), vm)
}

#[test]
fn up_brings_back_the_last_line_and_stops_at_the_oldest() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    assert_eq!(
        enter_line(&mut app, &vm, "hello"),
        vec![Action::Send(g(1), "hello".into())]
    );
    assert_eq!(
        enter_line(&mut app, &vm, "/theme classic"),
        vec![Action::Command(Command::Theme(Some("classic".into())))]
    );
    up(&mut app, &vm);
    assert_eq!(app.input, "/theme classic", "commands count too");
    assert_eq!(app.focus, Focus::Input);
    up(&mut app, &vm);
    assert_eq!(app.input, "hello");
    up(&mut app, &vm);
    assert_eq!(app.input, "hello", "the oldest line stays");
}

#[test]
fn down_walks_forward_and_gives_back_the_draft() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    enter_line(&mut app, &vm, "one");
    enter_line(&mut app, &vm, "two");
    down(&mut app, &vm);
    assert_eq!(app.input, "", "nothing to go forward to");
    type_text(&mut app, &vm, "half typed");
    up(&mut app, &vm);
    up(&mut app, &vm);
    assert_eq!(app.input, "one");
    down(&mut app, &vm);
    assert_eq!(app.input, "two");
    down(&mut app, &vm);
    assert_eq!(app.input, "half typed", "the draft comes back");
    down(&mut app, &vm);
    assert_eq!(app.input, "half typed");
}

#[test]
fn each_room_keeps_its_own_lines() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    enter_line(&mut app, &vm, "for the book club");
    app.selected = Some(g(2));
    up(&mut app, &vm);
    assert_eq!(app.input, "", "Bo's chat has no lines yet");
    enter_line(&mut app, &vm, "for Bo");
    up(&mut app, &vm);
    up(&mut app, &vm);
    assert_eq!(app.input, "for Bo");
    app.handle_key(key(KeyCode::Esc), &vm);
    app.selected = Some(g(1));
    up(&mut app, &vm);
    up(&mut app, &vm);
    assert_eq!(app.input, "for the book club");
}

#[test]
fn repeats_are_kept_once_empty_lines_never_and_at_most_100() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    enter_line(&mut app, &vm, "first");
    enter_line(&mut app, &vm, "again");
    enter_line(&mut app, &vm, "again");
    enter_line(&mut app, &vm, "   ");
    app.handle_key(key(KeyCode::Esc), &vm);
    up(&mut app, &vm);
    assert_eq!(app.input, "again");
    up(&mut app, &vm);
    assert_eq!(app.input, "first", "the repeat was kept once");
    app.handle_key(key(KeyCode::Esc), &vm);
    for n in 0..105 {
        enter_line(&mut app, &vm, &format!("line {n}"));
    }
    for _ in 0..120 {
        up(&mut app, &vm);
    }
    assert_eq!(app.input, "line 5", "the newest 100 lines stay");
}

#[test]
fn lines_that_stay_in_the_box_are_not_kept() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    enter_line(&mut app, &vm, "/nosuchcommand");
    assert_eq!(app.input, "/nosuchcommand", "an unknown command stays");
    app.handle_key(key(KeyCode::Esc), &vm);
    up(&mut app, &vm);
    assert_eq!(app.input, "");
    let vm = ended_crew(Ended::Closed);
    enter_line(&mut app, &vm, "nobody gets this");
    app.handle_key(key(KeyCode::Esc), &vm);
    up(&mut app, &vm);
    assert_eq!(app.input, "");
}

#[test]
fn editing_a_recalled_line_makes_it_the_draft() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    enter_line(&mut app, &vm, "one");
    enter_line(&mut app, &vm, "two");
    up(&mut app, &vm);
    type_text(&mut app, &vm, "!");
    assert_eq!(app.input, "two!");
    up(&mut app, &vm);
    assert_eq!(app.input, "two");
    down(&mut app, &vm);
    assert_eq!(app.input, "two!");
}

/// The message box shows one row with the cursor after the text, so a
/// draft of several lines has no line above the cursor to move to: Up
/// brings back an earlier line and Down gives the whole draft back.
#[test]
fn a_draft_of_several_lines_comes_back_whole() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    enter_line(&mut app, &vm, "sent");
    app.handle_paste("one\ntwo");
    up(&mut app, &vm);
    assert_eq!(app.input, "sent");
    down(&mut app, &vm);
    assert_eq!(app.input, "one\ntwo");
}

#[test]
fn tab_and_the_ghost_work_on_a_recalled_command() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    enter_line(&mut app, &vm, "/theme cl");
    up(&mut app, &vm);
    assert_eq!(app.input, "/theme cl");
    assert_eq!(app.ghost(&vm).as_deref(), Some("assic"));
    tab(&mut app, &vm);
    assert_eq!(app.input, "/theme classic");
}

#[test]
fn up_and_down_keep_their_jobs_outside_the_message_box() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    enter_line(&mut app, &vm, "hello");
    app.focus = Focus::Messages;
    up(&mut app, &vm);
    assert_eq!(app.scroll, 1);
    assert_eq!(app.input, "");
    app.focus = Focus::Groups;
    assert_eq!(
        app.handle_key(key(KeyCode::Down), &vm),
        vec![Action::Select(g(2))]
    );
    assert_eq!(app.input, "");
}

#[test]
fn help_line_while_an_earlier_line_shows() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    enter_line(&mut app, &vm, "hello");
    up(&mut app, &vm);
    insta::assert_snapshot!("help_line_recalling", help_row(&app, &vm));
    type_text(&mut app, &vm, "!");
    assert!(help_row(&app, &vm).starts_with("Enter send"));
}

#[test]
fn help_box_mentions_up_and_down() {
    let mut app = App::new();
    app.selected = Some(g(1));
    app.modal = Some(Modal::Help { offset: 0, pick: 0 });
    let s = render(&app, &crew(), 80, 60);
    assert!(
        modal_text(&s)
            .iter()
            .any(|r| r.starts_with("Up/Down") && r.contains("your earlier lines in this room")),
        "{s}"
    );
}

#[test]
fn about_says_whether_the_update_check_is_on() {
    let mut app = App::new();
    app.selected = Some(g(1));
    app.updates = "Update check: on. Last checked 2026-10-24 at 14:02.".into();
    app.modal = Some(Modal::About);
    let lines = about_lines(&app.updates);
    assert_eq!(lines.last(), Some(&app.updates));
    let s = render(&app, &crew(), 80, 24);
    assert!(
        s.contains("Update check: on. Last checked 2026-10-24 at 14:02."),
        "{s}"
    );
}

#[test]
fn the_update_notice_takes_the_help_line() {
    let notice = "Socketchat 0.5.2 is out. Run socketchat update.";
    let mut app = App::new();
    app.selected = Some(g(1));
    app.update_notice = Some(notice.into());
    let s = render(&app, &crew(), 100, 24);
    let last = s.lines().nth(23).unwrap();
    assert!(last.starts_with(notice), "{last}");
    assert!(
        last.ends_with(&format!("socketchat {}", env!("CARGO_PKG_VERSION"))),
        "{last}"
    );
    // A narrow window keeps the notice whole and drops the version.
    let s = render(&app, &crew(), 60, 24);
    assert_eq!(s.lines().nth(23).unwrap(), notice);
    // A status message still comes first, until the next key.
    app.status = Some("Theme: classic.".into());
    let s = render(&app, &crew(), 100, 24);
    assert!(s.lines().nth(23).unwrap().starts_with("Theme: classic."));
    // An open box keeps its own help.
    app.status = None;
    app.modal = Some(Modal::About);
    let s = render(&app, &crew(), 100, 24);
    assert!(s.lines().nth(23).unwrap().starts_with("Esc close"), "{s}");
    // Typing a command keeps the command help.
    app.modal = None;
    app.input = "/the".into();
    let s = render(&app, &crew(), 100, 24);
    assert!(
        s.lines()
            .nth(23)
            .unwrap()
            .starts_with("Enter run · Tab completes"),
        "{s}"
    );
}

// ---------- room topic ----------

#[test]
fn topic_commands_parse() {
    assert_eq!(parse_command("/topic"), Ok(Command::Topic(None)));
    assert_eq!(
        parse_command("/topic  Piranesi, chapters 1 to 5 "),
        Ok(Command::Topic(Some("Piranesi, chapters 1 to 5".into())))
    );
    assert_eq!(parse_command("/topic --clear"), Ok(Command::ClearTopic));
    assert!(HELP.iter().any(|(c, _)| *c == "/topic [text]"));
    assert!(HELP.iter().any(|(c, _)| *c == "/settings topic"));
}

/// The crew's room with a topic and its server named.
fn topic_crew(topic: &str) -> ViewModel {
    let mut vm = crew();
    vm.server = Some("chat.socketchat.org".into());
    vm.topic = Some(topic.into());
    vm.lines.push(LineView {
        time: "09:17:30".into(),
        sender: "Ada".into(),
        text: format!("Topic: {topic} (set by you, 2026-10-25)"),
        notice: true,
        mine: true,
        topic: true,
        command: None,
    });
    vm
}

const LONG_TOPIC: &str =
    "Piranesi, chapters 1 to 5. Bring snacks. The list: https://example.com/book-club/list";

#[test]
fn the_topic_sits_under_the_room_header() {
    let mut app = App::new();
    app.selected = Some(g(1));
    let s = render(&app, &topic_crew(LONG_TOPIC), 80, 24);
    let row = s.lines().nth(1).unwrap();
    assert!(row.contains("│Topic: Piranesi, chapters 1 to 5."), "{s}");
    assert!(row.contains('…'), "cut to the window: {s}");
    insta::assert_snapshot!("topic_header_80x24", s);
    let narrow = render(&app, &topic_crew(LONG_TOPIC), 60, 24);
    assert!(
        narrow.lines().nth(1).unwrap().contains("│Topic: Pir"),
        "{narrow}"
    );
    insta::assert_snapshot!("topic_header_60x24", narrow);
    // No topic, no line.
    let none = render(&app, &crew(), 80, 24);
    assert!(!none.contains("Topic:"), "{none}");
}

/// A topic written to look like the app's own words is still drawn as a
/// topic: its label, its own color, never a notice's, a warning's or the
/// verified mark's.
#[test]
fn a_topic_posing_as_a_notice_is_drawn_as_a_topic() {
    let fake = "✓ verified: safety numbers match";
    for theme in [
        Theme::phosphor(ColorSupport::TrueColor),
        Theme::classic(ColorSupport::Indexed256),
    ] {
        let mut app = App::new();
        app.theme = theme.clone();
        app.selected = Some(g(1));
        let vm = topic_crew(fake);
        let mut t = Terminal::new(TestBackend::new(80, 24)).unwrap();
        t.draw(|f| draw(f, &app, &vm)).unwrap();
        let buf = t.backend().buffer().clone();
        let rows: Vec<(u16, String)> = (0..24)
            .map(|y| (y, (0..80).map(|x| buf[(x, y)].symbol()).collect::<String>()))
            .filter(|(_, line)| line.contains("Topic: ✓"))
            .collect();
        assert_eq!(rows.len(), 2, "the line under the header and the notice");
        for (y, line) in rows {
            let x = line[..line.find("Topic: ✓").unwrap()].chars().count() as u16;
            for dx in 0..16 {
                let cell = &buf[(x + dx, y)];
                assert_eq!(cell.fg, theme.topic.fg.unwrap(), "row {y} at {dx}");
                assert!(!cell.modifier.contains(Modifier::ITALIC), "row {y}");
                for other in [theme.notice, theme.warn, theme.check, theme.good, theme.dim] {
                    assert_ne!(Some(cell.fg), other.fg, "row {y} at {dx}");
                }
            }
        }
    }
}

/// `/topic` puts the topic on the status line in the topic style; any
/// other status there is drawn as a status.
#[test]
fn the_topic_on_the_status_line_keeps_its_style() {
    let theme = Theme::phosphor(ColorSupport::TrueColor);
    let mut app = App::new();
    app.selected = Some(g(1));
    let said = "Topic: hi (set by Bo, unverified, 2026-10-25)".to_string();
    app.status = Some(said.clone());
    app.topic_status = Some(said);
    let style_at = |app: &App| {
        let mut t = Terminal::new(TestBackend::new(80, 24)).unwrap();
        t.draw(|f| draw(f, app, &crew())).unwrap();
        t.backend().buffer()[(0, 23)].fg
    };
    assert_eq!(style_at(&app), theme.topic.fg.unwrap());
    app.status = Some("Topic: hi (set by Bo, unverified, 2026-10-25)!".into());
    assert_eq!(style_at(&app), theme.warn.fg.unwrap());
}

// ---------- Up and Down after a slash, and commands from the help box ----------

/// The screen as `render` draws it, with "◀" after each row that has
/// cells in the selection style, so a snapshot shows the highlight.
fn render_marked(app: &App, vm: &ViewModel, w: u16, h: u16) -> String {
    let buf = buffer(app, vm, w, h);
    let bg = app.theme.selected.bg;
    render(app, vm, w, h)
        .lines()
        .enumerate()
        .map(|(y, line)| {
            let lit = (0..w).any(|x| Some(buf[(x, y as u16)].bg) == bg);
            if lit {
                format!("{line} ◀\n")
            } else {
                format!("{line}\n")
            }
        })
        .collect()
}

/// The command at the start of the row drawn in the selection style.
fn picked_at(app: &App, vm: &ViewModel, w: u16, h: u16) -> Option<String> {
    let buf = buffer(app, vm, w, h);
    let bg = app.theme.selected.bg;
    (0..h).find_map(|y| {
        let lit: String = (0..w)
            .filter(|x| Some(buf[(*x, y)].bg) == bg)
            .map(|x| buf[(x, y)].symbol())
            .collect();
        let word = lit.split_whitespace().next()?.to_string();
        word.starts_with('/').then_some(word)
    })
}

fn picked(app: &App, vm: &ViewModel) -> String {
    picked_at(app, vm, 80, 24).unwrap_or_default()
}

/// Every command word, once, in alphabetical order.
fn words_abc() -> Vec<&'static str> {
    let mut w: Vec<&str> = HELP
        .iter()
        .map(|(c, _)| c.split(' ').next().unwrap())
        .collect();
    w.sort();
    w.dedup();
    w
}

fn help_box() -> Modal {
    Modal::Help { offset: 0, pick: 0 }
}

#[test]
fn typing_a_slash_shows_no_list_of_commands() {
    let (mut app, vm) = (App::new(), crew());
    for text in ["/", "s"] {
        type_text(&mut app, &vm, text);
        let s = render(&app, &vm, 80, 24);
        assert!(!s.contains(" Commands "), "{s}");
        assert!(!s.contains("send a file, photo or video"), "{s}");
    }
}

#[test]
fn up_and_down_after_a_slash_and_letters_step_through_matching_commands() {
    let (mut app, vm) = (App::new(), crew());
    type_text(&mut app, &vm, "/s");
    let mut seen = vec![];
    for _ in 0..7 {
        down(&mut app, &vm);
        seen.push(app.input.clone());
    }
    assert_eq!(
        seen,
        [
            "/save",
            "/send",
            "/servers",
            "/settings",
            "/status",
            "/switch",
            "/save"
        ]
    );
    up(&mut app, &vm);
    assert_eq!(app.input, "/switch", "Up goes back round");
    let mut app = App::new();
    type_text(&mut app, &vm, "/s");
    up(&mut app, &vm);
    assert_eq!(app.input, "/switch", "Up first takes the last match");
    assert_eq!(app.focus, Focus::Input);
}

#[test]
fn typing_ends_the_step_through_and_starts_from_the_new_letters() {
    let (mut app, vm) = (App::new(), crew());
    type_text(&mut app, &vm, "/s");
    down(&mut app, &vm);
    down(&mut app, &vm);
    assert_eq!(app.input, "/send");
    app.handle_key(key(KeyCode::Backspace), &vm);
    assert_eq!(app.input, "/sen");
    down(&mut app, &vm);
    assert_eq!(app.input, "/send");
    down(&mut app, &vm);
    assert_eq!(app.input, "/send", "one match stays put");
    type_text(&mut app, &vm, "x");
    assert_eq!(app.input, "/sendx");
}

#[test]
fn a_lone_slash_and_up_bring_back_the_last_line() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    enter_line(&mut app, &vm, "hello");
    type_text(&mut app, &vm, "/");
    up(&mut app, &vm);
    assert_eq!(app.input, "hello");
    down(&mut app, &vm);
    assert_eq!(app.input, "/", "the draft comes back");
}

#[test]
fn up_and_down_stay_on_earlier_lines_through_a_recalled_command() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    enter_line(&mut app, &vm, "hello");
    enter_line(&mut app, &vm, "/about");
    up(&mut app, &vm);
    assert_eq!(app.input, "/about");
    up(&mut app, &vm);
    assert_eq!(app.input, "hello");
    down(&mut app, &vm);
    assert_eq!(app.input, "/about");
    down(&mut app, &vm);
    assert_eq!(app.input, "");
}

#[test]
fn tab_and_up_and_down_go_through_one_list() {
    let (mut app, vm) = (App::new(), crew());
    type_text(&mut app, &vm, "/c");
    tab(&mut app, &vm);
    tab(&mut app, &vm);
    assert_eq!(app.input, "/cancel");
    down(&mut app, &vm);
    assert_eq!(app.input, "/clear");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/close");
    up(&mut app, &vm);
    assert_eq!(app.input, "/clear");
}

#[test]
fn enter_on_a_lone_slash_opens_the_help_box() {
    let (mut app, vm) = (App::new(), crew());
    type_text(&mut app, &vm, "/");
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Command(Command::Help)]
    );
    assert_eq!(app.input, "");
    assert!(app.status.is_none(), "{:?}", app.status);
}

#[test]
fn enter_runs_the_only_command_that_starts_with_the_letters() {
    let vm = crew();
    let mut app = App::new();
    type_text(&mut app, &vm, "/q");
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Command(Command::Quit)]
    );
    // One that needs more goes in the box to type the rest.
    let mut app = App::new();
    type_text(&mut app, &vm, "/jo");
    assert!(app.handle_key(key(KeyCode::Enter), &vm).is_empty());
    assert_eq!(app.input, "/join ");
    assert!(app.status.is_none(), "{:?}", app.status);
    // Letters several commands start with run nothing.
    let mut app = App::new();
    type_text(&mut app, &vm, "/c");
    assert!(app.handle_key(key(KeyCode::Enter), &vm).is_empty());
    assert_eq!(app.input, "/c");
    assert!(app.status.is_some());
    // A whole word runs, even when a longer one starts with it.
    let mut app = App::new();
    type_text(&mut app, &vm, "/invite");
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Command(Command::Invite { dm: false })]
    );
}

#[test]
fn the_help_box_lists_commands_alphabetically_with_the_first_picked() {
    let (mut app, vm) = (App::new(), crew());
    app.modal = Some(help_box());
    let s = render(&app, &vm, 80, 60);
    let cmds: Vec<String> = modal_text(&s)
        .iter()
        .take_while(|r| !r.starts_with("/ then"))
        .filter_map(|r| r.split_whitespace().next().map(String::from))
        .filter(|w| w.starts_with('/'))
        .collect();
    let mut sorted = cmds.clone();
    sorted.sort();
    assert_eq!(cmds, sorted, "{s}");
    assert!(cmds.len() > 30, "{s}");
    assert_eq!(picked_at(&app, &vm, 80, 60).as_deref(), Some("/about"));
    // Rows that are not commands come after them.
    let rows = modal_text(&s);
    let last_cmd = rows.iter().rposition(|r| r.starts_with("/verify")).unwrap();
    let keys = rows.iter().position(|r| r.starts_with("Up/Down")).unwrap();
    assert!(keys > last_cmd, "{s}");
}

#[test]
fn up_and_down_move_the_help_highlight_and_keep_it_on_screen() {
    let vm = crew();
    let words = words_abc();
    for (w, h) in [(80, 24), (50, 16), (40, 12)] {
        let mut app = App::new();
        app.modal = Some(help_box());
        let mut seen = vec![picked_at(&app, &vm, w, h).unwrap_or_default()];
        // Each row of /invite and /settings is picked in turn.
        for _ in 0..HELP.len() {
            app.handle_key(key(KeyCode::Down), &vm);
            let p = picked_at(&app, &vm, w, h);
            assert!(
                p.is_some(),
                "{w}x{h}: highlight off screen\n{}",
                render(&app, &vm, w, h)
            );
            seen.push(p.unwrap());
        }
        let mut words_seen = seen.clone();
        words_seen.dedup();
        assert_eq!(words_seen.first().map(String::as_str), Some("/about"));
        assert_eq!(
            seen.last().map(String::as_str),
            Some("/about"),
            "{w}x{h}: wraps round"
        );
        let mut uniq = words_seen.clone();
        uniq.pop();
        assert_eq!(uniq, words, "{w}x{h}");
        app.handle_key(key(KeyCode::Up), &vm);
        assert_eq!(picked_at(&app, &vm, w, h).as_deref(), Some("/verify"));
    }
    let mut app = App::new();
    app.modal = Some(help_box());
    for _ in 0..14 {
        app.handle_key(key(KeyCode::Down), &vm);
    }
    insta::assert_snapshot!("help_pick_80x24", render_marked(&app, &vm, 80, 24));
    insta::assert_snapshot!("help_pick_50x16", render_marked(&app, &vm, 50, 16));
}

#[test]
fn enter_in_the_help_box_runs_or_fills_in_the_command() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    app.modal = Some(help_box());
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Command(Command::About)]
    );
    assert!(app.modal.is_none());
    // One that needs more goes in the message box to type the rest.
    app.modal = Some(help_box());
    app.handle_key(key(KeyCode::Down), &vm);
    assert_eq!(picked(&app, &vm), "/admin");
    assert!(app.handle_key(key(KeyCode::Enter), &vm).is_empty());
    assert!(app.modal.is_none());
    assert_eq!(app.input, "/admin ");
    assert_eq!(app.focus, Focus::Input);
    // A row with a word after the command keeps the word.
    let pick = |want: &str, app: &mut App| {
        app.input.clear();
        app.modal = Some(help_box());
        for _ in 0..HELP.len() {
            if highlighted_row(app, &vm).starts_with(want) {
                return;
            }
            app.handle_key(key(KeyCode::Down), &vm);
        }
        panic!("{want} is never picked");
    };
    pick("/invite --dm", &mut app);
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Command(Command::Invite { dm: true })]
    );
    pick("/settings slow", &mut app);
    assert!(app.handle_key(key(KeyCode::Enter), &vm).is_empty());
    assert_eq!(app.input, "/settings slow ");
    // /switch opens the room switcher, as typing it does.
    pick("/switch", &mut app);
    assert!(app.handle_key(key(KeyCode::Enter), &vm).is_empty());
    assert_eq!(app.switcher.as_deref(), Some(""));
}

/// The whole highlighted row's text at 80 by 24, trimmed.
fn highlighted_row(app: &App, vm: &ViewModel) -> String {
    let buf = buffer(app, vm, 80, 24);
    let bg = app.theme.selected.bg;
    (0..24)
        .map(|y| {
            (0..80)
                .filter(|x| Some(buf[(*x, y)].bg) == bg)
                .map(|x| buf[(x, y)].symbol())
                .collect::<String>()
        })
        .find(|l| l.trim_start().starts_with('/'))
        .unwrap_or_default()
        .trim()
        .to_string()
}

#[test]
fn page_down_in_the_help_box_brings_the_highlight_along() {
    let vm = crew();
    let mut app = App::new();
    app.modal = Some(help_box());
    // The screen is drawn before each key, as the chat screen does.
    render(&app, &vm, 80, 24);
    app.handle_key(key(KeyCode::PageDown), &vm);
    let p = picked(&app, &vm);
    assert!(p.as_str() > "/about", "{p}");
    app.handle_key(key(KeyCode::PageUp), &vm);
    let q = picked(&app, &vm);
    assert!(!q.is_empty() && q <= p, "{q} after {p}");
    assert_eq!(app.handle_key(key(KeyCode::Esc), &vm), vec![]);
    assert!(app.modal.is_none());
}

#[test]
fn the_help_box_says_how_to_reach_commands() {
    let mut app = App::new();
    app.modal = Some(help_box());
    let s = render(&app, &crew(), 80, 60);
    let rows = modal_text(&s);
    assert!(
        rows.iter()
            .any(|r| r.starts_with("/ then Enter") && r.contains("this list")),
        "{s}"
    );
    assert!(rows.iter().any(|r| r.starts_with("/s then Up/Down")), "{s}");
}

// ---------- Showing that encryption is on ----------

use socketchat_core::client::JoinCheck;
use socketchat_tui::app::encryption_text;
use socketchat_tui::ui::people_title;

/// A room's one-time line, as the app shows it: a notice, never a person's
/// message.
fn encryption_notice(state: &JoinCheck, is_dm: bool, others_verified: bool) -> LineView {
    LineView {
        time: "09:10:00".into(),
        sender: String::new(),
        text: encryption_text(state, is_dm, others_verified),
        notice: true,
        mine: false,
        topic: false,
        command: None,
    }
}

#[test]
fn the_encryption_line_says_what_the_room_is() {
    assert_eq!(
        encryption_text(&JoinCheck::Checked, false, true),
        "End-to-end encrypted. Only the people in the People list can read this room. The server passes messages along but cannot read them. /details says what it can see."
    );
    assert_eq!(
        encryption_text(&JoinCheck::Checked, true, true),
        "End-to-end encrypted. Only the two of you can read this chat. The server passes messages along but cannot read them. /details says what it can see."
    );
    let waiting = JoinCheck::Waiting {
        inviter: "Ada".into(),
    };
    assert_eq!(
        encryption_text(&waiting, false, false),
        "End-to-end encrypted. Waiting for Ada to confirm your invite, so nobody here is verified yet. The server passes messages along but cannot read them. /details says what it can see."
    );
    // Someone verified in another room shows verified here too, so the
    // line names only the inviter.
    assert_eq!(
        encryption_text(&waiting, false, true),
        "End-to-end encrypted. Waiting for Ada to confirm your invite, so Ada is not verified yet. The server passes messages along but cannot read them. /details says what it can see."
    );
    for dm in [false, true] {
        assert_eq!(
            encryption_text(&JoinCheck::Unchecked, dm, false),
            "End-to-end encrypted. The server passes messages along but cannot read them. /details says what it can see."
        );
    }
}

/// Ada alone in the room she just made.
fn just_made() -> ViewModel {
    let mut vm = crew();
    vm.lines = vec![encryption_notice(&JoinCheck::Checked, false, false)];
    vm.members.truncate(1);
    vm
}

#[test]
fn screen_a_new_room_opens_with_the_encryption_line() {
    let mut app = App::new();
    app.selected = Some(g(1));
    let s = render(&app, &just_made(), 80, 24);
    assert!(s.contains("09:10:00 · End-to-end encrypted."), "{s}");
    assert!(s.contains(" People 1 of 1 ✓ "), "{s}");
    insta::assert_snapshot!("encryption_line_new_room_80x24", s);
    let narrow = render(&app, &just_made(), 60, 24);
    assert!(narrow.contains(" People 1 of 1 ✓ "), "{narrow}");
    insta::assert_snapshot!("encryption_line_new_room_60x24", narrow);
}

/// Bo has just joined Ada's room: the line sits above the first message.
fn just_joined(state: JoinCheck) -> ViewModel {
    let mut vm = crew();
    let others = vm.members.iter().any(|m| !m.me && m.verified);
    vm.lines.insert(0, encryption_notice(&state, false, others));
    vm
}

#[test]
fn screen_a_joined_room_shows_the_line_above_its_messages() {
    let mut app = App::new();
    app.selected = Some(g(1));
    let vm = just_joined(JoinCheck::Checked);
    let s = render(&app, &vm, 80, 24);
    let first = s.lines().nth(1).unwrap();
    assert!(first.contains("09:10:00 · End-to-end"), "{s}");
    assert!(s.contains(" People 2 of 3 ✓ "), "{s}");
    insta::assert_snapshot!("encryption_line_joined_80x24", s);
    insta::assert_snapshot!("encryption_line_joined_60x24", render(&app, &vm, 60, 24));
}

#[test]
fn screen_a_waiting_join_says_who_it_waits_for() {
    let mut app = App::new();
    app.selected = Some(g(1));
    let mut vm = crew();
    for m in vm.members.iter_mut().filter(|m| !m.me) {
        m.verified = false;
    }
    vm.lines.insert(
        0,
        encryption_notice(
            &JoinCheck::Waiting {
                inviter: "Bo".into(),
            },
            false,
            false,
        ),
    );
    let s = render(&app, &vm, 80, 24);
    assert!(s.contains("Waiting for Bo to confirm"), "{s}");
    assert!(s.contains(" People 1 of 3 ✓ "), "{s}");
    insta::assert_snapshot!("encryption_line_waiting_80x24", s);
}

#[test]
fn screen_a_failed_check_keeps_the_red_warning_and_a_shorter_line() {
    let mut app = App::new();
    app.selected = Some(g(1));
    app.warning = Some("You joined, but the invite could not be checked: the invite was signed by someone other than the person in the link. Compare safety numbers with /verify before you trust anyone here.".into());
    let vm = just_joined(JoinCheck::Unchecked);
    let s = render(&app, &vm, 80, 24);
    assert!(!s.contains("Only the people"), "{s}");
    insta::assert_snapshot!("encryption_line_unchecked_80x24", s);
}

#[test]
fn screen_a_direct_chat_line_speaks_to_two_people() {
    let mut app = App::new();
    app.selected = Some(g(2));
    let mut vm = crew();
    vm.members.truncate(2);
    vm.lines = vec![encryption_notice(&JoinCheck::Checked, true, true)];
    let s = render(&app, &vm, 80, 24);
    assert!(s.contains("the two of you can read this"), "{s}");
    insta::assert_snapshot!("encryption_line_dm_80x24", s);
}

fn people(states: &[(bool, bool, bool)]) -> Vec<MemberLine> {
    states
        .iter()
        .enumerate()
        .map(|(i, (me, verified, changed_key))| MemberLine {
            key: k(i as u8 + 1),
            name: format!("P{i}"),
            verified: *verified,
            admin: false,
            me: *me,
            changed_key: *changed_key,
        })
        .collect()
}

/// The title counts the verified marks the list shows, the person's own
/// included, and shortens to fit.
#[test]
fn the_people_title_tracks_verification() {
    let three = people(&[
        (true, true, false),
        (false, true, false),
        (false, false, false),
    ]);
    assert_eq!(people_title(&three, 18), " People 2 of 3 ✓ ");
    assert_eq!(people_title(&three, 14), " People 2/3 ✓ ");
    assert_eq!(people_title(&three, 8), " 2/3 ✓ ");
    assert_eq!(people_title(&three, 6), "");
    assert_eq!(people_title(&[], 18), " People ");
    let mut many = vec![(true, true, false)];
    many.extend(std::iter::repeat_n((false, true, false), 11));
    many.extend(std::iter::repeat_n((false, false, false), 3));
    let many = people(&many);
    assert_eq!(people_title(&many, 18), " People 12/15 ✓ ");
    let check = people(&[
        (true, true, false),
        (false, true, false),
        (false, false, true),
    ]);
    assert_eq!(people_title(&check, 18), " People ! check ");
    assert_eq!(people_title(&check, 10), " ! check ");
    assert_eq!(people_title(&check, 4), " ! ");
}

/// Someone joins under the name of a member verified earlier, with another
/// key: the title asks for a check, their row is marked, and the room
/// says why.
#[test]
fn screen_someone_new_under_a_verified_name() {
    let mut app = App::new();
    app.selected = Some(g(1));
    let mut vm = crew();
    vm.members.push(MemberLine {
        key: k(4),
        name: "Bo".into(),
        verified: false,
        admin: false,
        me: false,
        changed_key: true,
    });
    vm.lines.push(LineView {
        time: "09:17:30".into(),
        sender: String::new(),
        text: socketchat_core::client::changed_key_notice("Bo", "Bo"),
        notice: true,
        mine: false,
        topic: false,
        command: None,
    });
    let s = render(&app, &vm, 80, 24);
    assert!(s.contains(" People ! check "), "{s}");
    assert!(s.contains("│! Bo"), "{s}");
    assert!(s.contains("09:17:30 · Bo joined with a different"), "{s}");
    insta::assert_snapshot!("people_check_80x24", s);
    insta::assert_snapshot!("people_check_50x24", render(&app, &vm, 50, 24));
}

#[test]
fn details_say_how_the_room_is_encrypted() {
    let mut d = details();
    let lines = details_lines(&d, "Book club", true, &utc_date);
    assert!(
        lines.contains(&"Encryption: end-to-end, MLS (RFC 9420)".into()),
        "{lines:?}"
    );
    d.post_quantum = false;
    let lines = details_lines(&d, "Book club", true, &utc_date);
    assert!(
        lines.contains(&"Post-quantum: no. This room uses the standard suite (0x0001).".into()),
        "{lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.starts_with("Post-quantum: yes")),
        "{lines:?}"
    );
}

/// The screen at `w` by `h`, with a row of `^` under each row that holds
/// selected cells in the messages pane, one under each such cell.
fn render_selection(app: &App, vm: &ViewModel, w: u16, h: u16) -> String {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    t.draw(|f| draw(f, app, vm)).unwrap();
    let buf = t.backend().buffer().clone();
    let lit = app.theme.selected.bg.unwrap();
    let mut out = String::new();
    for y in 0..h {
        let row: String = (0..w).map(|x| buf[(x, y)].symbol()).collect();
        out.push_str(row.trim_end());
        out.push('\n');
        let marks: String = (0..w)
            .map(|x| {
                // The messages pane, clear of the chat list's open room.
                let pane = (21..59).contains(&x);
                if pane && buf[(x, y)].bg == lit {
                    '^'
                } else {
                    ' '
                }
            })
            .collect();
        if marks.contains('^') {
            out.push_str(marks.trim_end());
            out.push('\n');
        }
    }
    out
}

/// A drag from "Saturday" in Cy's wrapped message to "snacks" two rows
/// down: the cells between are drawn selected, the indent is not, and
/// letting go copies the words as one line.
#[test]
fn a_selection_across_a_wrapped_message_at_80x24() {
    use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    let screen = render(&app, &vm, 80, 24);
    let at = |needle: &str| {
        let (y, row) = screen
            .lines()
            .enumerate()
            .find(|(_, r)| r.contains(needle))
            .unwrap();
        let x = row[..row.find(needle).unwrap()].chars().count() as u16;
        (x, y as u16)
    };
    let mouse = |kind, (column, row): (u16, u16)| MouseEvent {
        kind,
        column,
        row,
        modifiers: KeyModifiers::NONE,
    };
    let (from, to) = (at("Saturday"), at("snacks"));
    let to = (to.0 + 5, to.1);
    let now = std::time::Instant::now();
    app.drawn(now);
    app.handle_mouse(
        mouse(MouseEventKind::Down(MouseButton::Left), from),
        now,
        &vm,
    );
    app.handle_mouse(mouse(MouseEventKind::Drag(MouseButton::Left), to), now, &vm);
    insta::assert_snapshot!("selection_80x24", render_selection(&app, &vm, 80, 24));
    assert_eq!(
        app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), to), now, &vm),
        vec![Action::CopySelected(
            "Saturday still works for me, and I can bring snacks".into()
        )]
    );
}

#[test]
fn screen_details_scroll_to_the_encryption_section() {
    let mut app = App::new();
    app.selected = Some(g(1));
    let lines = details_lines(&details(), "Book club", true, &utc_date);
    app.modal = Some(Modal::Details { lines, offset: 0 });
    let vm = crew();
    // Too short for every line, so the box scrolls.
    let top = render(&app, &vm, 80, 20);
    assert!(!top.contains("The server sees:"), "{top}");
    for _ in 0..20 {
        app.handle_key(key(KeyCode::Down), &vm);
    }
    let s = render(&app, &vm, 80, 20);
    assert!(s.contains("The server sees:"), "{s}");
    insta::assert_snapshot!("details_encryption_80x20", s);
}

#[test]
fn about_says_what_the_server_still_sees() {
    assert_eq!(
        about_lines("")[2],
        "Socketchat is end-to-end encrypted chat with a server you run yourself. The server passes messages along but cannot read them. It still sees timing, message sizes, IP addresses and how many people are in each room."
    );
}

/// No word in the app's own lines about encryption overpromises.
#[test]
fn encryption_words_avoid_promises_the_app_cannot_keep() {
    let mut texts = vec![about_lines("")[2].clone()];
    for state in [
        JoinCheck::Checked,
        JoinCheck::Unchecked,
        JoinCheck::Waiting {
            inviter: "Ada".into(),
        },
    ] {
        for dm in [false, true] {
            texts.push(encryption_text(&state, dm, false));
        }
    }
    let mut d = details();
    texts.extend(details_lines(&d, "Book club", true, &utc_date));
    d.post_quantum = false;
    texts.extend(details_lines(&d, "Book club", true, &utc_date));
    texts.push(socketchat_core::client::changed_key_notice("Bo", "Bo"));
    for t in texts {
        let lower = t.to_lowercase();
        for word in [
            "secure",
            "private",
            "anonymous",
            "military",
            "quantum-safe",
            "quantum-proof",
        ] {
            assert!(!lower.contains(word), "{word} in {t}");
        }
    }
}

#[test]
fn the_messages_help_line_says_dragging_copies_while_the_mouse_is_on() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    app.focus = Focus::Messages;
    assert!(
        help_row(&app, &vm).starts_with("Drag to copy · PgUp/PgDn or Up/Down scroll · Tab move"),
        "{}",
        help_row(&app, &vm)
    );
    app.mouse = false;
    assert!(
        !help_row(&app, &vm).contains("Drag"),
        "{}",
        help_row(&app, &vm)
    );
}

/// A profile connected to its server with a group chat open.
fn status_view() -> socketchat_core::client::StatusView {
    use socketchat_core::client::{Link, RoomStatus, ServerStatus, StatusView};
    StatusView {
        name: "Ada".into(),
        safety_digits: "12345 67890 23456 78901 34567 89012".into(),
        server: Some(ServerStatus {
            host: "chat.socketchat.org".into(),
            port: 7444,
            cert_fpr: std::array::from_fn(|i| (i * 37 % 256) as u8),
            // 2026-10-19 at 12:00 UTC.
            link: Link::Connected {
                since_unix: 1_792_411_200,
                protocol: 3,
            },
            rooms: 3,
            members_invite: Some(true),
        }),
        other_servers: 1,
        room: Some(RoomStatus {
            is_dm: false,
            members: 3,
            verified: 2,
            admins: 1,
            admin: true,
            invite: WhoCanInvite::Admins,
            slow_secs: 30,
            topic_who: WhoCanSetTopic::Admins,
            topic: true,
            suite: "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519 (0x004F)".into(),
            post_quantum: true,
        }),
    }
}

fn app_status() -> AppStatus {
    AppStatus {
        theme: "phosphor".into(),
        mouse: true,
        updates: "Update check: on, once a day. Last checked 2026-10-19 at 12:00. The newest release then was 0.5.2.".into(),
    }
}

fn utc_date_time(unix: u64) -> String {
    chrono::DateTime::from_timestamp(unix as i64, 0)
        .unwrap()
        .format("%Y-%m-%d at %H:%M")
        .to_string()
}

fn status_text(s: &socketchat_core::client::StatusView, room: Option<&str>) -> Vec<String> {
    status_lines(s, room, &app_status(), &utc_date_time)
}

#[test]
fn status_lines_say_each_fact() {
    assert_eq!(
        status_text(&status_view(), Some("Book club")),
        vec![
            "Connection",
            "Server: chat.socketchat.org",
            "Port: 7444",
            "State: connected since 2026-10-19 at 12:00",
            "Protocol: 3",
            "Certificate fingerprint: 0025 4a6f 94b9 de03 284d 7297 bce1 062b 5075 9abf e409 2e53 789d c2e7 0c31 567b",
            "Inviting into rooms: each room's setting decides",
            "Other servers: 1",
            "",
            "You",
            "Name: Ada",
            "Your half of each safety number: 12345 67890 23456 78901 34567 89012",
            "Rooms on this server: 3",
            "",
            "This room",
            "Name: Book club",
            "Kind: group chat",
            "Members: 3, 2 verified",
            "Admins: 1",
            "Your role: admin",
            "Who can invite: admins only",
            "Slow mode: one message every 30 seconds for each member who isn't an admin",
            "Who can set the topic: admins only",
            "Has a topic: yes",
            "Encryption: end-to-end, MLS (RFC 9420)",
            "Suite: MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519 (0x004F)",
            "Post-quantum: yes for messages and files (ML-KEM-768 + X25519). Signatures and the link to the server are not post-quantum yet.",
            "",
            "App",
            &format!("Version: {}", env!("CARGO_PKG_VERSION")),
            "Update check: on, once a day. Last checked 2026-10-19 at 12:00. The newest release then was 0.5.2.",
            "Theme: phosphor",
            "Mouse: on",
            "",
            "/details lists what the server can and cannot see in each room.",
        ]
    );
}

#[test]
fn status_says_how_the_connection_stands() {
    use socketchat_core::client::Link;
    let state = |link: Link| {
        let mut s = status_view();
        let server = s.server.as_mut().unwrap();
        server.link = link;
        server.members_invite = None;
        status_text(&s, Some("Book club"))
    };
    let lines = state(Link::Unreachable("connection refused".into()));
    assert!(
        lines.contains(&"State: could not reach: connection refused".into()),
        "{lines:?}"
    );
    // Only a live connection has a protocol, and only it asks the rule.
    assert!(
        !lines.iter().any(|l| l.starts_with("Protocol")),
        "{lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.starts_with("Inviting")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("Certificate fingerprint: 0025 ")),
        "the pinned certificate still shows: {lines:?}"
    );
    let lines = state(Link::Lost);
    assert!(
        lines.contains(&"State: connection lost; reconnecting".into()),
        "{lines:?}"
    );
    let lines = state(Link::NotYet);
    assert!(
        lines.contains(&"State: not connected yet".into()),
        "{lines:?}"
    );
}

#[test]
fn status_names_the_server_rules_that_apply() {
    use socketchat_core::client::Link;
    let mut s = status_view();
    s.server.as_mut().unwrap().members_invite = Some(false);
    s.room.as_mut().unwrap().invite = WhoCanInvite::Anyone;
    let lines = status_text(&s, Some("Book club"));
    assert!(
        lines.contains(&"Inviting into rooms: admins only, in every room on this server".into()),
        "{lines:?}"
    );
    // The room's own line says whose rule it is, as /details does.
    assert!(
        lines.contains(
            &"Who can invite: admins only, because this server lets only admins invite people"
                .into()
        ),
        "{lines:?}"
    );
    // A server on protocol 2 cannot enforce the room's settings.
    let mut old = status_view();
    old.server.as_mut().unwrap().link = Link::Connected {
        since_unix: 1_792_411_200,
        protocol: 2,
    };
    old.server.as_mut().unwrap().members_invite = None;
    let lines = status_text(&old, Some("Book club"));
    assert!(lines.contains(&"Protocol: 2".into()), "{lines:?}");
    assert!(
        lines.contains(&"This server runs an older version of Socketchat, so it can't enforce who can invite or slow mode.".into()),
        "{lines:?}"
    );
}

#[test]
fn status_without_a_room_or_a_server_leaves_those_out() {
    let mut s = status_view();
    s.room = None;
    s.other_servers = 0;
    let lines = status_text(&s, None);
    assert!(!lines.contains(&"This room".into()), "{lines:?}");
    assert!(
        !lines.iter().any(|l| l.starts_with("Other servers")),
        "{lines:?}"
    );
    assert!(
        lines.contains(&"Rooms on this server: 3".into()),
        "{lines:?}"
    );
    s.server = None;
    let lines = status_text(&s, None);
    assert_eq!(lines[..3], ["Connection", "Server: none yet", ""]);
    assert!(
        !lines.iter().any(|l| l.starts_with("Rooms on")),
        "{lines:?}"
    );
    assert!(lines.contains(&"Name: Ada".into()), "{lines:?}");
}

#[test]
fn status_marks_a_direct_chat_and_a_member() {
    let mut s = status_view();
    let room = s.room.as_mut().unwrap();
    room.is_dm = true;
    room.members = 2;
    room.verified = 2;
    room.admins = 2;
    room.admin = false;
    room.topic = false;
    room.post_quantum = false;
    room.suite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001)".into();
    let lines = status_text(&s, Some("Bo"));
    for want in [
        "Name: Bo",
        "Kind: direct chat",
        "Members: 2, 2 verified",
        "Admins: 2",
        "Your role: member",
        "Has a topic: no",
        "Suite: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001)",
        "Post-quantum: no. This room uses the standard suite (0x0001).",
    ] {
        assert!(lines.contains(&want.into()), "{want}: {lines:?}");
    }
}

#[test]
fn status_says_what_the_update_check_last_found() {
    use socketchat_core::update::UpdateState;
    let on = UpdateState {
        on: true,
        asked_unix: Some(1_792_411_200),
        answered_unix: Some(1_792_411_200),
        latest: Some("0.5.3".into()),
    };
    assert_eq!(
        update_status(&on, false, &utc_date_time),
        "Update check: on, once a day. Last checked 2026-10-19 at 12:00. The newest release then was 0.5.3."
    );
    let never = UpdateState {
        answered_unix: None,
        latest: None,
        ..on.clone()
    };
    assert_eq!(
        update_status(&never, false, &utc_date_time),
        "Update check: on, once a day. Not checked yet."
    );
    let off = UpdateState {
        on: false,
        ..on.clone()
    };
    assert_eq!(
        update_status(&off, false, &utc_date_time),
        "Update check: off. Type /updates on to turn it on."
    );
    assert!(update_status(&on, true, &utc_date_time).starts_with("Update check: off for this run"));
}

#[test]
fn status_words_avoid_promises_the_app_cannot_keep() {
    let mut s = status_view();
    let mut texts = status_text(&s, Some("Book club"));
    s.room.as_mut().unwrap().post_quantum = false;
    texts.extend(status_text(&s, Some("Book club")));
    for t in texts {
        let lower = t.to_lowercase();
        for word in [
            "secure",
            "private",
            "anonymous",
            "military",
            "quantum-safe",
            "quantum-proof",
        ] {
            assert!(!lower.contains(word), "{word} in {t}");
        }
    }
}

fn status_app(s: &socketchat_core::client::StatusView, room: Option<&str>) -> App {
    let mut app = App::new();
    app.selected = room.map(|_| g(1));
    app.modal = Some(Modal::Status {
        lines: status_text(s, room),
        offset: 0,
    });
    app
}

#[test]
fn screen_status_connected() {
    let mut app = status_app(&status_view(), Some("Book club"));
    let s = render(&app, &crew(), 80, 24);
    assert!(s.contains(" Status "), "{s}");
    assert!(
        s.contains("State: connected since 2026-10-19 at 12:00"),
        "{s}"
    );
    insta::assert_snapshot!("status_connected_80x24", s);
    insta::assert_snapshot!("status_connected_50x24", render(&app, &crew(), 50, 24));
    // The box scrolls to its last line.
    for _ in 0..40 {
        app.handle_key(key(KeyCode::Down), &crew());
    }
    let s = render(&app, &crew(), 80, 24);
    assert!(
        s.contains("/details lists what the server can and cannot see"),
        "{s}"
    );
    insta::assert_snapshot!("status_connected_end_80x24", s);
    app.handle_key(key(KeyCode::Esc), &crew());
    assert!(app.modal.is_none());
}

#[test]
fn screen_status_offline() {
    use socketchat_core::client::Link;
    let mut st = status_view();
    let server = st.server.as_mut().unwrap();
    server.link = Link::Unreachable("connection refused".into());
    server.members_invite = None;
    let app = status_app(&st, Some("Book club"));
    let mut vm = crew();
    vm.connected = false;
    let s = render(&app, &vm, 80, 24);
    assert!(
        s.contains("State: could not reach: connection refused"),
        "{s}"
    );
    insta::assert_snapshot!("status_offline_80x24", s);
    insta::assert_snapshot!("status_offline_50x24", render(&app, &vm, 50, 24));
}

#[test]
fn screen_status_with_no_room_open() {
    let mut st = status_view();
    st.room = None;
    let app = status_app(&st, None);
    let mut vm = crew();
    vm.lines.clear();
    vm.members.clear();
    let s = render(&app, &vm, 80, 24);
    assert!(!s.contains("This room"), "{s}");
    assert!(s.contains("Rooms on this server: 3"), "{s}");
    insta::assert_snapshot!("status_no_room_80x24", s);
    insta::assert_snapshot!("status_no_room_50x24", render(&app, &vm, 50, 24));
}

#[test]
fn screen_status_direct_chat() {
    let mut st = status_view();
    let room = st.room.as_mut().unwrap();
    room.is_dm = true;
    room.members = 2;
    room.verified = 2;
    room.admins = 2;
    let lines = status_text(&st, Some("Bo"));
    let at = lines.iter().position(|l| l == "This room").unwrap();
    let mut app = status_app(&st, Some("Bo"));
    app.selected = Some(g(2));
    // Scrolled so the room's section starts the box at 80 columns, where
    // the certificate fingerprint above it takes two rows.
    app.modal = Some(Modal::Status {
        lines,
        offset: at + 1,
    });
    // Ada and Bo, as the direct chat's People list shows them.
    let mut vm = crew();
    vm.members.truncate(2);
    let s = render(&app, &vm, 80, 24);
    assert!(s.contains("Kind: direct chat"), "{s}");
    insta::assert_snapshot!("status_dm_80x24", s);
    insta::assert_snapshot!("status_dm_50x24", render(&app, &vm, 50, 24));
}

// ---------- /invite <name> and /join <room> ----------

#[test]
fn invite_and_join_parse_every_form() {
    assert_eq!(parse_command("/invite"), Ok(Command::Invite { dm: false }));
    assert_eq!(
        parse_command("/invite --dm"),
        Ok(Command::Invite { dm: true })
    );
    assert_eq!(
        parse_command("/invite Bo"),
        Ok(Command::InviteMember {
            name: "Bo".into(),
            room: None,
            quoted: false
        })
    );
    assert_eq!(
        parse_command("/invite Bo#1a2b"),
        Ok(Command::InviteMember {
            name: "Bo#1a2b".into(),
            room: None,
            quoted: false
        })
    );
    assert_eq!(
        parse_command("/invite Bo Smith"),
        Ok(Command::InviteMember {
            name: "Bo".into(),
            room: Some("Smith".into()),
            quoted: false
        })
    );
    assert_eq!(
        parse_command("/invite \"Bo Smith\" Climbing Saturdays"),
        Ok(Command::InviteMember {
            name: "Bo Smith".into(),
            room: Some("Climbing Saturdays".into()),
            quoted: true
        })
    );
    assert_eq!(parse_command("/join"), Ok(Command::Join(None)));
    assert_eq!(
        parse_command("/join Climbing Saturdays"),
        Ok(Command::Join(Some("Climbing Saturdays".into())))
    );
    assert!(parse_command("/add Bo").is_err(), "no /add command");
}

#[test]
fn help_lists_invite_by_name_and_join_by_room() {
    let rows: Vec<(&str, &str)> = HELP.to_vec();
    let at = rows.iter().position(|(c, _)| *c == "/invite").unwrap();
    assert_eq!(
        &rows[at..at + 5],
        &[
            (
                "/invite",
                "make a one-time link that brings someone into this chat"
            ),
            (
                "/invite <name>",
                "invite someone you share a room with to this room"
            ),
            (
                "/invite --dm",
                "make a link that opens a new two-person chat"
            ),
            (
                "/join <link or room>",
                "use a link, or join a room you were invited to"
            ),
            (
                "/join <number>",
                "pick one of several rooms you were invited to"
            ),
        ]
    );
    assert!(!rows.iter().any(|(c, _)| c.starts_with("/add")));
}

#[test]
fn typing_a_message_that_starts_with_y_answers_nothing() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    app.status = Some(
        "Ada invites you to Climbing Saturdays. Type /join Climbing Saturdays to join.".into(),
    );
    let mut acts = Vec::new();
    for c in "yeah see you there".chars() {
        acts.extend(app.handle_key(key(KeyCode::Char(c)), &vm));
    }
    assert!(acts.is_empty(), "{acts:?}");
    assert!(app.modal.is_none());
    assert_eq!(app.input, "yeah see you there");
}

#[test]
fn invite_statuses_say_what_happens_next() {
    use socketchat_core::client::InviteSent;
    use socketchat_tui::app::invite_sent_status;
    let sent = InviteSent {
        name: "Bo".into(),
        via: "Book club".into(),
        room: "Climbing Saturdays".into(),
        wait_secs: None,
    };
    assert_eq!(
        invite_sent_status(&sent, true),
        "Invited Bo through Book club. This room says when they join."
    );
    assert_eq!(
        invite_sent_status(&sent, false),
        "Invited Bo to Climbing Saturdays through Book club. Climbing Saturdays says when they join."
    );
    let held = InviteSent {
        wait_secs: Some(30),
        ..sent
    };
    assert_eq!(
        invite_sent_status(&held, true),
        "Book club limits fast posting, so Bo gets the invite in 30 seconds. This room says when they join."
    );
}

#[test]
fn invite_box_says_where_a_link_goes_and_how_to_invite_by_name() {
    let app = invite_app(LONG_LINK);
    let s = render(&app, &crew(), 100, 50);
    let flat = s
        .replace('│', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        flat.contains("They can paste it into an open chat with /join."),
        "{s}"
    );
    assert!(
        flat.contains(
            "To invite someone you already share a room with, type /invite and their name."
        ),
        "{s}"
    );
}

/// `/join` and `/invite` alone each do something, but the help rows that
/// name a room, a number or a person go in the message box to type the
/// rest, and so do letters only `/join` starts with.
#[test]
fn help_rows_with_a_name_or_number_wait_for_it() {
    use socketchat_tui::commands::help_entries;
    let vm = crew();
    for (usage, want) in [
        ("/join <link or room>", "/join "),
        ("/join <number>", "/join "),
        ("/invite <name>", "/invite "),
    ] {
        let mut app = App::new();
        app.selected = Some(g(1));
        let pick = help_entries()
            .iter()
            .position(|(u, _)| *u == usage)
            .unwrap();
        app.modal = Some(Modal::Help { offset: 0, pick });
        assert!(
            app.handle_key(key(KeyCode::Enter), &vm).is_empty(),
            "{usage}"
        );
        assert_eq!(app.input, want, "{usage}");
    }
    let mut app = App::new();
    let pick = help_entries()
        .iter()
        .position(|(u, _)| *u == "/invite")
        .unwrap();
    app.selected = Some(g(1));
    app.modal = Some(Modal::Help { offset: 0, pick });
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Command(Command::Invite { dm: false })]
    );
}

// ---------- the invite line's command ----------

const INVITE: &str =
    "Ada invites you to Climbing Saturdays. Type /join Climbing Saturdays to join.";

/// Book club with one invite line, its command marked.
fn invited_crew() -> ViewModel {
    let mut vm = crew();
    let at = INVITE.find("/join").unwrap();
    vm.lines.push(LineView {
        time: "09:17:30".into(),
        sender: String::new(),
        text: INVITE.into(),
        notice: true,
        mine: false,
        topic: false,
        command: Some(at..INVITE.len() - " to join.".len()),
    });
    vm
}

/// A window width at which the invite line breaks inside its command.
const WRAP_W: u16 = 114;

fn drawn(app: &App, vm: &ViewModel, w: u16, h: u16) -> ratatui::buffer::Buffer {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    t.draw(|f| draw(f, app, vm)).unwrap();
    t.backend().buffer().clone()
}

#[test]
fn the_invite_line_makes_its_command_stand_out() {
    for theme in [
        Theme::phosphor(ColorSupport::TrueColor),
        Theme::classic(ColorSupport::TrueColor),
    ] {
        let mut app = App::new();
        app.theme = theme.clone();
        app.selected = Some(g(1));
        let vm = invited_crew();
        let s = render(&app, &vm, 140, 24);
        assert!(s.contains("Type /join Climbing Saturdays to join."), "{s}");
        let buf = drawn(&app, &vm, 140, 24);
        let (x, y) = find_text(&buf, 140, 24, "/join Climbing Saturdays").unwrap();
        for i in 0.."/join Climbing Saturdays".chars().count() as u16 {
            let c = &buf[(x + i, y)];
            assert_eq!(c.fg, theme.command.fg.unwrap(), "{:?}", c.symbol());
            assert!(c.modifier.contains(Modifier::BOLD), "{:?}", c.symbol());
            assert!(!c.modifier.contains(Modifier::ITALIC), "{:?}", c.symbol());
        }
        // The words around it read as a notice.
        let (nx, ny) = find_text(&buf, 140, 24, "Ada invites").unwrap();
        assert_eq!(Some(buf[(nx, ny)].fg), theme.notice.fg);
        assert!(buf[(nx, ny)].modifier.contains(Modifier::ITALIC));
        let after = &buf[(x + 25, y)];
        assert_eq!(after.symbol(), "t");
        assert_eq!(Some(after.fg), theme.notice.fg);
        // The command has a style of its own, unlike a notice's or a name's.
        assert_ne!(theme.command, theme.notice);
    }
}

#[test]
fn the_command_stays_marked_where_the_line_wraps() {
    let mut app = App::new();
    app.selected = Some(g(1));
    let vm = invited_crew();
    // At this width the line breaks inside the command.
    let s = render(&app, &vm, WRAP_W, 24);
    let rows: Vec<&str> = s.lines().collect();
    let i = rows
        .iter()
        .position(|r| r.contains("Type /join Climbing "))
        .unwrap_or_else(|| panic!("{s}"));
    assert!(!rows[i].contains("Climbing Saturdays to"), "{s}");
    assert!(rows[i + 1].contains("Saturdays to join."), "{s}");
    let buf = drawn(&app, &vm, WRAP_W, 24);
    let (x, y) = find_text(&buf, WRAP_W, 24, "/join Climbing").unwrap();
    for k in 0..14 {
        assert!(buf[(x + k, y)].modifier.contains(Modifier::BOLD), "{k}");
    }
    let (x, y) = find_text(&buf, WRAP_W, 24, "Saturdays to join.").unwrap();
    for k in 0..9 {
        assert!(buf[(x + k, y)].modifier.contains(Modifier::BOLD), "{k}");
    }
    assert!(!buf[(x + 10, y)].modifier.contains(Modifier::BOLD));
    assert!(buf[(x + 10, y)].modifier.contains(Modifier::ITALIC));
}

// ---------- Tab after /invite and /join ----------

/// Book club, where Bo and Cy are; Dee and two people called Eve share
/// other rooms with Ada.
fn inviting_crew() -> ViewModel {
    let mut vm = crew();
    vm.invite_names = vec![
        "Dee".into(),
        "Dee Dee".into(),
        "Eve#1a2b".into(),
        "Eve#9f3c".into(),
        "Bo".into(),
        "Cy".into(),
    ];
    vm
}

#[test]
fn tab_after_invite_completes_names_and_goes_round() {
    let vm = inviting_crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    type_text(&mut app, &vm, "/invite ");
    let mut seen = vec![];
    for _ in 0..7 {
        tab(&mut app, &vm);
        seen.push(app.input.clone());
    }
    assert_eq!(
        seen,
        [
            "/invite Dee",
            "/invite \"Dee Dee\"",
            "/invite Eve#1a2b",
            "/invite Eve#9f3c",
            "/invite Bo",
            "/invite Cy",
            "/invite Dee",
        ]
    );
    assert_eq!(app.focus, Focus::Input);
    back_tab(&mut app, &vm);
    assert_eq!(app.input, "/invite Cy", "Shift-Tab goes back");
}

#[test]
fn tab_after_invite_and_letters_takes_the_names_that_start_with_them() {
    let vm = inviting_crew();
    let mut app = App::new();
    type_text(&mut app, &vm, "/invite e");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/invite Eve#1a2b");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/invite Eve#9f3c");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/invite Eve#1a2b");
    // The name Tab gave runs as one name.
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Command(Command::InviteMember {
            name: "Eve#1a2b".into(),
            room: None,
            quoted: false,
        })]
    );
    let mut app = App::new();
    type_text(&mut app, &vm, "/invite dee");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/invite Dee", "the exact name first");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/invite \"Dee Dee\"");
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Command(Command::InviteMember {
            name: "Dee Dee".into(),
            room: None,
            quoted: true,
        })]
    );
}

#[test]
fn tab_after_invite_says_when_no_name_fits() {
    let vm = inviting_crew();
    let mut app = App::new();
    type_text(&mut app, &vm, "/invite Zed");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/invite Zed");
    assert_eq!(app.focus, Focus::Input);
    assert_eq!(
        app.status.as_deref(),
        Some("Nobody called Zed shares a room with you.")
    );
    let mut app = App::new();
    type_text(&mut app, &vm, "/invite ");
    tab(&mut app, &crew());
    assert_eq!(app.input, "/invite ");
    assert_eq!(
        app.status.as_deref(),
        Some("Nobody else shares a room with you yet.")
    );
    // A name and a room, or the direct-chat switch, are not a name to
    // complete: Tab moves on as before.
    for typed in ["/invite Bo Hikes", "/invite --dm"] {
        let mut app = App::new();
        type_text(&mut app, &vm, typed);
        tab(&mut app, &vm);
        assert_eq!(app.input, typed);
        assert_eq!(app.focus, Focus::Groups, "{typed}");
    }
}

#[test]
fn the_ghost_after_invite_is_what_tab_would_give() {
    let vm = inviting_crew();
    let mut app = App::new();
    type_text(&mut app, &vm, "/invite c");
    assert_eq!(app.ghost(&vm).as_deref(), Some("y"));
    app.handle_key(key(KeyCode::Right), &vm);
    assert_eq!(app.input, "/invite Cy");
}

/// Ada has two invites waiting, the newer one first, as Tab offers them.
fn joining_crew() -> ViewModel {
    let mut vm = crew();
    vm.join_rooms = vec!["Hikes".into(), "Climbing Saturdays".into()];
    vm
}

#[test]
fn tab_after_join_completes_rooms_with_invites_newest_first() {
    let vm = joining_crew();
    let mut app = App::new();
    type_text(&mut app, &vm, "/join ");
    let mut seen = vec![];
    for _ in 0..3 {
        tab(&mut app, &vm);
        seen.push(app.input.clone());
    }
    assert_eq!(
        seen,
        ["/join Hikes", "/join Climbing Saturdays", "/join Hikes"]
    );
    back_tab(&mut app, &vm);
    assert_eq!(app.input, "/join Climbing Saturdays");
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Command(Command::Join(Some(
            "Climbing Saturdays".into()
        )))]
    );
    let mut app = App::new();
    type_text(&mut app, &vm, "/join cl");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/join Climbing Saturdays");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/join Climbing Saturdays", "one match stays put");
}

#[test]
fn tab_after_join_says_when_no_invite_waits() {
    let mut app = App::new();
    type_text(&mut app, &crew(), "/join ");
    tab(&mut app, &crew());
    assert_eq!(app.input, "/join ");
    assert_eq!(app.status.as_deref(), Some("No invite waits for you."));
    let vm = joining_crew();
    let mut app = App::new();
    type_text(&mut app, &vm, "/join Chess");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/join Chess");
    assert_eq!(
        app.status.as_deref(),
        Some("No invite to Chess waits for you.")
    );
}

#[test]
fn join_choices_are_newest_first_once_each_and_numbered_when_a_name_is_a_number() {
    let waiting = [
        (1, "Climbing Saturdays".to_string()),
        (2, "Hikes".to_string()),
        (3, "climbing  saturdays".to_string()),
        (4, "7".to_string()),
    ];
    assert_eq!(join_choices(&waiting), ["4", "climbing saturdays", "Hikes"]);
}

// ---------- Up and Down after /switch, /invite and /join ----------

#[test]
fn up_and_down_after_switch_step_through_the_rooms_tab_gives() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    type_text(&mut app, &vm, "/switch ");
    let mut seen = vec![];
    for _ in 0..4 {
        down(&mut app, &vm);
        seen.push(app.input.clone());
    }
    assert_eq!(
        seen,
        [
            "/switch Book club",
            "/switch Bo",
            "/switch Climbing Saturdays",
            "/switch Book club"
        ]
    );
    up(&mut app, &vm);
    assert_eq!(
        app.input, "/switch Climbing Saturdays",
        "Up goes back round"
    );
    assert_eq!(app.focus, Focus::Input);
    // Enter opens the room Up and Down picked.
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Select(g(3))]
    );
    let mut app = App::new();
    type_text(&mut app, &vm, "/switch b");
    up(&mut app, &vm);
    assert_eq!(app.input, "/switch Bo", "Up first takes the last match");
    // Tab and Up and Down go through one list.
    let mut app = App::new();
    type_text(&mut app, &vm, "/switch b");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/switch Book club");
    down(&mut app, &vm);
    assert_eq!(app.input, "/switch Bo");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/switch Book club");
    up(&mut app, &vm);
    assert_eq!(app.input, "/switch Bo");
    back_tab(&mut app, &vm);
    assert_eq!(app.input, "/switch Book club");
}

#[test]
fn up_and_down_after_invite_and_join_step_like_tab() {
    let vm = inviting_crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    type_text(&mut app, &vm, "/invite ");
    down(&mut app, &vm);
    assert_eq!(app.input, "/invite Dee");
    down(&mut app, &vm);
    assert_eq!(app.input, "/invite \"Dee Dee\"");
    up(&mut app, &vm);
    assert_eq!(app.input, "/invite Dee");
    up(&mut app, &vm);
    assert_eq!(app.input, "/invite Cy");
    let vm = joining_crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    type_text(&mut app, &vm, "/join ");
    up(&mut app, &vm);
    assert_eq!(app.input, "/join Climbing Saturdays");
    up(&mut app, &vm);
    assert_eq!(app.input, "/join Hikes");
    let mut app = App::new();
    type_text(&mut app, &crew(), "/join ");
    down(&mut app, &crew());
    assert_eq!(app.input, "/join ");
    assert_eq!(app.status.as_deref(), Some("No invite waits for you."));
}

#[test]
fn up_and_down_still_bring_back_earlier_lines_everywhere_else() {
    let vm = joining_crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    enter_line(&mut app, &vm, "hello");
    enter_line(&mut app, &vm, "/switch Bo");
    // Empty box.
    up(&mut app, &vm);
    assert_eq!(app.input, "/switch Bo");
    // A recalled /switch line keeps Up on earlier lines.
    up(&mut app, &vm);
    assert_eq!(app.input, "hello");
    down(&mut app, &vm);
    assert_eq!(app.input, "/switch Bo");
    down(&mut app, &vm);
    assert_eq!(app.input, "");
    // Plain text and a lone slash.
    for typed in ["hi", "/"] {
        let mut app = App::new();
        app.selected = Some(g(1));
        enter_line(&mut app, &vm, "hello");
        type_text(&mut app, &vm, typed);
        up(&mut app, &vm);
        assert_eq!(app.input, "hello", "{typed}");
    }
    // /switch without a space still steps through command words.
    let mut app = App::new();
    type_text(&mut app, &vm, "/switch");
    down(&mut app, &vm);
    assert_eq!(app.input, "/switch");
}

#[test]
fn help_says_tab_and_up_and_down_complete_after_switch_invite_and_join() {
    let switch = HELP.iter().find(|(c, _)| *c == "/switch [room]").unwrap();
    assert_eq!(switch.1, "open a room; Tab or Up/Down completes the name");
    let mut app = App::new();
    app.selected = Some(g(1));
    app.modal = Some(Modal::Help { offset: 0, pick: 0 });
    let s = render(&app, &crew(), 80, 60);
    let text = modal_text(&s).join(" ");
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        text.contains("Tab or Up/Down step through the rooms or names that fit after /switch, /invite or /join"),
        "{s}"
    );
}

#[test]
fn a_paste_ends_the_run_through_names() {
    let vm = inviting_crew();
    let mut app = App::new();
    type_text(&mut app, &vm, "/invite ");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/invite Dee");
    app.handle_paste("x");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/invite Deex");
    assert_eq!(
        app.status.as_deref(),
        Some("Nobody called Deex shares a room with you.")
    );
}

// ---------- Ctrl-C twice quits ----------

#[test]
fn one_ctrl_c_asks_for_another_and_two_quit() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    assert!(app.handle_key(ctrl('c'), &vm).is_empty());
    assert_eq!(app.status.as_deref(), Some("Press Ctrl-C again to quit."));
    assert!(help_row(&app, &vm).starts_with("Press Ctrl-C again to quit."));
    assert_eq!(app.handle_key(ctrl('c'), &vm), vec![Action::Quit]);
}

#[test]
fn another_key_between_the_two_starts_over() {
    let vm = crew();
    let mut app = App::new();
    assert!(app.handle_key(ctrl('c'), &vm).is_empty());
    app.handle_key(key(KeyCode::Char('x')), &vm);
    assert_eq!(app.status, None);
    assert_eq!(app.input, "x");
    assert!(app.handle_key(ctrl('c'), &vm).is_empty(), "asks again");
    assert_eq!(app.handle_key(ctrl('c'), &vm), vec![Action::Quit]);
}

#[test]
fn the_second_ctrl_c_counts_for_two_seconds() {
    let vm = crew();
    let mut app = App::new();
    app.handle_key(ctrl('c'), &vm);
    let armed = app.quit_deadline().expect("waiting for a second Ctrl-C");
    // The time runs out: the notice goes, and Ctrl-C asks again.
    app.quit_expire(armed + std::time::Duration::from_millis(1));
    assert_eq!(app.status, None);
    assert_eq!(app.quit_deadline(), None);
    assert!(app.handle_key(ctrl('c'), &vm).is_empty());
    // Before it runs out, nothing changes.
    let armed = app.quit_deadline().unwrap();
    app.quit_expire(armed - std::time::Duration::from_millis(500));
    assert_eq!(app.status.as_deref(), Some("Press Ctrl-C again to quit."));
    assert_eq!(app.handle_key(ctrl('c'), &vm), vec![Action::Quit]);
}

#[test]
fn ctrl_c_in_a_box_follows_the_same_two_presses() {
    let vm = crew();
    for m in [
        Modal::Help { offset: 0, pick: 0 },
        Modal::About,
        Modal::Confirm {
            question: "Leave Book club?".into(),
            yes: Box::new(Action::Command(Command::Leave)),
        },
    ] {
        let mut app = App::new();
        app.selected = Some(g(1));
        app.modal = Some(m.clone());
        assert!(app.handle_key(ctrl('c'), &vm).is_empty(), "{m:?}");
        assert_eq!(app.modal, Some(m.clone()), "the box stays open");
        assert_eq!(app.handle_key(ctrl('c'), &vm), vec![Action::Quit]);
    }
}

#[test]
fn help_box_says_ctrl_c_twice_quits() {
    let mut app = App::new();
    app.selected = Some(g(1));
    app.modal = Some(Modal::Help { offset: 0, pick: 0 });
    let s = render(&app, &crew(), 80, 60);
    let text = modal_text(&s).join(" ");
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        text.contains("Ctrl-C Ctrl-C quit; one Ctrl-C copies the text you selected"),
        "{s}"
    );
}
