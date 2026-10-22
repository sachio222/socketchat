use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::style::{Color, Modifier};
use ratatui::Terminal;
use socketchat_core::client::{Ended, RoomDetails};
use socketchat_core::close::CloseView;
use socketchat_core::keys::Key;
use socketchat_proto::msg::GroupId;
use socketchat_tui::app::{
    about_lines, details_lines, invite_row, leave_step, sent_file_status, Action, App, Focus,
    LeaveStep, Modal,
};
use socketchat_tui::commands::{parse_command, Command, HELP};
use socketchat_tui::theme::{ColorSupport, Theme};
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
            GroupView { id: g(1), name: "Book club".into(), unread: 0, is_dm: false, muted: false, ended: None },
            GroupView { id: g(2), name: "Bo".into(), unread: 3, is_dm: true, muted: false, ended: None },
            GroupView { id: g(3), name: "Climbing Saturdays".into(), unread: 12, is_dm: false, muted: false, ended: None },
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
        server: None,
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
        ("/clear", Command::Clear),
        ("/about", Command::About),
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
            "Join me on Socketchat, an encrypted chat.\n1. Install it from https://socketchat.org\n2. Then run: socketchat join \"{link}\""
        ))]
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
            "Admins: Ada, Bo",
            "Members: 3",
            "Created: 2026-03-02",
            "You joined: 2026-10-19",
            "Muted: no",
            "Closing: 1 of 2 admins agree",
        ]
    );
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
    app.modal = Some(Modal::Help { offset: 0 });
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
            .starts_with("Up/Down scroll · Esc close"),
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
    // Down at the end stays at the end, so one Up moves back at once.
    let at_end = render(&app, &vm, 80, 24);
    insta::assert_snapshot!("help_80x24_top", first);
    insta::assert_snapshot!("help_80x24_end", at_end);
    app.handle_key(key(KeyCode::Down), &vm);
    assert_eq!(render(&app, &vm, 80, 24), at_end);
    app.handle_key(key(KeyCode::Up), &vm);
    assert_ne!(render(&app, &vm, 80, 24), at_end);
    app.handle_key(key(KeyCode::PageUp), &vm);
    app.handle_key(key(KeyCode::PageUp), &vm);
    app.handle_key(key(KeyCode::PageUp), &vm);
    assert_eq!(render(&app, &vm, 80, 24), first);
    app.handle_key(key(KeyCode::PageDown), &vm);
    assert_ne!(render(&app, &vm, 80, 24), first);
    app.handle_key(key(KeyCode::Esc), &vm);
    assert!(app.modal.is_none());
}

#[test]
fn help_lists_the_new_commands_in_order() {
    let names: Vec<&str> = HELP.iter().map(|(c, _)| *c).collect();
    let at = names.iter().position(|c| *c == "/leave").unwrap();
    assert_eq!(
        &names[at..at + 13],
        &[
            "/leave",
            "/switch [room]",
            "/title <name>",
            "/close",
            "/keep",
            "/invites",
            "/cancel <number>",
            "/servers",
            "/forget <number>",
            "/mute",
            "/unmute",
            "/details",
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
    for line in about_lines().iter().filter(|l| l.len() < 70) {
        assert!(s.contains(line), "{line} is missing:\n{s}");
    }
    assert!(s.contains("Socketchat is encrypted chat"), "{s}");
    assert!(s.contains("but cannot read them."), "{s}");
    assert!(about_lines()[0].ends_with(env!("CARGO_PKG_VERSION")));
    assert!(about_lines().contains(&"License: MIT or Apache 2.0".to_string()));
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
fn tab_fills_the_common_prefix_then_cycles_in_help_order() {
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
    assert_eq!(seen, ["/clear", "/cancel", "/close"]);
    assert_eq!(app.focus, Focus::Input);
}

#[test]
fn tab_with_no_common_prefix_lists_matches_in_the_dim_help_line() {
    let (mut app, vm) = (App::new(), crew());
    type_text(&mut app, &vm, "/c");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/c");
    assert!(help_row(&app, &vm).contains("/close  /cancel  /clear"));
    let mut seen = vec![];
    for _ in 0..4 {
        tab(&mut app, &vm);
        seen.push(app.input.clone());
    }
    assert_eq!(seen, ["/close", "/cancel", "/clear", "/close"]);
}

#[test]
fn any_other_key_ends_cycling() {
    let (mut app, vm) = (App::new(), crew());
    type_text(&mut app, &vm, "/c");
    for _ in 0..3 {
        tab(&mut app, &vm);
    }
    assert_eq!(app.input, "/cancel");
    app.handle_key(key(KeyCode::Backspace), &vm);
    tab(&mut app, &vm);
    assert_eq!(app.input, "/cancel ", "a fresh Tab, not the next match");
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
    assert!(
        row.contains("/invite  /invite") || row.contains("/invite  /join"),
        "{row}"
    );
    assert!(row.contains("/join  /new"), "{row}");
    tab(&mut app, &vm);
    assert_eq!(app.input, "/invite");
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
