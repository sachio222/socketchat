use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::style::{Color, Modifier};
use ratatui::Terminal;
use socketchat_core::client::{Ended, RoomDetails};
use socketchat_core::close::CloseView;
use socketchat_core::keys::Key;
use socketchat_proto::msg::GroupId;
use socketchat_tui::app::{
    details_lines, invite_row, leave_step, sent_file_status, Action, App, Focus, LeaveStep, Modal,
};
use socketchat_tui::commands::{parse_command, Command, HELP};
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
    for _ in 0..4 {
        app.handle_key(key(KeyCode::Tab), &vm);
        seen.push(app.input.clone());
    }
    assert_eq!(
        seen,
        vec![
            "/switch Book club",
            "/switch Bo",
            "/switch Books 2",
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
    assert_eq!(
        s.lines().nth(23).unwrap(),
        "/cancel <number> stops a link · Esc close"
    );
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
    assert_eq!(first.lines().nth(23).unwrap(), "Up/Down scroll · Esc close");
    let mut presses = 0;
    loop {
        let s = render(&app, &vm, 80, 24);
        let inside = modal_text(&s);
        assert!(
            !inside.iter().any(|r| r.contains('…')),
            "a description is cut off:\n{s}"
        );
        shown.extend(inside);
        if s.contains(last) {
            assert!(!s.contains("↓ more"), "nothing is left below:\n{s}");
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
        &names[at..at + 11],
        &[
            "/leave",
            "/switch [room]",
            "/title <name>",
            "/close",
            "/keep",
            "/invites",
            "/cancel <number>",
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
    type_text(&mut app, &vm, "/switch bo");
    for _ in 0..3 {
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
    for _ in 0..3 {
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
    for _ in 0..3 {
        app.handle_key(key(KeyCode::Tab), &vm);
    }
    assert_eq!(app.switcher.as_deref(), Some("Bo"));
    let buf = buffer(&app, &vm, 80, 24);
    // Box at rows 6..18: "> Bo", then Book club, Bo (g2), Bo (g5).
    assert_eq!(find_in_row(&buf, 9, "Bo"), Some(21));
    assert_eq!(find_in_row(&buf, 10, "Bo"), Some(21));
    assert!(!buf[(21, 9)].modifier.contains(Modifier::REVERSED));
    assert!(buf[(21, 10)].modifier.contains(Modifier::REVERSED));
    assert_eq!(
        app.handle_key(key(KeyCode::Enter), &vm),
        vec![Action::Select(g(5))]
    );
}
