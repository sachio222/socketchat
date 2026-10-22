//! Seeing which server a room is on, the `/servers` box, and the question
//! `/forget` asks.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use socketchat_core::client::{RoomDetails, ServerState, ServerView};
use socketchat_proto::msg::GroupId;
use socketchat_tui::app::{details_lines, forget_question, server_row, Action, App, Modal};
use socketchat_tui::commands::{parse_command, Command, HELP};
use socketchat_tui::ui::{draw, GroupView, ViewModel};

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

fn g(n: u8) -> GroupId {
    GroupId([n; 16])
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

/// Ada with three rooms, Book club open, on chat.socketchat.org.
fn crew() -> ViewModel {
    ViewModel {
        me: "Ada".into(),
        groups: vec![
            room(1, "Book club"),
            room(2, "Climbing Saturdays"),
            room(3, "Old crew"),
        ],
        lines: vec![],
        members: vec![],
        connected: true,
        server: Some("chat.socketchat.org".into()),
    }
}

fn open_app() -> App {
    let mut app = App::new();
    app.selected = Some(g(1));
    app
}

fn view(id: i64, text: &str, rooms: usize, state: ServerState, new_rooms: bool) -> ServerView {
    ServerView {
        id,
        text: text.into(),
        rooms,
        state,
        new_rooms,
    }
}

fn three_servers() -> Vec<String> {
    [
        view(2, "chat.socketchat.org", 2, ServerState::Connected, true),
        view(
            1,
            "Jacobs-MacBook-Pro-2.local",
            4,
            ServerState::Unreachable("connection refused".into()),
            false,
        ),
        view(3, "127.0.0.1:9000", 0, ServerState::NotYet, false),
    ]
    .iter()
    .enumerate()
    .map(|(i, s)| server_row(i + 1, s))
    .collect()
}

#[test]
fn servers_and_forget_parse() {
    assert_eq!(parse_command("/servers"), Ok(Command::Servers));
    assert_eq!(parse_command("/forget 2"), Ok(Command::Forget(2)));
    assert_eq!(
        parse_command("/forget"),
        Err("Usage: /forget <number>".into())
    );
    assert_eq!(
        parse_command("/forget two"),
        Err("Usage: /forget <number>".into())
    );
}

#[test]
fn help_lists_servers_and_forget() {
    let cmds: Vec<&str> = HELP.iter().map(|(c, _)| *c).collect();
    assert!(cmds.contains(&"/servers"), "{cmds:?}");
    assert!(cmds.contains(&"/forget <number>"), "{cmds:?}");
}

#[test]
fn each_server_row_says_its_rooms_and_state() {
    assert_eq!(
        three_servers(),
        [
            "1. chat.socketchat.org: 2 rooms, connected (new rooms go here)",
            "2. Jacobs-MacBook-Pro-2.local: 4 rooms, could not reach: connection refused",
            "3. 127.0.0.1:9000: no rooms, not connected yet",
        ]
    );
    assert_eq!(
        server_row(1, &view(1, "h", 1, ServerState::Connected, false)),
        "1. h: 1 room, connected"
    );
}

#[test]
fn servers_box_at_80x24() {
    let mut app = open_app();
    app.modal = Some(Modal::Servers {
        rows: three_servers(),
        offset: 0,
    });
    let s = render(&app, &crew(), 80, 24);
    assert!(s.contains(" Your servers "), "{s}");
    assert!(
        s.lines()
            .nth(23)
            .unwrap()
            .starts_with("/forget <number> forgets a server · Esc close"),
        "{s}"
    );
    insta::assert_snapshot!("servers_80x24", s);
}

#[test]
fn servers_box_at_100x50() {
    let mut app = open_app();
    app.modal = Some(Modal::Servers {
        rows: three_servers(),
        offset: 0,
    });
    insta::assert_snapshot!("servers_100x50", render(&app, &crew(), 100, 50));
}

#[test]
fn many_servers_scroll() {
    let vm = crew();
    let mut app = open_app();
    let rows: Vec<String> = (1..=30)
        .map(|n| {
            server_row(
                n,
                &view(
                    n as i64,
                    &format!("host{n}.example"),
                    1,
                    ServerState::NotYet,
                    false,
                ),
            )
        })
        .collect();
    app.modal = Some(Modal::Servers { rows, offset: 0 });
    let first = render(&app, &vm, 80, 24);
    assert!(first.contains("↓ more"), "{first}");
    let mut presses = 0;
    while !render(&app, &vm, 80, 24).contains("30. host30.example") {
        presses += 1;
        assert!(presses < 40, "Down never reached server 30");
        app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE), &vm);
    }
    // Typing a command closes the box and goes into the message box.
    app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE), &vm);
    assert!(app.modal.is_none());
    assert_eq!(app.input, "/");
}

#[test]
fn forget_asks_first_naming_the_server_and_its_rooms() {
    assert_eq!(
        forget_question("Jacobs-MacBook-Pro-2.local", 4),
        "Forget Jacobs-MacBook-Pro-2.local? Its 4 rooms leave this computer, with their messages and keys. The server is not told, so others there still see you as a member until an admin removes you. If the server still works, /leave its rooms first. Press y to forget it or n to keep it."
    );
    assert!(forget_question("h", 1)
        .starts_with("Forget h? Its 1 room leaves this computer, with its messages and keys."));
    assert!(forget_question("h", 0).starts_with("Forget h? You have no rooms there."));
    let mut app = open_app();
    app.modal = Some(Modal::Confirm {
        question: forget_question("Jacobs-MacBook-Pro-2.local", 4),
        yes: Box::new(Action::ForgetServer(1)),
    });
    let s = render(&app, &crew(), 80, 24);
    insta::assert_snapshot!("forget_question_80x24", s);
    let vm = crew();
    assert_eq!(
        app.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE), &vm),
        vec![Action::ForgetServer(1)]
    );
}

#[test]
fn details_name_the_server() {
    let d = RoomDetails {
        name: "Book club".into(),
        server: "chat.socketchat.org".into(),
        admins: vec!["Ada".into()],
        size: 2,
        created_unix: Some(1_772_452_800),
        joined_unix: 1_792_411_200,
        muted: false,
        close: None,
    };
    let date = |_: u64| "2026-03-02".to_string();
    let lines = details_lines(&d, "Book club", true, &date);
    assert_eq!(
        lines[..2],
        ["Name: Book club", "Server: chat.socketchat.org"]
    );
    let mut app = open_app();
    app.modal = Some(Modal::Details { lines, offset: 0 });
    insta::assert_snapshot!("details_with_server_80x24", render(&app, &crew(), 80, 24));
}

#[test]
fn the_room_header_names_the_server() {
    let app = open_app();
    let s = render(&app, &crew(), 80, 24);
    assert!(
        s.lines()
            .next()
            .unwrap()
            .contains(" Book club · chat.socketchat.org "),
        "{s}"
    );
    insta::assert_snapshot!("header_with_server_80x24", s);

    // Offline, both still fit in a wider window.
    let mut vm = crew();
    vm.connected = false;
    let s = render(&app, &vm, 100, 24);
    assert!(
        s.lines()
            .next()
            .unwrap()
            .contains(" Book club · chat.socketchat.org · offline "),
        "{s}"
    );

    // A narrow window drops the server first: the name and the offline
    // note stay.
    let s = render(&app, &vm, 64, 24);
    let top = s.lines().next().unwrap();
    assert!(top.contains(" Book club · offline "), "{top}");
    assert!(!top.contains("socketchat.org"), "{top}");

    // No room open: nothing about a server.
    let s = render(&App::new(), &crew(), 80, 24);
    assert!(!s.lines().next().unwrap().contains("socketchat.org"), "{s}");
}
