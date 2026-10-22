//! Clicks and the scroll wheel on the chat screen.

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::Terminal;
use socketchat_core::keys::Key;
use socketchat_proto::msg::GroupId;
use socketchat_tui::app::{invite_message, Action, App, Focus, Modal};
use socketchat_tui::commands::{parse_command, Command};
use socketchat_tui::ui::{draw, GroupView, LineView, MemberLine, ViewModel};

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

fn line(n: usize) -> LineView {
    LineView {
        time: "09:00:00".into(),
        sender: "Bo".into(),
        text: format!("message {n}"),
        notice: false,
        mine: false,
    }
}

fn member(n: u8, name: &str) -> MemberLine {
    MemberLine {
        key: Key([n; 32]),
        name: name.into(),
        verified: true,
        admin: false,
        me: n == 1,
    }
}

fn crew() -> ViewModel {
    ViewModel {
        me: "Ada".into(),
        groups: vec![room(1, "Book club"), room(2, "Bo"), room(3, "Climbing")],
        lines: (0..40).map(line).collect(),
        members: vec![member(1, "Ada"), member(2, "Bo"), member(3, "Cy")],
        connected: true,
        server: None,
    }
}

/// Draws the screen, as the chat screen does before it reads input, and
/// notes when the draw happened.
fn shown(app: &mut App, vm: &ViewModel, at: Instant) -> Buffer {
    let mut t = Terminal::new(TestBackend::new(80, 24)).unwrap();
    t.draw(|f| draw(f, app, vm)).unwrap();
    app.drawn(at);
    t.backend().buffer().clone()
}

/// Where `needle` first starts on screen, as (column, row).
fn find(buf: &Buffer, needle: &str) -> (u16, u16) {
    for y in 0..buf.area.height {
        let text: String = (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect();
        if let Some(byte) = text.find(needle) {
            return (text[..byte].chars().count() as u16, y);
        }
    }
    panic!("{needle:?} is not on screen");
}

fn mouse(kind: MouseEventKind, (column, row): (u16, u16)) -> MouseEvent {
    MouseEvent {
        kind,
        column,
        row,
        modifiers: KeyModifiers::NONE,
    }
}

fn click(at: (u16, u16)) -> MouseEvent {
    mouse(MouseEventKind::Down(MouseButton::Left), at)
}

fn later(t: Instant) -> Instant {
    t + Duration::from_millis(5)
}

#[test]
fn clicking_a_room_in_chats_opens_it() {
    let (mut app, vm) = (App::new(), crew());
    app.selected = Some(g(1));
    let t = Instant::now();
    let buf = shown(&mut app, &vm, t);
    let acts = app.handle_mouse(click(find(&buf, "# Bo ")), later(t), &vm);
    assert_eq!(acts, vec![Action::Select(g(2))]);
    assert_eq!(app.focus, Focus::Groups);
    // Below the last room: the panel takes focus and nothing opens.
    let (x, y) = find(&buf, "# Climbing");
    assert!(app
        .handle_mouse(click((x, y + 3)), later(t), &vm)
        .is_empty());
}

#[test]
fn clicking_a_panel_focuses_it() {
    let (mut app, vm) = (App::new(), crew());
    app.selected = Some(g(1));
    let t = Instant::now();
    let buf = shown(&mut app, &vm, t);
    app.handle_mouse(click(find(&buf, "message 39")), later(t), &vm);
    assert_eq!(app.focus, Focus::Messages);
    app.handle_mouse(click(find(&buf, "Cy")), later(t), &vm);
    assert_eq!(app.focus, Focus::Members);
    assert_eq!(app.member_cursor, 2, "the person clicked is picked");
    app.handle_mouse(click(find(&buf, "What's on your mind?")), later(t), &vm);
    assert_eq!(app.focus, Focus::Input);
}

#[test]
fn the_wheel_scrolls_the_messages() {
    let (mut app, vm) = (App::new(), crew());
    app.selected = Some(g(1));
    let t = Instant::now();
    let buf = shown(&mut app, &vm, t);
    let at = find(&buf, "message 39");
    app.handle_mouse(mouse(MouseEventKind::ScrollUp, at), later(t), &vm);
    assert_eq!(app.scroll, 3);
    app.handle_mouse(mouse(MouseEventKind::ScrollUp, at), later(t), &vm);
    app.handle_mouse(mouse(MouseEventKind::ScrollDown, at), later(t), &vm);
    assert_eq!(app.scroll, 3);
    for _ in 0..3 {
        app.handle_mouse(mouse(MouseEventKind::ScrollDown, at), later(t), &vm);
    }
    assert_eq!(app.scroll, 0, "never below the newest message");
}

#[test]
fn the_wheel_scrolls_help_invites_and_details() {
    let vm = crew();
    let t = Instant::now();
    let boxes = [
        Modal::Help { offset: 0 },
        Modal::Invites {
            rows: (1..=40).map(|n| format!("{n}. Link")).collect(),
            offset: 0,
        },
        Modal::Details {
            lines: (1..=40).map(|n| format!("Line {n}")).collect(),
            offset: 0,
        },
    ];
    for m in boxes {
        let mut app = App::new();
        app.modal = Some(m.clone());
        let buf = shown(&mut app, &vm, t);
        let at = find(&buf, "↓ more");
        app.handle_mouse(mouse(MouseEventKind::ScrollDown, at), later(t), &vm);
        let offset = match &app.modal {
            Some(Modal::Help { offset })
            | Some(Modal::Invites { offset, .. })
            | Some(Modal::Details { offset, .. }) => *offset,
            other => panic!("the box closed: {other:?}"),
        };
        assert_eq!(offset, 3, "{m:?}");
        assert_eq!(app.scroll, 0, "the messages behind stay put");
    }
}

fn confirm() -> Modal {
    Modal::Confirm {
        question: "Leave Book club?".into(),
        yes: Box::new(Action::LeaveRoom(g(1))),
    }
}

#[test]
fn clicking_yes_or_no_answers_a_question() {
    let vm = crew();
    let mut app = App::new();
    app.modal = Some(confirm());
    let t = Instant::now();
    let buf = shown(&mut app, &vm, t);
    assert_eq!(
        app.handle_mouse(click(find(&buf, "[ Yes ]")), later(t), &vm),
        vec![Action::LeaveRoom(g(1))]
    );
    assert!(app.modal.is_none());
    app.modal = Some(confirm());
    let buf = shown(&mut app, &vm, t);
    assert!(app
        .handle_mouse(click(find(&buf, "[ No ]")), later(t), &vm)
        .is_empty());
    assert!(app.modal.is_none());
}

#[test]
fn a_click_from_before_the_question_showed_never_answers_it() {
    let vm = crew();
    let mut app = App::new();
    app.modal = Some(confirm());
    let t = Instant::now();
    let buf = shown(&mut app, &vm, later(t));
    let yes = find(&buf, "[ Yes ]");
    assert!(app.handle_mouse(click(yes), t, &vm).is_empty());
    assert_eq!(app.modal, Some(confirm()), "the question stays open");
    // Drawn again, it is still the same question from the same moment.
    shown(&mut app, &vm, later(later(t)));
    assert!(app.handle_mouse(click(yes), t, &vm).is_empty());
    // A click in the message box behind it does nothing either.
    let input = find(&buf, "Leave Book club?");
    assert!(app
        .handle_mouse(click((input.0, 22)), later(later(t)), &vm)
        .is_empty());
    assert_eq!(app.modal, Some(confirm()));
}

const LINK: &str = "socketchat://chat.example.com:7444/j/AAECAwQFBgcICQoLDA0ODw#3q2-7wABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhs";

fn invite(copied: bool) -> Modal {
    Modal::Invite {
        link: LINK.into(),
        hours: 2,
        copied,
    }
}

#[test]
fn the_invite_box_says_whether_it_copied_under_the_link() {
    let vm = crew();
    let t = Instant::now();
    for (copied, said) in [
        (true, "Copied. Press C to copy again."),
        (false, "Press C to copy."),
    ] {
        let mut app = App::new();
        app.modal = Some(invite(copied));
        let buf = shown(&mut app, &vm, t);
        let (x, y) = find(&buf, said);
        let (_, link_end) = find(&buf, "xgZGhs");
        assert_eq!(y, link_end + 1, "directly under the link");
        // The C stands out.
        let c = x + said.find("C ").unwrap() as u16;
        assert_eq!(buf[(c, y)].symbol(), "C");
        assert!(buf[(c, y)]
            .modifier
            .contains(ratatui::style::Modifier::BOLD));
        // Clicking the line copies, like C.
        assert_eq!(
            app.handle_mouse(click((x, y)), later(t), &vm),
            vec![Action::Copy(invite_message(LINK))]
        );
        assert!(app.modal.is_some(), "copying keeps the link on screen");
    }
}

#[test]
fn clicking_close_shuts_the_invite_box() {
    let vm = crew();
    let mut app = App::new();
    app.modal = Some(invite(true));
    let t = Instant::now();
    let buf = shown(&mut app, &vm, t);
    assert!(app
        .handle_mouse(click(find(&buf, "[ Close ]")), later(t), &vm)
        .is_empty());
    assert!(app.modal.is_none());
}

#[test]
fn c_still_copies_from_the_keyboard() {
    let vm = crew();
    let mut app = App::new();
    app.modal = Some(invite(false));
    assert_eq!(
        app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE), &vm),
        vec![Action::Copy(invite_message(LINK))]
    );
}

#[test]
fn mouse_command_takes_on_or_off() {
    assert_eq!(parse_command("/mouse"), Ok(Command::Mouse(None)));
    assert_eq!(parse_command("/mouse on"), Ok(Command::Mouse(Some(true))));
    assert_eq!(parse_command("/mouse off"), Ok(Command::Mouse(Some(false))));
    assert_eq!(
        parse_command("/mouse maybe"),
        Err("Usage: /mouse on, or /mouse off".into())
    );
}

#[test]
fn help_says_how_to_select_text() {
    let vm = crew();
    let mut app = App::new();
    app.modal = Some(Modal::Help { offset: 0 });
    let mut all = String::new();
    // Every page of the box.
    for _ in 0..10 {
        let buf = shown(&mut app, &vm, Instant::now());
        for y in 0..buf.area.height {
            let row: String = (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect();
            all.push_str(&row);
            all.push('\n');
        }
        app.handle_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE), &vm);
    }
    assert!(all.contains("/mouse [on|off]"), "{all}");
    assert!(all.contains("hold Shift"), "{all}");
    assert!(all.contains("Option"), "{all}");
}

/// The boxes that ask before sending a video, or a photo Socketchat
/// cannot clean, have Send it and Cancel buttons, and a click from before
/// the box showed never presses them.
#[test]
fn photo_and_video_questions_have_send_and_cancel_buttons() {
    let vm = crew();
    let asks = [
        Modal::ConfirmVideo {
            group: g(1),
            path: "/tmp/beach.mov".into(),
        },
        Modal::ConfirmPhoto {
            group: g(1),
            path: "/tmp/beach.heic".into(),
        },
    ];
    for ask in asks {
        let path = match &ask {
            Modal::ConfirmVideo { path, .. } | Modal::ConfirmPhoto { path, .. } => path.clone(),
            _ => unreachable!(),
        };
        let mut app = App::new();
        app.modal = Some(ask.clone());
        let t = Instant::now();
        let buf = shown(&mut app, &vm, later(t));
        let send = find(&buf, "[ Send it ]");
        assert!(app.handle_mouse(click(send), t, &vm).is_empty(), "{ask:?}");
        assert_eq!(app.modal, Some(ask.clone()), "a stale click leaves it open");
        assert_eq!(
            app.handle_mouse(click(send), later(later(t)), &vm),
            vec![Action::ConfirmVideo(g(1), path)],
            "{ask:?}"
        );
        assert!(app.modal.is_none());

        app.modal = Some(ask.clone());
        let buf = shown(&mut app, &vm, t);
        let cancel = find(&buf, "[ Cancel ]");
        assert!(app.handle_mouse(click(cancel), later(t), &vm).is_empty());
        assert!(app.modal.is_none(), "{ask:?}");
    }
}
