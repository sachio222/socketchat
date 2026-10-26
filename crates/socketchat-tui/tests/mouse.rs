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
        topic: false,
        command: None,
    }
}

fn member(n: u8, name: &str) -> MemberLine {
    MemberLine {
        key: Key([n; 32]),
        name: name.into(),
        verified: true,
        admin: false,
        me: n == 1,
        changed_key: false,
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
        topic: None,
        invite_names: vec![],
        join_rooms: vec![],
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
fn the_wheel_scrolls_invites_and_details() {
    let vm = crew();
    let t = Instant::now();
    let boxes = [
        Modal::Invites {
            rows: (1..=40).map(|n| format!("{n}. Link")).collect(),
            offset: 0,
        },
        Modal::Details {
            lines: (1..=40).map(|n| format!("Line {n}")).collect(),
            offset: 0,
        },
        Modal::Status {
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
            Some(Modal::Invites { offset, .. })
            | Some(Modal::Details { offset, .. })
            | Some(Modal::Status { offset, .. }) => *offset,
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
    app.modal = Some(Modal::Help { offset: 0, pick: 0 });
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
    assert!(all.contains("Drag over messages"), "{all}");
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

/// The command at the start of the row drawn in the selection style.
fn picked(app: &App, buf: &Buffer) -> String {
    let bg = app.theme.selected.bg.unwrap();
    (0..buf.area.height)
        .find_map(|y| {
            let lit: String = (0..buf.area.width)
                .filter(|x| buf[(*x, y)].bg == bg)
                .map(|x| buf[(x, y)].symbol())
                .collect();
            let word = lit.split_whitespace().next()?.to_string();
            word.starts_with('/').then_some(word)
        })
        .unwrap_or_default()
}

fn help_box() -> Modal {
    Modal::Help { offset: 0, pick: 0 }
}

#[test]
fn the_wheel_moves_the_help_highlight() {
    let (mut app, vm) = (App::new(), crew());
    app.modal = Some(help_box());
    let t = Instant::now();
    let buf = shown(&mut app, &vm, t);
    assert_eq!(picked(&app, &buf), "/about");
    let at = find(&buf, "/cancel");
    app.handle_mouse(mouse(MouseEventKind::ScrollDown, at), later(t), &vm);
    let buf = shown(&mut app, &vm, t);
    assert_eq!(picked(&app, &buf), "/admin");
    for _ in 0..3 {
        app.handle_mouse(mouse(MouseEventKind::ScrollUp, at), later(t), &vm);
    }
    let buf = shown(&mut app, &vm, t);
    assert_eq!(picked(&app, &buf), "/about", "the wheel stops at the top");
    assert_eq!(app.scroll, 0, "the messages behind stay put");
}

#[test]
fn clicking_a_help_row_picks_it_and_a_second_click_uses_it() {
    let vm = crew();
    let mut app = App::new();
    app.selected = Some(g(1));
    app.modal = Some(help_box());
    let t = Instant::now();
    let buf = shown(&mut app, &vm, t);
    let at = find(&buf, "/clear ");
    // A click from before the box showed does nothing.
    assert!(app
        .handle_mouse(click(at), t - Duration::from_millis(5), &vm)
        .is_empty());
    let buf = shown(&mut app, &vm, t);
    assert_eq!(picked(&app, &buf), "/about");
    assert!(app.handle_mouse(click(at), later(t), &vm).is_empty());
    let buf = shown(&mut app, &vm, t);
    assert_eq!(picked(&app, &buf), "/clear");
    assert!(app.modal.is_some());
    // The second click uses it as the button comes up, so a drag that
    // starts on the picked row selects text instead.
    assert!(app.handle_mouse(click(at), later(t), &vm).is_empty());
    assert_eq!(
        app.handle_mouse(
            mouse(MouseEventKind::Up(MouseButton::Left), at),
            later(t),
            &vm
        ),
        vec![Action::Command(Command::Clear)]
    );
    assert!(app.modal.is_none());
}

#[test]
fn with_the_mouse_off_the_help_box_ignores_it() {
    let (mut app, vm) = (App::new(), crew());
    app.mouse = false;
    app.modal = Some(help_box());
    let t = Instant::now();
    let buf = shown(&mut app, &vm, t);
    let at = find(&buf, "/clear ");
    assert!(app
        .handle_mouse(mouse(MouseEventKind::ScrollDown, at), later(t), &vm)
        .is_empty());
    assert!(app.handle_mouse(click(at), later(t), &vm).is_empty());
    let buf = shown(&mut app, &vm, t);
    assert_eq!(picked(&app, &buf), "/about");
}

// ---------- selecting and copying text ----------

fn press(at: (u16, u16)) -> MouseEvent {
    mouse(MouseEventKind::Down(MouseButton::Left), at)
}

fn drag_to(at: (u16, u16)) -> MouseEvent {
    mouse(MouseEventKind::Drag(MouseButton::Left), at)
}

fn release(at: (u16, u16)) -> MouseEvent {
    mouse(MouseEventKind::Up(MouseButton::Left), at)
}

/// Presses at `from`, drags to `to` and lets go there; what the release
/// returns.
fn select(app: &mut App, vm: &ViewModel, from: (u16, u16), to: (u16, u16)) -> Vec<Action> {
    let t = Instant::now();
    app.handle_mouse(press(from), later(t), vm);
    app.handle_mouse(drag_to(to), later(t), vm);
    app.handle_mouse(release(to), later(t), vm)
}

/// `at` moved `n` columns to the right.
fn right((x, y): (u16, u16), n: u16) -> (u16, u16) {
    (x + n, y)
}

/// A room whose only message, from Bo, says `text`.
fn one_message(text: &str) -> ViewModel {
    let mut vm = crew();
    vm.lines = vec![LineView {
        text: text.into(),
        ..line(0)
    }];
    vm
}

fn open(vm: &ViewModel) -> (App, Buffer) {
    let mut app = App::new();
    app.selected = Some(g(1));
    let buf = shown(&mut app, vm, Instant::now());
    (app, buf)
}

#[test]
fn dragging_over_messages_copies_what_it_covers() {
    let vm = crew();
    let (mut app, buf) = open(&vm);
    let from = find(&buf, "message 38");
    let to = right(find(&buf, "message 39"), 9);
    assert_eq!(
        select(&mut app, &vm, from, to),
        vec![Action::CopySelected(
            "message 38\n09:00:00 Bo: message 39".into()
        )]
    );
    assert_eq!(app.focus, Focus::Messages);
    // Dragged backwards, the same text.
    let (mut app, _) = open(&vm);
    assert_eq!(
        select(&mut app, &vm, to, from),
        vec![Action::CopySelected(
            "message 38\n09:00:00 Bo: message 39".into()
        )]
    );
}

#[test]
fn a_click_without_a_drag_copies_nothing() {
    let vm = crew();
    let (mut app, buf) = open(&vm);
    let at = find(&buf, "message 38");
    let t = Instant::now();
    assert!(app.handle_mouse(press(at), later(t), &vm).is_empty());
    assert!(app.handle_mouse(release(at), later(t), &vm).is_empty());
    assert_eq!(app.focus, Focus::Messages, "the click still moves focus");
    assert_eq!(app.selected_text(&vm), None);
}

#[test]
fn a_wrapped_message_copies_as_one_line() {
    let text = "Got it, thanks. Saturday still works for me, and I can bring snacks for everyone.";
    let vm = one_message(text);
    let (mut app, buf) = open(&vm);
    let (_, top) = find(&buf, "Got it");
    let end = right(find(&buf, "everyone."), 8);
    assert!(end.1 > top, "the message wraps onto more rows");
    assert_eq!(
        select(&mut app, &vm, find(&buf, "Got it"), end),
        vec![Action::CopySelected(text.into())]
    );
    // From the time on, with the name, still one line.
    let (mut app, _) = open(&vm);
    assert_eq!(
        select(&mut app, &vm, find(&buf, "09:00:00"), end),
        vec![Action::CopySelected(format!("09:00:00 Bo: {text}"))]
    );
}

#[test]
fn a_word_cut_across_rows_comes_back_whole() {
    let word = "x".repeat(50);
    let vm = one_message(&word);
    let (mut app, buf) = open(&vm);
    let (x, y) = find(&buf, "xxxxx");
    // The last row of the word, at its last x.
    let last = (0..buf.area.height)
        .rev()
        .find(|&row| buf[(x, row)].symbol() == "x")
        .unwrap();
    let end_x = (x..buf.area.width)
        .take_while(|&col| buf[(col, last)].symbol() == "x")
        .last()
        .unwrap();
    assert!(last > y, "the word is cut across rows");
    assert_eq!(
        select(&mut app, &vm, (x, y), (end_x, last)),
        vec![Action::CopySelected(word)]
    );
}

#[test]
fn a_message_of_several_lines_copies_them_without_the_indent() {
    let vm = one_message("first line\nsecond line");
    let (mut app, buf) = open(&vm);
    let from = find(&buf, "09:00:00 Bo: first");
    let second = find(&buf, "second line");
    assert!(second.0 > from.0, "the second line is indented");
    assert_eq!(
        select(&mut app, &vm, from, right(second, 10)),
        vec![Action::CopySelected(
            "09:00:00 Bo: first line\nsecond line".into()
        )]
    );
    // A drag that starts in the indent starts at the text.
    let (mut app, _) = open(&vm);
    assert_eq!(
        select(&mut app, &vm, (from.0, second.1), (79, second.1)),
        vec![Action::CopySelected("second line".into())]
    );
}

#[test]
fn the_selection_is_drawn_in_the_themes_selection_style() {
    let vm = crew();
    let (mut app, buf) = open(&vm);
    let from = find(&buf, "message 38");
    let to = right(find(&buf, "message 39"), 6);
    let t = Instant::now();
    app.handle_mouse(press(from), later(t), &vm);
    app.handle_mouse(drag_to(to), later(t), &vm);
    let buf = shown(&mut app, &vm, t);
    let lit = |x: u16, y: u16| buf[(x, y)].bg == app.theme.selected.bg.unwrap();
    // "message 38" to the end of its row, and the next row up to "message".
    for x in from.0..from.0 + 10 {
        assert!(lit(x, from.1), "column {x} of the first row");
    }
    assert!(!lit(from.0 - 1, from.1), "before the press");
    let (x39, y39) = find(&buf, "09:00:00 Bo: message 39");
    for x in x39..=to.0 {
        assert!(lit(x, y39), "column {x} of the last row");
    }
    assert!(!lit(to.0 + 1, y39), "after the pointer");
    assert!(!lit(from.0, from.1 - 1), "the row above");
}

#[test]
fn dragging_past_the_top_scrolls_up_a_row_at_a_time() {
    let vm = crew();
    let (mut app, buf) = open(&vm);
    let t = Instant::now();
    let from = find(&buf, "message 39");
    let above = (from.0, 0);
    app.handle_mouse(press(from), later(t), &vm);
    app.handle_mouse(drag_to(above), later(t), &vm);
    assert_eq!(app.scroll, 1);
    shown(&mut app, &vm, t);
    app.handle_mouse(drag_to(above), later(t), &vm);
    assert_eq!(app.scroll, 2);
    shown(&mut app, &vm, t);
    // Held still above the messages, it keeps going.
    app.drag_tick();
    assert_eq!(app.scroll, 3);
    shown(&mut app, &vm, t);
    let acts = app.handle_mouse(release(above), later(t), &vm);
    let [Action::CopySelected(text)] = acts.as_slice() else {
        panic!("{acts:?}");
    };
    assert!(
        text.starts_with("09:00:00 Bo: message 19\n09:00:00 Bo: message 20\n"),
        "{text}"
    );
    assert!(text.ends_with("message 38\n09:00:00 Bo: m"), "{text}");
    assert_eq!(text.lines().count(), 21, "{text}");
    // Letting go stops it.
    app.drag_tick();
    assert_eq!(app.scroll, 3);
}

#[test]
fn dragging_below_scrolls_down_and_stops_at_the_newest() {
    let vm = crew();
    let (mut app, _) = open(&vm);
    app.scroll = 2;
    let t = Instant::now();
    let buf = shown(&mut app, &vm, t);
    let from = find(&buf, "message 30");
    let below = (from.0, 21);
    app.handle_mouse(press(from), later(t), &vm);
    for _ in 0..5 {
        app.handle_mouse(drag_to(below), later(t), &vm);
        shown(&mut app, &vm, t);
        app.drag_tick();
        shown(&mut app, &vm, t);
    }
    assert_eq!(app.scroll, 0, "never below the newest message");
    let acts = app.handle_mouse(release(below), later(t), &vm);
    let [Action::CopySelected(text)] = acts.as_slice() else {
        panic!("{acts:?}");
    };
    assert!(text.starts_with("message 30\n"), "{text}");
    assert!(text.ends_with("09:00:00 Bo: message 39"), "{text}");
}

#[test]
fn dragging_past_the_oldest_message_stops_there() {
    let mut vm = crew();
    vm.lines.truncate(3);
    let (mut app, buf) = open(&vm);
    let t = Instant::now();
    let from = find(&buf, "message 2");
    app.handle_mouse(press(from), later(t), &vm);
    for _ in 0..5 {
        app.handle_mouse(drag_to((from.0, 0)), later(t), &vm);
        shown(&mut app, &vm, t);
        app.drag_tick();
    }
    assert_eq!(app.scroll, 0, "nothing older to show");
    assert_eq!(
        app.handle_mouse(release((from.0, 0)), later(t), &vm),
        vec![Action::CopySelected(
            "09:00:00 Bo: message 0\n09:00:00 Bo: message 1\n09:00:00 Bo: m".into()
        )]
    );
}

#[test]
fn esc_typing_and_a_new_click_clear_the_selection() {
    let vm = crew();
    let from = (24, 17);
    let to = (40, 18);
    let clears: [&dyn Fn(&mut App); 4] = [
        &|app| {
            app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE), &vm);
        },
        &|app| {
            app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE), &vm);
        },
        &|app| {
            app.handle_mouse(press((30, 5)), Instant::now(), &vm);
        },
        &|app| {
            app.handle_paste("hi");
        },
    ];
    for (i, clear) in clears.iter().enumerate() {
        let (mut app, _) = open(&vm);
        select(&mut app, &vm, from, to);
        assert!(app.selected_text(&vm).is_some(), "case {i}");
        clear(&mut app);
        assert_eq!(app.selected_text(&vm), None, "case {i}");
    }
}

#[test]
fn new_messages_clear_the_selection() {
    let vm = crew();
    let (mut app, buf) = open(&vm);
    select(
        &mut app,
        &vm,
        find(&buf, "message 38"),
        right(find(&buf, "message 39"), 9),
    );
    app.keep_selection(&vm);
    assert_eq!(
        app.selected_text(&vm).as_deref(),
        Some("message 38\n09:00:00 Bo: message 39"),
        "nothing moved"
    );
    let mut more = vm.clone();
    more.lines.push(line(40));
    app.keep_selection(&more);
    assert_eq!(app.selected_text(&more), None);
}

fn details() -> Modal {
    Modal::Details {
        lines: vec![
            "Name: Book club".into(),
            "Server: chat.example.com".into(),
            format!(
                "Topic: {} (set by Ada, 2026-10-25)",
                "Piranesi, chapters 1 to 5, and snacks "
                    .repeat(2)
                    .trim_end()
            ),
            "Members: 3".into(),
        ],
        offset: 0,
    }
}

#[test]
fn text_in_the_details_box_can_be_selected_and_copied() {
    let vm = crew();
    let mut app = App::new();
    app.modal = Some(details());
    let buf = shown(&mut app, &vm, Instant::now());
    let host = find(&buf, "chat.example.com");
    assert_eq!(
        select(&mut app, &vm, host, right(host, 15)),
        vec![Action::CopySelected("chat.example.com".into())]
    );
    assert_eq!(app.modal, Some(details()), "the box stays open");
    // A line the box wraps comes back as one line.
    let Modal::Details { lines, .. } = details() else {
        unreachable!()
    };
    let topic = find(&buf, "Topic: ");
    let end = right(find(&buf, "2026-10-25)"), 10);
    assert!(end.1 > topic.1, "the topic wraps");
    assert_eq!(
        select(&mut app, &vm, topic, end),
        vec![Action::CopySelected(lines[2].clone())]
    );
}

/// A certificate fingerprint the status box wraps copies as one line, so
/// it can be pasted next to the one the server printed.
#[test]
fn a_fingerprint_in_the_status_box_copies_whole() {
    let vm = crew();
    let fpr = "0025 4a6f 94b9 de03 284d 7297 bce1 062b 5075 9abf e409 2e53 789d c2e7 0c31 567b";
    let status = Modal::Status {
        lines: vec![
            "Connection".into(),
            "Server: chat.example.com".into(),
            format!("Certificate fingerprint: {fpr}"),
        ],
        offset: 0,
    };
    let mut app = App::new();
    app.modal = Some(status.clone());
    let buf = shown(&mut app, &vm, Instant::now());
    let from = find(&buf, "0025 ");
    let end = right(find(&buf, "567b"), 3);
    assert!(end.1 > from.1, "the fingerprint wraps");
    assert_eq!(
        select(&mut app, &vm, from, end),
        vec![Action::CopySelected(fpr.into())]
    );
    assert_eq!(app.modal, Some(status), "the box stays open");
}

#[test]
fn text_in_the_help_box_can_be_selected_and_copied() {
    let vm = crew();
    let mut app = App::new();
    app.modal = Some(help_box());
    let buf = shown(&mut app, &vm, Instant::now());
    let from = find(&buf, "/invite ");
    let (_, desc) = socketchat_tui::commands::HELP[0];
    let last_word = desc.rsplit(' ').next().unwrap();
    // The description's last word, on the row under the command.
    let y = from.1 + 1;
    let row: String = (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect();
    let byte = row
        .find(&format!("{last_word}   "))
        .expect("the description wraps");
    let x = row[..byte].chars().count() as u16;
    assert_eq!(
        select(
            &mut app,
            &vm,
            from,
            right((x, y), last_word.len() as u16 - 1)
        ),
        vec![Action::CopySelected(format!("{:<22}{desc}", "/invite"))]
    );
}

#[test]
fn a_click_on_a_box_button_still_presses_it() {
    let vm = crew();
    let mut app = App::new();
    app.modal = Some(details());
    let t = Instant::now();
    let buf = shown(&mut app, &vm, t);
    let close = find(&buf, "[ Close ]");
    assert!(app.handle_mouse(press(close), later(t), &vm).is_empty());
    assert!(app.handle_mouse(release(close), later(t), &vm).is_empty());
    assert!(app.modal.is_none());
}

/// A drag that starts on the help box's picked row selects text and runs
/// nothing; a plain click on that row still uses it.
#[test]
fn a_drag_on_the_picked_help_row_copies_instead_of_using_it() {
    let vm = crew();
    let mut app = App::new();
    app.modal = Some(help_box());
    let buf = shown(&mut app, &vm, Instant::now());
    let from = find(&buf, "/about ");
    assert_eq!(picked(&app, &buf), "/about");
    assert_eq!(
        select(&mut app, &vm, from, right(from, 5)),
        vec![Action::CopySelected("/about".into())]
    );
    assert!(
        matches!(app.modal, Some(Modal::Help { .. })),
        "the box stays open"
    );
}

/// Dragging past the bottom of the help box moves the highlight on and
/// scrolls the box, so a selection can grow past one screen.
#[test]
fn dragging_past_the_help_box_scrolls_it() {
    let vm = crew();
    let mut app = App::new();
    app.modal = Some(help_box());
    let t = Instant::now();
    let buf = shown(&mut app, &vm, t);
    let from = find(&buf, "/about ");
    let below = find(&buf, "↓ more");
    app.handle_mouse(press(from), later(t), &vm);
    for _ in 0..3 {
        app.handle_mouse(drag_to(below), later(t), &vm);
        shown(&mut app, &vm, t);
    }
    let Some(Modal::Help { offset, .. }) = app.modal else {
        panic!("{:?}", app.modal);
    };
    assert!(offset > 0, "the box scrolled");
    let acts = app.handle_mouse(release(below), later(t), &vm);
    let [Action::CopySelected(text)] = acts.as_slice() else {
        panic!("{acts:?}");
    };
    assert!(text.starts_with("/about "), "{text}");
    assert!(text.lines().count() > 18, "{text}");
}

/// An invite line copies as plain text: the command it makes stand out
/// copies with the words around it.
#[test]
fn an_invite_line_copies_as_plain_text() {
    let text = "Ada invites you to Climbing Saturdays. Type /join Climbing Saturdays to join.";
    let at = text.find("/join").unwrap();
    let mut vm = crew();
    vm.lines = vec![LineView {
        sender: String::new(),
        text: text.into(),
        notice: true,
        command: Some(at..text.len() - " to join.".len()),
        ..line(0)
    }];
    let (mut app, buf) = open(&vm);
    let from = find(&buf, "Ada invites");
    let to = right(find(&buf, "to join."), 7);
    assert_eq!(
        select(&mut app, &vm, from, to),
        vec![Action::CopySelected(text.into())]
    );
}

/// Ctrl-C with text selected copies it, as letting go of the drag did,
/// and the next two quit.
#[test]
fn ctrl_c_copies_a_selection_before_it_quits() {
    let vm = crew();
    let (mut app, buf) = open(&vm);
    let from = find(&buf, "message 38");
    let to = right(find(&buf, "message 38"), 9);
    let copied = vec![Action::CopySelected("message 38".into())];
    assert_eq!(select(&mut app, &vm, from, to), copied);
    let c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
    assert_eq!(app.handle_key(c, &vm), copied);
    assert_ne!(app.status.as_deref(), Some("Press Ctrl-C again to quit."));
    assert!(app.handle_key(c, &vm).is_empty());
    assert_eq!(app.status.as_deref(), Some("Press Ctrl-C again to quit."));
    assert_eq!(app.handle_key(c, &vm), vec![Action::Quit]);
}
