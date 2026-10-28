//! Keys that arrive all in one read are a paste: some terminals write a
//! dropped file's path as plain keys, with no paste markers around it.

use super::*;
use crossterm::event::{
    Event as TermEvent, KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers,
};
use std::collections::VecDeque;
use std::time::Duration;

use super::super::{Input, Read, Reader};

/// What Nyx writes for a file dropped on its window: 66 bytes, the path
/// in single quotes with its spaces bare, and no paste markers.
const NYX_DROP: &str = "'/Users/jupiter/Downloads/engineering_interview_cribsheet (1).pdf'";

fn press(code: KeyCode, mods: KeyModifiers) -> TermEvent {
    TermEvent::Key(KeyEvent::new(code, mods))
}

fn release(c: char) -> TermEvent {
    TermEvent::Key(KeyEvent {
        code: KeyCode::Char(c),
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Release,
        state: KeyEventState::NONE,
    })
}

/// Each character as a terminal reports it typed: capitals with Shift.
fn typed(text: &str) -> Vec<TermEvent> {
    text.chars()
        .map(|c| {
            let mods = match c.is_uppercase() {
                true => KeyModifiers::SHIFT,
                false => KeyModifiers::NONE,
            };
            press(KeyCode::Char(c), mods)
        })
        .collect()
}

/// A terminal that hands over `reads`, each a group of events that
/// arrive together: a look that waits gets the next group, a look that
/// does not wait sees only what is left of the group already arriving.
fn reader(
    reads: Vec<Vec<TermEvent>>,
) -> Reader<impl FnMut(Duration) -> std::io::Result<Option<TermEvent>>> {
    let mut reads: VecDeque<VecDeque<TermEvent>> = reads.into_iter().map(VecDeque::from).collect();
    Reader::new(move |wait: Duration| {
        if let Some(ev) = reads.front_mut().and_then(VecDeque::pop_front) {
            return Ok(Some(ev));
        }
        if wait.is_zero() {
            return Ok(None);
        }
        reads.pop_front();
        Ok(reads.front_mut().and_then(VecDeque::pop_front))
    })
}

/// What the screen hears, until the terminal has nothing more.
fn heard(mut r: Reader<impl FnMut(Duration) -> std::io::Result<Option<TermEvent>>>) -> Vec<String> {
    let mut out = vec![];
    for _ in 0..1000 {
        match r.next() {
            Read::Got(Input::Key(k, _)) => out.push(format!("key {:?} {:?}", k.code, k.modifiers)),
            Read::Got(Input::Paste(t)) => out.push(format!("paste {t}")),
            Read::Got(_) => out.push("other".into()),
            // Every read the fake terminal holds has some event in it.
            Read::Nothing | Read::Stop => return out,
        }
    }
    panic!("the reader never ran dry: {out:?}");
}

fn key(c: char) -> String {
    let mods = match c.is_uppercase() {
        true => KeyModifiers::SHIFT,
        false => KeyModifiers::NONE,
    };
    format!("key {:?} {:?}", KeyCode::Char(c), mods)
}

#[test]
fn a_dropped_path_written_as_keys_is_one_paste() {
    assert_eq!(NYX_DROP.len(), 66);
    assert_eq!(
        heard(reader(vec![typed(NYX_DROP)])),
        [format!("paste {NYX_DROP}")]
    );
    // With Enter in the same read: the paste, then Enter as a key.
    let mut burst = typed(NYX_DROP);
    burst.push(press(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(
        heard(reader(vec![burst])),
        [
            format!("paste {NYX_DROP}"),
            format!("key {:?} {:?}", KeyCode::Enter, KeyModifiers::NONE)
        ]
    );
}

#[test]
fn typing_and_key_repeat_stay_keys() {
    // One key per read, as a person types or a held key repeats.
    let one_by_one = |text: &str| text.chars().map(|c| typed(&c.to_string())).collect();
    assert_eq!(
        heard(reader(one_by_one("Hi Bo"))),
        "Hi Bo".chars().map(key).collect::<Vec<_>>()
    );
    assert_eq!(heard(reader(one_by_one("aaaaaaaa"))), vec![key('a'); 8]);
    // Two keys pressed together can share a read: still keys.
    assert_eq!(
        heard(reader(vec![typed("th"), typed("e")])),
        [key('t'), key('h'), key('e')]
    );
}

#[test]
fn a_burst_stops_at_the_first_key_that_is_not_a_character() {
    let mut burst = typed("ab");
    burst.push(press(KeyCode::Char('c'), KeyModifiers::CONTROL));
    burst.extend(typed("defg"));
    burst.push(press(KeyCode::Backspace, KeyModifiers::NONE));
    burst.extend(typed("hij"));
    assert_eq!(
        heard(reader(vec![burst])),
        [
            key('a'),
            key('b'),
            format!("key {:?} {:?}", KeyCode::Char('c'), KeyModifiers::CONTROL),
            "paste defg".into(),
            format!("key {:?} {:?}", KeyCode::Backspace, KeyModifiers::NONE),
            "paste hij".into(),
        ]
    );
    // Alt makes a key that is not plain text either.
    let mut burst = typed("xyz");
    burst.push(press(KeyCode::Char('b'), KeyModifiers::ALT));
    assert_eq!(heard(reader(vec![burst]))[0], "paste xyz");
}

#[test]
fn capitals_and_key_releases_do_not_break_a_burst() {
    // Windows reports each key's release too.
    let burst: Vec<TermEvent> = "My doc"
        .chars()
        .flat_map(|c| [typed(&c.to_string()).remove(0), release(c)])
        .collect();
    assert_eq!(heard(reader(vec![burst])), ["paste My doc"]);
}

/// Text that piled up while the app was busy ends up in the box as the
/// same text, whether it came as keys or as one paste.
#[test]
fn piled_up_typing_ends_as_the_same_text() {
    let words = "See you at 6, Bo! (bring snacks)";
    let mut typed_app = crate::app::App::new();
    let vm = blank_view();
    for c in words.chars() {
        typed_app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE), &vm);
    }
    let mut pasted_app = crate::app::App::new();
    let heard = heard(reader(vec![typed(words)]));
    assert_eq!(heard, [format!("paste {words}")]);
    pasted_app.handle_paste(words);
    assert_eq!(pasted_app.input, typed_app.input);
}

fn blank_view() -> crate::ui::ViewModel {
    crate::ui::ViewModel {
        me: "Bo".into(),
        groups: vec![],
        lines: vec![],
        members: vec![],
        connected: true,
        server: None,
        topic: None,
        invite_names: vec![],
        join_rooms: vec![],
        save_files: vec![],
    }
}

/// The whole way: Nyx's drop, read as one paste, waits in the box as a
/// file, and nothing goes to the room until Enter.
#[cfg(unix)]
#[tokio::test]
async fn a_drop_written_as_keys_becomes_a_placeholder_at_once() {
    let srv = TestServer::start().await;
    let (g, _a, mut bo, _dir) = room_with_bo(&srv).await;
    bo.act(Action::Select(g)).await;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("engineering_interview_cribsheet (1).pdf");
    std::fs::write(&p, b"%PDF-1.7").unwrap();
    let drop = format!("'{}'", p.display());
    let before = bo.client.messages(g, 50).len();
    let mut r = reader(vec![typed(&drop)]);
    while let Read::Got(i) = r.next() {
        let vm = bo.view();
        let acts = match i {
            Input::Key(k, _) => bo.app.handle_key(k, &vm),
            Input::Paste(t) => bo.app.handle_paste(&t),
            _ => vec![],
        };
        for a in acts {
            bo.act(a).await;
        }
    }
    assert_eq!(bo.app.input, "[File 1] ");
    assert_eq!(
        bo.app.status.as_deref(),
        Some("File 1 is engineering_interview_cribsheet (1).pdf, 8 bytes. Enter sends it.")
    );
    assert_eq!(bo.client.messages(g, 50).len(), before, "nothing went");
}

/// A burst over an open box, or with another panel focused, does what a
/// paste does there: the box closes, and the text goes in the message
/// box.
#[test]
fn a_burst_over_a_box_or_another_panel_acts_as_a_paste() {
    let vm = blank_view();
    for setup in [
        |a: &mut crate::app::App| a.modal = Some(crate::app::Modal::Help { offset: 0, pick: 0 }),
        |a: &mut crate::app::App| a.focus = crate::app::Focus::Members,
    ] {
        let mut app = crate::app::App::new();
        setup(&mut app);
        let mut r = reader(vec![typed("hello")]);
        while let Read::Got(i) = r.next() {
            match i {
                Input::Key(k, _) => drop(app.handle_key(k, &vm)),
                Input::Paste(t) => drop(app.handle_paste(&t)),
                _ => {}
            }
        }
        assert_eq!(app.modal, None);
        assert_eq!(app.focus, crate::app::Focus::Input);
        assert_eq!(app.input, "hello");
    }
}
