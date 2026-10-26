use ratatui::backend::TestBackend;
use ratatui::style::Color;
use ratatui::Terminal;
use socketchat_core::keys::Key;
use socketchat_proto::msg::GroupId;
use socketchat_tui::app::App;
use socketchat_tui::commands::{parse_command, Command, HELP};
use socketchat_tui::theme::{pick_theme, ColorSupport, Theme, ThemeName};
use socketchat_tui::ui::{draw, GroupView, LineView, MemberLine, ViewModel};

fn vm() -> ViewModel {
    ViewModel {
        me: "Ada".into(),
        groups: vec![GroupView {
            id: GroupId([1; 16]),
            name: "Book club".into(),
            unread: 0,
            is_dm: false,
            muted: false,
            ended: None,
        }],
        lines: vec![LineView {
            time: "00:36:08".into(),
            sender: "Ada".into(),
            text: "Finished Piranesi last night.".into(),
            notice: false,
            mine: true,
            topic: false,
            command: None,
        }],
        members: vec![MemberLine {
            key: Key([1; 32]),
            name: "Ada".into(),
            verified: true,
            admin: false,
            me: true,
            changed_key: false,
        }],
        connected: true,
        server: None,
        topic: None,
        invite_names: vec![],
        join_rooms: vec![],
    }
}

fn buffer(app: &App) -> ratatui::buffer::Buffer {
    let mut t = Terminal::new(TestBackend::new(80, 24)).unwrap();
    t.draw(|f| draw(f, app, &vm())).unwrap();
    t.backend().buffer().clone()
}

fn app() -> App {
    let mut a = App::new();
    a.selected = Some(GroupId([1; 16]));
    a
}

#[test]
fn the_theme_defaults_to_phosphor() {
    assert_eq!(App::new().theme.name, ThemeName::Phosphor);
    assert_eq!(pick_theme(None, None, None).name, ThemeName::Phosphor);
}

#[test]
fn a_saved_choice_is_used() {
    assert_eq!(
        pick_theme(Some("classic"), None, None).name,
        ThemeName::Classic
    );
}

#[test]
fn the_env_var_beats_the_saved_choice() {
    let t = pick_theme(Some("phosphor"), Some("classic"), None);
    assert_eq!(t.name, ThemeName::Classic);
    let t = pick_theme(Some("classic"), Some("phosphor"), None);
    assert_eq!(t.name, ThemeName::Phosphor);
    // A name nobody knows falls back to the saved choice.
    let t = pick_theme(Some("classic"), Some("neon"), None);
    assert_eq!(t.name, ThemeName::Classic);
}

#[test]
fn truecolor_comes_from_colorterm() {
    assert_eq!(
        ColorSupport::from_colorterm(Some("truecolor")),
        ColorSupport::TrueColor
    );
    assert_eq!(
        ColorSupport::from_colorterm(Some("24bit")),
        ColorSupport::TrueColor
    );
    assert_eq!(ColorSupport::from_colorterm(None), ColorSupport::Indexed256);
    assert_eq!(
        ColorSupport::from_colorterm(Some("")),
        ColorSupport::Indexed256
    );
    assert_eq!(
        ColorSupport::from_colorterm(Some("yes")),
        ColorSupport::Indexed256
    );
}

#[test]
fn phosphor_uses_rgb_on_truecolor_and_indexed_colors_otherwise() {
    let rgb = pick_theme(None, None, Some("truecolor"));
    assert_eq!(rgb.selected.bg, Some(Color::Rgb(125, 255, 106)));
    assert_eq!(rgb.base.bg, Some(Color::Rgb(4, 6, 5)));
    let idx = pick_theme(None, None, Some("256color"));
    assert_eq!(idx.selected.bg, Some(Color::Indexed(119)));
    assert_eq!(idx.base.bg, Some(Color::Indexed(232)));
    for c in [
        idx.base.fg,
        idx.base.bg,
        idx.good.fg,
        idx.accent.fg,
        idx.dim.fg,
        idx.warn.fg,
    ] {
        assert!(matches!(c, Some(Color::Indexed(_))), "{c:?}");
    }
}

#[test]
fn classic_keeps_the_terminals_own_colors() {
    let t = Theme::classic(ColorSupport::Indexed256);
    assert_eq!(t.base.bg, None);
    assert_eq!(t.base.fg, None);
    assert_eq!(t.dim.fg, Some(Color::DarkGray));
    assert_eq!(t.accent.fg, Some(Color::Cyan));
    assert_eq!(t.good.fg, Some(Color::Green));
    assert_eq!(t.warn.fg, Some(Color::Yellow));
}

#[test]
fn classic_keeps_what_the_terminal_can_show() {
    let t = Theme::new(ThemeName::Classic, ColorSupport::TrueColor);
    assert_eq!(t.support, ColorSupport::TrueColor);
    let t = Theme::new(ThemeName::Classic, ColorSupport::Indexed256);
    assert_eq!(t.support, ColorSupport::Indexed256);
    // Only the field differs: classic draws the same named colors on both.
    let mut rgb = Theme::classic(ColorSupport::TrueColor);
    rgb.support = ColorSupport::Indexed256;
    assert_eq!(rgb, Theme::classic(ColorSupport::Indexed256));
}

#[test]
fn warnings_stay_red_and_yellow_in_both_themes() {
    for t in [
        Theme::classic(ColorSupport::Indexed256),
        Theme::new(ThemeName::Phosphor, ColorSupport::TrueColor),
        Theme::new(ThemeName::Phosphor, ColorSupport::Indexed256),
    ] {
        assert!(t.banner.bg.is_some() && t.warn.fg.is_some());
        assert_ne!(t.warn.fg, t.good.fg);
        assert_ne!(t.banner.bg, t.base.bg);
    }
}

#[test]
fn phosphor_paints_the_whole_screen_and_the_selected_chat_as_a_green_block() {
    let buf = buffer(&app());
    for (x, y) in [(0, 0), (79, 0), (40, 12), (79, 23), (0, 23)] {
        assert_eq!(buf[(x, y)].bg, Color::Rgb(4, 6, 5), "({x}, {y})");
    }
    // "# Book club" in the chat list: black on bright green.
    let sel = &buf[(2, 1)];
    assert_eq!(sel.bg, Color::Rgb(125, 255, 106));
    assert_eq!(sel.fg, Color::Rgb(3, 16, 4));
    // The timestamp is green on the dark screen.
    assert_eq!(buf[(22, 1)].fg, Color::Rgb(125, 255, 106));
}

#[test]
fn classic_leaves_the_background_to_the_terminal() {
    let mut a = app();
    a.theme = Theme::classic(ColorSupport::Indexed256);
    let buf = buffer(&a);
    assert_eq!(buf[(40, 12)].bg, Color::Reset);
    assert_eq!(buf[(0, 0)].fg, Color::DarkGray);
}

#[test]
fn theme_command_parses() {
    assert_eq!(parse_command("/theme"), Ok(Command::Theme(None)));
    assert_eq!(
        parse_command("/theme classic"),
        Ok(Command::Theme(Some("classic".into())))
    );
    assert!(HELP.iter().any(|(c, _)| c.starts_with("/theme")));
}
