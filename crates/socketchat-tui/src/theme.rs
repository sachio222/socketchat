//! The chat screen's colors, in one place. Every style the screen uses
//! comes from a [`Theme`].
//!
//! Two themes: `phosphor` (green on near black, painted over the whole
//! screen) and `classic` (the terminal's own colors and background).

use ratatui::style::{Color, Modifier, Style};

pub const THEMES: [&str; 2] = ["phosphor", "classic"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThemeName {
    Phosphor,
    Classic,
}

impl ThemeName {
    pub fn as_str(self) -> &'static str {
        match self {
            ThemeName::Phosphor => "phosphor",
            ThemeName::Classic => "classic",
        }
    }

    /// Reads a theme name, ignoring case and surrounding spaces.
    pub fn parse(s: &str) -> Option<ThemeName> {
        match s.trim().to_lowercase().as_str() {
            "phosphor" => Some(ThemeName::Phosphor),
            "classic" => Some(ThemeName::Classic),
            _ => None,
        }
    }
}

/// How many colors the terminal can show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorSupport {
    /// 24-bit RGB.
    TrueColor,
    /// The 256-color palette, which every common terminal has.
    Indexed256,
}

impl ColorSupport {
    /// Truecolor when `COLORTERM` says `truecolor` or `24bit`.
    pub fn from_colorterm(v: Option<&str>) -> ColorSupport {
        match v.map(|s| s.trim().to_lowercase()).as_deref() {
            Some("truecolor") | Some("24bit") => ColorSupport::TrueColor,
            _ => ColorSupport::Indexed256,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Theme {
    pub name: ThemeName,
    pub support: ColorSupport,
    /// Text and background under everything. Classic sets neither, so the
    /// terminal's own show through.
    pub base: Style,
    pub border: Style,
    pub border_focus: Style,
    /// The frame of the switcher box.
    pub overlay: Style,
    /// Panel titles.
    pub title: Style,
    /// Your own name, and a verified check mark's green.
    pub good: Style,
    /// Other people's names, links and the command list.
    pub accent: Style,
    /// The open room's name in the message box.
    pub room: Style,
    pub time_mine: Style,
    pub time_other: Style,
    pub name_mine: Style,
    pub name_other: Style,
    /// The check mark before a verified person.
    pub check: Style,
    /// Hints, muted rooms, version.
    pub dim: Style,
    /// File and notice lines.
    pub notice: Style,
    /// Status messages and people not yet verified.
    pub warn: Style,
    /// The warning bar at the top of the messages.
    pub banner: Style,
    /// The chat, person or match the cursor is on.
    pub selected: Style,
}

fn fg(c: Color) -> Style {
    Style::default().fg(c)
}

impl Theme {
    pub fn new(name: ThemeName, support: ColorSupport) -> Theme {
        match name {
            ThemeName::Phosphor => Theme::phosphor(support),
            ThemeName::Classic => Theme::classic(support),
        }
    }

    /// Today's look: named terminal colors, no background of its own.
    /// `support` only records what the terminal can show, so switching back
    /// to phosphor keeps its exact colors.
    pub fn classic(support: ColorSupport) -> Theme {
        let good = fg(Color::Green);
        let accent = fg(Color::Cyan);
        Theme {
            name: ThemeName::Classic,
            support,
            base: Style::default(),
            border: fg(Color::DarkGray),
            border_focus: accent.add_modifier(Modifier::BOLD),
            overlay: Style::default(),
            title: Style::default(),
            good,
            accent,
            room: accent.add_modifier(Modifier::BOLD),
            time_mine: good,
            time_other: accent,
            name_mine: good,
            name_other: accent,
            check: Style::default(),
            dim: fg(Color::DarkGray),
            notice: fg(Color::DarkGray).add_modifier(Modifier::ITALIC),
            warn: fg(Color::Yellow),
            banner: Style::default().fg(Color::White).bg(Color::Red),
            selected: Style::default().add_modifier(Modifier::REVERSED),
        }
    }

    /// Green on near black, after the landing page. Exact RGB on a
    /// truecolor terminal; on others, 256-color values picked by hand.
    ///
    /// | role              | RGB       | 256 |
    /// |-------------------|-----------|-----|
    /// | screen            | `#040605` | 232 |
    /// | text              | `#b9ccbc` | 250 |
    /// | titles            | `#c2cfc5` | 251 |
    /// | border            | `#2d4a33` | 238 |
    /// | focused border    | `#4aa63e` | 71  |
    /// | times, you, check | `#7dff6a` | 119 |
    /// | other names, room | `#8af0c6` | 122 |
    /// | dim, notices      | `#6b7c6e` | 242 |
    /// | selected text     | `#031004` | 16  |
    /// | warning           | `#f2c94c` | 221 |
    /// | warning bar       | white on `#b3261e` | 231 on 124 |
    pub fn phosphor(support: ColorSupport) -> Theme {
        let c = |(r, g, b): (u8, u8, u8), idx: u8| match support {
            ColorSupport::TrueColor => Color::Rgb(r, g, b),
            ColorSupport::Indexed256 => Color::Indexed(idx),
        };
        let screen = c((4, 6, 5), 232);
        let text = c((185, 204, 188), 250);
        let title = c((194, 207, 197), 251);
        let line = c((45, 74, 51), 238);
        let focus = c((74, 166, 62), 71);
        let green = c((125, 255, 106), 119);
        let mint = c((138, 240, 198), 122);
        let dim = c((107, 124, 110), 242);
        let ink = c((3, 16, 4), 16);
        let amber = c((242, 201, 76), 221);
        let red = c((179, 38, 30), 124);
        let white = c((255, 255, 255), 231);
        Theme {
            name: ThemeName::Phosphor,
            support,
            base: Style::default().fg(text).bg(screen),
            border: fg(line),
            border_focus: fg(focus).add_modifier(Modifier::BOLD),
            overlay: fg(line),
            title: fg(title),
            good: fg(green),
            accent: fg(mint),
            room: fg(mint).add_modifier(Modifier::BOLD),
            time_mine: fg(green),
            time_other: fg(green),
            name_mine: fg(green),
            name_other: fg(mint),
            check: fg(green),
            dim: fg(dim),
            notice: fg(dim).add_modifier(Modifier::ITALIC),
            warn: fg(amber),
            banner: Style::default().fg(white).bg(red),
            selected: Style::default().fg(ink).bg(green),
        }
    }
}

impl Default for Theme {
    fn default() -> Theme {
        Theme::phosphor(ColorSupport::TrueColor)
    }
}

/// The theme for this run: the `SOCKETCHAT_THEME` value if it names a
/// theme, else the choice saved in the profile, else phosphor. `colorterm`
/// is the `COLORTERM` value.
pub fn pick_theme(saved: Option<&str>, env: Option<&str>, colorterm: Option<&str>) -> Theme {
    let name = env
        .and_then(ThemeName::parse)
        .or_else(|| saved.and_then(ThemeName::parse))
        .unwrap_or(ThemeName::Phosphor);
    Theme::new(name, ColorSupport::from_colorterm(colorterm))
}
