//! Selecting text with the mouse: the cells a drag covers, and the text
//! they hold as the screen shows it, ready to copy.

use ratatui::layout::Rect;

use crate::ui::drawn_clusters;

/// How a row of text follows the row above it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Join {
    /// It starts a line of its own: a new message, a line break inside
    /// one, or a new line in a box.
    Line,
    /// The screen wrapped a line at a space.
    Space,
    /// The screen cut a word too long for one row.
    Cut,
}

/// One row of text as drawn: what it shows from the left edge of its
/// area, how many columns at its start are indent rather than text, and
/// how it follows the row above.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextRow {
    pub text: String,
    pub indent: usize,
    pub join: Join,
}

/// Where a selection is made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Area {
    Messages,
    /// The open box.
    Box,
}

/// A cell in an area's text. `row` counts rows down the area; in the
/// messages it counts back from the newest row as a negative number, so
/// a spot stays on its text while the messages scroll. `col` counts
/// columns from the area's left edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Spot {
    pub row: i64,
    pub col: usize,
}

/// Where the last draw put an area's rows of text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextArea {
    /// The cells the rows of text take, one screen row each.
    pub rect: Rect,
    /// The [`Spot::row`] of the top row.
    pub top: i64,
    /// Whether rows are hidden above the top, or below the bottom.
    pub more_above: bool,
    pub more_below: bool,
    /// The width the rows were wrapped to.
    pub width: usize,
}

impl TextArea {
    /// The spot under the screen cell `(x, y)`, held to the rows on
    /// screen, and which way the cell lies outside them: -1 above, 1
    /// below, 0 level with them. `None` while no rows show.
    pub fn spot(&self, x: u16, y: u16) -> Option<(Spot, i8)> {
        let r = self.rect;
        if r.height == 0 {
            return None;
        }
        let col = if x < r.x {
            0
        } else if x >= r.right() {
            usize::MAX
        } else {
            (x - r.x) as usize
        };
        Some(if y < r.y {
            (
                Spot {
                    row: self.top,
                    col: 0,
                },
                -1,
            )
        } else if y >= r.bottom() {
            (
                Spot {
                    row: self.top + r.height as i64 - 1,
                    col: usize::MAX,
                },
                1,
            )
        } else {
            (
                Spot {
                    row: self.top + (y - r.y) as i64,
                    col,
                },
                0,
            )
        })
    }
}

/// What `row` shows from column `from` up to and including column `to`,
/// in the clusters ratatui draws, leaving out the indent: the text, and
/// the columns it takes, from the first up to but not including the end.
pub fn covered(row: &TextRow, from: usize, to: usize) -> (String, Option<(usize, usize)>) {
    let from = from.max(row.indent);
    let mut text = String::new();
    let mut span: Option<(usize, usize)> = None;
    let mut col = 0;
    for (g, w) in drawn_clusters(&row.text) {
        let (start, end) = (col, col + w);
        col = end;
        if start > to {
            break;
        }
        // A cluster that takes no column shows nothing.
        if w > 0 && end > from {
            text.push_str(g);
            span = Some((span.map_or(start, |s| s.0), end));
        }
    }
    (text, span)
}

/// The two ends of a selection, the earlier first.
pub fn ordered(a: Spot, b: Spot) -> (Spot, Spot) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

/// The columns of the row at `row` that the selection from `a` to `b`
/// covers: from, and to, inclusive.
pub fn cols_of(row: i64, a: Spot, b: Spot) -> Option<(usize, usize)> {
    let (s, e) = ordered(a, b);
    let from = if row == s.row { s.col } else { 0 };
    let to = if row == e.row { e.col } else { usize::MAX };
    (s.row..=e.row).contains(&row).then_some((from, to))
}

/// The text a selection from `a` to `b` covers in `rows`, each with its
/// [`Spot::row`], top first. Rows the screen wrapped come back as one
/// line, joined at the space the wrap took or at nothing where a word
/// was cut; a row that starts a line starts a new line. Indents, the
/// spaces at the end of each line and the blank lines at the end are
/// left out.
pub fn picked<'a>(rows: impl IntoIterator<Item = (i64, &'a TextRow)>, a: Spot, b: Spot) -> String {
    let mut out = String::new();
    for (id, row) in rows {
        let Some((from, to)) = cols_of(id, a, b) else {
            continue;
        };
        let (text, _) = covered(row, from, to);
        if !out.is_empty() {
            match row.join {
                Join::Line => out.push('\n'),
                Join::Space if !out.ends_with(char::is_whitespace) => out.push(' '),
                Join::Space | Join::Cut => {}
            }
        }
        out.push_str(&text);
    }
    let lines: Vec<&str> = out.lines().map(str::trim_end).collect();
    lines.join("\n").trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(text: &str, indent: usize, join: Join) -> TextRow {
        TextRow {
            text: text.into(),
            indent,
            join,
        }
    }

    fn spot(row: i64, col: usize) -> Spot {
        Spot { row, col }
    }

    #[test]
    fn rows_join_by_how_they_were_wrapped() {
        let rows = [
            row("09:00 Bo: one two", 0, Join::Line),
            row("      three", 6, Join::Space),
            row("      four", 6, Join::Cut),
            row("      second line  ", 6, Join::Line),
        ];
        let all = |a, b| picked(rows.iter().enumerate().map(|(i, r)| (i as i64, r)), a, b);
        assert_eq!(
            all(spot(0, 0), spot(3, usize::MAX)),
            "09:00 Bo: one two threefour\nsecond line"
        );
        // Backwards, the same text.
        assert_eq!(
            all(spot(3, usize::MAX), spot(0, 0)),
            "09:00 Bo: one two threefour\nsecond line"
        );
        // Starting in the indent starts at the text; columns are inclusive.
        assert_eq!(all(spot(1, 2), spot(1, 8)), "thr");
        // Past the end of a row and on into the next: no space before it.
        assert_eq!(all(spot(0, 40), spot(1, 10)), "three");
    }

    #[test]
    fn wide_characters_are_taken_whole() {
        let r = row("漢字ab", 0, Join::Line);
        // Column 1 is the right half of 漢, column 2 the left of 字.
        assert_eq!(covered(&r, 1, 2), ("漢字".to_string(), Some((0, 4))));
        assert_eq!(covered(&r, 4, 4), ("a".to_string(), Some((4, 5))));
        assert_eq!(covered(&r, 9, 12), (String::new(), None));
    }

    #[test]
    fn a_spot_is_held_to_the_rows_on_screen() {
        let a = TextArea {
            rect: Rect::new(10, 5, 20, 3),
            top: -7,
            more_above: true,
            more_below: false,
            width: 20,
        };
        assert_eq!(a.spot(12, 6), Some((spot(-6, 2), 0)));
        assert_eq!(a.spot(12, 2), Some((spot(-7, 0), -1)));
        assert_eq!(a.spot(12, 9), Some((spot(-5, usize::MAX), 1)));
        assert_eq!(a.spot(40, 5), Some((spot(-7, usize::MAX), 0)));
        assert_eq!(a.spot(0, 5), Some((spot(-7, 0), 0)));
        let empty = TextArea {
            rect: Rect::new(10, 5, 20, 0),
            ..a
        };
        assert_eq!(empty.spot(12, 5), None);
    }
}
