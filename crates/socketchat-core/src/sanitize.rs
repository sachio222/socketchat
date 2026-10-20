//! Cleans text from other people before it reaches a terminal: no control
//! characters that could move the cursor or recolor the screen, no
//! direction overrides that could disguise a name, no invisible characters
//! that make two different names look the same, and a size cap.

/// Longest display name, in characters.
pub const MAX_NAME_CHARS: usize = 64;
/// Longest message, in bytes.
pub const MAX_TEXT_BYTES: usize = 16 * 1024;

/// Unicode's format characters (general category Cf, Unicode 16): they
/// draw nothing, or change how the text around them is laid out. This
/// covers zero-width spaces and joiners, direction marks and overrides,
/// the byte-order mark and the tag characters.
fn format_char(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

/// Hangul fillers: letters that draw as blank space, so a name made of
/// them looks empty.
fn hangul_filler(c: char) -> bool {
    matches!(c, '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}')
}

fn unsafe_char(c: char, keep_newline: bool) -> bool {
    if keep_newline && c == '\n' {
        return false;
    }
    c.is_control() || format_char(c) || hangul_filler(c)
}

/// A display name with unsafe characters removed, trimmed and capped.
pub fn clean_name(s: &str) -> String {
    let cleaned: String = s.chars().filter(|c| !unsafe_char(*c, false)).collect();
    cleaned.trim().chars().take(MAX_NAME_CHARS).collect()
}

/// Message text with unsafe characters removed (newlines kept), capped.
pub fn clean_text(s: &str) -> String {
    let cleaned: String = s.chars().filter(|c| !unsafe_char(*c, true)).collect();
    if cleaned.len() <= MAX_TEXT_BYTES {
        return cleaned;
    }
    let mut end = MAX_TEXT_BYTES;
    while !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    cleaned[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_escape_sequences() {
        assert_eq!(clean_name("\x1b[31mAda\x1b[0m"), "[31mAda[0m");
        assert_eq!(clean_text("hi\x07\x1b]0;title\x07"), "hi]0;title");
    }

    #[test]
    fn strips_bidi_overrides() {
        assert_eq!(clean_name("Ada\u{202E}gnp.exe"), "Adagnp.exe");
        assert_eq!(clean_name("\u{2066}Bo\u{2069}"), "Bo");
    }

    #[test]
    fn strips_invisible_format_characters() {
        assert_eq!(clean_name("A\u{200B}d\u{200C}a\u{200D}"), "Ada");
        assert_eq!(clean_name("\u{2060}Bo\u{FEFF}"), "Bo");
        assert_eq!(clean_name("Cy\u{E0041}\u{E007F}"), "Cy");
        assert_eq!(clean_name("soft\u{00AD}ware"), "software");
        assert_eq!(clean_name("x\u{2064}\u{206F}\u{FFF9}y"), "xy");
        assert_eq!(clean_text("hi\u{200B}there\u{FEFF}"), "hithere");
    }

    #[test]
    fn strips_hangul_fillers() {
        assert_eq!(clean_name("\u{3164}"), "");
        assert_eq!(clean_name("D\u{115F}\u{1160}a\u{FFA0}n"), "Dan");
        assert_eq!(clean_text("a\u{3164}b"), "ab");
    }

    #[test]
    fn names_capped_and_trimmed() {
        let long = "x".repeat(200);
        assert_eq!(clean_name(&long).chars().count(), MAX_NAME_CHARS);
        assert_eq!(clean_name("  Ada \n"), "Ada");
        assert_eq!(clean_name(&"é".repeat(100)).chars().count(), MAX_NAME_CHARS);
    }

    #[test]
    fn text_keeps_newlines_and_caps_on_char_boundary() {
        assert_eq!(clean_text("a\nb\r\n"), "a\nb\n");
        let t = clean_text(&"é".repeat(20_000));
        assert!(t.len() <= MAX_TEXT_BYTES);
        assert!(t.chars().all(|c| c == 'é'));
    }
}
