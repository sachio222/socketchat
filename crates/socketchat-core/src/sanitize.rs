//! Cleans text from other people before it reaches a terminal: no control
//! characters that could move the cursor or recolor the screen, no
//! direction overrides that could disguise a name, and a size cap.

/// Longest display name, in characters.
pub const MAX_NAME_CHARS: usize = 64;
/// Longest message, in bytes.
pub const MAX_TEXT_BYTES: usize = 16 * 1024;

fn unsafe_char(c: char, keep_newline: bool) -> bool {
    if keep_newline && c == '\n' {
        return false;
    }
    c.is_control()
        || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}')
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
