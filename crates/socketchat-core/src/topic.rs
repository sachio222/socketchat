//! A room's topic as people read it: one line, set by an admin, or by
//! anyone in a room that allows it.
//!
//! The topic travels inside the room's encrypted messages
//! ([`crate::appmsg::Topic`]), so the server never sees it. Every app
//! cleans it with [`crate::sanitize::clean_topic`] before it is kept or
//! shown, and every place it shows starts it with `Topic:`.

use crate::keys::Key;

/// A room's topic, as this app holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TopicView {
    /// The topic, cleaned.
    pub text: String,
    /// Who set it, as this app names them.
    pub by: String,
    /// Their key in the room.
    pub by_key: Key,
    /// Whether this person marked them verified.
    pub verified: bool,
    /// This person set it.
    pub mine: bool,
    /// When it was set, by the setter's clock, never later than when this
    /// app learned it.
    pub set_unix: u64,
}

impl TopicView {
    /// "Topic: <text> (set by Ada, verified, 2026-10-25)", with the date
    /// `date` gives.
    pub fn words(&self, date: &str) -> String {
        words(&self.text, &self.by, self.verified, self.mine, date)
    }
}

/// How the app writes a topic and who set it: "Topic: <text> (set by
/// Ada, verified, 2026-10-25)", "(set by you, ...)" for one's own, and
/// "Topic: none (cleared by ...)" for empty text. The text is cleaned
/// again here, so no caller can print it raw.
pub fn words(text: &str, by: &str, verified: bool, mine: bool, date: &str) -> String {
    let text = crate::sanitize::clean_topic(text);
    let who = if mine {
        "you".to_string()
    } else {
        let by = crate::sanitize::clean_name(by);
        let state = if verified { "verified" } else { "unverified" };
        format!("{by}, {state}")
    };
    if text.is_empty() {
        format!("Topic: none (cleared by {who}, {date})")
    } else {
        format!("Topic: {text} (set by {who}, {date})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_topic_reads_with_who_set_it_and_when() {
        assert_eq!(
            words("Piranesi", "Ada", true, false, "2026-10-25"),
            "Topic: Piranesi (set by Ada, verified, 2026-10-25)"
        );
        assert_eq!(
            words("Piranesi", "Bo", false, false, "2026-10-25"),
            "Topic: Piranesi (set by Bo, unverified, 2026-10-25)"
        );
        assert_eq!(
            words("Piranesi", "Ada", false, true, "2026-10-25"),
            "Topic: Piranesi (set by you, 2026-10-25)"
        );
        assert_eq!(
            words("", "Ada", true, false, "2026-10-25"),
            "Topic: none (cleared by Ada, verified, 2026-10-25)"
        );
        assert_eq!(
            words("a\n\x1b[2Jb", "M\u{202E}al", false, false, "d"),
            "Topic: a [2Jb (set by Mal, unverified, d)"
        );
    }
}
