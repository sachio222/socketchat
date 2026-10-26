//! A room's settings: who can bring people in, how often members who are
//! not admins can post, and who can set the room's topic.
//!
//! They travel the way the admin list does, as a GroupContext extension
//! ([`crate::suite::ROOM_SETTINGS_EXT`]) that only a signed group change
//! can set. Group changes travel signed but not encrypted, so the server
//! reads the settings and enforces them, and so does every app; neither
//! the server nor a member who is not an admin can change them.
//!
//! A room on the defaults carries no extension at all, so it looks exactly
//! like a room made before settings existed.

use openmls::prelude::*;

use crate::suite::ROOM_SETTINGS_EXT;

/// Who can bring people into a room: make its invite links and add the
/// people who use them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WhoCanInvite {
    /// Anyone in the room. The default, as before settings existed.
    #[default]
    Anyone,
    /// Only the room's admins.
    Admins,
}

/// Who can set a room's topic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WhoCanSetTopic {
    /// Only the room's admins, as IRC's +t mode does. The default.
    #[default]
    Admins,
    /// Anyone in the room.
    Anyone,
}

/// The longest slow mode an admin can set: six hours, as Discord allows.
pub const MAX_SLOW_SECS: u32 = 6 * 3600;

/// Most bytes the extension may hold, settings from newer apps included.
const MAX_BYTES: usize = 1024;

/// Entry types. Each entry is a 2-byte type, a 2-byte length and the
/// value, in increasing order of type. A type this app does not know is
/// kept as it is, so changing one setting never drops a newer one.
const T_INVITE: u16 = 1;
const T_SLOW: u16 = 2;
const T_TOPIC: u16 = 3;

/// A room's settings.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoomSettings {
    pub invite: WhoCanInvite,
    /// Seconds each member who is not an admin waits between posts. 0 is
    /// off.
    pub slow_secs: u32,
    pub topic: WhoCanSetTopic,
    /// Entries from a newer Socketchat, by type, kept as they came.
    newer: Vec<(u16, Vec<u8>)>,
}

impl RoomSettings {
    /// Settings with these values and nothing from a newer app.
    pub fn new(invite: WhoCanInvite, slow_secs: u32) -> RoomSettings {
        RoomSettings {
            invite,
            slow_secs,
            ..RoomSettings::default()
        }
    }

    /// Whether these are the settings of a room that never changed any.
    pub fn is_default(&self) -> bool {
        *self == RoomSettings::default()
    }

    /// The bytes of the extension. Settings at their default are left out.
    pub fn encode(&self) -> Vec<u8> {
        let mut entries: Vec<(u16, Vec<u8>)> = self.newer.clone();
        if self.invite == WhoCanInvite::Admins {
            entries.push((T_INVITE, vec![1]));
        }
        if self.slow_secs > 0 {
            entries.push((T_SLOW, self.slow_secs.to_be_bytes().to_vec()));
        }
        if self.topic == WhoCanSetTopic::Anyone {
            entries.push((T_TOPIC, vec![1]));
        }
        entries.sort_by_key(|(t, _)| *t);
        let mut out = Vec::new();
        for (t, v) in entries {
            out.extend_from_slice(&t.to_be_bytes());
            out.extend_from_slice(&(v.len() as u16).to_be_bytes());
            out.extend_from_slice(&v);
        }
        out
    }

    /// Reads the extension's bytes. `None` for anything malformed: types
    /// out of order or repeated, a known setting with the wrong length or
    /// a value out of range, or more than 1 KB in all.
    pub fn decode(b: &[u8]) -> Option<RoomSettings> {
        Self::decode_known(b, true)
    }

    /// Reads the extension's bytes as an app from before type 3 does,
    /// keeping the topic setting as an entry it does not know.
    #[cfg(test)]
    fn decode_as_older(b: &[u8]) -> Option<RoomSettings> {
        Self::decode_known(b, false)
    }

    fn decode_known(b: &[u8], knows_topic: bool) -> Option<RoomSettings> {
        if b.len() > MAX_BYTES {
            return None;
        }
        let mut s = RoomSettings::default();
        let mut last: Option<u16> = None;
        let mut i = 0;
        while i < b.len() {
            let head = b.get(i..i + 4)?;
            let t = u16::from_be_bytes([head[0], head[1]]);
            let n = u16::from_be_bytes([head[2], head[3]]) as usize;
            let v = b.get(i + 4..i + 4 + n)?;
            if last.is_some_and(|l| t <= l) {
                return None;
            }
            last = Some(t);
            match t {
                T_INVITE => {
                    s.invite = match v {
                        [0] => WhoCanInvite::Anyone,
                        [1] => WhoCanInvite::Admins,
                        _ => return None,
                    }
                }
                T_SLOW => {
                    let secs = u32::from_be_bytes(v.try_into().ok()?);
                    if secs > MAX_SLOW_SECS {
                        return None;
                    }
                    s.slow_secs = secs;
                }
                T_TOPIC if knows_topic => {
                    s.topic = match v {
                        [0] => WhoCanSetTopic::Admins,
                        [1] => WhoCanSetTopic::Anyone,
                        _ => return None,
                    }
                }
                _ => s.newer.push((t, v.to_vec())),
            }
            i += 4 + n;
        }
        Some(s)
    }

    /// The settings as a GroupContext extension.
    pub fn extension(&self) -> Extension {
        Extension::Unknown(ROOM_SETTINGS_EXT, UnknownExtension(self.encode()))
    }
}

/// How often slow mode lets a member post, for people: "every 30
/// seconds", "every minute", "every 2 hours".
pub fn every(secs: u32) -> String {
    match secs {
        1 => "every second".into(),
        60 => "every minute".into(),
        3600 => "every hour".into(),
        s if s >= 3600 && s % 3600 == 0 => format!("every {} hours", s / 3600),
        s if s >= 60 && s % 60 == 0 => format!("every {} minutes", s / 60),
        s => format!("every {s} seconds"),
    }
}

/// The settings in a set of GroupContext extensions: the defaults when
/// there is no settings extension, `None` when there is one and it is
/// malformed. The server and every app refuse a group change that would
/// leave a malformed one.
pub fn settings_in(exts: &Extensions<GroupContext>) -> Option<RoomSettings> {
    match exts
        .iter()
        .find(|e| matches!(e, Extension::Unknown(t, _) if *t == ROOM_SETTINGS_EXT))
    {
        None => Some(RoomSettings::default()),
        Some(Extension::Unknown(_, UnknownExtension(b))) => RoomSettings::decode(b),
        Some(_) => None,
    }
}

/// The settings in force in a group: what [`settings_in`] reads, and the
/// defaults for a malformed extension, which no accepted change can leave.
pub fn room_settings(exts: &Extensions<GroupContext>) -> RoomSettings {
    settings_in(exts).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_encode_to_nothing() {
        let s = RoomSettings::default();
        assert!(s.is_default());
        assert_eq!(s.encode(), Vec::<u8>::new());
        assert_eq!(RoomSettings::decode(&[]), Some(s));
    }

    #[test]
    fn settings_round_trip() {
        for (invite, slow_secs) in [
            (WhoCanInvite::Admins, 0),
            (WhoCanInvite::Anyone, 30),
            (WhoCanInvite::Admins, MAX_SLOW_SECS),
        ] {
            let s = RoomSettings {
                invite,
                slow_secs,
                ..RoomSettings::default()
            };
            assert!(!s.is_default());
            assert_eq!(RoomSettings::decode(&s.encode()), Some(s));
        }
        let s = RoomSettings {
            invite: WhoCanInvite::Admins,
            slow_secs: 30,
            ..RoomSettings::default()
        };
        assert_eq!(s.encode(), [0, 1, 0, 1, 1, 0, 2, 0, 4, 0, 0, 0, 30]);
    }

    #[test]
    fn malformed_settings_read_as_none() {
        let bad: &[&[u8]] = &[
            // Cut short.
            &[0, 1, 0],
            &[0, 1, 0, 2, 1],
            // Who can invite: only 0 or 1, one byte.
            &[0, 1, 0, 1, 2],
            &[0, 1, 0, 2, 1, 0],
            // Slow mode: four bytes, at most six hours.
            &[0, 2, 0, 2, 0, 30],
            &[0, 2, 0, 4, 0, 0, 0x54, 0x61],
            // Out of order, or twice.
            &[0, 2, 0, 4, 0, 0, 0, 30, 0, 1, 0, 1, 1],
            &[0, 1, 0, 1, 1, 0, 1, 0, 1, 1],
        ];
        for b in bad {
            assert_eq!(RoomSettings::decode(b), None, "{b:?}");
        }
        assert_eq!(RoomSettings::decode(&vec![0; MAX_BYTES + 1]), None);
    }

    /// A setting from a newer app survives a change made here.
    #[test]
    fn newer_settings_are_kept() {
        let b = [0, 1, 0, 1, 1, 0, 4, 0, 1, 1, 0, 9, 0, 0];
        let mut s = RoomSettings::decode(&b).unwrap();
        assert_eq!(s.invite, WhoCanInvite::Admins);
        assert!(!s.is_default());
        s.slow_secs = 10;
        let again = RoomSettings::decode(&s.encode()).unwrap();
        assert_eq!(again.slow_secs, 10);
        assert_eq!(again.newer, vec![(4, vec![1]), (9, vec![])]);
        s.invite = WhoCanInvite::Anyone;
        s.slow_secs = 0;
        assert!(
            !s.is_default(),
            "the newer entries still need the extension"
        );
    }

    /// Type 3, who can set the topic: admins by default, left out then;
    /// anyone in the room as a one-byte 1.
    #[test]
    fn who_can_set_the_topic_round_trips() {
        let s = RoomSettings {
            topic: WhoCanSetTopic::Anyone,
            ..RoomSettings::default()
        };
        assert!(!s.is_default());
        assert_eq!(s.encode(), [0, 3, 0, 1, 1]);
        assert_eq!(RoomSettings::decode(&s.encode()), Some(s.clone()));
        assert_eq!(RoomSettings::default().topic, WhoCanSetTopic::Admins);
        // Admins only, written out, reads as the default.
        assert_eq!(
            RoomSettings::decode(&[0, 3, 0, 1, 0]),
            Some(RoomSettings::default())
        );
        let all = RoomSettings {
            invite: WhoCanInvite::Admins,
            slow_secs: 30,
            topic: WhoCanSetTopic::Anyone,
            ..RoomSettings::default()
        };
        assert_eq!(
            all.encode(),
            [0, 1, 0, 1, 1, 0, 2, 0, 4, 0, 0, 0, 30, 0, 3, 0, 1, 1]
        );
        assert_eq!(RoomSettings::decode(&all.encode()), Some(all));
        for bad in [&[0u8, 3, 0, 1, 2][..], &[0, 3, 0, 2, 1, 0], &[0, 3, 0, 0]] {
            assert_eq!(RoomSettings::decode(bad), None, "{bad:?}");
        }
    }

    /// An app from before type 3 keeps it as an entry it does not know:
    /// its own changes carry it on unchanged, and it never refuses it.
    #[test]
    fn an_older_app_keeps_the_topic_setting_opaque() {
        let room = RoomSettings {
            topic: WhoCanSetTopic::Anyone,
            ..RoomSettings::default()
        };
        let mut old = RoomSettings::decode_as_older(&room.encode()).unwrap();
        assert_eq!(old.topic, WhoCanSetTopic::Admins, "unknown to it");
        assert_eq!(old.newer, vec![(3, vec![1])]);
        assert!(!old.is_default());
        old.slow_secs = 60;
        let back = RoomSettings::decode(&old.encode()).unwrap();
        assert_eq!(back.topic, WhoCanSetTopic::Anyone);
        assert_eq!(back.slow_secs, 60);
        // Any value of a type it does not know is kept, never refused.
        let odd = [0, 3, 0, 3, 7, 7, 7];
        assert!(RoomSettings::decode_as_older(&odd).is_some());
        assert!(RoomSettings::decode(&odd).is_none());
    }

    #[test]
    fn periods_read_in_plain_words() {
        assert_eq!(every(1), "every second");
        assert_eq!(every(30), "every 30 seconds");
        assert_eq!(every(60), "every minute");
        assert_eq!(every(90), "every 90 seconds");
        assert_eq!(every(300), "every 5 minutes");
        assert_eq!(every(3600), "every hour");
        assert_eq!(every(7200), "every 2 hours");
        assert_eq!(every(5400), "every 90 minutes");
    }

    #[test]
    fn a_missing_extension_reads_as_the_defaults() {
        let none = Extensions::<GroupContext>::empty();
        assert_eq!(settings_in(&none), Some(RoomSettings::default()));
        let bad = Extensions::from_vec(vec![Extension::Unknown(
            ROOM_SETTINGS_EXT,
            UnknownExtension(vec![0, 1, 0, 1, 7]),
        )])
        .unwrap();
        assert_eq!(settings_in(&bad), None);
        assert_eq!(room_settings(&bad), RoomSettings::default());
    }
}
