//! Each room's rules as the server enforces them, and how fast each member
//! may post.
//!
//! A room's admins and settings live in its MLS group context, which only a
//! signed group change can set (`groups::check_commit` decides who may).
//! Reading them means loading the whole group, so they are kept here per
//! room, loaded on first use and replaced whenever a change is merged.
//!
//! The pace limit is a token bucket per member key per room, counting
//! messages and bytes: a burst, then a steady refill. A room's slow mode
//! adds a second limit for members who are not admins: one post per
//! period. A post must pass both, so the stricter limit wins. Buckets live
//! in memory only; a restart gives everyone a full burst.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use openmls::prelude::*;
use rusqlite::Connection;
use socketchat_core::settings::{room_settings, RoomSettings};
use socketchat_core::suite::admins_from;
use socketchat_proto::msg::{GroupId as Gid, Key};

use crate::groups::MAX_MLS;
use crate::{relock, State};

/// What the server enforces in one room.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RoomRules {
    pub admins: Vec<Key>,
    pub settings: RoomSettings,
}

impl RoomRules {
    pub fn from_context(exts: &Extensions<GroupContext>) -> RoomRules {
        RoomRules {
            admins: admins_from(exts),
            settings: room_settings(exts),
        }
    }
}

/// Rooms' rules by group, as last read or merged.
#[derive(Default)]
pub(crate) struct Rules(Mutex<HashMap<Gid, Arc<RoomRules>>>);

impl Rules {
    /// The rules of `group`, loaded from its stored state on first use.
    /// `None` when the group cannot be loaded.
    pub fn get(&self, db: &Connection, group: &Gid) -> Option<Arc<RoomRules>> {
        if let Some(r) = relock(&self.0).get(group) {
            return Some(r.clone());
        }
        let storage = crate::groups::storage(db);
        let pg = PublicGroup::load(&storage, &GroupId::from_slice(&group.0))
            .ok()
            .flatten()?;
        let rules = Arc::new(RoomRules::from_context(pg.group_context().extensions()));
        relock(&self.0).insert(*group, rules.clone());
        Some(rules)
    }

    /// Records the rules a merged change left. Called with the database
    /// lock held, so no post reads the room between the merge and this.
    pub fn set(&self, group: Gid, rules: RoomRules) {
        relock(&self.0).insert(group, Arc::new(rules));
    }

    pub fn forget(&self, group: &Gid) {
        relock(&self.0).remove(group);
    }
}

/// One member's allowance in one room.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    messages: f64,
    bytes: f64,
    /// When the allowance was last brought up to date, in milliseconds.
    at_ms: u64,
    /// When this member's last post that counted went in.
    last_post_ms: Option<u64>,
    /// After this the bucket is full and no slow-mode wait is left, so
    /// dropping it changes nothing.
    keep_until_ms: u64,
}

/// How often the server drops buckets that no longer hold anyone back.
pub(crate) const PRUNE_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

/// How many times a member's pace an admin gets. Admins bring people in,
/// and the app posts on their behalf for each one, but one account that
/// makes its own room still meets a limit.
pub(crate) const ADMIN_PACE: f64 = 10.0;

/// The pace limit for every member of every room.
#[derive(Default)]
pub(crate) struct Limiter(Mutex<HashMap<(Gid, Key), Bucket>>);

/// The limits in force for one post. A rate of 0 means no limit of that
/// kind.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Pace {
    pub burst_messages: f64,
    /// Milliseconds for one message back; 0 is no message limit.
    pub ms_per_message: f64,
    pub burst_bytes: f64,
    /// Bytes back each millisecond; 0 is no byte limit.
    pub bytes_per_ms: f64,
    /// The room's slow mode for this member, in milliseconds; 0 when off
    /// or when the member is an admin.
    pub slow_ms: u64,
}

impl Pace {
    /// The server's limits from its config, for a poster who is or is not
    /// an admin, in a room with this slow mode.
    pub fn new(state: &State, slow_secs: u32, admin: bool) -> Pace {
        let c = &state.cfg;
        Pace::from_config(
            [
                c.rate_burst_messages,
                c.rate_seconds_per_message,
                c.rate_burst_kb,
                c.rate_kb_per_second,
            ],
            slow_secs,
            admin,
        )
    }

    /// The limits from the four `rate_*` settings, in config order. A
    /// burst of 0 turns the server's pace off; a refill of 0 turns off
    /// that kind of limit. Admins get [`ADMIN_PACE`] times the burst and
    /// the refill, and no slow mode.
    pub fn from_config(rate: [u32; 4], slow_secs: u32, admin: bool) -> Pace {
        let [burst, secs, burst_kb, kb_per_s] = rate;
        let k = if admin { ADMIN_PACE } else { 1.0 };
        let messages_on = burst > 0 && secs > 0;
        let bytes_on = burst > 0 && kb_per_s > 0;
        Pace {
            burst_messages: if messages_on {
                f64::from(burst) * k
            } else {
                0.0
            },
            ms_per_message: if messages_on {
                f64::from(secs) * 1000.0 / k
            } else {
                0.0
            },
            burst_bytes: if bytes_on {
                (f64::from(burst_kb) * 1000.0).max(MAX_MLS as f64) * k
            } else {
                0.0
            },
            bytes_per_ms: if bytes_on {
                f64::from(kb_per_s) * k
            } else {
                0.0
            },
            slow_ms: if admin {
                0
            } else {
                u64::from(slow_secs) * 1000
            },
        }
    }

    fn messages_on(&self) -> bool {
        self.ms_per_message > 0.0
    }

    fn bytes_on(&self) -> bool {
        self.bytes_per_ms > 0.0
    }
}

impl Limiter {
    /// Counts a post of `bytes` by `member` in `group` at `now_ms`, or
    /// returns how many milliseconds to wait before it would go. A refused
    /// post counts for nothing. Callers charge only a post that nothing
    /// else will refuse.
    pub fn take(
        &self,
        group: Gid,
        member: Key,
        bytes: usize,
        now_ms: u64,
        pace: Pace,
    ) -> Result<(), u32> {
        if !pace.messages_on() && !pace.bytes_on() && pace.slow_ms == 0 {
            return Ok(());
        }
        let mut all = relock(&self.0);
        let b = all.entry((group, member)).or_insert(Bucket {
            messages: pace.burst_messages,
            bytes: pace.burst_bytes,
            at_ms: now_ms,
            last_post_ms: None,
            keep_until_ms: now_ms,
        });
        // Refill for the time since the last look, never past the burst in
        // force now.
        let dt = now_ms.saturating_sub(b.at_ms) as f64;
        b.messages = if pace.messages_on() {
            (b.messages + dt / pace.ms_per_message).min(pace.burst_messages)
        } else {
            pace.burst_messages
        };
        b.bytes = if pace.bytes_on() {
            (b.bytes + dt * pace.bytes_per_ms).min(pace.burst_bytes)
        } else {
            pace.burst_bytes
        };
        b.at_ms = now_ms.max(b.at_ms);
        let bytes = bytes as f64;
        let mut wait: f64 = 0.0;
        if pace.messages_on() && b.messages < 1.0 {
            wait = wait.max((1.0 - b.messages) * pace.ms_per_message);
        }
        if pace.bytes_on() && b.bytes < bytes {
            wait = wait.max((bytes - b.bytes) / pace.bytes_per_ms);
        }
        if let Some(last) = b.last_post_ms {
            let next = last + pace.slow_ms;
            if now_ms < next {
                wait = wait.max((next - now_ms) as f64);
            }
        }
        if wait > 0.0 {
            return Err(wait.ceil().min(f64::from(u32::MAX)) as u32);
        }
        let mut keep = now_ms + pace.slow_ms;
        if pace.messages_on() {
            b.messages -= 1.0;
            let full_in = (pace.burst_messages - b.messages) * pace.ms_per_message;
            keep = keep.max(now_ms + full_in.ceil() as u64);
        }
        if pace.bytes_on() {
            b.bytes -= bytes;
            let full_in = (pace.burst_bytes - b.bytes) / pace.bytes_per_ms;
            keep = keep.max(now_ms + full_in.ceil() as u64);
        }
        b.last_post_ms = Some(now_ms);
        b.keep_until_ms = keep;
        Ok(())
    }

    /// Drops every bucket that no longer holds anyone back. The server
    /// runs this every [`PRUNE_EVERY`], so no post pays for it.
    pub fn prune(&self, now_ms: u64) {
        relock(&self.0).retain(|_, b| b.keep_until_ms > now_ms);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        relock(&self.0).len()
    }

    /// Forgets a member who left a room.
    pub fn forget(&self, group: &Gid, member: &Key) {
        relock(&self.0).remove(&(*group, *member));
    }

    /// Forgets everyone in a room that is gone.
    pub fn forget_room(&self, group: &Gid) {
        relock(&self.0).retain(|(g, _), _| g != group);
    }
}

/// "4 seconds", "1 second": a wait for people, rounded up.
pub(crate) fn wait_text(ms: u32) -> String {
    let secs = ms.div_ceil(1000).max(1);
    if secs == 1 {
        "1 second".into()
    } else {
        format!("{secs} seconds")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A member's pace from the four `rate_*` values.
    fn pace(burst: u32, secs: u32, slow_secs: u32) -> Pace {
        Pace::from_config([burst, secs, 2_000, 10], slow_secs, false)
    }

    const G: Gid = Gid([1; 16]);
    const A: Key = Key([2; 32]);
    const B: Key = Key([3; 32]);

    #[test]
    fn burst_then_refill() {
        let l = Limiter::default();
        let p = pace(3, 5, 0);
        for _ in 0..3 {
            l.take(G, A, 300, 0, p).unwrap();
        }
        assert_eq!(l.take(G, A, 300, 0, p), Err(5000));
        assert_eq!(l.take(G, A, 300, 2000, p), Err(3000));
        l.take(G, A, 300, 5000, p).unwrap();
        assert!(l.take(G, A, 300, 5000, p).is_err());
    }

    #[test]
    fn members_and_rooms_have_their_own_buckets() {
        let l = Limiter::default();
        let p = pace(1, 60, 0);
        l.take(G, A, 1, 0, p).unwrap();
        assert!(l.take(G, A, 1, 0, p).is_err());
        l.take(G, B, 1, 0, p).unwrap();
        l.take(Gid([9; 16]), A, 1, 0, p).unwrap();
    }

    #[test]
    fn slow_mode_and_pace_both_apply() {
        let l = Limiter::default();
        let p = pace(10, 5, 30);
        l.take(G, A, 1, 0, p).unwrap();
        assert_eq!(l.take(G, A, 1, 1000, p), Err(29_000));
        l.take(G, A, 1, 30_000, p).unwrap();
        // A refused post did not count.
        let p = pace(1, 60, 1);
        l.take(G, B, 1, 0, p).unwrap();
        assert_eq!(l.take(G, B, 1, 1000, p), Err(59_000));
    }

    #[test]
    fn a_burst_of_zero_is_no_limit() {
        let l = Limiter::default();
        let p = pace(0, 5, 0);
        for _ in 0..100 {
            l.take(G, A, 1_000_000, 0, p).unwrap();
        }
        assert_eq!(l.len(), 0, "nothing to keep");
    }

    /// A refill of 0 turns that kind of limit off rather than holding
    /// anyone for ever.
    #[test]
    fn a_refill_of_zero_is_no_limit_of_that_kind() {
        let l = Limiter::default();
        let no_bytes = Pace::from_config([3, 5, 1, 0], 0, false);
        assert!(!no_bytes.bytes_on());
        for _ in 0..3 {
            l.take(G, A, 1_000_000, 0, no_bytes).unwrap();
        }
        assert_eq!(l.take(G, A, 1, 0, no_bytes), Err(5000));
        let no_messages = Pace::from_config([3, 0, 2_000, 10], 0, false);
        for _ in 0..100 {
            l.take(G, B, 10, 0, no_messages).unwrap();
        }
    }

    /// Admins get ten times the burst and the refill, and no slow mode.
    #[test]
    fn admins_get_ten_times_the_pace() {
        let member = Pace::from_config([2, 60, 2_000, 10], 3600, false);
        let admin = Pace::from_config([2, 60, 2_000, 10], 3600, true);
        assert_eq!(admin.burst_messages, 20.0);
        assert_eq!(admin.ms_per_message, 6_000.0);
        assert_eq!(admin.burst_bytes, member.burst_bytes * 10.0);
        assert_eq!(admin.bytes_per_ms, member.bytes_per_ms * 10.0);
        assert_eq!(admin.slow_ms, 0);
        let l = Limiter::default();
        for _ in 0..20 {
            l.take(G, A, 1, 0, admin).unwrap();
        }
        assert_eq!(l.take(G, A, 1, 0, admin), Err(6_000));
    }

    /// A bucket stays only while it still holds someone back: until it is
    /// full again and any slow-mode wait is over.
    #[test]
    fn prune_drops_only_buckets_that_hold_no_one_back() {
        let l = Limiter::default();
        let p = pace(3, 5, 0);
        l.take(G, A, 1, 0, p).unwrap();
        let slow = pace(3, 5, 600);
        l.take(G, B, 1, 0, slow).unwrap();
        l.prune(4_999);
        assert_eq!(l.len(), 2);
        l.prune(5_000);
        assert_eq!(l.len(), 1, "A's bucket is full again");
        // B still waits out the slow mode.
        assert_eq!(l.take(G, B, 1, 5_000, slow), Err(595_000));
        l.prune(600_000);
        assert_eq!(l.len(), 0);
    }

    #[test]
    fn waits_read_as_whole_seconds() {
        assert_eq!(wait_text(1), "1 second");
        assert_eq!(wait_text(1000), "1 second");
        assert_eq!(wait_text(1001), "2 seconds");
        assert_eq!(wait_text(29_000), "29 seconds");
    }
}
