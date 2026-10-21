//! Closing a room once its admins agree: how many must, and the tally of
//! their votes. No I/O: the client hands it the stored votes and the list
//! of admins still in the room.

use crate::keys::Key;

/// How long a request to close stays open, counted from its first vote.
pub const CLOSE_ASK_SECS: u64 = 7 * 24 * 3600;

/// How many admins must agree to close a room with `admins` admins: every
/// one of them up to three, a majority above that.
pub fn close_needed(admins: usize) -> usize {
    if admins <= 3 {
        admins
    } else {
        admins / 2 + 1
    }
}

/// One stored vote. Rows come oldest first, as they arrived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vote {
    pub close_id: [u8; 16],
    pub voter: Key,
    pub yes: bool,
    /// When this app first got the voter's vote on this request.
    pub at_unix: u64,
}

/// One request to close, counted over the admins still in the room.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub close_id: [u8; 16],
    /// The first admin who said yes.
    pub asked_by: Option<Key>,
    /// When its first counted vote arrived.
    pub first_unix: u64,
    pub yes: usize,
    pub no: usize,
    pub needed: usize,
    pub admins: usize,
    /// This member's own vote, whether or not it counts.
    pub my_vote: Option<bool>,
}

impl Request {
    /// Enough admins said yes: the room closes.
    pub fn met(&self) -> bool {
        self.admins > 0 && self.yes >= self.needed
    }

    /// Too many admins said no for the rest to reach `needed`.
    pub fn kept(&self) -> bool {
        self.admins.saturating_sub(self.no) < self.needed
    }

    fn live(&self, now: u64) -> bool {
        now < self.first_unix.saturating_add(CLOSE_ASK_SECS)
    }

    /// Still asking: someone said yes, it is not kept, and its seven days
    /// have not run out.
    pub fn open(&self, now: u64) -> bool {
        self.yes > 0 && !self.kept() && self.live(now)
    }
}

/// Every request with at least one vote from a current admin, in the
/// order their first counted vote arrived. Only votes from `admins` count,
/// and a voter's newer vote replaces the older.
pub fn requests(votes: &[Vote], admins: &[Key], me: &Key) -> Vec<Request> {
    let mut out: Vec<Request> = Vec::new();
    let mut ids: Vec<[u8; 16]> = Vec::new();
    for v in votes {
        if !ids.contains(&v.close_id) {
            ids.push(v.close_id);
        }
    }
    let needed = close_needed(admins.len());
    for id in ids {
        let mine: Vec<&Vote> = votes.iter().filter(|v| v.close_id == id).collect();
        // The newest vote of each voter, in the order voters first voted.
        let mut latest: Vec<&Vote> = Vec::new();
        for v in &mine {
            match latest.iter_mut().find(|l| l.voter == v.voter) {
                Some(l) => *l = v,
                None => latest.push(v),
            }
        }
        let first_at = |voter: &Key| {
            mine.iter()
                .find(|v| v.voter == *voter)
                .map(|v| v.at_unix)
                .unwrap_or(0)
        };
        let counted: Vec<&&Vote> = latest
            .iter()
            .filter(|v| admins.contains(&v.voter))
            .collect();
        let Some(first) = counted.first() else {
            continue;
        };
        out.push(Request {
            close_id: id,
            asked_by: counted.iter().find(|v| v.yes).map(|v| v.voter),
            first_unix: first_at(&first.voter),
            yes: counted.iter().filter(|v| v.yes).count(),
            no: counted.iter().filter(|v| !v.yes).count(),
            needed,
            admins: admins.len(),
            my_vote: latest.iter().find(|v| v.voter == *me).map(|v| v.yes),
        });
    }
    out.sort_by_key(|r| r.first_unix);
    out
}

/// The request a new vote goes to: the first one still open.
pub fn open_request(reqs: &[Request], now: u64) -> Option<&Request> {
    reqs.iter().find(|r| r.open(now))
}

/// The request to show: the open one, or else the newest of the last
/// seven days, which tells whether it was kept.
pub fn current(reqs: &[Request], now: u64) -> Option<&Request> {
    open_request(reqs, now).or_else(|| reqs.iter().rev().find(|r| r.live(now)))
}

/// A request to close as one member sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseView {
    pub close_id: [u8; 16],
    /// The name of the admin who asked.
    pub asked_by: String,
    pub yes: usize,
    pub no: usize,
    pub needed: usize,
    pub admins: usize,
    pub my_vote: Option<bool>,
    /// Too few admins can still agree: the room stays open.
    pub kept: bool,
}

/// What a vote to close led to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseOutcome {
    Closed,
    Waiting { yes: usize, needed: usize },
    Kept,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Key;

    #[test]
    fn needed_counts() {
        let got: Vec<usize> = (1..=7).map(close_needed).collect();
        assert_eq!(got, vec![1, 2, 3, 3, 3, 4, 4]);
        assert_eq!(CLOSE_ASK_SECS, 7 * 24 * 3600);
    }

    fn k(n: u8) -> Key {
        Key([n; 32])
    }

    fn vote(id: u8, voter: u8, yes: bool, at: u64) -> Vote {
        Vote {
            close_id: [id; 16],
            voter: k(voter),
            yes,
            at_unix: at,
        }
    }

    #[test]
    fn only_admin_votes_count() {
        let admins = [k(1), k(2), k(3)];
        let votes = [vote(1, 1, true, 10), vote(1, 9, true, 11)];
        let rs = requests(&votes, &admins, &k(1));
        assert_eq!(rs.len(), 1);
        assert_eq!((rs[0].yes, rs[0].needed, rs[0].admins), (1, 3, 3));
        // Votes from nobody who is an admin make no request.
        assert!(requests(&[vote(2, 9, true, 10)], &admins, &k(1)).is_empty());
    }

    #[test]
    fn newer_vote_replaces_older() {
        let admins = [k(1), k(2)];
        let votes = [
            vote(1, 1, true, 10),
            vote(1, 2, true, 11),
            vote(1, 2, false, 12),
        ];
        let r = &requests(&votes, &admins, &k(2))[0];
        assert_eq!((r.yes, r.no), (1, 1));
        assert_eq!(r.my_vote, Some(false));
        assert_eq!(r.asked_by, Some(k(1)));
    }

    #[test]
    fn met_and_kept() {
        let admins = [k(1), k(2), k(3), k(4)];
        let met = requests(
            &[
                vote(1, 1, true, 0),
                vote(1, 2, true, 0),
                vote(1, 3, true, 0),
            ],
            &admins,
            &k(1),
        );
        assert!(met[0].met() && !met[0].kept());
        // Four admins need three: two saying no leave only two who could agree.
        let kept = requests(
            &[
                vote(1, 1, true, 0),
                vote(1, 2, false, 0),
                vote(1, 3, false, 0),
            ],
            &admins,
            &k(1),
        );
        assert!(kept[0].kept() && !kept[0].met());
        assert!(open_request(&kept, 0).is_none());
        assert_eq!(current(&kept, 0).map(|r| r.close_id), Some([1; 16]));
        let one_no = requests(&[vote(1, 1, true, 0), vote(1, 2, false, 0)], &admins, &k(1));
        assert!(!one_no[0].kept());
    }

    #[test]
    fn request_open_for_seven_days_from_its_first_vote() {
        let admins = [k(1), k(2)];
        let rs = requests(
            &[vote(1, 1, true, 100), vote(1, 2, true, 200)],
            &admins,
            &k(1),
        );
        assert!(rs[0].met());
        assert!(open_request(&rs, 100 + CLOSE_ASK_SECS - 1).is_some());
        assert!(open_request(&rs, 100 + CLOSE_ASK_SECS).is_none());
        assert!(current(&rs, 100 + CLOSE_ASK_SECS).is_none());
    }

    #[test]
    fn first_open_request_wins() {
        let admins = [k(1), k(2), k(3)];
        let rs = requests(&[vote(1, 1, true, 5), vote(2, 2, true, 6)], &admins, &k(3));
        assert_eq!(open_request(&rs, 6).map(|r| r.close_id), Some([1; 16]));
    }
}
