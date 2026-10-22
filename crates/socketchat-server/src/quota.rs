//! Limits on how many accounts one account brings onto the server, and on
//! what one room, one member and the whole server may keep on disk.
//!
//! Per-account counts keep only a number and the day their window began,
//! never which links or accounts they counted. Storage is counted from what
//! the server already holds: a room's messages through a running total in
//! `groups.log_bytes`, finished files by their sizes and unfinished ones by
//! the bytes received, Welcomes by their bytes. What
//! the server deletes, because members fetched it or it outlived
//! `retention_days`, stops counting. A count that cannot be read counts as
//! nothing, so a database error never reads as a full room.

use std::time::{Duration, Instant};

use rusqlite::{params, Connection, OptionalExtension};
use socketchat_proto::msg::{GroupId as Gid, Key, Response};

use crate::{relock, State, DAY_SECS};

/// Bytes each log entry counts for on top of its MLS message, for the
/// row's own fields.
pub(crate) const ENTRY_ROW: u64 = 64;

/// The least a file counts for: one chunk, so empty files still cost.
pub(crate) const FILE_FLOOR: u64 = 64 * 1024;

/// An upload that has not finished this long after it began is deleted.
pub(crate) const UPLOAD_LIFE_SECS: u64 = 6 * 3600;

/// How long a count of the server's stored bytes is reused.
const TOTAL_FRESH: Duration = Duration::from_secs(1);

const MB: u64 = 1_000_000;

/// What a log entry of `len` bytes counts for.
pub(crate) fn entry_cost(len: usize) -> u64 {
    len as u64 + ENTRY_ROW
}

/// A per-account count with a window.
#[derive(Clone, Copy)]
pub(crate) enum Count {
    /// Server invite links the account made.
    ServerInvites,
    /// Room links the account made that may register a new account.
    RoomLinkAccounts,
}

impl Count {
    fn table(self) -> &'static str {
        match self {
            Count::ServerInvites => "invite_quota",
            Count::RoomLinkAccounts => "link_quota",
        }
    }
}

/// Seconds in an account's window: the invite lifetime rounded up to whole
/// days, plus a day, so every link made in one window has expired before
/// the next starts.
pub(crate) fn window_secs(state: &State) -> u64 {
    let ttl = state.cfg.invite_ttl_hours as u64 * 3600;
    ttl.div_ceil(DAY_SECS) * DAY_SECS + DAY_SECS
}

/// Counts one more against `account` and returns true, or returns false
/// when it already counted `limit` in its current window. Callers run this
/// in the transaction that saves what it counts.
pub(crate) fn take(
    state: &State,
    db: &Connection,
    count: Count,
    account: &Key,
    limit: i64,
) -> rusqlite::Result<bool> {
    let table = count.table();
    let now = state.now();
    let row: Option<(i64, i64)> = db
        .query_row(
            &format!("SELECT since_unix, used FROM {table} WHERE account = ?1"),
            [account.0.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match row {
        Some((since, used)) if now < since as u64 + window_secs(state) => {
            if used >= limit {
                return Ok(false);
            }
            db.execute(
                &format!("UPDATE {table} SET used = used + 1 WHERE account = ?1"),
                [account.0.as_slice()],
            )?;
        }
        _ => {
            if limit < 1 {
                return Ok(false);
            }
            db.execute(
                &format!(
                    "INSERT OR REPLACE INTO {table} (account, since_unix, used) VALUES (?1, ?2, 1)"
                ),
                params![account.0.as_slice(), state.today() as i64],
            )?;
        }
    }
    Ok(true)
}

/// Deletes per-account counts whose window has ended.
pub(crate) fn sweep_counts(state: &State, db: &Connection) {
    let cutoff = state.now().saturating_sub(window_secs(state)) as i64;
    for count in [Count::ServerInvites, Count::RoomLinkAccounts] {
        let _ = db.execute(
            &format!("DELETE FROM {} WHERE since_unix <= ?1", count.table()),
            [cutoff],
        );
    }
}

/// What the server holds, as last counted, reused for `TOTAL_FRESH`.
#[derive(Default)]
pub(crate) struct Stored {
    counted: Option<(Instant, Usage)>,
}

/// Bytes the server holds in messages (log entries and Welcomes) and in
/// files.
#[derive(Clone, Copy, Default)]
pub(crate) struct Usage {
    pub messages: u64,
    pub files: u64,
}

impl Usage {
    fn total(self) -> u64 {
        self.messages.saturating_add(self.files)
    }
}

/// File bytes in each received piece but the last: 64 KiB. The cipher's
/// 16-byte tag on each piece is not counted, so a file counts the same
/// before and after it finishes.
const PIECE: u64 = 64 * 1024;

/// What a file counts for: a finished one at its size, an unfinished one
/// at the bytes received so far. SQL over a row of `files`.
fn file_bytes() -> String {
    format!("CASE WHEN complete THEN MAX(size, {FILE_FLOOR}) ELSE chunks * {PIECE} END")
}

/// What the server holds now.
pub(crate) fn stored(state: &State, db: &Connection) -> Usage {
    let mut s = relock(&state.stored);
    if let Some((at, u)) = s.counted {
        if at.elapsed() < TOTAL_FRESH {
            return u;
        }
    }
    let read = |n: rusqlite::Result<i64>| n.map(|n| n.max(0) as u64).unwrap_or(0);
    let u = Usage {
        messages: read(db.query_row(
            "SELECT (SELECT COALESCE(SUM(log_bytes), 0) FROM groups)
                  + (SELECT COALESCE(SUM(length(welcome) + length(voucher)), 0) FROM welcomes)",
            [],
            |r| r.get(0),
        )),
        files: read(db.query_row(
            &format!("SELECT COALESCE(SUM({}), 0) FROM files", file_bytes()),
            [],
            |r| r.get(0),
        )),
    };
    s.counted = Some((Instant::now(), u));
    u
}

/// Adds bytes just stored to the last count. Call it while the database
/// lock is still held, so the next check under the lock sees them.
pub(crate) fn note_stored(state: &State, messages: u64, files: u64) {
    if let Some((_, u)) = relock(&state.stored).counted.as_mut() {
        u.messages = u.messages.saturating_add(messages);
        u.files = u.files.saturating_add(files);
    }
}

/// Makes the next check count again, after a large deletion.
pub(crate) fn recount(state: &State) {
    relock(&state.stored).counted = None;
}

/// Bytes of messages waiting in `group`'s log.
pub(crate) fn room_messages(db: &Connection, group: &Gid) -> u64 {
    db.query_row(
        "SELECT log_bytes FROM groups WHERE id = ?1",
        [group.0.as_slice()],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n.max(0) as u64)
    .unwrap_or(0)
}

fn files_where(db: &Connection, column: &str, value: &[u8]) -> u64 {
    db.query_row(
        &format!(
            "SELECT COALESCE(SUM({}), 0) FROM files WHERE {column} = ?1",
            file_bytes()
        ),
        [value],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n.max(0) as u64)
    .unwrap_or(0)
}

/// Welcomes waiting for people joining `group`.
pub(crate) fn room_welcomes(db: &Connection, group: &Gid) -> u64 {
    db.query_row(
        "SELECT COUNT(*) FROM welcomes
             WHERE mailbox IN (SELECT key FROM mailboxes WHERE group_id = ?1)",
        [group.0.as_slice()],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n.max(0) as u64)
    .unwrap_or(0)
}

/// Joins waiting in `group`: Welcomes not yet fetched, and links redeemed
/// whose joiner has not been added yet.
fn room_joins_waiting(db: &Connection, group: &Gid) -> u64 {
    let joins: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM joins WHERE group_id = ?1",
            [group.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap_or(0);
    room_welcomes(db, group).saturating_add(joins.max(0) as u64)
}

fn over(used: u64, more: u64, limit: u64) -> bool {
    used.saturating_add(more) > limit
}

fn mb(n: u64) -> u64 {
    n.saturating_mul(MB)
}

/// Largest leave request a full room still takes. Apps send 141 bytes.
pub(crate) const EXEMPT_LEAVE_MAX: usize = 4 * 1024;

/// Most authenticated data (MLS AAD) a change a full room still takes may
/// carry. Apps send none.
pub(crate) const EXEMPT_AAD_MAX: usize = 64;

/// How far past its limit a room's messages may go with changes that only
/// make the room smaller: a tenth more.
fn room_ceiling(limit: u64) -> u64 {
    limit.saturating_add(limit / 10)
}

/// How far past `max_stored_mb` the server may go with such changes.
fn stored_ceiling(limit: u64) -> u64 {
    limit.saturating_add(limit / 50)
}

/// The share of `max_stored_mb` files may use, so files never crowd out
/// messages: nine tenths.
fn files_share(limit: u64) -> u64 {
    limit / 10 * 9
}

fn server_full() -> Response {
    Response::Refused(
        "this server is full; it takes new messages and files again as members fetch older ones or they expire".into(),
    )
}

fn room_full(state: &State) -> Response {
    Response::Refused(format!(
        "this room holds this server's limit of {} MB of messages that members have not fetched yet; they leave once everyone has them, or after {} days",
        state.cfg.max_room_messages_mb, state.cfg.retention_days
    ))
}

/// Why `group` cannot take `cost` more bytes of messages, with `extra`
/// more bytes of Welcome beside them, if it cannot. A change that only
/// makes the room smaller (`shrinks`) may go a little past the limits.
pub(crate) fn messages_refused(
    state: &State,
    db: &Connection,
    group: &Gid,
    cost: u64,
    extra: u64,
    shrinks: bool,
) -> Option<Response> {
    let (room_limit, stored_limit) = {
        let room = mb(state.cfg.max_room_messages_mb);
        let stored = mb(state.cfg.max_stored_mb);
        if shrinks {
            (room_ceiling(room), stored_ceiling(stored))
        } else {
            (room, stored)
        }
    };
    if over(room_messages(db, group), cost, room_limit) {
        return Some(room_full(state));
    }
    if over(stored(state, db).total(), cost + extra, stored_limit) {
        return Some(server_full());
    }
    None
}

/// Most uploads one member may have started and not finished at once.
pub(crate) const OPEN_UPLOADS: i64 = 3;

/// `member`'s unfinished uploads past the newest `OPEN_UPLOADS - 1`, oldest
/// first: what must go before they start another. A mailbox belongs to one
/// room, so this counts within that room.
pub(crate) fn uploads_to_drop(db: &Connection, member: &Key) -> Vec<Vec<u8>> {
    db.prepare(
        "SELECT id FROM files WHERE uploader = ?1 AND complete = 0
             ORDER BY created_unix DESC, rowid DESC LIMIT -1 OFFSET ?2",
    )
    .and_then(|mut st| {
        st.query_map(params![member.0.as_slice(), OPEN_UPLOADS - 1], |r| r.get(0))
            .map(|rows| rows.filter_map(Result::ok).collect())
    })
    .unwrap_or_default()
}

/// Why `member` cannot store `more` bytes of files in `group`, if they
/// cannot: at the start of an upload, `more` is its size; for each piece,
/// the piece.
pub(crate) fn file_refused(
    state: &State,
    db: &Connection,
    group: &Gid,
    member: &Key,
    more: u64,
) -> Option<Response> {
    let days = state.cfg.retention_days;
    let limit = state.cfg.max_member_files_mb;
    if over(files_where(db, "uploader", &member.0), more, mb(limit)) {
        return Some(Response::Refused(format!(
            "you have this server's limit of {limit} MB of files in this room that others have not fetched yet; files leave once everyone has them, or after {days} days"
        )));
    }
    let limit = state.cfg.max_room_files_mb;
    if over(files_where(db, "group_id", &group.0), more, mb(limit)) {
        return Some(Response::Refused(format!(
            "this room holds this server's limit of {limit} MB of files that members have not fetched yet; files leave once everyone has them, or after {days} days"
        )));
    }
    let u = stored(state, db);
    let stored_limit = mb(state.cfg.max_stored_mb);
    if over(u.files, more, files_share(stored_limit)) || over(u.total(), more, stored_limit) {
        return Some(server_full());
    }
    None
}

fn people(n: u32) -> String {
    match n {
        1 => "1 person".into(),
        n => format!("{n} people"),
    }
}

/// Why `group` cannot take one more Welcome, if it cannot.
pub(crate) fn welcome_refused(state: &State, db: &Connection, group: &Gid) -> Option<Response> {
    let limit = state.cfg.max_room_welcomes;
    (room_welcomes(db, group) >= limit as u64).then(|| {
        Response::Refused(format!(
            "{} invited to this room have not opened their invitation yet, this server's limit; add more once some of them join",
            people(limit)
        ))
    })
}

/// Room a join needs in its room's message log: one add.
const JOIN_ROOM: u64 = 64 * 1024;

/// Why a link into `group` cannot be redeemed now, if it cannot: the room
/// has as many joins waiting as it may have, or no room for the add.
/// Checked when the joiner's app redeems the link, so the joiner hears it.
pub(crate) fn join_refused(state: &State, db: &Connection, group: &Gid) -> Option<Response> {
    let limit = state.cfg.max_room_welcomes;
    if room_joins_waiting(db, group) >= limit as u64 {
        return Some(Response::Refused(format!(
            "{} invited to this room have not opened their invitation yet, this server's limit; try this link again once some of them join",
            people(limit)
        )));
    }
    messages_refused(state, db, group, JOIN_ROOM, 0, false)
}

/// Lowers `group`'s message total by the entries `filter` picks before
/// they are deleted. `filter` is SQL over `log` with `?1` for the group.
pub(crate) fn forget_entries(db: &Connection, group: &Gid, filter: &str) -> rusqlite::Result<()> {
    db.execute(
        &format!(
            "UPDATE groups SET log_bytes = MAX(0, log_bytes - (
                 SELECT COALESCE(SUM(length(mls) + {ENTRY_ROW}), 0) FROM log
                 WHERE group_id = ?1 AND {filter}))
             WHERE id = ?1"
        ),
        [group.0.as_slice()],
    )?;
    Ok(())
}
