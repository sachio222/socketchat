//! The hourly sweep: whatever outlives its time on the server goes.

use rusqlite::params;
use socketchat_proto::msg::{FileId, GroupId};

use crate::invites::JOIN_WAIT_SECS;
use crate::{quota, State, DAY_SECS};

/// Mailboxes made for a group nobody created, or for an invite nobody
/// completed, go after this long.
const STALE_MAILBOX_SECS: u64 = JOIN_WAIT_SECS;

pub fn sweep(state: &State) {
    let now = state.now();
    let cutoff = now.saturating_sub(state.cfg.retention_days as u64 * 24 * 3600) as i64;
    let join_cutoff = now.saturating_sub(JOIN_WAIT_SECS) as i64;
    // Mailbox times are rounded down to the day, so allow one more day:
    // a mailbox waiting on a join is never removed before the full wait.
    let mailbox_cutoff = now.saturating_sub(STALE_MAILBOX_SECS + DAY_SECS) as i64;
    let db = state.db();
    // Expired entries stop counting toward their room's limit as they go.
    let _ = (|| -> rusqlite::Result<()> {
        let t = db.unchecked_transaction()?;
        t.execute(
            "UPDATE groups SET log_bytes = MAX(0, log_bytes - (
                 SELECT COALESCE(SUM(length(mls) + ?2), 0) FROM log
                 WHERE log.group_id = groups.id AND created_unix < ?1))",
            params![cutoff, quota::ENTRY_ROW as i64],
        )?;
        t.execute("DELETE FROM log WHERE created_unix < ?1", [cutoff])?;
        t.commit()
    })();
    let _ = db.execute("DELETE FROM welcomes WHERE created_unix < ?1", [cutoff]);
    let _ = db.execute(
        "DELETE FROM joins WHERE lodged_unix < ?1
             OR (lodged_unix IS NULL AND NOT EXISTS (
                 SELECT 1 FROM invites WHERE invites.token = joins.token AND invites.expires_unix >= ?2))",
        params![join_cutoff, now as i64],
    );
    // A used link stays while its join waits: it names the member whose
    // leaving ends that join.
    let _ = db.execute(
        "DELETE FROM invites WHERE expires_unix < ?1
             AND NOT EXISTS (SELECT 1 FROM joins WHERE joins.token = invites.token)",
        [now as i64],
    );
    quota::sweep_counts(state, &db);
    let _ = db.execute(
        "DELETE FROM mailboxes WHERE joined_seq IS NULL AND created_unix < ?1",
        params![mailbox_cutoff],
    );
    // A room with no joined member is deleted whole. An app that leaves
    // alone asks for this itself; the sweep catches rooms where that request
    // never arrived or the members were removed.
    let empty: Vec<Vec<u8>> = db
        .prepare(
            "SELECT id FROM groups WHERE NOT EXISTS (
                 SELECT 1 FROM mailboxes
                 WHERE mailboxes.group_id = groups.id AND joined_seq IS NOT NULL)",
        )
        .and_then(|mut st| {
            st.query_map([], |r| r.get(0))
                .map(|rows| rows.filter_map(Result::ok).collect())
        })
        .unwrap_or_default();
    for id in empty {
        if let Ok(id) = <[u8; 16]>::try_from(id.as_slice()) {
            let _ = crate::groups::delete_group(&db, state, &GroupId(id));
        }
    }
    // Files past retention, and uploads that never finished.
    let upload_cutoff = now.saturating_sub(quota::UPLOAD_LIFE_SECS) as i64;
    let old_files: Vec<Vec<u8>> = db
        .prepare(
            "SELECT id FROM files WHERE created_unix < ?1 OR (complete = 0 AND created_unix < ?2)",
        )
        .and_then(|mut st| {
            st.query_map(params![cutoff, upload_cutoff], |r| r.get(0))
                .map(|rows| rows.filter_map(Result::ok).collect())
        })
        .unwrap_or_default();
    for id in old_files {
        if let Ok(id) = <[u8; 16]>::try_from(id.as_slice()) {
            crate::files::delete(state, &db, &FileId(id));
        }
    }
    quota::recount(state);
    crate::db::checkpoint(&db);
}
