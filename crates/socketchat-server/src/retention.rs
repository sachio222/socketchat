//! The hourly sweep: whatever outlives its time on the server goes.

use rusqlite::params;
use socketchat_proto::msg::FileId;

use crate::invites::JOIN_WAIT_SECS;
use crate::State;

/// Mailboxes made for a group nobody created, or for an invite nobody
/// completed, go after this long.
const STALE_MAILBOX_SECS: u64 = JOIN_WAIT_SECS;

pub fn sweep(state: &State) {
    let now = state.now();
    let cutoff = now.saturating_sub(state.cfg.retention_days as u64 * 24 * 3600) as i64;
    let join_cutoff = now.saturating_sub(JOIN_WAIT_SECS) as i64;
    let mailbox_cutoff = now.saturating_sub(STALE_MAILBOX_SECS) as i64;
    let db = state.db.lock().unwrap();
    let _ = db.execute("DELETE FROM log WHERE created_unix < ?1", [cutoff]);
    let _ = db.execute("DELETE FROM welcomes WHERE created_unix < ?1", [cutoff]);
    let _ = db.execute("DELETE FROM invites WHERE expires_unix < ?1", [now as i64]);
    let _ = db.execute(
        "DELETE FROM joins WHERE lodged_unix < ?1
             OR (lodged_unix IS NULL AND NOT EXISTS (SELECT 1 FROM invites WHERE invites.token = joins.token))",
        [join_cutoff],
    );
    let _ = db.execute(
        "DELETE FROM mailboxes WHERE joined_seq IS NULL AND created_unix < ?1",
        params![mailbox_cutoff],
    );
    let old_files: Vec<Vec<u8>> = db
        .prepare("SELECT id FROM files WHERE created_unix < ?1")
        .and_then(|mut st| {
            st.query_map([cutoff], |r| r.get(0))
                .map(|rows| rows.filter_map(Result::ok).collect())
        })
        .unwrap_or_default();
    for id in old_files {
        if let Ok(id) = <[u8; 16]>::try_from(id.as_slice()) {
            crate::files::delete(state, &db, &FileId(id));
        }
    }
}
