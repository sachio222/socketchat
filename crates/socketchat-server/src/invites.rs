//! Join requests: a joiner lodges a KeyPackage under the invite token they
//! redeemed, and the group's online members hear about it.

use rusqlite::params;
use socketchat_proto::msg::{GroupId as Gid, JoinRequest, Key, Push, Response, ServerFrame};
use socketchat_proto::Token;

use crate::conn::ConnState;
use crate::groups::{joined_keys, member_key};
use crate::State;

/// How long a lodged join request waits for someone to act: 7 days.
pub const JOIN_WAIT_SECS: u64 = 7 * 24 * 3600;

/// Largest KeyPackage bundle a joiner may lodge.
const MAX_KEY_PACKAGE: usize = 64 * 1024;

pub fn redeem(
    state: &State,
    cs: &ConnState,
    token: Token,
    key_package: Vec<u8>,
    mac: [u8; 32],
) -> Response {
    if key_package.len() > MAX_KEY_PACKAGE {
        return Response::Refused("that key package is too large".into());
    }
    let now = state.now();
    let db = state.db.lock().unwrap();
    let row: Option<(Vec<u8>, Vec<u8>)> = db
        .query_row(
            "SELECT group_id, mailbox FROM joins WHERE token = ?1 AND key_package IS NULL",
            [token.0.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    let Some((group, mailbox)) = row else {
        return Response::Refused("redeem the invite with your new mailbox first".into());
    };
    let Ok(mailbox) = <[u8; 32]>::try_from(mailbox.as_slice()).map(Key) else {
        return Response::Error("stored mailbox is malformed".into());
    };
    let Ok(group) = <[u8; 16]>::try_from(group.as_slice()).map(Gid) else {
        return Response::Error("stored group is malformed".into());
    };
    if !cs.proven.contains(&mailbox) {
        return Response::Refused("sign in with the mailbox that redeemed this invite".into());
    }
    if db
        .execute(
            "UPDATE joins SET key_package = ?1, mac = ?2, lodged_unix = ?3 WHERE token = ?4",
            params![key_package, mac.as_slice(), now as i64, token.0.as_slice()],
        )
        .is_err()
    {
        return Response::Error("could not save the join request".into());
    }
    let members = joined_keys(&db, &group);
    drop(db);
    let request = JoinRequest {
        token,
        key_package,
        mac,
        lodged_unix: now,
    };
    state.online.push_many(
        &members,
        &ServerFrame::Push(Push::JoinRequest { group, request }),
        Some(cs.id),
    );
    Response::JoinLodged
}

pub fn pending(state: &State, cs: &ConnState, group: Gid) -> Response {
    let now = state.now();
    let db = state.db.lock().unwrap();
    if member_key(&db, cs, &group).is_none() {
        return Response::Refused("you are not a member of this group".into());
    }
    let mut st = db
        .prepare(
            "SELECT token, key_package, mac, lodged_unix FROM joins
             WHERE group_id = ?1 AND key_package IS NOT NULL AND lodged_unix > ?2",
        )
        .expect("static SQL");
    let rows = st.query_map(
        params![
            group.0.as_slice(),
            now.saturating_sub(JOIN_WAIT_SECS) as i64
        ],
        |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, i64>(3)?,
            ))
        },
    );
    let Ok(rows) = rows else {
        return Response::Error("could not read join requests".into());
    };
    let joins = rows
        .filter_map(Result::ok)
        .filter_map(|(t, kp, mac, at)| {
            Some(JoinRequest {
                token: Token(t.try_into().ok()?),
                key_package: kp,
                mac: mac.try_into().ok()?,
                lodged_unix: at as u64,
            })
        })
        .collect();
    Response::Joins(joins)
}
