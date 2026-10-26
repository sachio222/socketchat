//! Join requests: a joiner lodges a KeyPackage under the invite token they
//! redeemed, and the group's online members hear about it.

use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::{KeyPackageIn, ProtocolVersion};
use rusqlite::params;
use socketchat_proto::msg::{
    from_body, to_frame, GroupId as Gid, JoinRequest, Key, Push, Response, ServerFrame,
};
use socketchat_proto::Token;

use crate::conn::ConnState;
use crate::groups::{joined_keys, member_key, REPLY_BYTES};
use crate::State;

/// How long a lodged join request waits for someone to act: 7 days.
pub const JOIN_WAIT_SECS: u64 = 7 * 24 * 3600;

/// Largest KeyPackage bundle a joiner may lodge. A bundle holds one
/// KeyPackage per cipher suite; a post-quantum one measures about 2.7 KB, a
/// standard one about 0.3 KB, so two post-quantum ones fit with room to spare.
const MAX_KEY_PACKAGE: usize = 8 * 1024;

/// Most KeyPackages in one bundle: one per cipher suite the server accepts.
const MAX_KEY_PACKAGES: usize = 2;

/// Bytes a join request adds to a reply besides its KeyPackages: token,
/// MAC, time and length, at their largest.
const JOIN_OVERHEAD: usize = 64;

/// True when `blob` is what clients lodge: a list of one or two MLS
/// KeyPackages, encoded exactly, each made for `mailbox`.
fn key_packages_ok(blob: &[u8], mailbox: &Key) -> bool {
    let Ok(kps) = from_body::<Vec<Vec<u8>>>(blob) else {
        return false;
    };
    if kps.is_empty() || kps.len() > MAX_KEY_PACKAGES {
        return false;
    }
    // Nothing after the list.
    if to_frame(&kps).map(|f| f.len() - 4) != Ok(blob.len()) {
        return false;
    }
    kps.iter().all(|b| {
        KeyPackageIn::tls_deserialize_exact(b)
            .is_ok_and(|kp| kp.unverified_credential().signature_key.as_slice() == mailbox.0)
    })
}

/// Whether every KeyPackage in a lodged blob says its app knows room
/// settings. Run after [`key_packages_ok`].
fn takes_settings_all(blob: &[u8]) -> bool {
    let Ok(kps) = from_body::<Vec<Vec<u8>>>(blob) else {
        return false;
    };
    kps.iter().all(|b| {
        KeyPackageIn::tls_deserialize_exact(b)
            .ok()
            .and_then(|kp| {
                kp.validate(
                    &openmls_rust_crypto::RustCrypto::default(),
                    ProtocolVersion::Mls10,
                )
                .ok()
            })
            .is_some_and(|kp| socketchat_core::suite::takes_settings(kp.leaf_node().capabilities()))
    })
}

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
    let db = state.db();
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
    let maker: Option<Vec<u8>> = db
        .query_row(
            "SELECT maker FROM invites WHERE token = ?1",
            [token.0.as_slice()],
            |r| r.get(0),
        )
        .ok()
        .flatten();
    if !crate::groups::maker_may_invite(state, &db, &group, maker.as_deref()) {
        return Response::Refused(crate::groups::MAKER_CANNOT_INVITE.into());
    }
    if !key_packages_ok(&key_package, &mailbox) {
        return Response::Refused("that is not a key package for your mailbox".into());
    }
    // A room with settings takes only apps that know them; an older app
    // hears so now rather than waiting for an add that cannot happen.
    let has_settings = state
        .rules
        .get(&db, &group)
        .is_some_and(|r| !r.settings.is_default());
    if has_settings && !takes_settings_all(&key_package) {
        return Response::Refused(
            "this room needs Socketchat 0.5.2 or later; update Socketchat, then ask for a new invite link".into(),
        );
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

/// Join requests waiting in `group`, ordered by (lodged time, token), as
/// many as fit one reply. With `after`, the list starts strictly after that
/// position, so a client pages past requests nobody completes.
pub fn pending(state: &State, cs: &ConnState, group: Gid, after: Option<(u64, Token)>) -> Response {
    let now = state.now();
    let db = state.db();
    if member_key(&db, cs, &group).is_none() {
        return Response::Refused("you are not a member of this group".into());
    }
    // Before every real request when no position is given. SQLite compares
    // the token blobs byte by byte, the same order as the Rust arrays.
    let (after_at, after_token) = match after {
        Some((at, t)) => (at.min(i64::MAX as u64) as i64, t.0.to_vec()),
        None => (i64::MIN, Vec::new()),
    };
    let read = || -> rusqlite::Result<Vec<JoinRequest>> {
        let mut st = db.prepare(
            "SELECT token, key_package, mac, lodged_unix FROM joins
             WHERE group_id = ?1 AND key_package IS NOT NULL AND lodged_unix > ?2
               AND (lodged_unix > ?3 OR (lodged_unix = ?3 AND token > ?4))
             ORDER BY lodged_unix, token",
        )?;
        let mut rows = st.query(params![
            group.0.as_slice(),
            now.saturating_sub(JOIN_WAIT_SECS) as i64,
            after_at,
            after_token
        ])?;
        let mut out = Vec::new();
        let mut bytes = 0;
        while let Some(r) = rows.next()? {
            let t: Vec<u8> = r.get(0)?;
            let kp: Vec<u8> = r.get(1)?;
            let mac: Vec<u8> = r.get(2)?;
            let at: i64 = r.get(3)?;
            let size = kp.len() + JOIN_OVERHEAD;
            if !out.is_empty() && bytes + size > REPLY_BYTES {
                break;
            }
            let (Ok(token), Ok(mac)) = (t.try_into(), mac.try_into()) else {
                continue;
            };
            bytes += size;
            out.push(JoinRequest {
                token: Token(token),
                key_package: kp,
                mac,
                lodged_unix: at as u64,
            });
        }
        Ok(out)
    };
    match read() {
        Ok(joins) => Response::Joins(joins),
        Err(_) => Response::Error("could not read join requests".into()),
    }
}
