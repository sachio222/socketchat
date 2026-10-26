//! Sign-in: a random challenge per connection, signed by each key the
//! client wants to use on it.

use rand_core::{OsRng, RngCore};
use rusqlite::{params, OptionalExtension};
use socketchat_core::keys::{verify, CTX_AUTH};
use socketchat_proto::msg::{Key, Response, Sig};
use socketchat_proto::Token;

use crate::conn::ConnState;
use crate::State;

pub fn challenge(cs: &mut ConnState) -> Response {
    let mut c = [0u8; 32];
    OsRng.fill_bytes(&mut c);
    cs.challenge = Some(c);
    Response::Challenge(c)
}

/// True when `sig` signs this connection's challenge and `key`.
pub fn signed(cs: &ConnState, key: &Key, sig: &Sig) -> bool {
    let Some(c) = cs.challenge else { return false };
    verify(key, CTX_AUTH, &[c.as_slice(), &key.0].concat(), sig)
}

fn refused(why: &str) -> Response {
    Response::Refused(why.to_string())
}

/// Marks `key` as proven on this connection and lets pushes for it arrive.
pub fn admit(state: &State, cs: &mut ConnState, key: Key) {
    cs.proven.insert(key);
    state.online.add(key, cs.id, cs.tx.clone());
}

pub fn prove(state: &State, cs: &mut ConnState, key: Key, sig: Sig) -> Response {
    if !signed(cs, &key, &sig) {
        return refused("signature check failed; ask for a new challenge");
    }
    let db = state.db();
    let known: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE key = ?1)
                 OR EXISTS(SELECT 1 FROM mailboxes WHERE key = ?1)",
            [key.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap_or(false);
    drop(db);
    if !known {
        return refused("this server does not know that key");
    }
    admit(state, cs, key);
    Response::Ok
}

/// An invite as stored, if it exists.
pub struct Invite {
    pub group: Option<Vec<u8>>,
    pub expires_unix: u64,
    pub uses_left: i64,
    pub account_used: bool,
    /// Who made a room link, until a join through it completes.
    pub maker: Option<Vec<u8>>,
}

pub fn load_invite(db: &rusqlite::Connection, token: &Token) -> Option<Invite> {
    db.query_row(
        "SELECT group_id, expires_unix, uses_left, account_used, maker FROM invites WHERE token = ?1",
        [token.0.as_slice()],
        |r| {
            Ok(Invite {
                group: r.get(0)?,
                expires_unix: r.get::<_, i64>(1)? as u64,
                uses_left: r.get(2)?,
                account_used: r.get(3)?,
                maker: r.get(4)?,
            })
        },
    )
    .optional()
    .ok()
    .flatten()
}

pub fn register_account(
    state: &State,
    cs: &mut ConnState,
    token: Token,
    key: Key,
    sig: Sig,
) -> Response {
    if !signed(cs, &key, &sig) {
        return refused("signature check failed; ask for a new challenge");
    }
    let now = state.now();
    let db = state.db();
    let Some(inv) = load_invite(&db, &token) else {
        return refused("this invite link is not valid on this server");
    };
    if now > inv.expires_unix {
        return refused("this invite link has expired; ask for a new one");
    }
    let used = match inv.group {
        // A server invite: one use, spent here.
        None => {
            if inv.uses_left < 1 {
                return refused("this invite link was already used");
            }
            db.execute(
                "UPDATE invites SET uses_left = uses_left - 1 WHERE token = ?1",
                [token.0.as_slice()],
            )
        }
        // A group invite: registers one account when the operator allows it.
        // The group join itself spends the invite. Once a mailbox has
        // redeemed it, only that mailbox's connection may still take the
        // account, and only until the join completes.
        Some(_) => {
            let unspent = inv.uses_left >= 1;
            let redeemer: Option<Vec<u8>> = db
                .query_row(
                    "SELECT mailbox FROM joins WHERE token = ?1",
                    [token.0.as_slice()],
                    |r| r.get(0),
                )
                .optional()
                .ok()
                .flatten();
            let holds_mailbox =
                redeemer.is_some_and(|m| cs.proven.iter().any(|k| k.0[..] == m[..]));
            let may = inv
                .group
                .as_deref()
                .and_then(|g| <[u8; 16]>::try_from(g).ok())
                .is_some_and(|g| {
                    crate::groups::maker_may_invite(
                        state,
                        &db,
                        &socketchat_proto::msg::GroupId(g),
                        inv.maker.as_deref(),
                    )
                });
            if !may {
                return refused(crate::groups::MAKER_CANNOT_INVITE);
            }
            if !state.cfg.members_make_accounts || inv.account_used || !(unspent || holds_mailbox) {
                return refused("this invite link cannot register a new account");
            }
            db.execute(
                "UPDATE invites SET account_used = 1 WHERE token = ?1",
                [token.0.as_slice()],
            )
        }
    };
    if used.is_err() {
        return Response::Error("could not record the invite".into());
    }
    if db
        .execute(
            "INSERT OR IGNORE INTO accounts (key, created_unix) VALUES (?1, ?2)",
            params![key.0.as_slice(), state.today() as i64],
        )
        .is_err()
    {
        return Response::Error("could not save the account".into());
    }
    drop(db);
    admit(state, cs, key);
    Response::Ok
}
