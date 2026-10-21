//! Groups on the server: an ordered log per group, and checks on every
//! signed group change before anyone sees it.
//!
//! The server tracks each group as an OpenMLS `PublicGroup`: the member
//! list, their public keys and the admin list, with no key that decrypts
//! anything. Application messages stay opaque.

use std::collections::{BTreeSet, HashMap};

use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::SqliteStorageProvider;
use rusqlite::{params, Connection, OptionalExtension};
use socketchat_core::provider::JsonCodec;
use socketchat_core::suite::{parse_admins, FALLBACK_SUITE, MAX_PAST_EPOCHS, SUITE};
use socketchat_proto::msg::{
    Entry, GroupId as Gid, InviteInfo, Key, MemberInfo, Push, Response, ServerFrame, Sig,
    WelcomeIn, WelcomeOut,
};
use socketchat_proto::{Token, MAX_FRAME};

use crate::auth::{admit, load_invite, signed};
use crate::conn::ConnState;
use crate::{State, DAY_SECS};

type Storage<'a> = SqliteStorageProvider<JsonCodec, &'a Connection>;

/// Most entries one fetch returns.
const FETCH_LIMIT: u16 = 500;

/// Bytes of entries one reply carries, at most: well under the 1 MiB frame,
/// with room for the frame's own fields. A reply always carries at least
/// one entry, which fits by `MAX_MLS`.
pub(crate) const REPLY_BYTES: usize = 900 * 1024;

/// Largest MLS message the log takes. Leaves room in a 1 MiB frame for the
/// fields around one entry, so any entry can always be fetched or pushed.
pub(crate) const MAX_MLS: usize = MAX_FRAME - 1024;

/// Bytes an entry adds to a reply besides its MLS message: sequence number
/// and length, at their largest.
const ENTRY_OVERHEAD: usize = 16;

/// Server invites one account may make in a window of `quota_window` days.
const SERVER_INVITE_QUOTA: i64 = 5;

/// Unused, unexpired invite links one member may hold in a group.
pub(crate) const OPEN_INVITES: i64 = 20;

fn refused(why: &str) -> Response {
    Response::Refused(why.to_string())
}

fn mls_gid(g: &Gid) -> GroupId {
    GroupId::from_slice(&g.0)
}

fn key_of(bytes: &[u8]) -> Option<Key> {
    bytes.try_into().ok().map(Key)
}

fn is_account(db: &Connection, k: &Key) -> bool {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM accounts WHERE key = ?1)",
        [k.0.as_slice()],
        |r| r.get(0),
    )
    .unwrap_or(false)
}

fn key_registered(db: &Connection, k: &Key) -> bool {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM mailboxes WHERE key = ?1)
             OR EXISTS(SELECT 1 FROM accounts WHERE key = ?1)",
        [k.0.as_slice()],
        |r| r.get(0),
    )
    .unwrap_or(true)
}

/// The key this connection holds that is a joined member of `group`.
pub(crate) fn member_key(db: &Connection, cs: &ConnState, group: &Gid) -> Option<Key> {
    cs.proven.iter().copied().find(|k| {
        db.query_row(
            "SELECT EXISTS(SELECT 1 FROM mailboxes
                 WHERE key = ?1 AND group_id = ?2 AND joined_seq IS NOT NULL)",
            params![k.0.as_slice(), group.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap_or(false)
    })
}

/// Keys of the joined members of `group`.
pub(crate) fn joined_keys(db: &Connection, group: &Gid) -> Vec<Key> {
    joined(db, group).into_keys().collect()
}

/// Joined members of `group` with the log sequence at which each joined.
fn joined(db: &Connection, group: &Gid) -> HashMap<Key, u64> {
    let mut st = db
        .prepare(
            "SELECT key, joined_seq FROM mailboxes WHERE group_id = ?1 AND joined_seq IS NOT NULL",
        )
        .expect("static SQL");
    st.query_map([group.0.as_slice()], |r| {
        Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?))
    })
    .map(|rows| {
        rows.filter_map(Result::ok)
            .filter_map(|(k, s)| key_of(&k).map(|k| (k, s as u64)))
            .collect()
    })
    .unwrap_or_default()
}

pub fn register_mailbox(
    state: &State,
    cs: &mut ConnState,
    token: Option<Token>,
    key: Key,
    sig: Sig,
) -> Response {
    if !signed(cs, &key, &sig) {
        return refused("signature check failed; ask for a new challenge");
    }
    let now = state.now();
    let db = state.db();
    if key_registered(&db, &key) {
        return refused("that key is already registered here; make a fresh one");
    }
    match token {
        None => {
            if !cs.proven.iter().any(|k| is_account(&db, k)) {
                return refused("sign in with a server account before making a group");
            }
            if db
                .execute(
                    "INSERT INTO mailboxes (key, group_id, created_unix) VALUES (?1, NULL, ?2)",
                    params![key.0.as_slice(), state.today() as i64],
                )
                .is_err()
            {
                return Response::Error("could not save the mailbox".into());
            }
        }
        Some(token) => {
            let Some(inv) = load_invite(&db, &token) else {
                return refused("this invite link is not valid on this server");
            };
            let Some(group) = inv.group else {
                return refused("this is a server invite; it does not lead into a group");
            };
            if now > inv.expires_unix {
                return refused("this invite link has expired; ask for a new one");
            }
            if inv.uses_left < 1 {
                return refused("this invite link was already used");
            }
            let ok = db.unchecked_transaction().and_then(|t| {
                // A used link no longer names who made it.
                t.execute(
                    "UPDATE invites SET uses_left = uses_left - 1, maker = NULL WHERE token = ?1",
                    [token.0.as_slice()],
                )?;
                t.execute(
                    "INSERT INTO mailboxes (key, group_id, created_unix) VALUES (?1, ?2, ?3)",
                    params![key.0.as_slice(), group, state.today() as i64],
                )?;
                t.execute(
                    "INSERT INTO joins (token, group_id, mailbox) VALUES (?1, ?2, ?3)",
                    params![token.0.as_slice(), group, key.0.as_slice()],
                )?;
                t.commit()
            });
            if ok.is_err() {
                return Response::Error("could not save the mailbox".into());
            }
        }
    }
    drop(db);
    admit(state, cs, key);
    Response::Ok
}

pub fn create_group(
    state: &State,
    cs: &ConnState,
    group_info: &[u8],
    ratchet_tree: &[u8],
) -> Response {
    let mut guard = state.db();
    // Everything below, the group state OpenMLS stores included, goes
    // through this transaction: a refusal or a failed write leaves nothing.
    let Ok(db) = guard.transaction() else {
        return Response::Error("could not save the group".into());
    };
    if !cs.proven.iter().any(|k| is_account(&db, k)) {
        return refused("sign in with a server account before making a group");
    }
    let Ok(MlsMessageBodyIn::GroupInfo(vgi)) =
        MlsMessageIn::tls_deserialize_exact(group_info).map(|m| m.extract())
    else {
        return refused("that is not an MLS GroupInfo");
    };
    let Ok(tree) = RatchetTreeIn::tls_deserialize_exact(ratchet_tree) else {
        return refused("that is not an MLS ratchet tree");
    };
    let suite = vgi.ciphersuite();
    let allowed = if state.cfg.require_standard_suite {
        suite == FALLBACK_SUITE
    } else {
        suite == SUITE || suite == FALLBACK_SUITE
    };
    if !allowed {
        return refused("this server does not accept that cipher suite");
    }
    let Ok(gid) = <[u8; 16]>::try_from(vgi.group_id().as_slice()).map(Gid) else {
        return refused("group IDs on this server are 16 random bytes");
    };
    let exists: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM groups WHERE id = ?1)",
            [gid.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap_or(true);
    if exists {
        return refused("a group with that ID already exists");
    }
    let storage = Storage::new(&db);
    let Ok((pg, _)) = PublicGroup::from_external(
        &RustCrypto::default(),
        &storage,
        tree,
        vgi,
        ProposalStore::new(),
    ) else {
        return refused("the group info did not check out");
    };
    let members: Vec<Member> = pg.members().collect();
    let creator = members.first().and_then(|m| key_of(&m.signature_key));
    let valid_creator = members.len() == 1
        && creator.is_some_and(|k| {
            cs.proven.contains(&k)
            && db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM mailboxes WHERE key = ?1 AND group_id IS NULL)",
                    [k.0.as_slice()],
                    |r| r.get::<_, bool>(0),
                )
                .unwrap_or(false)
            && parse_admins(pg.group_context()) == vec![k]
        });
    if !valid_creator {
        return refused(
            "a new group must hold only its creator, as its only admin, using a fresh mailbox",
        );
    }
    let creator = creator.expect("checked above");
    let epoch = pg.group_context().epoch().as_u64();
    let now = state.now() as i64;
    let ok = db
        .execute(
            "INSERT INTO groups (id, epoch, next_seq, created_unix) VALUES (?1, ?2, 1, ?3)",
            params![gid.0.as_slice(), epoch as i64, now],
        )
        .and_then(|_| {
            db.execute(
                "UPDATE mailboxes SET group_id = ?1, joined_seq = 0, cursor = 0 WHERE key = ?2",
                params![gid.0.as_slice(), creator.0.as_slice()],
            )
        })
        .and_then(|_| db.commit());
    if ok.is_err() {
        return Response::Error("could not save the group".into());
    }
    Response::Ok
}

/// Appends `mls` to the group log and returns its sequence number.
fn append(db: &Connection, group: &Gid, mls: &[u8], now: u64) -> rusqlite::Result<u64> {
    let seq: i64 = db.query_row(
        "SELECT next_seq FROM groups WHERE id = ?1",
        [group.0.as_slice()],
        |r| r.get(0),
    )?;
    db.execute(
        "INSERT INTO log (group_id, seq, mls, created_unix) VALUES (?1, ?2, ?3, ?4)",
        params![group.0.as_slice(), seq, mls, now as i64],
    )?;
    db.execute(
        "UPDATE groups SET next_seq = next_seq + 1 WHERE id = ?1",
        [group.0.as_slice()],
    )?;
    Ok(seq as u64)
}

/// Why a commit is refused, if it is.
fn check_commit(
    pg: &PublicGroup,
    committer: &Key,
    sc: &StagedCommit,
    join_order: &HashMap<Key, u64>,
    members_can_add: bool,
) -> Result<(), &'static str> {
    let old_admins = parse_admins(pg.group_context());
    let is_admin = old_admins.contains(committer);
    let leaf_key = |i: LeafNodeIndex| {
        pg.leaf(i)
            .and_then(|l| key_of(l.signature_key().as_slice()))
    };

    let mut departed = BTreeSet::new();
    let mut added = BTreeSet::new();
    let mut has_gce = false;
    for q in sc.queued_proposals() {
        match q.proposal() {
            Proposal::Add(a) => {
                if !is_admin && !members_can_add {
                    return Err("adding people needs an admin");
                }
                if let Some(k) = key_of(a.key_package().leaf_node().signature_key().as_slice()) {
                    added.insert(k);
                }
            }
            Proposal::Remove(r) => {
                let leaving_themselves =
                    matches!(q.sender(), Sender::Member(s) if *s == r.removed());
                if !leaving_themselves && !is_admin {
                    return Err("removing someone needs an admin");
                }
                if let Some(k) = leaf_key(r.removed()) {
                    departed.insert(k);
                }
            }
            Proposal::Update(_) => {}
            Proposal::GroupContextExtensions(_) => has_gce = true,
            _ => return Err("this kind of group change is not allowed here"),
        }
    }

    let remaining_old: Vec<Key> = pg
        .members()
        .filter_map(|m| key_of(&m.signature_key))
        .filter(|k| !departed.contains(k))
        .collect();
    let new_admins = parse_admins(sc.group_context());
    let old_admin_stays = old_admins.iter().any(|a| remaining_old.contains(a));

    if !remaining_old.is_empty() && !old_admin_stays {
        // The last admin is leaving: the commit must hand the role to the
        // longest-standing remaining member, and anyone may send it.
        let longest = remaining_old
            .iter()
            .min_by_key(|k| (join_order.get(k).copied().unwrap_or(u64::MAX), k.0))
            .copied();
        if !has_gce || longest.map(|l| vec![l]) != Some(new_admins) {
            return Err("the last admin is leaving; the change must make the longest-standing member an admin");
        }
        return Ok(());
    }
    if has_gce {
        if !is_admin {
            return Err("changing admins needs an admin");
        }
        let new_members: Vec<&Key> = remaining_old.iter().chain(added.iter()).collect();
        if !new_admins.iter().any(|a| new_members.contains(&a)) {
            return Err("a group needs at least one admin");
        }
    }
    Ok(())
}

pub fn post(
    state: &State,
    cs: &ConnState,
    group: Gid,
    mls: &[u8],
    welcome: Option<WelcomeOut>,
) -> Response {
    if mls.len() > MAX_MLS {
        return refused("that message is too large for this server");
    }
    let now = state.now();
    let mut guard = state.db();
    // One transaction for the whole request: the group state OpenMLS
    // stores, the log, the epoch, the member list and the Welcome change
    // together or not at all.
    let Ok(db) = guard.transaction() else {
        return Response::Error("could not store the message".into());
    };
    if member_key(&db, cs, &group).is_none() {
        return refused("you are not a member of this group");
    }
    let Ok(pm) = MlsMessageIn::tls_deserialize_exact(mls).map(|m| m.try_into_protocol_message())
    else {
        return refused("that is not an MLS message");
    };
    let Ok(pm) = pm else {
        return refused("that is not an MLS group message");
    };
    if pm.group_id() != &mls_gid(&group) {
        return refused("that message belongs to another group");
    }
    let Ok(epoch) = db.query_row(
        "SELECT epoch FROM groups WHERE id = ?1",
        [group.0.as_slice()],
        |r| r.get::<_, i64>(0),
    ) else {
        return refused("no such group");
    };
    let epoch = epoch as u64;
    let old_members: Vec<Key> = joined(&db, &group).into_keys().collect();

    if let ProtocolMessage::PrivateMessage(_) = &pm {
        if pm.content_type() != ContentType::Application {
            return refused("group changes must travel as signed PublicMessages");
        }
        let e = pm.epoch().as_u64();
        if e > epoch || epoch - e > MAX_PAST_EPOCHS as u64 {
            return refused(
                "that message is for an epoch this group has left; catch up and resend",
            );
        }
        let Ok(seq) = append(&db, &group, mls, now).and_then(|seq| db.commit().map(|_| seq)) else {
            return Response::Error("could not store the message".into());
        };
        drop(guard);
        push_entry(state, cs, &group, seq, mls, &old_members);
        return Response::Posted { seq };
    }

    if pm.epoch().as_u64() != epoch {
        return Response::Conflict { epoch };
    }
    let storage = Storage::new(&db);
    let Ok(Some(mut pg)) = PublicGroup::load(&storage, &mls_gid(&group)) else {
        return Response::Error("could not load the group".into());
    };
    let processed = match pg.process_message(&RustCrypto::default(), pm) {
        Ok(p) => p,
        Err(e) => return Response::Refused(format!("the group change did not check out: {e}")),
    };
    let Sender::Member(sender_idx) = processed.sender().clone() else {
        return refused("only members can change the group");
    };
    let Some(sender_key) = pg
        .leaf(sender_idx)
        .and_then(|l| key_of(l.signature_key().as_slice()))
    else {
        return refused("unknown sender");
    };
    if !cs.proven.contains(&sender_key) {
        return refused("sign in with the key that made this change");
    }

    match processed.into_content() {
        ProcessedMessageContent::ProposalMessage(qp) => {
            let leaving = matches!(qp.proposal(), Proposal::Remove(r) if r.removed() == sender_idx);
            if !leaving {
                return refused("members may only propose to leave");
            }
            if pg.add_proposal(&storage, *qp).is_err() {
                return Response::Error("could not store the proposal".into());
            }
            let Ok(seq) = append(&db, &group, mls, now).and_then(|seq| db.commit().map(|_| seq))
            else {
                return Response::Error("could not store the message".into());
            };
            drop(guard);
            push_entry(state, cs, &group, seq, mls, &old_members);
            Response::Posted { seq }
        }
        ProcessedMessageContent::StagedCommitMessage(sc) => {
            let order = joined(&db, &group);
            if let Err(why) =
                check_commit(&pg, &sender_key, &sc, &order, state.cfg.members_can_invite)
            {
                return refused(why);
            }
            let added: Vec<Key> = sc
                .add_proposals()
                .filter_map(|a| {
                    key_of(
                        a.add_proposal()
                            .key_package()
                            .leaf_node()
                            .signature_key()
                            .as_slice(),
                    )
                })
                .collect();
            for k in &added {
                let waiting: bool = db
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM mailboxes
                             WHERE key = ?1 AND group_id = ?2 AND joined_seq IS NULL)",
                        params![k.0.as_slice(), group.0.as_slice()],
                        |r| r.get(0),
                    )
                    .unwrap_or(false);
                if !waiting {
                    return refused(
                        "the person being added has not redeemed an invite on this server",
                    );
                }
            }
            if pg.merge_commit(&storage, *sc).is_err() {
                return Response::Error("could not apply the group change".into());
            }
            let new_epoch = pg.group_context().epoch().as_u64();
            let new_members: Vec<Key> = pg
                .members()
                .filter_map(|m| key_of(&m.signature_key))
                .collect();
            let mut welcomed = None;
            let stored = (|| -> rusqlite::Result<u64> {
                let seq = append(&db, &group, mls, now)?;
                db.execute(
                    "UPDATE groups SET epoch = ?1 WHERE id = ?2",
                    params![new_epoch as i64, group.0.as_slice()],
                )?;
                for k in &added {
                    db.execute(
                        "UPDATE mailboxes SET joined_seq = ?1, cursor = ?1 WHERE key = ?2",
                        params![seq as i64, k.0.as_slice()],
                    )?;
                }
                for k in old_members.iter().filter(|k| !new_members.contains(k)) {
                    db.execute("DELETE FROM mailboxes WHERE key = ?1", [k.0.as_slice()])?;
                }
                if let Some(w) = welcome {
                    let mailbox: Option<Vec<u8>> = db
                        .query_row(
                            "SELECT mailbox FROM joins WHERE token = ?1 AND group_id = ?2",
                            params![w.token.0.as_slice(), group.0.as_slice()],
                            |r| r.get(0),
                        )
                        .optional()?;
                    if let Some(mb) = mailbox
                        .as_deref()
                        .and_then(key_of)
                        .filter(|k| added.contains(k))
                    {
                        db.execute(
                            "INSERT INTO welcomes (mailbox, welcome, voucher, created_unix) VALUES (?1, ?2, ?3, ?4)",
                            params![mb.0.as_slice(), w.welcome, w.voucher, now as i64],
                        )?;
                        db.execute("DELETE FROM joins WHERE token = ?1", [w.token.0.as_slice()])?;
                        welcomed = Some(WelcomeIn {
                            mailbox: mb,
                            welcome: w.welcome,
                            voucher: w.voucher,
                        });
                    }
                }
                Ok(seq)
            })();
            let Ok(seq) = stored.and_then(|seq| db.commit().map(|_| seq)) else {
                return Response::Error("could not store the message".into());
            };
            drop(guard);
            if let Some(w) = welcomed {
                let mb = w.mailbox;
                state
                    .online
                    .push_many(&[mb], &ServerFrame::Push(Push::Welcome(w)), None);
            }
            push_entry(state, cs, &group, seq, mls, &old_members);
            Response::Posted { seq }
        }
        _ => refused("that kind of message is not allowed here"),
    }
}

fn push_entry(state: &State, cs: &ConnState, group: &Gid, seq: u64, mls: &[u8], to: &[Key]) {
    let frame = ServerFrame::Push(Push::Entry {
        group: *group,
        entry: Entry {
            seq,
            mls: mls.to_vec(),
        },
    });
    state.online.push_many(to, &frame, Some(cs.id));
}

pub fn fetch(state: &State, cs: &ConnState, group: Gid, after: u64, limit: u16) -> Response {
    let db = state.db();
    let Some(me) = member_key(&db, cs, &group) else {
        return refused("you are not a member of this group");
    };
    let since: i64 = db
        .query_row(
            "SELECT joined_seq FROM mailboxes WHERE key = ?1",
            [me.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let after = after.max(since as u64);
    let limit = limit.clamp(1, FETCH_LIMIT);
    let read = || -> rusqlite::Result<Vec<Entry>> {
        let mut st = db.prepare(
            "SELECT seq, mls FROM log WHERE group_id = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3",
        )?;
        let mut rows = st.query(params![group.0.as_slice(), after as i64, limit as i64])?;
        let mut out = Vec::new();
        let mut bytes = 0;
        while let Some(r) = rows.next()? {
            let mls: Vec<u8> = r.get(1)?;
            let size = mls.len() + ENTRY_OVERHEAD;
            if !out.is_empty() && bytes + size > REPLY_BYTES {
                break;
            }
            bytes += size;
            out.push(Entry {
                seq: r.get::<_, i64>(0)? as u64,
                mls,
            });
        }
        Ok(out)
    };
    match read() {
        Ok(es) => Response::Entries(es),
        Err(_) => Response::Error("could not read the group log".into()),
    }
}

pub fn ack(state: &State, cs: &ConnState, group: Gid, seq: u64) -> Response {
    let db = state.db();
    let Some(me) = member_key(&db, cs, &group) else {
        return refused("you are not a member of this group");
    };
    let ok = db
        .execute(
            "UPDATE mailboxes SET cursor = max(cursor, ?1) WHERE key = ?2",
            params![seq as i64, me.0.as_slice()],
        )
        .and_then(|_| {
            db.execute(
                "DELETE FROM log WHERE group_id = ?1 AND seq <= (
                     SELECT min(cursor) FROM mailboxes WHERE group_id = ?1 AND joined_seq IS NOT NULL)",
                [group.0.as_slice()],
            )
        });
    match ok {
        Ok(_) => Response::Ok,
        Err(_) => Response::Error("could not record the acknowledgement".into()),
    }
}

pub fn members(state: &State, cs: &ConnState, group: Gid) -> Response {
    let db = state.db();
    if member_key(&db, cs, &group).is_none() {
        return refused("you are not a member of this group");
    }
    let mut v: Vec<MemberInfo> = joined(&db, &group)
        .into_iter()
        .map(|(key, joined_seq)| MemberInfo { key, joined_seq })
        .collect();
    v.sort_by_key(|m| (m.joined_seq, m.key.0));
    Response::Members(v)
}

pub fn create_invite(state: &State, cs: &ConnState, group: Option<Gid>) -> Response {
    let now = state.now();
    let expires = now + state.cfg.invite_ttl_hours as u64 * 3600;
    let db = state.db();
    let token = crate::random_token();
    match group {
        Some(g) => {
            let Some(me) = member_key(&db, cs, &g) else {
                return refused("you are not a member of this group");
            };
            if !state.cfg.members_can_invite {
                let storage = Storage::new(&*db);
                let is_admin = PublicGroup::load(&storage, &mls_gid(&g))
                    .ok()
                    .flatten()
                    .is_some_and(|pg| parse_admins(pg.group_context()).contains(&me));
                if !is_admin {
                    return refused("on this server only admins can make invite links");
                }
            }
            let open: i64 = match db.query_row(
                "SELECT COUNT(*) FROM invites
                     WHERE maker = ?1 AND group_id = ?2 AND uses_left > 0 AND expires_unix >= ?3",
                params![me.0.as_slice(), g.0.as_slice(), now as i64],
                |r| r.get(0),
            ) {
                Ok(n) => n,
                Err(_) => return Response::Error("could not save the invite".into()),
            };
            if open >= OPEN_INVITES {
                return Response::Refused(format!(
                    "you have {OPEN_INVITES} open invite links in this group; wait for some to be used or expire"
                ));
            }
            if db
                .execute(
                    "INSERT INTO invites (token, group_id, expires_unix, uses_left, maker) VALUES (?1, ?2, ?3, 1, ?4)",
                    params![token.0.as_slice(), g.0.as_slice(), expires as i64, me.0.as_slice()],
                )
                .is_err()
            {
                return Response::Error("could not save the invite".into());
            }
        }
        None => {
            let account = cs.proven.iter().copied().find(|k| is_account(&db, k));
            let (true, Some(account)) = (state.cfg.members_can_invite, account) else {
                return refused("on this server only the operator can invite new people");
            };
            match take_server_invite(state, &db, &account, now, &token, expires) {
                Ok(true) => {}
                Ok(false) => {
                    return Response::Refused(format!(
                        "you have made {SERVER_INVITE_QUOTA} server invite links lately; try again in a day or two"
                    ))
                }
                Err(_) => return Response::Error("could not save the invite".into()),
            }
        }
    }
    Response::Invite {
        token,
        expires_unix: expires,
    }
}

/// Most server invites one `ListInvites` may ask about.
const LIST_SERVER_TOKENS: usize = 100;

/// Most links one `ListInvites` answers.
const LIST_INVITES: usize = 500;

const LINK_GONE: &str = "that link was already used, has expired or was cancelled";

/// Open group links made by this connection's keys, plus the open server
/// links named by `server_tokens`. Oldest expiry first.
pub fn list_invites(state: &State, cs: &ConnState, server_tokens: &[Token]) -> Response {
    if server_tokens.len() > LIST_SERVER_TOKENS {
        return refused("ask about at most 100 links at a time");
    }
    let now = state.now() as i64;
    let db = state.db();
    let read = || -> rusqlite::Result<Vec<InviteInfo>> {
        let mut out = Vec::new();
        let mut by_maker = db.prepare(
            "SELECT token, group_id, expires_unix FROM invites
                 WHERE maker = ?1 AND group_id IS NOT NULL AND uses_left > 0 AND expires_unix >= ?2",
        )?;
        for key in &cs.proven {
            let rows = by_maker.query_map(params![key.0.as_slice(), now], invite_row)?;
            out.extend(rows.filter_map(|r| r.ok().flatten()));
        }
        let mut by_token = db.prepare(
            "SELECT token, group_id, expires_unix FROM invites
                 WHERE token = ?1 AND group_id IS NULL AND uses_left > 0 AND expires_unix >= ?2",
        )?;
        for t in server_tokens {
            let rows = by_token.query_map(params![t.0.as_slice(), now], invite_row)?;
            out.extend(rows.filter_map(|r| r.ok().flatten()));
        }
        Ok(out)
    };
    match read() {
        Ok(mut v) => {
            v.sort_by_key(|i| (i.expires_unix, i.token.0));
            v.dedup_by_key(|i| i.token.0);
            v.truncate(LIST_INVITES);
            Response::Invites(v)
        }
        Err(_) => Response::Error("could not read the invites".into()),
    }
}

fn invite_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Option<InviteInfo>> {
    let token: Vec<u8> = r.get(0)?;
    let group: Option<Vec<u8>> = r.get(1)?;
    let expires: i64 = r.get(2)?;
    let Ok(token) = <[u8; 16]>::try_from(token.as_slice()) else {
        return Ok(None);
    };
    let group = match group {
        None => None,
        Some(g) => match <[u8; 16]>::try_from(g.as_slice()) {
            Ok(g) => Some(Gid(g)),
            Err(_) => return Ok(None),
        },
    };
    Ok(Some(InviteInfo {
        token: Token(token),
        group,
        expires_unix: expires as u64,
    }))
}

/// Deletes an open link the connection made: a group link by one of its
/// proven keys, or a server link while it holds a proven account. A
/// cancelled server link does not give back invite quota.
pub fn cancel_invite(state: &State, cs: &ConnState, token: Token) -> Response {
    let now = state.now() as i64;
    let db = state.db();
    let open = "token = ?1 AND uses_left > 0 AND expires_unix >= ?2";
    let mut gone = 0;
    for key in &cs.proven {
        match db.execute(
            &format!("DELETE FROM invites WHERE {open} AND group_id IS NOT NULL AND maker = ?3"),
            params![token.0.as_slice(), now, key.0.as_slice()],
        ) {
            Ok(n) => gone += n,
            Err(_) => return Response::Error("could not cancel the invite".into()),
        }
    }
    if gone == 0 && cs.proven.iter().any(|k| is_account(&db, k)) {
        match db.execute(
            &format!("DELETE FROM invites WHERE {open} AND group_id IS NULL"),
            params![token.0.as_slice(), now],
        ) {
            Ok(n) => gone += n,
            Err(_) => return Response::Error("could not cancel the invite".into()),
        }
    }
    if gone == 0 {
        return refused(LINK_GONE);
    }
    Response::Ok
}

/// When the group was created, for a member.
pub fn group_created(state: &State, cs: &ConnState, group: Gid) -> Response {
    let db = state.db();
    if member_key(&db, cs, &group).is_none() {
        return refused("you are not a member of this group");
    }
    match db.query_row(
        "SELECT created_unix FROM groups WHERE id = ?1",
        [group.0.as_slice()],
        |r| r.get::<_, i64>(0),
    ) {
        Ok(t) => Response::GroupCreated {
            created_unix: t as u64,
        },
        Err(_) => Response::Error("could not read the group".into()),
    }
}

/// Days in an account's server-invite window: long enough that every link
/// made in one window has expired before the next starts.
pub(crate) fn quota_window_secs(state: &State) -> u64 {
    let ttl = state.cfg.invite_ttl_hours as u64 * 3600;
    ttl.div_ceil(DAY_SECS) * DAY_SECS + DAY_SECS
}

/// Counts one server invite against `account` and saves it, or returns
/// false when the account has made its share. Only a count and the day its
/// window began are kept, never which invites the account made.
fn take_server_invite(
    state: &State,
    db: &Connection,
    account: &Key,
    now: u64,
    token: &Token,
    expires: u64,
) -> rusqlite::Result<bool> {
    let t = db.unchecked_transaction()?;
    let row: Option<(i64, i64)> = t
        .query_row(
            "SELECT since_unix, used FROM invite_quota WHERE account = ?1",
            [account.0.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let fresh = match row {
        Some((since, used)) if now < since as u64 + quota_window_secs(state) => {
            if used >= SERVER_INVITE_QUOTA {
                return Ok(false);
            }
            false
        }
        _ => true,
    };
    if fresh {
        t.execute(
            "INSERT OR REPLACE INTO invite_quota (account, since_unix, used) VALUES (?1, ?2, 1)",
            params![account.0.as_slice(), state.today() as i64],
        )?;
    } else {
        t.execute(
            "UPDATE invite_quota SET used = used + 1 WHERE account = ?1",
            [account.0.as_slice()],
        )?;
    }
    t.execute(
        "INSERT INTO invites (token, group_id, expires_unix, uses_left) VALUES (?1, NULL, ?2, 1)",
        params![token.0.as_slice(), expires as i64],
    )?;
    t.commit()?;
    Ok(true)
}

/// Welcomes waiting for this connection's mailboxes, as many as fit one
/// reply. Only those sent are removed; the rest come on the next call.
pub fn fetch_welcomes(state: &State, cs: &ConnState) -> Response {
    let db = state.db();
    let read = || -> rusqlite::Result<Vec<WelcomeIn>> {
        let t = db.unchecked_transaction()?;
        let mut out = Vec::new();
        let mut bytes = 0;
        let mut sent = Vec::new();
        'keys: for k in &cs.proven {
            let mut st =
                t.prepare("SELECT rowid, welcome, voucher FROM welcomes WHERE mailbox = ?1")?;
            let mut rows = st.query([k.0.as_slice()])?;
            while let Some(r) = rows.next()? {
                let welcome: Vec<u8> = r.get(1)?;
                let voucher: Vec<u8> = r.get(2)?;
                let size = welcome.len() + voucher.len() + 64;
                if !out.is_empty() && bytes + size > REPLY_BYTES {
                    break 'keys;
                }
                bytes += size;
                sent.push(r.get::<_, i64>(0)?);
                out.push(WelcomeIn {
                    mailbox: *k,
                    welcome,
                    voucher,
                });
            }
        }
        for id in sent {
            t.execute("DELETE FROM welcomes WHERE rowid = ?1", [id])?;
        }
        t.commit()?;
        Ok(out)
    };
    match read() {
        Ok(ws) => Response::Welcomes(ws),
        Err(_) => Response::Error("could not read welcomes".into()),
    }
}
