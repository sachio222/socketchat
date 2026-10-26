//! Groups on the server: an ordered log per group, and checks on every
//! signed group change before anyone sees it.
//!
//! The server tracks each group as an OpenMLS `PublicGroup`: the member
//! list, their public keys and the admin list, with no key that decrypts
//! anything. Application messages stay opaque.

use std::collections::{BTreeSet, HashMap};

use openmls::ciphersuite::hash_ref::ProposalRef;
use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_sqlite_storage::SqliteStorageProvider;
use openmls_traits::public_storage::PublicStorageProvider as _;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use socketchat_core::provider::JsonCodec;
use socketchat_core::settings::{room_settings, settings_in, WhoCanInvite};
use socketchat_core::suite::{parse_admins, FALLBACK_SUITE, MAX_PAST_EPOCHS, SUITE};
use socketchat_proto::msg::{
    Entry, FileId, GroupId as Gid, InviteInfo, Key, MemberInfo, Push, Response, ServerFrame, Sig,
    WelcomeIn, WelcomeOut,
};
use socketchat_proto::{Token, MAX_FRAME};

use crate::auth::{admit, load_invite, signed};
use crate::conn::ConnState;
use crate::quota::{self, Count};
use crate::rules::{wait_text, Pace, RoomRules};
use crate::State;

type Storage<'a> = SqliteStorageProvider<JsonCodec, &'a Connection>;

/// The OpenMLS group storage in the server's database.
pub(crate) fn storage(db: &Connection) -> Storage<'_> {
    Storage::new(db)
}

/// The answer to a post that came too fast: `SlowDown` for apps that read
/// it, words with the wait for older ones.
fn slow_down(cs: &ConnState, ms: u32) -> Response {
    if cs.version >= 3 {
        Response::SlowDown { retry_after_ms: ms }
    } else {
        Response::Refused(format!(
            "this room limits fast posting; try again in {}",
            wait_text(ms)
        ))
    }
}

/// Counts a post of `bytes` by `member` against their pace in `group`, or
/// says how long to wait. Admins are not held by the room's slow mode, as
/// Discord leaves moderators out of it, and get ten times a member's pace:
/// the app posts on their behalf for every person they bring in, and one
/// account that makes its own room still meets a limit.
fn pace_refused(
    state: &State,
    rules: Option<&RoomRules>,
    group: &Gid,
    member: &Key,
    bytes: usize,
) -> Result<(), u32> {
    let admin = rules.is_some_and(|r| r.admins.contains(member));
    let slow = rules.map_or(0, |r| r.settings.slow_secs);
    state.limiter.take(
        *group,
        *member,
        bytes,
        state.now_ms(),
        Pace::new(state, slow, admin),
    )
}

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

/// Largest ratchet tree a new group may send. A new group holds only its
/// creator, whose tree measures under 2 KB on either suite.
const MAX_NEW_TREE: usize = 16 * 1024;

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

/// How `retired_keys` names a group key that left a room.
fn retired_hash(k: &Key) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"socketchat/v1/retired-key");
    h.update(k.0);
    h.finalize().into()
}

/// Whether a key is in use here, or left a room that still exists.
fn key_registered(db: &Connection, k: &Key) -> bool {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM mailboxes WHERE key = ?1)
             OR EXISTS(SELECT 1 FROM accounts WHERE key = ?1)
             OR EXISTS(SELECT 1 FROM retired_keys WHERE hash = ?2)",
        params![k.0.as_slice(), retired_hash(k).as_slice()],
        |r| r.get(0),
    )
    .unwrap_or(true)
}

/// Someone left `group` or was removed from it: their mailbox goes, the
/// links they made there stop working, joins waiting on those links go with
/// the joiners' mailboxes, and their key cannot sign up again while the
/// room lasts.
fn retire(db: &Connection, group: &Gid, k: &Key) -> rusqlite::Result<()> {
    // A Welcome nobody fetched goes with the mailbox it was for, whether
    // that person left or waited on a link whose maker left.
    db.execute("DELETE FROM welcomes WHERE mailbox = ?1", [k.0.as_slice()])?;
    db.execute("DELETE FROM mailboxes WHERE key = ?1", [k.0.as_slice()])?;
    drop_links(db, group, k)?;
    db.execute(
        "INSERT OR IGNORE INTO retired_keys (hash, group_id) VALUES (?1, ?2)",
        params![retired_hash(k).as_slice(), group.0.as_slice()],
    )?;
    Ok(())
}

/// The links `k` made in `group` stop working, and joins waiting on them
/// go with the joiners' mailboxes and any Welcome not yet fetched.
fn drop_links(db: &Connection, group: &Gid, k: &Key) -> rusqlite::Result<()> {
    db.execute(
        "DELETE FROM welcomes WHERE mailbox IN (
             SELECT j.mailbox FROM joins j JOIN invites i ON i.token = j.token
             WHERE i.maker = ?1 AND i.group_id = ?2)",
        params![k.0.as_slice(), group.0.as_slice()],
    )?;
    db.execute(
        "DELETE FROM mailboxes WHERE joined_seq IS NULL AND key IN (
             SELECT j.mailbox FROM joins j JOIN invites i ON i.token = j.token
             WHERE i.maker = ?1 AND i.group_id = ?2)",
        params![k.0.as_slice(), group.0.as_slice()],
    )?;
    db.execute(
        "DELETE FROM joins WHERE token IN (
             SELECT token FROM invites WHERE maker = ?1 AND group_id = ?2)",
        params![k.0.as_slice(), group.0.as_slice()],
    )?;
    db.execute(
        "DELETE FROM invites WHERE maker = ?1 AND group_id = ?2",
        params![k.0.as_slice(), group.0.as_slice()],
    )?;
    Ok(())
}

/// Said when a link's maker can no longer bring people into its room.
pub(crate) const MAKER_CANNOT_INVITE: &str = "this invite link stopped working, because the person who made it can no longer invite people into this room; ask an admin of the room for a new one";

/// Whether the member who made a room link may still bring people into
/// `group`: an admin always, anyone else only while both the server and
/// the room let members invite. A link with no recorded maker passes.
pub(crate) fn maker_may_invite(
    state: &State,
    db: &Connection,
    group: &Gid,
    maker: Option<&[u8]>,
) -> bool {
    let Some(maker) = maker.and_then(key_of) else {
        return true;
    };
    let Some(rules) = state.rules.get(db, group) else {
        return false;
    };
    rules.admins.contains(&maker)
        || (state.cfg.members_can_invite_to_rooms && rules.settings.invite == WhoCanInvite::Anyone)
}

/// A room just went admins-only, or lost an admin while admins-only: the
/// links made by members who are not admins stop working, with the joins
/// waiting on them.
fn drop_members_links(db: &Connection, group: &Gid, admins: &[Key]) -> rusqlite::Result<()> {
    let makers: Vec<Vec<u8>> = db
        .prepare("SELECT DISTINCT maker FROM invites WHERE group_id = ?1 AND maker IS NOT NULL")?
        .query_map([group.0.as_slice()], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    for m in makers.iter().filter_map(|m| key_of(m)) {
        if !admins.contains(&m) {
            drop_links(db, group, &m)?;
        }
    }
    Ok(())
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
            if let Ok(gid) = <[u8; 16]>::try_from(group.as_slice()).map(Gid) {
                if !maker_may_invite(state, &db, &gid, inv.maker.as_deref()) {
                    return refused(MAKER_CANNOT_INVITE);
                }
                // A room that could not take this person's add says so now,
                // to the joiner, and the link stays unused.
                if let Some(r) = quota::join_refused(state, &db, &gid) {
                    return r;
                }
            }
            let ok = db.unchecked_transaction().and_then(|t| {
                // A used link names who made it until the join completes,
                // so the join goes if that member leaves first.
                t.execute(
                    "UPDATE invites SET uses_left = uses_left - 1 WHERE token = ?1",
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
    if !cs.proven.iter().any(|k| is_account(&state.db(), k)) {
        return refused("sign in with a server account before making a group");
    }
    const ONLY_CREATOR: &str =
        "a new group must hold only its creator, as its only admin, using a fresh mailbox";
    if ratchet_tree.len() > MAX_NEW_TREE {
        return refused(ONLY_CREATOR);
    }
    // The whole check runs without the database lock, against storage
    // that is thrown away, so a large group cannot hold up other requests.
    state.cfg.new_room_check_hold.pass();
    let (vgi, tree) = match parse_new_group(group_info, ratchet_tree) {
        Ok(parsed) => parsed,
        Err(why) => return refused(why),
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
    let Ok((pg, _)) = PublicGroup::from_external(
        &RustCrypto::default(),
        &MemoryStorage::default(),
        tree,
        vgi,
        ProposalStore::new(),
    ) else {
        return refused("the group info did not check out");
    };
    let members: Vec<Member> = pg.members().collect();
    let creator = members.first().and_then(|m| key_of(&m.signature_key));
    let Some(creator) = creator.filter(|k| {
        members.len() == 1 && cs.proven.contains(k) && parse_admins(pg.group_context()) == vec![*k]
    }) else {
        return refused(ONLY_CREATOR);
    };
    if settings_in(pg.group_context().extensions()).is_none() {
        return refused("the room's settings do not read");
    }
    let epoch = pg.group_context().epoch().as_u64();

    let mut guard = state.db();
    // Everything below, the group state OpenMLS stores included, goes
    // through this transaction: a refusal or a failed write leaves nothing.
    let Ok(db) = guard.transaction() else {
        return Response::Error("could not save the group".into());
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
    let fresh_mailbox = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM mailboxes WHERE key = ?1 AND group_id IS NULL)",
            [creator.0.as_slice()],
            |r| r.get::<_, bool>(0),
        )
        .unwrap_or(false);
    if !fresh_mailbox {
        return refused(ONLY_CREATOR);
    }
    // Stored from the same bytes, checked again: one leaf, so it is quick.
    let storage = Storage::new(&db);
    let stored = parse_new_group(group_info, ratchet_tree).is_ok_and(|(vgi, tree)| {
        PublicGroup::from_external(
            &RustCrypto::default(),
            &storage,
            tree,
            vgi,
            ProposalStore::new(),
        )
        .is_ok()
    });
    if !stored {
        return Response::Error("could not save the group".into());
    }
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

fn parse_new_group(
    group_info: &[u8],
    ratchet_tree: &[u8],
) -> Result<(VerifiableGroupInfo, RatchetTreeIn), &'static str> {
    let Ok(MlsMessageBodyIn::GroupInfo(vgi)) =
        MlsMessageIn::tls_deserialize_exact(group_info).map(|m| m.extract())
    else {
        return Err("that is not an MLS GroupInfo");
    };
    let Ok(tree) = RatchetTreeIn::tls_deserialize_exact(ratchet_tree) else {
        return Err("that is not an MLS ratchet tree");
    };
    Ok((vgi, tree))
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
        "UPDATE groups SET next_seq = next_seq + 1, log_bytes = log_bytes + ?2 WHERE id = ?1",
        params![group.0.as_slice(), quota::entry_cost(mls.len()) as i64],
    )?;
    Ok(seq as u64)
}

/// Why a commit is refused, if it is. Everything is judged by the room as
/// it stood before the commit: its admins and its settings then.
/// `server_lets_members_invite` is the operator's own rule; when false,
/// every room is admins-only for adds, whatever its setting says.
fn check_commit(
    pg: &PublicGroup,
    committer: &Key,
    sc: &StagedCommit,
    join_order: &HashMap<Key, u64>,
    server_lets_members_invite: bool,
) -> Result<(), &'static str> {
    let old_admins = parse_admins(pg.group_context());
    let is_admin = old_admins.contains(committer);
    let old_settings = room_settings(pg.group_context().extensions());
    let Some(new_settings) = settings_in(sc.group_context().extensions()) else {
        return Err("the room's new settings do not read; nothing changed");
    };
    let members_can_add = old_settings.invite == WhoCanInvite::Anyone;
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
                if !is_admin && !server_lets_members_invite {
                    return Err("on this server only admins can add people to rooms");
                }
                if !is_admin && !members_can_add {
                    return Err("in this room only admins can add people");
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
        if new_settings != old_settings {
            return Err("handing on the admin role cannot change the room's settings");
        }
        return Ok(());
    }
    if has_gce {
        if !is_admin && new_settings != old_settings {
            return Err("changing this room's settings needs an admin");
        }
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
    let parsed = MlsMessageIn::tls_deserialize_exact(mls).map(|m| m.try_into_protocol_message());
    if let Ok(Ok(pm)) = &parsed {
        if matches!(pm, ProtocolMessage::PublicMessage(_))
            && pm.content_type() == ContentType::Commit
        {
            let Ok(Ok(pm)) = parsed else {
                unreachable!("matched above")
            };
            return post_commit(state, cs, group, mls, pm, welcome);
        }
    }
    let now = state.now();
    let cost = quota::entry_cost(mls.len());
    let mut guard = state.db();
    // One transaction for the whole request: the group state OpenMLS
    // stores, the log and the epoch change together or not at all.
    let Ok(db) = guard.transaction() else {
        return Response::Error("could not store the message".into());
    };
    let Some(me) = member_key(&db, cs, &group) else {
        return refused("you are not a member of this group");
    };
    let Ok(pm) = parsed else {
        return refused("that is not an MLS message");
    };
    let Ok(pm) = pm else {
        return refused("that is not an MLS group message");
    };
    if pm.group_id() != &mls_gid(&group) {
        return refused("that message belongs to another group");
    }
    let Ok(epoch) = epoch_of(&db, &group) else {
        return refused("no such group");
    };
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
        if let Some(r) = quota::messages_refused(state, &db, &group, cost, 0, false) {
            return r;
        }
        let rules = state.rules.get(&db, &group);
        if let Err(ms) = pace_refused(state, rules.as_deref(), &group, &me, mls.len()) {
            return slow_down(cs, ms);
        }
        let Ok(seq) = append(&db, &group, mls, now).and_then(|seq| db.commit().map(|_| seq)) else {
            return Response::Error("could not store the message".into());
        };
        quota::note_stored(state, cost, 0);
        push_entry(state, cs, &group, seq, mls, &old_members);
        drop(guard);
        state.cfg.post_written_hold.pass();
        return Response::Posted { seq };
    }

    if pm.epoch().as_u64() != epoch {
        return Response::Conflict { epoch };
    }
    // A proposal: one signature to check, so it is checked here.
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
    let aad = processed.aad().len();
    let ProcessedMessageContent::ProposalMessage(qp) = processed.into_content() else {
        return refused("that kind of message is not allowed here");
    };
    let leaving = matches!(qp.proposal(), Proposal::Remove(r) if r.removed() == sender_idx);
    if !leaving {
        return refused("members may only propose to leave");
    }
    // A request to leave is never held by the pace or slow mode, so the
    // server takes one per member per epoch, at the size apps send it.
    if mls.len() > quota::EXEMPT_LEAVE_MAX || aad > quota::EXEMPT_AAD_MAX {
        return refused("that request to leave is larger than Socketchat apps send");
    }
    let asked_before = pg.queued_proposals(&storage).map_or(true, |qs| {
        qs.iter().any(|(_, q)| {
            matches!(q.sender(), Sender::Member(s) if *s == sender_idx)
                && matches!(q.proposal(), Proposal::Remove(r) if r.removed() == sender_idx)
        })
    });
    if asked_before {
        return refused("you already asked to leave; the room lets you go at its next change");
    }
    // A full room still takes each member's request to leave, up to a
    // little past the limit.
    if quota::messages_refused(state, &db, &group, cost, 0, false).is_some() {
        if let Some(r) = quota::messages_refused(state, &db, &group, cost, 0, true) {
            return r;
        }
    }
    if pg.add_proposal(&storage, *qp).is_err() {
        return Response::Error("could not store the proposal".into());
    }
    let Ok(seq) = append(&db, &group, mls, now).and_then(|seq| db.commit().map(|_| seq)) else {
        return Response::Error("could not store the message".into());
    };
    quota::note_stored(state, cost, 0);
    push_entry(state, cs, &group, seq, mls, &old_members);
    drop(guard);
    state.cfg.post_written_hold.pass();
    Response::Posted { seq }
}

fn epoch_of(db: &Connection, group: &Gid) -> rusqlite::Result<u64> {
    db.query_row(
        "SELECT epoch FROM groups WHERE id = ?1",
        [group.0.as_slice()],
        |r| r.get::<_, i64>(0),
    )
    .map(|e| e as u64)
}

fn queued_refs(pg: &PublicGroup, storage: &Storage) -> Option<Vec<ProposalRef>> {
    pg.queued_proposals(storage)
        .ok()
        .map(|qs| qs.into_iter().map(|(r, _)| r).collect())
}

/// Whether every proposal queued when a Commit was read is still queued.
/// Proposals leave the queue only with a Commit, so one that arrived since
/// (a request to leave) does not change what the Commit was checked
/// against. The queue comes back in no set order, so this compares sets.
fn still_queued(read: &[ProposalRef], now: Option<Vec<ProposalRef>>) -> bool {
    now.is_some_and(|now| read.iter().all(|r| now.contains(r)))
}

/// A Commit, in three steps so that its check, which can take a long time
/// for a large one, runs without the database lock: read the group under
/// the lock, check the Commit without it, then take the lock again and
/// write only if the group is as it was read. Of two Commits checked at
/// once for one epoch, the first written wins and the other hears
/// `Conflict`.
fn post_commit(
    state: &State,
    cs: &ConnState,
    group: Gid,
    mls: &[u8],
    pm: ProtocolMessage,
    welcome: Option<WelcomeOut>,
) -> Response {
    let (epoch, mut pg, queued, order) = {
        let db = state.db();
        if member_key(&db, cs, &group).is_none() {
            return refused("you are not a member of this group");
        }
        if pm.group_id() != &mls_gid(&group) {
            return refused("that message belongs to another group");
        }
        let Ok(epoch) = epoch_of(&db, &group) else {
            return refused("no such group");
        };
        if pm.epoch().as_u64() != epoch {
            return Response::Conflict { epoch };
        }
        // Past even what a change that shrinks the room may use, nothing
        // goes, so there is nothing to check.
        let cost = quota::entry_cost(mls.len());
        if let Some(r) = quota::messages_refused(state, &db, &group, cost, 0, true) {
            return r;
        }
        let storage = Storage::new(&db);
        let Ok(Some(pg)) = PublicGroup::load(&storage, &mls_gid(&group)) else {
            return Response::Error("could not load the group".into());
        };
        let Some(queued) = queued_refs(&pg, &storage) else {
            return Response::Error("could not load the group".into());
        };
        (epoch, pg, queued, joined(&db, &group))
    };
    let rules_before = RoomRules::from_context(pg.group_context().extensions());

    let delay = state.cfg.commit_check_delay.get();
    if !delay.is_zero() {
        std::thread::sleep(delay);
    }
    state.cfg.commit_check_hold.pass();
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
    let aad = processed.aad().len();
    let ProcessedMessageContent::StagedCommitMessage(sc) = processed.into_content() else {
        return refused("that kind of message is not allowed here");
    };
    if let Err(why) = check_commit(
        &pg,
        &sender_key,
        &sc,
        &order,
        state.cfg.members_can_invite_to_rooms,
    ) {
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
    // A change that only takes people out, with no extra data, may go a
    // little past the room's and the server's limits, so a full room can
    // still shrink.
    let shrinks =
        added.is_empty() && sc.remove_proposals().next().is_some() && aad <= quota::EXEMPT_AAD_MAX;
    // Taking people out, a member's own leave included, is never held up
    // by the pace limit.
    let removes_only = added.is_empty() && sc.remove_proposals().next().is_some();
    let rules_after = RoomRules::from_context(sc.group_context().extensions());

    let now = state.now();
    let mut guard = state.db();
    // One transaction for the writes: the group state OpenMLS stores, the
    // log, the epoch, the member list and the Welcome change together or
    // not at all.
    let Ok(db) = guard.transaction() else {
        return Response::Error("could not store the message".into());
    };
    let Ok(current) = epoch_of(&db, &group) else {
        return refused("no such group");
    };
    let storage = Storage::new(&db);
    if current != epoch || !still_queued(&queued, queued_refs(&pg, &storage)) {
        return Response::Conflict { epoch: current };
    }
    if !is_joined(&db, &group, &sender_key) {
        return refused("you are not a member of this group");
    }
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
            return refused("the person being added has not redeemed an invite on this server");
        }
    }
    let cost = quota::entry_cost(mls.len());
    let welcome_bytes = welcome
        .as_ref()
        .map_or(0, |w| (w.welcome.len() + w.voucher.len()) as u64);
    if !added.is_empty() && welcome.is_some() {
        if let Some(r) = quota::welcome_refused(state, &db, &group) {
            return r;
        }
    }
    if let Some(r) = quota::messages_refused(state, &db, &group, cost, welcome_bytes, shrinks) {
        return r;
    }
    // Charged last, so a change refused for any other reason spends none.
    if !removes_only {
        if let Err(ms) = pace_refused(state, Some(&rules_before), &group, &sender_key, mls.len()) {
            return slow_down(cs, ms);
        }
    }
    let old_members: Vec<Key> = joined(&db, &group).into_keys().collect();
    if pg.merge_commit(&storage, *sc).is_err() {
        return Response::Error("could not apply the group change".into());
    }
    let new_epoch = pg.group_context().epoch().as_u64();
    let new_members: Vec<Key> = pg
        .members()
        .filter_map(|m| key_of(&m.signature_key))
        .collect();
    let mut welcomed = None;
    let mut unwanted = Vec::new();
    let mut left = false;
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
        // The Welcome first: a commit that adds a joiner and removes
        // the maker of their link still lets them in.
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
                // A completed join no longer names who made its link.
                db.execute(
                    "UPDATE invites SET maker = NULL WHERE token = ?1",
                    [w.token.0.as_slice()],
                )?;
                welcomed = Some(WelcomeIn {
                    mailbox: mb,
                    welcome: w.welcome,
                    voucher: w.voucher,
                });
            }
        }
        let mut retired = false;
        for k in old_members.iter().filter(|k| !new_members.contains(k)) {
            retire(&db, &group, k)?;
            retired = true;
            left = true;
        }
        let admins_only_after = rules_after.settings.invite == WhoCanInvite::Admins
            || !state.cfg.members_can_invite_to_rooms;
        let switched = rules_before.settings.invite != rules_after.settings.invite;
        if admins_only_after && (switched || rules_before.admins != rules_after.admins) {
            drop_members_links(&db, &group, &rules_after.admins)?;
        }
        // Files only those who left were waiting for go with them.
        if retired {
            unwanted = crate::files::drop_unwanted(&db, &group)?;
        }
        Ok(seq)
    })();
    let Ok(seq) = stored.and_then(|seq| db.commit().map(|_| seq)) else {
        return Response::Error("could not store the message".into());
    };
    // Still under the database lock: the next post reads the new rules.
    state.rules.set(group, rules_after);
    for k in old_members.iter().filter(|k| !new_members.contains(k)) {
        state.limiter.forget(&group, k);
    }
    quota::note_stored(state, cost + welcome_bytes, 0);
    if !unwanted.is_empty() || left {
        quota::recount(state);
    }
    // A used link no longer names its maker, and a departure deleted rows:
    // neither stays in the write-ahead log.
    if left || welcomed.is_some() {
        crate::db::checkpoint(&guard);
    }
    if let Some(w) = welcomed {
        let mb = w.mailbox;
        state
            .online
            .push_many(&[mb], &ServerFrame::Push(Push::Welcome(w)), None);
    }
    push_entry(state, cs, &group, seq, mls, &old_members);
    drop(guard);
    state.cfg.post_written_hold.pass();
    for f in unwanted {
        let _ = std::fs::remove_dir_all(crate::files::file_dir(state, &f));
    }
    Response::Posted { seq }
}

fn is_joined(db: &Connection, group: &Gid, k: &Key) -> bool {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM mailboxes
             WHERE key = ?1 AND group_id = ?2 AND joined_seq IS NOT NULL)",
        params![k.0.as_slice(), group.0.as_slice()],
        |r| r.get(0),
    )
    .unwrap_or(false)
}

/// Pushes a new entry to the room. Called before the write lets go of the
/// database lock, so the push is queued on every member's connection ahead
/// of the answer to anything that member asks next, and pushes leave in log
/// order: a member told it is out of the room already holds the commit
/// that took it out.
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
    // An `after` past what SQLite holds as a positive number is the end of
    // the log, never a way back to before this member joined.
    let after = i64::try_from(after).unwrap_or(i64::MAX).max(since);
    let limit = limit.clamp(1, FETCH_LIMIT);
    let read = || -> rusqlite::Result<Vec<Entry>> {
        let mut st = db.prepare(
            "SELECT seq, mls FROM log WHERE group_id = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3",
        )?;
        let mut rows = st.query(params![group.0.as_slice(), after, limit as i64])?;
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
    // Entries every member has go, and stop counting toward the room's
    // limit.
    let ok = (|| -> rusqlite::Result<()> {
        let t = db.unchecked_transaction()?;
        t.execute(
            "UPDATE mailboxes SET cursor = max(cursor, ?1) WHERE key = ?2",
            params![i64::try_from(seq).unwrap_or(i64::MAX), me.0.as_slice()],
        )?;
        let fetched = "seq <= (SELECT min(cursor) FROM mailboxes
                                WHERE group_id = ?1 AND joined_seq IS NOT NULL)";
        quota::forget_entries(&t, &group, fetched)?;
        t.execute(
            &format!("DELETE FROM log WHERE group_id = ?1 AND {fetched}"),
            [group.0.as_slice()],
        )?;
        t.commit()
    })();
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
            let Some(rules) = state.rules.get(&db, &g) else {
                return Response::Error("could not load the group".into());
            };
            let is_admin = rules.admins.contains(&me);
            if !state.cfg.members_can_invite_to_rooms && !is_admin {
                return refused("on this server only admins can make invite links");
            }
            if rules.settings.invite == WhoCanInvite::Admins && !is_admin {
                return refused("in this room only admins can make invite links");
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
            // A room link may register one new account, counted against
            // the account on this connection; past that account's share,
            // or with no account here, it only leads into the room.
            let account = cs.proven.iter().copied().find(|k| is_account(&db, k));
            let saved = (|| -> rusqlite::Result<()> {
                let t = db.unchecked_transaction()?;
                let can_register = match (state.cfg.members_make_accounts, account) {
                    (true, Some(a)) => quota::take(
                        state,
                        &t,
                        Count::RoomLinkAccounts,
                        &a,
                        state.cfg.max_accounts_from_room_links as i64,
                    )?,
                    _ => false,
                };
                t.execute(
                    "INSERT INTO invites (token, group_id, expires_unix, uses_left, account_used, maker)
                         VALUES (?1, ?2, ?3, 1, ?4, ?5)",
                    params![
                        token.0.as_slice(),
                        g.0.as_slice(),
                        expires as i64,
                        !can_register,
                        me.0.as_slice()
                    ],
                )?;
                t.commit()
            })();
            if saved.is_err() {
                return Response::Error("could not save the invite".into());
            }
        }
        None => {
            let account = cs.proven.iter().copied().find(|k| is_account(&db, k));
            let (true, Some(account)) = (state.cfg.members_make_accounts, account) else {
                return refused("on this server only the operator can invite new people");
            };
            match take_server_invite(state, &db, &account, &token, expires) {
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

/// The server's own rules that rooms cannot change.
pub fn server_rules(state: &State) -> Response {
    Response::ServerRules {
        members_can_invite_to_rooms: state.cfg.members_can_invite_to_rooms,
    }
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

/// The only member of a group leaves: everything the server holds for the
/// group goes. Refused unless the OpenMLS group holds exactly one member and
/// that member is the caller.
pub fn last_leave(state: &State, cs: &ConnState, group: Gid) -> Response {
    let db = state.db();
    let Some(me) = member_key(&db, cs, &group) else {
        return refused("you are not a member of this group");
    };
    let storage = Storage::new(&*db);
    let alone = match PublicGroup::load(&storage, &mls_gid(&group)) {
        Ok(Some(pg)) => {
            let mut keys = pg.members().map(|m| key_of(&m.signature_key));
            keys.next() == Some(Some(me)) && keys.next().is_none()
        }
        _ => false,
    };
    if !alone || joined(&db, &group).len() != 1 {
        return refused("other people are still in this group");
    }
    match delete_group(&db, state, &group) {
        Ok(()) => Response::Ok,
        Err(_) => Response::Error("could not delete the group".into()),
    }
}

/// Deletes a group and everything held for it, in one transaction: its
/// files (chunks too), log, Welcomes waiting for its mailboxes, join
/// requests, invites, mailboxes, the keys that left it, the group row and
/// the OpenMLS state.
pub(crate) fn delete_group(db: &Connection, state: &State, group: &Gid) -> rusqlite::Result<()> {
    let g = group.0.as_slice();
    let t = db.unchecked_transaction()?;
    let files: Vec<Vec<u8>> = t
        .prepare("SELECT id FROM files WHERE group_id = ?1")?
        .query_map([g], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    for id in &files {
        t.execute("DELETE FROM file_done WHERE file_id = ?1", [id])?;
    }
    t.execute("DELETE FROM files WHERE group_id = ?1", [g])?;
    t.execute("DELETE FROM log WHERE group_id = ?1", [g])?;
    t.execute(
        "DELETE FROM welcomes WHERE mailbox IN (SELECT key FROM mailboxes WHERE group_id = ?1)",
        [g],
    )?;
    t.execute("DELETE FROM joins WHERE group_id = ?1", [g])?;
    t.execute("DELETE FROM invites WHERE group_id = ?1", [g])?;
    t.execute("DELETE FROM mailboxes WHERE group_id = ?1", [g])?;
    t.execute("DELETE FROM retired_keys WHERE group_id = ?1", [g])?;
    t.execute("DELETE FROM groups WHERE id = ?1", [g])?;
    {
        let storage = Storage::new(&*t);
        PublicGroup::delete(&storage, &mls_gid(group)).map_err(to_sql_error)?;
        storage
            .clear_proposal_queue::<GroupId, openmls::prelude::hash_ref::ProposalRef>(&mls_gid(
                group,
            ))
            .map_err(to_sql_error)?;
    }
    t.commit()?;
    state.rules.forget(group);
    state.limiter.forget_room(group);
    crate::db::checkpoint(db);
    quota::recount(state);
    // The chunks go once the rows are gone for good.
    for id in files {
        if let Ok(id) = <[u8; 16]>::try_from(id.as_slice()) {
            let _ = std::fs::remove_dir_all(crate::files::file_dir(state, &FileId(id)));
        }
    }
    Ok(())
}

fn to_sql_error(e: impl std::error::Error + Send + Sync + 'static) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(e))
}

/// Counts one server invite against `account` and saves it, or returns
/// false when the account has made its share.
fn take_server_invite(
    state: &State,
    db: &Connection,
    account: &Key,
    token: &Token,
    expires: u64,
) -> rusqlite::Result<bool> {
    let t = db.unchecked_transaction()?;
    if !quota::take(
        state,
        &t,
        Count::ServerInvites,
        account,
        SERVER_INVITE_QUOTA,
    )? {
        return Ok(false);
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
