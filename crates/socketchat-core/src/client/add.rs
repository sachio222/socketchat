//! Inviting someone this person already shares a room with to another
//! room, through the shared room's encrypted messages, as IRC's `/invite`
//! does. `crate::add` holds the sealing; this holds the steps on each side.
//!
//! The inviter's side, in `adds_out`: ask, wait for the person's key, send
//! the sealed offer, wait for the sealed answer that comes when they type
//! `/join`, then add them with a Welcome or end the invite. The other side,
//! in `adds_in`: give a key, wait for the offer, say in the shared room
//! that an invite came, then, once the person joins, send the sealed
//! answer. Every step is stored, so a room that limits fast posting, or an
//! app that closes, only delays it.

use openmls::prelude::tls_codec::Serialize as _;
use openmls_traits::OpenMlsProvider as _;
use socketchat_proto::msg::{GroupId, Request, Response, WelcomeOut};

use super::{
    connection_lost, key_of, kind, mark_command, mls_err, room_label, server_text, slowed, AppMsg,
    Client, DmAsk, Event, ADD_LINK_PREFIX,
};
use crate::add::{
    knows_add, new_ask, new_key_pair, open_answer, open_offer, seal_answer, seal_offer, Answer,
    AskId, Context, Offer, Sealed, ADD_KEY_LEN, ADD_TTL_SECS,
};
use crate::invite::{key_packages_with, pick_key_package};
use crate::keys::{Key, KeyPair};
use crate::net::NetError;
use crate::sanitize::{same_name, single_spaced};
use crate::settings::{room_settings, WhoCanInvite};
use crate::store::{AddIn, AddOut, PendingJoin};
use crate::suite::{admins_from, takes_settings};
use crate::CoreError;
use std::collections::{HashMap, HashSet};
use std::ops::Range;

/// The inviter's steps.
mod out_step {
    /// The ask waits to go.
    pub const ASK: i64 = 0;
    /// Asked; waiting for the person's app to give its key.
    pub const ASKED: i64 = 1;
    /// The sealed offer waits to go.
    pub const OFFER: i64 = 2;
    /// Offered; waiting for the person to join.
    pub const OFFERED: i64 = 3;
    /// They joined: the add waits to go.
    pub const ADD: i64 = 4;
    /// Over: the invite token waits to be cancelled.
    pub const END: i64 = 5;
}

/// The steps of the person invited.
mod in_step {
    /// Their app's key waits to go.
    pub const KEY: i64 = 0;
    /// Key sent; waiting for the offer.
    pub const KEY_SENT: i64 = 1;
    /// The offer arrived: the invite waits for `/join`.
    pub const WAITING: i64 = 2;
    /// The sealed answer waits to go.
    pub const ANSWER: i64 = 3;
}

/// How long, after an invite runs out without a `/join`, this person's app
/// ignores new invites from the same person.
pub const ADD_QUIET_SECS: u64 = 3600;

/// How long an ask may wait for its offer before it goes, on top of twice
/// the shared room's slow mode.
pub const ADD_OFFER_WAIT_SECS: u64 = 600;

/// Most open asks one member may have with this person in one room.
const MAX_ASKS_PER_MEMBER: usize = 3;

/// Most invites that wait for this person to join, from everyone.
const MAX_WAITING: usize = 20;

/// Slack for clocks that differ, in seconds.
const CLOCK_SLACK: u64 = 3600;

/// What `/invite <name>` set going.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteSent {
    /// The person's name as this app shows it.
    pub name: String,
    /// The room the invite travels through.
    pub via: String,
    /// The room they are invited to.
    pub room: String,
    /// The room it travels through limits fast posting: the invite goes
    /// in about this many seconds.
    pub wait_secs: Option<u64>,
}

/// An invite to a room that waits for this person's `/join`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomInvite {
    /// The room the invite came through.
    pub via: GroupId,
    /// The inviter's key in `via`.
    pub from: Key,
    pub ask: AskId,
    /// The inviter's name, with the start of their key, as `Ada#1a2b`,
    /// when someone else in `via` has the same name.
    pub from_name: String,
    /// This person marked the inviter verified.
    pub from_verified: bool,
    pub via_name: String,
    /// The room to join, as the inviter's app names it.
    pub room: String,
    /// The room's server, when this profile has never used it.
    pub server: Option<String>,
    pub expires_unix: u64,
    /// When this app got the invite, on its clock.
    pub received_unix: u64,
    /// The number `/join <number>` takes for it. Invites are numbered in
    /// the order they arrive.
    pub number: u64,
}

/// The line an invite puts in the room it came through.
pub fn invite_line(r: &RoomInvite) -> String {
    invite_text(r).0
}

/// [`invite_line`], and where in it the command to type sits.
fn invite_text(r: &RoomInvite) -> (String, Range<usize>) {
    let server = match &r.server {
        Some(s) => format!(", on {s}, a server you have not used"),
        None => String::new(),
    };
    let unverified = if r.from_verified {
        String::new()
    } else {
        format!(" You have not verified {}.", r.from_name)
    };
    let head = format!(
        "{} invites you to {}{server}.{unverified} Type ",
        r.from_name, r.room
    );
    let command = format!("/join {}", r.room);
    let at = head.len()..head.len() + command.len();
    (format!("{head}{command} to join."), at)
}

/// One person `/invite <name>` could mean: their identity, the name this
/// app shows for them, and each room they share with this person, with
/// their key there.
struct Candidate {
    identity: Key,
    name: String,
    rooms: Vec<(GroupId, Key)>,
}

fn hex2(k: &Key) -> String {
    format!("{:02x}{:02x}", k.0[0], k.0[1])
}

/// A name as `/invite` and `/dm` take it: the name, and the start of the
/// person's key after the last `#`, as in `Bo#1a2b`, when there is one.
fn split_tag(typed: &str) -> (&str, Option<String>) {
    match typed.rsplit_once('#') {
        Some((n, t)) if t.len() >= 2 && t.chars().all(|c| c.is_ascii_hexdigit()) => {
            (n, Some(t.to_lowercase()))
        }
        _ => (typed, None),
    }
}

/// " (verified)" for someone this person verified.
fn verified_mark(verified: bool) -> &'static str {
    if verified {
        " (verified)"
    } else {
        ""
    }
}

fn other(why: impl Into<String>) -> CoreError {
    CoreError::Other(why.into())
}

/// "a and b", "a, b and c".
fn and_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// "x, or y", "x, y, or z".
fn or_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} or {last}", rest.join(", ")),
    }
}

/// How much sooner than the person's app stops waiting the inviter's app
/// stops sending the offer, for clocks that differ.
const OFFER_MARGIN_SECS: u64 = 60;

/// "1. from Ada", or with `room`, "1. Climbing Saturdays from Ada", with
/// "(verified)" after an inviter this person verified, and the server when
/// the person has never used it.
fn numbered(i: &RoomInvite, room: bool) -> String {
    let from = format!("{}{}", i.from_name, verified_mark(i.from_verified));
    let what = if room {
        format!("{} from {from}", i.room)
    } else {
        format!("from {from}")
    };
    match &i.server {
        Some(s) => format!("{}. {what} (on {s})", i.number),
        None => format!("{}. {what}", i.number),
    }
}

/// The list of invites `/join` could mean, and what to type for each.
fn pick_list(head: &str, many: &[&RoomInvite], room: bool) -> CoreError {
    let listed: Vec<String> = many.iter().map(|i| numbered(i, room)).collect();
    let typed: Vec<String> = many.iter().map(|i| format!("/join {}", i.number)).collect();
    other(format!(
        "{head}: {}. Type {}.",
        listed.join(", "),
        or_list(&typed)
    ))
}

impl Client {
    /// Invites someone this person shares another room with to `target`.
    /// `name` follows `/dm`'s rules: a name, or a name and the start of the
    /// person's key in one room, as `Bo#1a2b`.
    pub async fn invite_member(
        &mut self,
        target: GroupId,
        name: &str,
    ) -> Result<InviteSent, CoreError> {
        let Some(live) = self.groups.get(&target) else {
            return Err(other("You are not in that room."));
        };
        if live.row.is_dm {
            return Err(other(
                "This is a direct chat for two people. To invite people, start a room with /new.",
            ));
        }
        let room = self.label(&target);
        let my_key = live.row.key.public();
        // The person's app learns this member's name in the new room.
        self.check_not_held(target)?;
        let skip = self.skip_add_checks();
        let is_admin = self.current_admins(&target).contains(&my_key);
        let admins_only = self
            .room_settings(target)
            .is_some_and(|s| s.invite == WhoCanInvite::Admins);
        if !skip && !is_admin && admins_only {
            return Err(other("In this room only admins can invite people."));
        }
        let who = self.add_lookup(name)?;
        let shown = who.name.clone();
        // A person picked by the start of their key keeps it in the line
        // this room keeps, as the pick named them.
        let picked = match (split_tag(name).1, who.rooms.first()) {
            (Some(_), Some((_, k))) => format!("{shown}#{}", hex2(k)),
            _ => shown.clone(),
        };
        if who.rooms.iter().any(|(g, _)| *g == target) {
            return Err(other(format!("{shown} is already in {room}.")));
        }
        let now = self.now();
        let mut waiting = false;
        for a in self.store.adds_out()? {
            if a.target != target || a.identity != who.identity || a.step == out_step::END {
                continue;
            }
            // An ask the person's app has not answered after the time it
            // would wait for an offer gives way to a new invite; one whose
            // app is closed still gets the new one when it opens.
            let stale = a.step <= out_step::ASKED
                && now > a.created_unix + ADD_OFFER_WAIT_SECS + 2 * self.slow_secs(a.via);
            if stale {
                self.end_add(&a, None)?;
            } else {
                waiting = true;
            }
        }
        if waiting {
            return Err(other(format!(
                "You already invited {shown} to this room. This room says when they join."
            )));
        }
        let (via, to) = self.add_route(&who)?;
        let server_id = self.server_of(&target)?;
        if !skip && !is_admin && self.server_lets_members_invite(server_id).await == Some(false) {
            return Err(other(
                "This server lets only admins invite people into its rooms.",
            ));
        }
        // The token the person's mailbox registers with. The server checks
        // here, as for any link, that this member may bring people in.
        let Response::Invite {
            token,
            expires_unix,
        } = self
            .request(
                server_id,
                Request::CreateInvite {
                    group: Some(target),
                },
            )
            .await?
        else {
            return Err(CoreError::Net(NetError::Unexpected("no invite".into())));
        };
        self.store
            .save_invite_made(&token, server_id, Some(&target), expires_unix)?;
        let kp = new_key_pair(self.prov.crypto()).ok_or_else(|| other("could not make a key"))?;
        let now = self.now();
        let via_name = self.label(&via);
        let row = AddOut {
            ask: new_ask(),
            via,
            to,
            identity: who.identity,
            name: shown.clone(),
            via_name: via_name.clone(),
            target,
            token,
            reply_pk: kp.public,
            reply_sk: kp.private,
            their_key: None,
            offer_by: None,
            key_packages: None,
            step: out_step::ASK,
            created_unix: now,
            expires_unix: expires_unix.min(now + ADD_TTL_SECS),
        };
        self.store.save_add_out(&row)?;
        let wait_secs = match self.add_out_step(row.clone()).await {
            Ok(()) => None,
            // Asked on a later sync, once the room lets this member post.
            Err(CoreError::Net(NetError::SlowDown { retry_after_ms })) => {
                Some(crate::net::wait_secs(retry_after_ms))
            }
            Err(e) => {
                self.store.delete_add_out(&row.ask)?;
                let _ = self
                    .request(server_id, Request::CancelInvite { token })
                    .await;
                self.store.forget_invite(&token)?;
                return Err(e);
            }
        };
        // Only this app keeps the line: nothing about it goes to the room.
        let last = self.groups[&target].row.last_seq;
        self.add_notice(target, last, format!("Invite sent to {picked}."))?;
        Ok(InviteSent {
            name: shown,
            via: via_name,
            room,
            wait_secs,
        })
    }

    fn skip_add_checks(&self) -> bool {
        #[cfg(feature = "test-hooks")]
        return self.hooks.skip_add_checks;
        #[cfg(not(feature = "test-hooks"))]
        false
    }

    /// The one person `typed` names among everyone who shares a room with
    /// this person, or why there is not exactly one.
    fn add_lookup(&self, typed: &str) -> Result<Candidate, CoreError> {
        let (name, tag) = split_tag(typed);
        let me = self.profile.identity.public();
        let mut found: Vec<Candidate> = Vec::new();
        let mut rooms: Vec<GroupId> = self.groups.keys().copied().collect();
        rooms.sort_by_key(|g| (self.label(g), g.0));
        for g in rooms {
            let identities: Vec<(Key, Option<Key>)> = self
                .store
                .members(&g)?
                .into_iter()
                .map(|m| (m.key, m.identity))
                .collect();
            for m in self.members(g) {
                let hex: String = m.key.0.iter().map(|b| format!("{b:02x}")).collect();
                if m.me
                    || !same_name(name, &m.name)
                    || tag.as_ref().is_some_and(|t| !hex.starts_with(t.as_str()))
                {
                    continue;
                }
                // Someone whose profile has not arrived cannot be told apart
                // from anyone else yet.
                let Some(identity) = identities
                    .iter()
                    .find(|(k, _)| *k == m.key)
                    .and_then(|(_, i)| *i)
                else {
                    continue;
                };
                if identity == me {
                    continue;
                }
                match found.iter_mut().find(|c| c.identity == identity) {
                    Some(c) => c.rooms.push((g, m.key)),
                    None => found.push(Candidate {
                        identity,
                        name: m.name.clone(),
                        rooms: vec![(g, m.key)],
                    }),
                }
            }
        }
        match found.len() {
            0 => Err(other(format!(
                "Nobody called {name} shares a room with you."
            ))),
            1 => Ok(found.remove(0)),
            _ => {
                let picks: Vec<(String, String, bool)> = found
                    .iter()
                    .map(|c| {
                        let (g, k) = c.rooms[0];
                        let verified = self.store.is_trusted(&c.identity).unwrap_or(false);
                        (format!("{name}#{}", hex2(&k)), self.label(&g), verified)
                    })
                    .collect();
                let listed: Vec<String> = picks
                    .iter()
                    .map(|(t, r, v)| format!("{t}{} in {r}", verified_mark(*v)))
                    .collect();
                let typed: Vec<String> =
                    picks.iter().map(|(t, ..)| format!("/invite {t}")).collect();
                Err(other(format!(
                    "More than one person called {name} shares a room with you: {}. Type {}.",
                    and_list(&listed),
                    or_list(&typed)
                )))
            }
        }
    }

    /// What `/invite` takes for each person who shares a room with this
    /// person, as Tab offers them: people not in `target` first, then by
    /// name. A name that two people go by gets the start of each one's key,
    /// as `Bo#1a2b`, as the list `/invite` gives when a name fits two
    /// people, so each one names one person. Someone whose profile has not
    /// arrived is left out, as `/invite` leaves them out.
    pub fn invite_names(&self, target: Option<GroupId>) -> Vec<String> {
        let me = self.profile.identity.public();
        // Each person under each name they go by, with their key in the
        // first room, in the order `/invite` reads the rooms.
        let mut seen: Vec<(Key, String, Key)> = Vec::new();
        let mut inside: HashSet<Key> = HashSet::new();
        let mut rooms: Vec<GroupId> = self.groups.keys().copied().collect();
        rooms.sort_by_key(|g| (self.label(g), g.0));
        for g in rooms {
            let identities: HashMap<Key, Key> = self
                .store
                .members(&g)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|m| Some((m.key, m.identity?)))
                .collect();
            for m in self.members(g) {
                let Some(identity) = identities.get(&m.key).copied() else {
                    continue;
                };
                if m.me || identity == me {
                    continue;
                }
                if Some(g) == target {
                    inside.insert(identity);
                }
                if !seen
                    .iter()
                    .any(|(i, n, _)| *i == identity && same_name(n, &m.name))
                {
                    seen.push((identity, m.name.clone(), m.key));
                }
            }
        }
        let mut out: Vec<(bool, String, String, String)> = seen
            .iter()
            .map(|(identity, name, key)| {
                let shared = seen
                    .iter()
                    .any(|(i, n, _)| i != identity && same_name(n, name));
                // A name that ends like a tag gets one too, so `/invite`
                // reads all of it as the name.
                let text = if shared || split_tag(name).1.is_some() {
                    format!("{name}#{}", hex2(key))
                } else {
                    name.clone()
                };
                let order = single_spaced(name).to_lowercase();
                (inside.contains(identity), order, text.to_lowercase(), text)
            })
            .collect();
        out.sort();
        out.into_iter().map(|(.., text)| text).collect()
    }

    /// The room to send the invite through, and the person's key there: one
    /// where this person's own profile is out, the other person's app knows
    /// this kind of invite, and they are still a member. A direct chat
    /// comes first, then the smallest room, as fewer people see that an
    /// invite went by.
    fn add_route(&self, who: &Candidate) -> Result<(GroupId, Key), CoreError> {
        let mut usable: Vec<(bool, usize, String, GroupId, Key)> = Vec::new();
        let mut too_old = false;
        let mut held = None;
        for (g, k) in &who.rooms {
            let Some(live) = self.groups.get(g) else {
                continue;
            };
            if self.drifted.contains(g) || !live.mls.members().any(|m| m.signature_key == k.0) {
                continue;
            }
            if self.store.profile_held(g)? {
                held = Some(*g);
                continue;
            }
            let version = self
                .store
                .members(g)?
                .into_iter()
                .find(|m| m.key == *k)
                .and_then(|m| m.app_version);
            if !knows_add(version.as_deref()) {
                too_old = true;
                continue;
            }
            usable.push((
                !live.row.is_dm,
                live.mls.members().count(),
                self.label(g),
                *g,
                *k,
            ));
        }
        usable.sort_by(|a, b| (a.0, a.1, &a.2, a.3 .0).cmp(&(b.0, b.1, &b.2, b.3 .0)));
        if let Some((.., g, k)) = usable.first() {
            return Ok((*g, *k));
        }
        if too_old {
            return Err(other(format!(
                "{}'s app is too old for this kind of invite. Send them a link with /invite.",
                who.name
            )));
        }
        if let Some(g) = held {
            self.check_not_held(g)?;
        }
        Err(other(format!(
            "Socketchat cannot reach {} through a room you share right now.",
            who.name
        )))
    }

    /// Invites that wait for this person's `/join`, oldest first.
    pub fn room_invites(&self) -> Vec<RoomInvite> {
        let now = self.now();
        let mut v: Vec<RoomInvite> = self
            .store
            .adds_in()
            .unwrap_or_default()
            .iter()
            .filter(|r| r.step == in_step::WAITING && r.expires_unix >= now)
            .filter_map(|r| self.room_invite(r))
            .collect();
        v.sort_by_key(|r| (r.number, r.ask));
        v
    }

    fn room_invite(&self, r: &AddIn) -> Option<RoomInvite> {
        let offer = r.offer.as_ref()?;
        if !self.groups.contains_key(&r.via) {
            return None;
        }
        let known = self
            .store
            .server_pin(&offer.host, offer.port)
            .ok()
            .flatten()
            .is_some();
        Some(RoomInvite {
            via: r.via,
            from: r.from,
            ask: r.ask,
            from_name: self.tagged_name(&r.via, &r.from),
            from_verified: self.store.is_trusted(&r.identity).unwrap_or(false),
            via_name: self.label(&r.via),
            room: room_label(&offer.room_name, false),
            server: (!known).then(|| server_text(&offer.host, offer.port)),
            expires_unix: r.expires_unix,
            received_unix: r.created_unix,
            number: r.number,
        })
    }

    /// A member's name, with the start of their key when someone else in
    /// the room goes by the same name, as `/invite` and `/dm` take it.
    fn tagged_name(&self, gid: &GroupId, key: &Key) -> String {
        let name = self.name_for(gid, key);
        let same = self
            .members(*gid)
            .iter()
            .filter(|m| m.key != *key && same_name(&name, &m.name))
            .count();
        if same == 0 {
            name
        } else {
            format!("{name}#{}", hex2(key))
        }
    }

    /// The waiting invite `typed` names. With no words, the one invite
    /// that waits. A bare number names the invite with that number while
    /// one has it, before any room of that name: every list of invites
    /// gives numbers, so a room called "2" is joined by its own number.
    /// Anything else is the name of the room. More than one invite that
    /// fits is refused with each one's number.
    pub fn find_invite(&self, typed: Option<&str>) -> Result<RoomInvite, CoreError> {
        let all = self.room_invites();
        let Some(typed) = typed.map(str::trim) else {
            return match all.as_slice() {
                [] => Err(other(
                    "No invite waits for you. To use a link, type /join and the link.",
                )),
                [one] => Ok(one.clone()),
                many => Err(pick_list(
                    "More than one invite waits for you",
                    &many.iter().collect::<Vec<_>>(),
                    true,
                )),
            };
        };
        let number = typed
            .parse::<u64>()
            .ok()
            .filter(|_| typed.bytes().all(|b| b.is_ascii_digit()));
        if let Some(i) = number.and_then(|n| all.iter().find(|i| i.number == n)) {
            return Ok(i.clone());
        }
        let hits: Vec<&RoomInvite> = all.iter().filter(|r| same_name(typed, &r.room)).collect();
        match hits.as_slice() {
            [] if number.is_some() => Err(other(format!(
                "No invite numbered {typed} or to a room called {typed} waits for you."
            ))),
            [] => Err(other(format!("No invite to {typed} waits for you."))),
            [one] => Ok((*one).clone()),
            many => Err(pick_list(
                &format!("More than one invite waits for {}", many[0].room),
                many,
                false,
            )),
        }
    }

    /// Whether `name` names exactly one person who shares a room with this
    /// person, as `/invite <name>` would take it.
    pub fn someone_named(&self, name: &str) -> bool {
        self.add_lookup(name).is_ok()
    }

    /// Room `gid`'s slow mode in seconds, 0 when off or unknown.
    fn slow_secs(&self, gid: GroupId) -> u64 {
        self.room_settings(gid)
            .map_or(0, |s| u64::from(s.slow_secs))
    }

    /// Joins the room an invite names: registers a mailbox there with its
    /// token and sends KeyPackages for it, sealed for the inviter, whose app
    /// then adds this person.
    pub async fn accept_invite(&mut self, invite: &RoomInvite) -> Result<(), CoreError> {
        let (via, from, ask) = (invite.via, invite.from, invite.ask);
        let gone = || other("That invite is no longer open.");
        let mut row = self
            .store
            .add_in(&via, &from, &ask)?
            .filter(|r| r.step == in_step::WAITING)
            .ok_or_else(gone)?;
        let me = self.my_group_key(via).ok_or_else(gone)?;
        if self.now() > row.expires_unix {
            self.store.delete_add_in(&via, &from, &ask)?;
            return Err(other("That invite expired."));
        }
        let offer = row.offer.clone().ok_or_else(gone)?;
        let answer = match self.prepare_join(&row, &offer).await {
            Ok(a) => a,
            Err(e) => {
                if !connection_lost(&e) {
                    self.store.delete_add_in(&via, &from, &ask)?;
                }
                return Err(e);
            }
        };
        let cx = Context {
            via: &via,
            ask: &ask,
            from: &me,
            to: &from,
        };
        let sealed = seal_answer(self.prov.crypto(), &row.reply_pk, &cx, &answer)
            .ok_or_else(|| other("could not seal the answer"))?;
        row.answer = Some(sealed);
        row.step = in_step::ANSWER;
        self.store.save_add_in(&row)?;
        let inviter = self.tagged_name(&via, &from);
        self.store
            .save_add_join(&offer.group, &offer.room_name, &inviter, row.expires_unix)?;
        match self.add_in_step(row).await {
            // Sent on a later sync, once the room lets this member post.
            Err(e) if slowed(&e) => Ok(()),
            r => r,
        }
    }

    /// Registers a mailbox in the offered room with its token, and makes
    /// KeyPackages for it. The join waits for a Welcome from the inviter's
    /// key in that room.
    async fn prepare_join(&mut self, row: &AddIn, offer: &Offer) -> Result<Answer, CoreError> {
        let room = room_label(&offer.room_name, false);
        if self.groups.contains_key(&offer.group) {
            return Err(other(format!("You are already in {room}.")));
        }
        if self.store.add_join(&offer.group)?.is_some() {
            return Err(other(format!("You are already joining {room}.")));
        }
        if let Some(old) = self.store.server_pin(&offer.host, offer.port)? {
            if old != offer.cert_fpr {
                let inviter = self.name_for(&row.via, &row.from);
                return Err(other(format!(
                    "{room} is on {}, but the certificate {inviter}'s app gave for it is not the one Socketchat trusts for that server. Ask {inviter} for an invite link instead.",
                    server_text(&offer.host, offer.port)
                )));
            }
        }
        // A server this profile did not know stays only if the mailbox
        // registers there, so an offer that leads nowhere pins nothing.
        let known = self.store.server_pin(&offer.host, offer.port)?.is_some();
        let server_id = self
            .store
            .add_server(&offer.host, offer.port, &offer.cert_fpr)?;
        let key = KeyPair::generate();
        let registered = match self.conn(server_id).await {
            Ok(c) => c
                .register_mailbox(Some(offer.token), &key)
                .await
                .map_err(CoreError::from),
            Err(e) => Err(e),
        };
        if let Err(e) = registered {
            if !known {
                self.conns.remove(&server_id);
                self.last_error.remove(&server_id);
                self.store.forget_server(server_id)?;
            }
            return Err(match e {
                CoreError::Net(NetError::Refused(why)) => {
                    other(format!("Could not join {room}: {why}."))
                }
                e => e,
            });
        }
        let kps = key_packages_with(&self.prov, &key, None, self.leaf_capabilities())?;
        self.store.save_pending_join(&PendingJoin {
            token: offer.token,
            server_id,
            link: DmAsk {
                identity: row.identity,
                dm_key: offer.adder_key,
                group: offer.group,
            }
            .to_link_with(ADD_LINK_PREFIX),
            key,
            lodged_unix: self.now(),
            key_package_refs: kps.refs,
        })?;
        Ok(Answer {
            key_packages: kps.blob,
        })
    }

    // ---------- reading the steps ----------

    /// Someone asks this member, `to`, about an invite. The app gives a key
    /// for the offer on its own, for a few asks per member at most, and for
    /// none while this member's own invite to the room is unconfirmed, or
    /// within an hour of an invite from the same person running out.
    pub(super) fn take_add_ask(
        &mut self,
        gid: GroupId,
        sender: Key,
        to: Key,
        ask: AskId,
        reply_key: Vec<u8>,
    ) -> Result<(), CoreError> {
        if self.my_group_key(gid) != Some(to)
            || sender == to
            || reply_key.len() != ADD_KEY_LEN
            || self.store.profile_held(&gid)?
        {
            return Ok(());
        }
        let Some(identity) = self
            .store
            .members(&gid)?
            .into_iter()
            .find(|m| m.key == sender)
            .and_then(|m| m.identity)
        else {
            return Ok(());
        };
        let now = self.now();
        if now < self.store.add_quiet_until(&identity, now)? {
            return Ok(());
        }
        let open = self.store.adds_in()?;
        let from_them = open
            .iter()
            .filter(|r| r.via == gid && r.from == sender)
            .count();
        let waiting = open.iter().filter(|r| r.step == in_step::WAITING).count();
        if from_them >= MAX_ASKS_PER_MEMBER
            || waiting >= MAX_WAITING
            || open
                .iter()
                .any(|r| r.via == gid && r.from == sender && r.ask == ask)
        {
            return Ok(());
        }
        let Some(kp) = new_key_pair(self.prov.crypto()) else {
            return Ok(());
        };
        self.store.save_add_in(&AddIn {
            via: gid,
            from: sender,
            ask,
            identity,
            reply_pk: reply_key,
            my_pk: kp.public,
            my_sk: kp.private,
            offer: None,
            answer: None,
            step: in_step::KEY,
            number: 0,
            created_unix: now,
            expires_unix: now + ADD_TTL_SECS,
            line_seq: None,
        })
    }

    /// The person invited gave a key for the offer.
    pub(super) fn take_add_key(
        &mut self,
        gid: GroupId,
        sender: Key,
        to: Key,
        ask: AskId,
        key: Vec<u8>,
        offer_by: u64,
    ) -> Result<(), CoreError> {
        let Some(mut row) = self.store.add_out(&ask)? else {
            return Ok(());
        };
        if row.via != gid
            || row.to != sender
            || self.my_group_key(gid) != Some(to)
            || row.step != out_step::ASKED
            || key.len() != ADD_KEY_LEN
        {
            return Ok(());
        }
        row.their_key = Some(key);
        row.offer_by = Some(offer_by);
        row.step = out_step::OFFER;
        self.store.save_add_out(&row)
    }

    /// The inviter's sealed offer arrived: once it opens and checks out,
    /// the app says in the room it came through that an invite waits.
    pub(super) fn take_add_offer(
        &mut self,
        gid: GroupId,
        sender: Key,
        to: Key,
        ask: AskId,
        sealed: &Sealed,
    ) -> Result<(), CoreError> {
        if self.my_group_key(gid) != Some(to) {
            return Ok(());
        }
        let Some(mut row) = self
            .store
            .add_in(&gid, &sender, &ask)?
            .filter(|r| r.step == in_step::KEY_SENT)
        else {
            return Ok(());
        };
        let cx = Context {
            via: &gid,
            ask: &ask,
            from: &sender,
            to: &to,
        };
        let Some(mut offer) = open_offer(self.prov.crypto(), &row.my_sk, &cx, sealed) else {
            return Ok(());
        };
        let now = self.now();
        let latest = row.created_unix + ADD_TTL_SECS + CLOCK_SLACK;
        if offer.expires_unix <= now
            || offer.expires_unix > latest
            || offer.port == 0
            || !socketchat_proto::valid_host(&offer.host)
        {
            return Ok(());
        }
        offer.room_name = crate::sanitize::clean_name(&offer.room_name);
        // Already there: nothing to say.
        if self.groups.contains_key(&offer.group) {
            return self.store.delete_add_in(&gid, &sender, &ask);
        }
        row.expires_unix = row.expires_unix.min(offer.expires_unix);
        row.offer = Some(offer);
        row.step = in_step::WAITING;
        row.number = self.store.next_add_number()?;
        self.store.save_add_in(&row)?;
        if let Some(invite) = self.room_invite(&row) {
            // The room on screen, as IRC shows an invite in the window the
            // person has open. With no chat screen, the room it came
            // through, until one opens.
            let shown = self.open_room.filter(|g| self.groups.contains_key(g));
            let place = shown.unwrap_or(gid);
            let last = self.groups[&place].row.last_seq;
            let (text, at) = invite_text(&invite);
            let seq = self.add_line(place, last, text, Some(at))?;
            if shown.is_none() {
                row.line_seq = Some(seq);
                self.store.save_add_in(&row)?;
            }
            self.emit(Event::Invited(invite));
        }
        Ok(())
    }

    /// Says which room the chat screen shows, `None` when none does. The
    /// line of each invite that came while no chat screen was open moves
    /// there from the room it came through, once.
    pub fn set_open_room(&mut self, g: Option<GroupId>) -> Result<(), CoreError> {
        self.open_room = g;
        let Some(g) = g.filter(|g| self.groups.contains_key(g)) else {
            return Ok(());
        };
        for mut row in self.store.adds_in()? {
            let Some(seq) = row.line_seq else {
                continue;
            };
            row.line_seq = None;
            self.store.save_add_in(&row)?;
            if row.via == g || row.step != in_step::WAITING {
                continue;
            }
            let Some(invite) = self.room_invite(&row) else {
                continue;
            };
            self.store.delete_invite_line(&row.via, seq)?;
            let last = self.groups[&g].row.last_seq;
            let (text, at) = invite_text(&invite);
            self.add_line(g, last, text, Some(at))?;
        }
        Ok(())
    }

    /// The person's sealed answer arrived: they typed `/join`.
    pub(super) fn take_add_answer(
        &mut self,
        gid: GroupId,
        sender: Key,
        to: Key,
        ask: AskId,
        sealed: &Sealed,
    ) -> Result<(), CoreError> {
        let Some(mut row) = self.store.add_out(&ask)? else {
            return Ok(());
        };
        if row.via != gid
            || row.to != sender
            || self.my_group_key(gid) != Some(to)
            || row.step != out_step::OFFERED
        {
            return Ok(());
        }
        let cx = Context {
            via: &gid,
            ask: &ask,
            from: &sender,
            to: &to,
        };
        if let Some(answer) = open_answer(self.prov.crypto(), &row.reply_sk, &cx, sealed) {
            row.key_packages = Some(answer.key_packages);
            row.step = out_step::ADD;
            self.store.save_add_out(&row)?;
        }
        Ok(())
    }

    /// After someone joins a room through an invite by name: the first name
    /// the room gives itself, `name`, is checked against the name the
    /// invite gave, and the room says when they differ.
    pub(super) fn check_invited_name(
        &mut self,
        gid: GroupId,
        seq: u64,
        name: &str,
    ) -> Result<(), CoreError> {
        let Some((offered, inviter, _)) = self.store.add_join(&gid)? else {
            return Ok(());
        };
        self.store.delete_add_join(&gid)?;
        if !offered.is_empty() && !same_name(&offered, name) {
            let text = format!("This room is called {name}, not {offered} as {inviter} said.");
            let now = self.now();
            self.store
                .add_message(&gid, seq, None, kind::NOTICE, &text, now)?;
        }
        Ok(())
    }

    // ---------- moving the steps on ----------

    /// Moves every open invite on, both ways, and ends those that expired
    /// or whose people left the room they travel through. A step held back
    /// by a room's pace, or by a lost connection, waits for a later sync.
    pub(super) async fn add_steps(&mut self) -> Result<(), CoreError> {
        let now = self.now();
        for row in self.store.adds_out()? {
            if !self.groups.contains_key(&row.target) {
                self.store.delete_add_out(&row.ask)?;
                continue;
            }
            if row.step != out_step::END {
                let via_live = self.groups.contains_key(&row.via);
                let present = self
                    .groups
                    .get(&row.via)
                    .is_some_and(|l| l.mls.members().any(|m| m.signature_key == row.to.0));
                let joined = self
                    .store
                    .members(&row.target)?
                    .iter()
                    .any(|m| m.identity == Some(row.identity));
                let room = self.label(&row.target);
                let ended = if joined {
                    Some(None)
                } else if !via_live {
                    Some(Some(format!(
                        "You are no longer in {}, so your invite to {} ended.",
                        row.via_name, row.name
                    )))
                } else if !present {
                    Some(Some(format!(
                        "{} is no longer in {}, so your invite to them ended.",
                        row.name, row.via_name
                    )))
                } else if now > row.expires_unix {
                    Some(Some(format!("{} didn't join {room}.", row.name)))
                } else {
                    None
                };
                if let Some(notice) = ended {
                    self.end_add(&row, notice)?;
                }
            }
            let Some(row) = self.store.add_out(&row.ask)? else {
                continue;
            };
            if !matches!(
                row.step,
                out_step::ASK | out_step::OFFER | out_step::ADD | out_step::END
            ) {
                continue;
            }
            let name = row.name.clone();
            let r = self.add_out_step(row).await;
            self.add_step_result(r, &format!("Could not finish inviting {name}"))?;
        }
        for row in self.store.adds_in()? {
            let present = self
                .groups
                .get(&row.via)
                .is_some_and(|l| l.mls.members().any(|m| m.signature_key == row.from.0));
            let no_offer = row.step < in_step::WAITING && now > self.offer_by(&row);
            let there = row
                .offer
                .as_ref()
                .is_some_and(|o| self.groups.contains_key(&o.group));
            if row.step == in_step::WAITING && now > row.expires_unix {
                // Nobody joined: the same person's next invite waits an hour.
                self.store
                    .set_add_quiet(&row.identity, now + ADD_QUIET_SECS)?;
            }
            if now > row.expires_unix || !present || no_offer || there {
                self.store.delete_add_in(&row.via, &row.from, &row.ask)?;
                continue;
            }
            if matches!(row.step, in_step::KEY | in_step::ANSWER) {
                let r = self.add_in_step(row).await;
                self.add_step_result(r, "Could not answer an invite to a room")?;
            }
        }
        // A join that never led to a Welcome: once its invite has run out,
        // its keys go, and the person hears that nobody added them.
        for p in self.store.pending_joins()? {
            let Some(rest) = p.link.strip_prefix(ADD_LINK_PREFIX) else {
                continue;
            };
            let group = DmAsk::parse(rest).map(|a| a.group);
            let named = match group {
                Some(g) => self.store.add_join(&g)?,
                None => None,
            };
            let expires = named
                .as_ref()
                .map_or(p.lodged_unix + ADD_TTL_SECS, |(_, _, e)| *e);
            if now <= expires + CLOCK_SLACK {
                continue;
            }
            self.delete_key_packages(&p.key_package_refs)?;
            self.store.delete_pending_join(&p.token)?;
            if let (Some(g), Some((room, inviter, _))) = (group, named) {
                self.store.delete_add_join(&g)?;
                let room = room_label(&room, false);
                self.emit(Event::Warning(format!(
                    "{inviter} did not add you to {room}."
                )));
            }
        }
        Ok(())
    }

    /// A step that waits for a room's pace or a connection says nothing;
    /// anything else becomes a warning.
    fn add_step_result(&mut self, r: Result<(), CoreError>, what: &str) -> Result<(), CoreError> {
        match r {
            Ok(()) => Ok(()),
            Err(e) if slowed(&e) || connection_lost(&e) => Ok(()),
            Err(e) => {
                self.emit(Event::Warning(format!("{what}: {e}")));
                Ok(())
            }
        }
    }

    /// Ends an invite on the inviter's side, with a notice in the room it
    /// was for. Its token is cancelled on the next step.
    fn end_add(&mut self, row: &AddOut, notice: Option<String>) -> Result<(), CoreError> {
        if let (Some(text), Some(last)) =
            (notice, self.groups.get(&row.target).map(|l| l.row.last_seq))
        {
            self.add_notice(row.target, last, text)?;
        }
        let mut r = row.clone();
        r.step = out_step::END;
        self.store.save_add_out(&r)
    }

    fn add_notice(&mut self, gid: GroupId, last: u64, text: String) -> Result<(), CoreError> {
        self.add_line(gid, last, text, None).map(|_| ())
    }

    /// A notice, or with `command`, an invite line whose command to type
    /// sits there in `text`; the place it took.
    fn add_line(
        &mut self,
        gid: GroupId,
        last: u64,
        text: String,
        command: Option<Range<usize>>,
    ) -> Result<u64, CoreError> {
        let seq = self.store.notice_seq(&gid, last)?;
        let now = self.now();
        let (kind, body) = match &command {
            Some(at) => (kind::INVITE, mark_command(&text, at.clone())),
            None => (kind::NOTICE, text.clone()),
        };
        self.store.add_message(&gid, seq, None, kind, &body, now)?;
        let mut line = self.line(&gid, seq, None, text, now, true);
        line.command = command;
        self.emit(Event::Message { group: gid, line });
        Ok(seq)
    }

    /// Takes the inviter's next step for one invite.
    async fn add_out_step(&mut self, mut row: AddOut) -> Result<(), CoreError> {
        match row.step {
            out_step::ASK => {
                self.send_app(
                    row.via,
                    &AppMsg::AddAsk {
                        to: row.to,
                        ask: row.ask,
                        reply_key: row.reply_pk.clone(),
                    },
                )
                .await?;
                row.step = out_step::ASKED;
                self.store.save_add_out(&row)
            }
            out_step::OFFER => {
                // The person's app stops waiting for the offer at the time
                // it gave: past that, the offer would go nowhere.
                let by = row.offer_by.unwrap_or(0);
                if self.now() + OFFER_MARGIN_SECS > by {
                    let text = format!(
                        "Your invite to {} ran out before it reached them. Invite them again with /invite {}.",
                        row.name, row.name
                    );
                    return self.end_add(&row, Some(text));
                }
                let (Some(their_key), Some(me), Some(adder_key)) = (
                    row.their_key.clone(),
                    self.my_group_key(row.via),
                    self.my_group_key(row.target),
                ) else {
                    return Ok(());
                };
                let server_id = self.server_of(&row.target)?;
                let Some(server) = self
                    .store
                    .servers()?
                    .into_iter()
                    .find(|s| s.id == server_id)
                else {
                    return Ok(());
                };
                #[cfg(feature = "test-hooks")]
                let (port, room_name) = (
                    self.hooks.add_offer_port.unwrap_or(server.port),
                    self.hooks
                        .add_offer_name
                        .clone()
                        .unwrap_or_else(|| self.groups[&row.target].row.name.clone()),
                );
                #[cfg(not(feature = "test-hooks"))]
                let (port, room_name) = (server.port, self.groups[&row.target].row.name.clone());
                let offer = Offer {
                    room_name,
                    group: row.target,
                    host: server.host,
                    port,
                    cert_fpr: server.cert_fpr,
                    token: row.token,
                    adder_key,
                    expires_unix: row.expires_unix,
                };
                let cx = Context {
                    via: &row.via,
                    ask: &row.ask,
                    from: &me,
                    to: &row.to,
                };
                let Some(sealed) = seal_offer(self.prov.crypto(), &their_key, &cx, &offer) else {
                    // Said once, not on every sync.
                    let text = format!(
                        "{}'s app sent a key Socketchat cannot use, so your invite to them ended.",
                        row.name
                    );
                    return self.end_add(&row, Some(text));
                };
                self.send_app(
                    row.via,
                    &AppMsg::AddOffer {
                        to: row.to,
                        ask: row.ask,
                        sealed,
                    },
                )
                .await?;
                row.step = out_step::OFFERED;
                self.store.save_add_out(&row)
            }
            out_step::ADD => self.complete_add(row).await,
            out_step::END => {
                // The token stops working; a server on protocol 1 lets it
                // expire.
                if let Ok(server_id) = self.server_of(&row.target) {
                    match self
                        .request(server_id, Request::CancelInvite { token: row.token })
                        .await
                    {
                        Err(e) if connection_lost(&e) => return Err(e),
                        _ => {}
                    }
                }
                self.store.forget_invite(&row.token)?;
                self.store.delete_add_out(&row.ask)
            }
            _ => Ok(()),
        }
    }

    /// Adds the person who joined, with a Welcome under the invite's token,
    /// by the same rules as any add: the room's settings, checked here,
    /// then the server's own checks.
    async fn complete_add(&mut self, row: AddOut) -> Result<(), CoreError> {
        let target = row.target;
        if self.holds_commit(&target) {
            return Ok(());
        }
        self.settle_sent(target).await?;
        let kps = row.key_packages.clone().unwrap_or_default();
        let skip = self.skip_add_checks();
        for _ in 0..3 {
            let Some(live) = self.groups.get_mut(&target) else {
                return self.store.delete_add_out(&row.ask);
            };
            let my_key = live.row.key.public();
            let admins = admins_from(live.mls.extensions());
            let settings = room_settings(live.mls.extensions());
            if !skip && !admins.contains(&my_key) && settings.invite == WhoCanInvite::Admins {
                let text = format!(
                    "{} accepted your invite, but in this room only admins can add people now.",
                    row.name
                );
                return self.end_add(&row, Some(text));
            }
            let Some(kp) = pick_key_package(&self.prov, &kps, live.mls.ciphersuite()) else {
                let text = format!(
                    "{} accepted your invite, but their app sent keys this room cannot use.",
                    row.name
                );
                return self.end_add(&row, Some(text));
            };
            if !settings.is_default() && !takes_settings(kp.leaf_node().capabilities()) {
                let text = format!(
                    "{} accepted your invite, but their app is too old for this room's settings.",
                    row.name
                );
                return self.end_add(&row, Some(text));
            }
            let Some(joiner) = key_of(kp.leaf_node().signature_key().as_slice()) else {
                return self.end_add(&row, None);
            };
            // A key on the admin list that is not in the room belongs to an
            // admin who left; it never comes back, as for a link's joiner.
            if live.mls.members().any(|m| m.signature_key == joiner.0) || admins.contains(&joiner) {
                return self.end_add(&row, None);
            }
            let (commit, welcome, _) = live
                .mls
                .add_members(&self.prov, &live.row.key, std::slice::from_ref(&kp))
                .map_err(mls_err)?;
            let welcome = WelcomeOut {
                token: row.token,
                welcome: welcome.tls_serialize_detached().map_err(mls_err)?,
                voucher: vec![],
            };
            match self.post_commit(target, commit, Some(welcome)).await {
                Ok(Some(seq)) => {
                    self.store.upsert_member(&target, &joiner, Some(seq))?;
                    self.store.delete_add_out(&row.ask)?;
                    self.store.drop_invite_made(&row.token)?;
                    let text = format!("{} accepted your invite and joined.", row.name);
                    self.add_notice(target, seq, text)?;
                    self.emit(Event::MembersChanged { group: target });
                    // Owed from here on: if sharing fails, or the room
                    // limits fast posting, a later sync sends it.
                    self.owe_repost(target)?;
                    return match self.after_add(target).await {
                        Ok(()) => self.paid_repost(target),
                        Err(e) if slowed(&e) => Ok(()),
                        Err(e) => Err(e),
                    };
                }
                Ok(None) => continue,
                Err(CoreError::Net(NetError::Refused(why))) => {
                    let text = format!(
                        "{} accepted your invite, but Socketchat could not add them: {why}",
                        row.name
                    );
                    return self.end_add(&row, Some(text));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Until when this person's app waits for an invite's offer: a while
    /// after the ask arrived, longer in a room with slow mode.
    fn offer_by(&self, row: &AddIn) -> u64 {
        row.created_unix + ADD_OFFER_WAIT_SECS + 2 * self.slow_secs(row.via)
    }

    /// Takes the next step of the person invited for one invite.
    async fn add_in_step(&mut self, mut row: AddIn) -> Result<(), CoreError> {
        match row.step {
            in_step::KEY => {
                let offer_by = self.offer_by(&row);
                self.send_app(
                    row.via,
                    &AppMsg::AddKey {
                        to: row.from,
                        ask: row.ask,
                        key: row.my_pk.clone(),
                        offer_by,
                    },
                )
                .await?;
                row.step = in_step::KEY_SENT;
                self.store.save_add_in(&row)
            }
            in_step::ANSWER => {
                let Some(sealed) = row.answer.clone() else {
                    return self.store.delete_add_in(&row.via, &row.from, &row.ask);
                };
                self.send_app(
                    row.via,
                    &AppMsg::AddAnswer {
                        to: row.from,
                        ask: row.ask,
                        sealed,
                    },
                )
                .await?;
                self.store.delete_add_in(&row.via, &row.from, &row.ask)
            }
            _ => Ok(()),
        }
    }
}
