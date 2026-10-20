//! The client engine: one person's profile, their servers and their groups.
//!
//! Every screen, and every test, drives this. It keeps its state in the
//! encrypted store and reports what happened as [`Event`]s.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::str::FromStr;

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;
use rand_core::{OsRng, RngCore};
use socketchat_proto::msg::{Entry, Push, Request, Response, WelcomeIn, WelcomeOut};
use socketchat_proto::{InviteLink, Token};

use crate::appmsg::AppMsg;
use crate::invite::{join_sig, key_package_blob, pick_key_package, signed_key_package_blob};
use crate::keys::{
    fingerprint, invite_proof, invite_signing_key, join_request_ok, open_voucher, proof_matches,
    seal_voucher, sign_join_request, voucher_seal_key, Binding, GroupId, Key, KeyPair, Voucher,
};
use crate::net::{Conn, NetError};
use crate::provider::Provider;
use crate::store::{GroupRow, PendingJoin, Profile, Store, StoredVoucher};
use crate::suite::{
    admins_from, group_context_extensions, group_create_config, group_join_config, SUITE,
};
use crate::CoreError;

/// Kinds of stored message line.
pub mod kind {
    pub const TEXT: i64 = 0;
    pub const NOTICE: i64 = 1;
    pub const FILE: i64 = 2;
}

/// "12 KB", "3.4 MB": sizes for people.
pub fn human_size(n: u64) -> String {
    const K: f64 = 1000.0;
    let f = n as f64;
    if f < K {
        format!("{n} bytes")
    } else if f < K * K {
        format!("{:.0} KB", f / K)
    } else if f < K * K * K {
        format!("{:.1} MB", f / (K * K))
    } else {
        format!("{:.1} GB", f / (K * K * K))
    }
}

/// Why [`Client::wait`] returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wake {
    Push,
    Dropped,
    Timeout,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JoinStatus {
    /// A server invite: this person now has an account there.
    Registered,
    /// A group invite: the join request waits for the inviter or an admin.
    Waiting { for_name: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verification {
    Verified,
    Unverified { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatLine {
    pub seq: u64,
    pub sender: String,
    pub sender_key: Option<Key>,
    pub text: String,
    pub sent_unix: u64,
    pub notice: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberView {
    pub key: Key,
    pub name: String,
    pub verified: bool,
    pub admin: bool,
    pub me: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupSummary {
    pub id: GroupId,
    pub name: String,
    pub is_dm: bool,
    pub left: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Joined {
        group: GroupId,
        verification: Verification,
    },
    JoinRequestHandled {
        group: GroupId,
    },
    Message {
        group: GroupId,
        line: ChatLine,
    },
    MembersChanged {
        group: GroupId,
    },
    GroupRenamed {
        group: GroupId,
    },
    NameChanged {
        group: GroupId,
        old: String,
        new: String,
    },
    Left {
        group: GroupId,
    },
    FileOffered {
        group: GroupId,
        file: crate::files::FileOffer,
    },
    Warning(String),
    Disconnected,
    Reconnected,
}

/// A group this client is in. A commit it sent whose reply never came
/// stays staged in `mls` (OpenMLS keeps it on disk) until the log shows
/// whether it landed.
struct Live {
    row: GroupRow,
    mls: MlsGroup,
}

/// The server's answer when a mailbox is no longer in the group: this
/// member was removed or their leave went through.
pub const NOT_A_MEMBER: &str = "you are not a member of this group";

/// Largest MLS message the server takes, in bytes: a frame of 1 MiB less
/// room for the request around it.
pub const MAX_MLS_BYTES: usize = 1_047_552;

/// Errors that mean the connection to a server is gone, as opposed to one
/// group or one request going wrong.
fn connection_lost(e: &CoreError) -> bool {
    matches!(
        e,
        CoreError::Net(
            NetError::Disconnected
                | NetError::Io(_)
                | NetError::Timeout
                | NetError::Tls(_)
                | NetError::CertMismatch { .. }
                | NetError::Version(_)
        )
    )
}

/// How often a member refreshes its own encryption keys in each group.
pub const KEY_REFRESH_SECS: u64 = 7 * 24 * 3600;

pub struct Client {
    store: Store,
    prov: Provider,
    profile: Profile,
    conns: HashMap<i64, Conn>,
    groups: HashMap<GroupId, Live>,
    events: VecDeque<Event>,
    clock_offset: u64,
    /// Groups where someone joined, so this member owes them a profile.
    repost: HashSet<GroupId>,
    /// Groups with a member's request to leave waiting for a commit.
    leaves: HashSet<GroupId>,
    /// Direct messages this client offered: token -> (new chat, the
    /// member asked, in the shared group).
    dm_offers: HashMap<Token, (GroupId, Key)>,
    /// Direct-message steps to take once the current fetch is done.
    dm_todo: Vec<DmTodo>,
    /// Groups already reported as out of step since this client opened.
    drifted: HashSet<GroupId>,
    /// Join requests already reported as failing their check since this
    /// client opened.
    bad_requests: HashSet<Token>,
    /// Groups whose commit was posted but timed out: the server may still
    /// be working on it, so it stays staged through one more sync round
    /// even when the log ends without it.
    commit_grace: HashSet<GroupId>,
    #[cfg(feature = "test-hooks")]
    hooks: Hooks,
}

/// What tests ask a client to do wrong on purpose.
#[cfg(feature = "test-hooks")]
#[derive(Default)]
struct Hooks {
    /// Groups whose every fetch fails.
    broken: HashSet<GroupId>,
    /// Groups whose next fetch the server refuses, with the reason given.
    refuse_fetch: HashMap<GroupId, String>,
    /// KeyPackages seen in direct-message answers meant for someone else.
    dm_accepts_seen: Vec<Vec<u8>>,
    /// Groups whose fetches come back as the same old page again and again,
    /// as a hostile server could send them.
    stale_pages: HashSet<GroupId>,
}

enum DmTodo {
    Accept {
        shared: GroupId,
        from: Key,
        group: GroupId,
        token: Token,
        dm_key: Key,
    },
    Complete {
        group: GroupId,
        token: Token,
        key_packages: Vec<u8>,
    },
}

/// The keys a staged commit adds and removes, read before it is merged.
fn commit_changes(mls: &MlsGroup, sc: &StagedCommit) -> (Vec<Key>, Vec<Key>) {
    let added = sc
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
    let removed = sc
        .remove_proposals()
        .filter_map(|r| mls.member_at(r.remove_proposal().removed()))
        .filter_map(|m| key_of(&m.signature_key))
        .collect();
    (added, removed)
}

fn mls_gid(g: &GroupId) -> openmls::group::GroupId {
    openmls::group::GroupId::from_slice(&g.0)
}

fn key_of(b: &[u8]) -> Option<Key> {
    <[u8; 32]>::try_from(b).ok().map(Key)
}

fn mls_err(e: impl std::fmt::Display) -> CoreError {
    CoreError::Mls(e.to_string())
}

fn too_large() -> CoreError {
    CoreError::Other("that message is too large to send".into())
}

fn ser(m: &MlsMessageOut) -> Result<Vec<u8>, CoreError> {
    m.tls_serialize_detached().map_err(mls_err)
}

/// Pending joins for direct messages store this prefix instead of an
/// invite link, then in hex and split by `:`: the asker's identity key,
/// their key in the new chat, and the new chat's group ID.
const DM_LINK_PREFIX: &str = "dm:";

/// Who asked for a direct message, as a pending join remembers it.
struct DmAsk {
    identity: Key,
    /// The asker's key in the new chat: the one that should add this member.
    dm_key: Key,
    group: GroupId,
}

impl DmAsk {
    fn to_link(&self) -> String {
        format!(
            "{DM_LINK_PREFIX}{}:{}:{}",
            hex(&self.identity.0),
            hex(&self.dm_key.0),
            hex(&self.group.0)
        )
    }

    /// `None` for a pending join made before the asker's chat key was
    /// recorded; such a join cannot be checked.
    fn parse(rest: &str) -> Option<DmAsk> {
        let mut parts = rest.split(':');
        let ask = DmAsk {
            identity: Key(hex_bytes(parts.next()?)?),
            dm_key: Key(hex_bytes(parts.next()?)?),
            group: GroupId(hex_bytes(parts.next()?)?),
        };
        parts.next().is_none().then_some(ask)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_bytes<const N: usize>(h: &str) -> Option<[u8; N]> {
    if h.len() != 2 * N {
        return None;
    }
    let mut k = [0u8; N];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(h.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(k)
}

fn short(k: &Key) -> String {
    k.0[..3].iter().map(|b| format!("{b:02x}")).collect()
}

impl Client {
    /// Makes a new profile in `dir`.
    pub async fn create_profile(
        dir: &Path,
        passphrase: &str,
        display_name: &str,
    ) -> Result<Client, CoreError> {
        let (store, prov) = Store::create(dir, passphrase)?;
        let profile = Profile {
            identity: KeyPair::generate(),
            display_name: crate::sanitize::clean_name(display_name),
        };
        store.set_profile(&profile)?;
        store.trust(&profile.identity.public())?;
        Self::from_parts(store, prov, profile)
    }

    /// Opens the profile in `dir`.
    pub async fn open(dir: &Path, passphrase: &str) -> Result<Client, CoreError> {
        let (store, prov) = Store::open(dir, passphrase)?;
        let profile = store.profile()?.ok_or(CoreError::NoProfile)?;
        Self::from_parts(store, prov, profile)
    }

    fn from_parts(store: Store, prov: Provider, profile: Profile) -> Result<Client, CoreError> {
        let mut groups = HashMap::new();
        for row in store.groups()? {
            if row.left {
                continue;
            }
            if let Some(mls) = MlsGroup::load(prov.storage(), &mls_gid(&row.id)).map_err(mls_err)? {
                groups.insert(row.id, Live { row, mls });
            }
        }
        Ok(Client {
            store,
            prov,
            profile,
            conns: HashMap::new(),
            groups,
            events: VecDeque::new(),
            clock_offset: 0,
            repost: HashSet::new(),
            leaves: HashSet::new(),
            dm_offers: HashMap::new(),
            dm_todo: Vec::new(),
            drifted: HashSet::new(),
            bad_requests: HashSet::new(),
            commit_grace: HashSet::new(),
            #[cfg(feature = "test-hooks")]
            hooks: Hooks::default(),
        })
    }

    pub fn display_name(&self) -> &str {
        &self.profile.display_name
    }

    pub fn identity(&self) -> Key {
        self.profile.identity.public()
    }

    /// Moves this client's clock forward, for tests.
    pub fn advance_clock(&mut self, secs: u64) {
        self.clock_offset += secs;
    }

    pub(crate) fn now(&self) -> u64 {
        crate::now_unix() + self.clock_offset
    }

    /// Events since the last call, oldest first.
    pub fn take_events(&mut self) -> Vec<Event> {
        self.events.drain(..).collect()
    }

    /// Waits up to `max` for a server to push something or drop. Safe to
    /// cancel: it only listens. Call [`Client::sync`] afterwards to act on it.
    pub async fn wait(&mut self, max: std::time::Duration) -> Wake {
        if self.conns.is_empty() {
            tokio::time::sleep(max).await;
            return Wake::Timeout;
        }
        let poll = std::future::poll_fn(|cx| {
            for c in self.conns.values_mut() {
                match c.poll_push(cx) {
                    std::task::Poll::Ready(Some(_)) => return std::task::Poll::Ready(Wake::Push),
                    std::task::Poll::Ready(None) => return std::task::Poll::Ready(Wake::Dropped),
                    std::task::Poll::Pending => {}
                }
            }
            std::task::Poll::Pending
        });
        tokio::time::timeout(max, poll)
            .await
            .unwrap_or(Wake::Timeout)
    }

    /// Whether every server this client uses is connected right now.
    pub fn connected(&self) -> bool {
        self.conns.values().all(|c| c.is_alive())
    }

    fn emit(&mut self, e: Event) {
        self.events.push_back(e);
    }

    // ---------- connections ----------

    /// Connects to a server if needed and signs in with every key this
    /// client uses there.
    async fn conn(&mut self, server_id: i64) -> Result<&mut Conn, CoreError> {
        let alive = self.conns.get(&server_id).is_some_and(|c| c.is_alive());
        if !alive {
            let had = self.conns.remove(&server_id).is_some();
            let row = self
                .store
                .servers()?
                .into_iter()
                .find(|s| s.id == server_id)
                .ok_or_else(|| CoreError::Other("unknown server".into()))?;
            let c = Conn::connect(&row.host, row.port, row.cert_fpr).await?;
            // An account the server no longer knows (it was set up again)
            // must not stop the connection: a new server invite replaces it.
            if let Some(a) = &row.account {
                if let Err(e) = c.prove(a).await {
                    if !matches!(e, NetError::Refused(_)) {
                        return Err(e.into());
                    }
                }
            }
            for g in self
                .groups
                .values()
                .filter(|g| g.row.server_id == server_id)
            {
                if let Err(e) = c.prove(&g.row.key).await {
                    if !matches!(e, NetError::Refused(_)) {
                        return Err(e.into());
                    }
                }
            }
            for p in self.store.pending_joins()? {
                if p.server_id == server_id {
                    let _ = c.prove(&p.key).await;
                }
            }
            self.conns.insert(server_id, c);
            if had {
                self.emit(Event::Reconnected);
            }
        }
        Ok(self.conns.get_mut(&server_id).expect("inserted above"))
    }

    async fn request(&mut self, server_id: i64, req: Request) -> Result<Response, CoreError> {
        let c = self.conn(server_id).await?;
        match c.request(req).await? {
            Response::Refused(why) => Err(CoreError::Net(NetError::Refused(why))),
            r => Ok(r),
        }
    }

    fn server_of(&self, g: &GroupId) -> Result<i64, CoreError> {
        self.groups
            .get(g)
            .map(|l| l.row.server_id)
            .ok_or_else(|| CoreError::Other("you are not in that group".into()))
    }

    fn account_server(&self) -> Result<i64, CoreError> {
        self.store
            .servers()?
            .into_iter()
            .find(|s| s.account.is_some())
            .map(|s| s.id)
            .ok_or_else(|| {
                CoreError::Other("join a server with a server invite before making a group".into())
            })
    }

    // ---------- joining ----------

    /// Redeems an invite link: a server invite registers an account, a group
    /// invite lodges a join request. A link that names a server this profile
    /// already uses with a different certificate is refused with
    /// [`CoreError::NewCertificate`]; see [`Client::join_new_certificate`].
    pub async fn join(&mut self, link: &InviteLink) -> Result<JoinStatus, CoreError> {
        self.join_with(link, None, false).await
    }

    /// [`Client::join`] for a link whose server certificate differs from the
    /// one this profile trusts, after the person accepted the new one. The
    /// new certificate replaces the old only once a connection to it and the
    /// redeem have both worked.
    pub async fn join_new_certificate(
        &mut self,
        link: &InviteLink,
    ) -> Result<JoinStatus, CoreError> {
        self.join_with(link, None, true).await
    }

    /// [`Client::join`], with the join request signed by `signer` instead of
    /// the key the link gives, when one is passed.
    async fn join_with(
        &mut self,
        link: &InviteLink,
        signer: Option<KeyPair>,
        new_certificate: bool,
    ) -> Result<JoinStatus, CoreError> {
        // A link with another certificate for a known server comes from an
        // operator who set the server up again, or from someone who wants
        // this person cut off from every chat there. Only the person decides.
        let repin = match self.store.server_pin(&link.host, link.port)? {
            Some(old) if old != link.cert_fpr => {
                if !new_certificate {
                    return Err(CoreError::NewCertificate {
                        host: link.host.clone(),
                        port: link.port,
                        pinned: old,
                        offered: link.cert_fpr,
                    });
                }
                true
            }
            _ => false,
        };
        let server_id = self
            .store
            .add_server(&link.host, link.port, &link.cert_fpr)?;
        if repin {
            // The redeem uses a connection made under the link's certificate;
            // the old pin stays until it succeeds.
            let c = Conn::connect(&link.host, link.port, link.cert_fpr).await?;
            self.conns.insert(server_id, c);
        }
        let r = self.redeem(link, server_id, signer).await;
        if repin {
            // That connection signed in with the new keys only. The next
            // request reconnects and signs in with every key.
            self.conns.remove(&server_id);
            if r.is_ok() {
                self.store
                    .set_server_pin(&link.host, link.port, &link.cert_fpr)?;
                self.emit(Event::Warning(format!(
                    "socketchat now trusts the new certificate for {}.",
                    crate::sanitize::clean_name(&link.host)
                )));
            }
        }
        r
    }

    async fn redeem(
        &mut self,
        link: &InviteLink,
        server_id: i64,
        signer: Option<KeyPair>,
    ) -> Result<JoinStatus, CoreError> {
        let has_account = self
            .store
            .servers()?
            .iter()
            .any(|s| s.id == server_id && s.account.is_some());
        let conn = self.conn(server_id).await?;
        let (Some(_), Some(secret)) = (link.inviter_fpr, link.secret) else {
            let account = KeyPair::generate();
            conn.register_account(link.token, &account).await?;
            self.store.set_account(server_id, &account)?;
            return Ok(JoinStatus::Registered);
        };
        let key = KeyPair::generate();
        conn.register_mailbox(Some(link.token), &key).await?;
        if !has_account {
            let account = KeyPair::generate();
            if conn.register_account(link.token, &account).await.is_ok() {
                self.store.set_account(server_id, &account)?;
            }
        }
        // Signed with a key only the link's holder can derive. Members hold
        // its public half, so they can check this request but not make one.
        let signer = signer.unwrap_or_else(|| invite_signing_key(&secret));
        let sig = sign_join_request(&signer, &link.token, &key.public());
        let blob = signed_key_package_blob(&self.prov, &key, Some(&sig))?;
        self.store.save_pending_join(&PendingJoin {
            token: link.token,
            server_id,
            link: link.to_string(),
            key: key.clone(),
            lodged_unix: self.now(),
        })?;
        let conn = self.conn(server_id).await?;
        match conn
            .request(Request::RedeemInvite {
                token: link.token,
                key_package: blob,
                // Unused: the signature rides inside the KeyPackages.
                mac: [0; 32],
            })
            .await?
        {
            Response::JoinLodged => Ok(JoinStatus::Waiting {
                for_name: "the person who invited you or a group admin".into(),
            }),
            Response::Refused(why) => Err(CoreError::Net(NetError::Refused(why))),
            other => Err(CoreError::Net(NetError::Unexpected(format!("{other:?}")))),
        }
    }

    async fn handle_welcome(&mut self, w: WelcomeIn) -> Result<(), CoreError> {
        let Some(pending) = self
            .store
            .pending_joins()?
            .into_iter()
            .find(|p| p.key.public() == w.mailbox)
        else {
            return Ok(());
        };
        let dm_rest = pending.link.strip_prefix(DM_LINK_PREFIX);
        let dm_ask = dm_rest.and_then(DmAsk::parse);
        let link = match dm_rest {
            Some(_) => None,
            None => Some(
                InviteLink::from_str(&pending.link).map_err(|e| CoreError::Other(e.to_string()))?,
            ),
        };
        let MlsMessageBodyIn::Welcome(welcome) = MlsMessageIn::tls_deserialize_exact(&w.welcome)
            .map_err(mls_err)?
            .extract()
        else {
            return Err(CoreError::Mls("not a Welcome".into()));
        };
        let staged =
            StagedWelcome::new_from_welcome(&self.prov, &group_join_config(), welcome, None)
                .map_err(mls_err)?;
        let adder = staged
            .welcome_sender()
            .ok()
            .and_then(|l| key_of(l.signature_key().as_slice()));
        let mls = staged.into_group(&self.prov).map_err(mls_err)?;
        let gid = GroupId(
            mls.group_id()
                .as_slice()
                .try_into()
                .map_err(|_| CoreError::Mls("group ID is not 16 bytes".into()))?,
        );
        let now = self.now();
        let (inviter_fpr, link_secret) = link
            .as_ref()
            .map(|l| (l.inviter_fpr, l.secret))
            .unwrap_or((None, None));
        // A voucher that does not open under the link's secret counts as
        // missing: the invite could not be checked.
        let voucher: Option<Voucher> =
            link_secret.and_then(|s| open_voucher(&voucher_seal_key(&s), &w.voucher));
        let verification = match (&voucher, inviter_fpr, link_secret, adder) {
            _ if dm_rest.is_some() => match &dm_ask {
                // A direct message offered inside a shared group: the
                // request came from that member, encrypted end to end, and
                // named the key that would add this member to which chat.
                Some(ask) if adder != Some(ask.dm_key) || gid != ask.group => {
                    Verification::Unverified {
                        reason: "you were added by someone other than the person who asked".into(),
                    }
                }
                Some(ask) if self.store.is_trusted(&ask.identity)? => Verification::Verified,
                Some(_) => Verification::Unverified {
                    reason: "you have not verified this person yet".into(),
                },
                None => Verification::Unverified {
                    reason: "the request could not be checked".into(),
                },
            },
            (Some(v), Some(fpr), Some(secret), Some(adder)) => match v.verify(&fpr, now) {
                Err(e) => Verification::Unverified {
                    reason: e.to_string(),
                },
                Ok(())
                    if v.token != pending.token || !v.secret_matches(&secret) || v.group != gid =>
                {
                    Verification::Unverified {
                        reason: "the invite details do not match the link".into(),
                    }
                }
                Ok(())
                    if adder == v.inviter_group_key
                        || admins_from(mls.extensions()).contains(&adder) =>
                {
                    Verification::Verified
                }
                Ok(()) => Verification::Unverified {
                    reason: "you were added by someone who is neither the inviter nor an admin"
                        .into(),
                },
            },
            _ => Verification::Unverified {
                reason: "the invite could not be checked".into(),
            },
        };
        let row = GroupRow {
            id: gid,
            server_id: pending.server_id,
            key: pending.key.clone(),
            name: String::new(),
            is_dm: dm_rest.is_some(),
            left: false,
            last_seq: 0,
            last_update_unix: now,
            joined_unix: now,
        };
        self.store.add_group(&row)?;
        for m in mls.members() {
            if let Some(k) = key_of(&m.signature_key) {
                self.store.upsert_member(&gid, &k, Some(0))?;
            }
        }
        if let (Verification::Verified, Some(v)) = (&verification, &voucher) {
            self.store.trust(&v.inviter_identity)?;
            self.store
                .set_member_profile(&gid, &v.inviter_group_key, &v.inviter_identity, "")?;
        }
        // The proof tells the link's maker this member holds the link
        // itself, which no other member can claim, so the maker can mark them
        // verified. It is owed from here on: a connection that drops before
        // it goes out sends it on a later sync.
        if let Some(secret) = link_secret {
            let proof = invite_proof(&secret, &gid, &pending.key.public());
            self.store.owe_proof(&gid, &pending.token, &proof)?;
        }
        self.store.delete_pending_join(&pending.token)?;
        self.groups.insert(gid, Live { row, mls });
        self.emit(Event::Joined {
            group: gid,
            verification,
        });
        // The profile is owed the same way until it goes out.
        self.repost.insert(gid);
        self.post_profile(gid).await?;
        self.repost.remove(&gid);
        self.send_owed_proofs(gid).await
    }

    /// Posts the invite proofs this member still owes in a group.
    async fn send_owed_proofs(&mut self, gid: GroupId) -> Result<(), CoreError> {
        for (token, proof) in self.store.owed_proofs(&gid)? {
            self.send_app(gid, &AppMsg::InviteProof { token, proof })
                .await?;
            self.store.paid_proof(&gid, &token)?;
        }
        Ok(())
    }

    // ---------- groups ----------

    /// Makes a new group on the server where this person has an account.
    pub async fn create_group(&mut self, name: &str) -> Result<GroupId, CoreError> {
        let server_id = self.account_server()?;
        self.create_group_on(server_id, name, false).await
    }

    async fn create_group_on(
        &mut self,
        server_id: i64,
        name: &str,
        is_dm: bool,
    ) -> Result<GroupId, CoreError> {
        let key = KeyPair::generate();
        self.conn(server_id)
            .await?
            .register_mailbox(None, &key)
            .await?;
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        let gid = GroupId(id);
        let create = |suite| {
            MlsGroup::new_with_group_id(
                &self.prov,
                &key,
                &group_create_config(suite, &[key.public()]),
                mls_gid(&gid),
                key.credential(),
            )
        };
        let mls = create(SUITE).map_err(mls_err)?;
        let gi = ser(&mls
            .export_group_info(self.prov.crypto(), &key, false)
            .map_err(mls_err)?)?;
        let tree = mls
            .export_ratchet_tree()
            .tls_serialize_detached()
            .map_err(mls_err)?;
        self.request(
            server_id,
            Request::CreateGroup {
                group_info: gi,
                ratchet_tree: tree,
            },
        )
        .await?;
        let now = self.now();
        let row = GroupRow {
            id: gid,
            server_id,
            key: key.clone(),
            name: crate::sanitize::clean_name(name),
            is_dm,
            left: false,
            last_seq: 0,
            last_update_unix: now,
            joined_unix: now,
        };
        self.store.add_group(&row)?;
        self.store.upsert_member(&gid, &key.public(), Some(0))?;
        self.groups.insert(gid, Live { row, mls });
        self.post_profile(gid).await?;
        if !name.is_empty() {
            self.send_app(
                gid,
                &AppMsg::GroupName {
                    name: crate::sanitize::clean_name(name),
                },
            )
            .await?;
        }
        Ok(gid)
    }

    /// Posts this person's name and identity binding to a group.
    async fn post_profile(&mut self, gid: GroupId) -> Result<(), CoreError> {
        let key = self.groups[&gid].row.key.public();
        let binding = Binding::new(&self.profile.identity, gid, key);
        self.store.set_member_profile(
            &gid,
            &key,
            &self.profile.identity.public(),
            &self.profile.display_name,
        )?;
        let msg = AppMsg::Profile {
            display_name: self.profile.display_name.clone(),
            binding,
        };
        self.send_app(gid, &msg).await?;
        Ok(())
    }

    /// Encrypts and posts an application message. Returns its log sequence.
    pub(crate) async fn send_app(&mut self, gid: GroupId, msg: &AppMsg) -> Result<u64, CoreError> {
        let server_id = self.server_of(&gid)?;
        for attempt in 0..2 {
            let live = self.groups.get_mut(&gid).expect("checked by server_of");
            let out = live
                .mls
                .create_message(&self.prov, &live.row.key, &msg.encode())
                .map_err(mls_err)?;
            let bytes = ser(&out)?;
            if bytes.len() > MAX_MLS_BYTES {
                return Err(too_large());
            }
            match self
                .request(
                    server_id,
                    Request::Post {
                        group: gid,
                        mls: bytes,
                        welcome: None,
                    },
                )
                .await
            {
                Ok(Response::Posted { seq }) => return Ok(seq),
                Err(CoreError::Net(NetError::Refused(_))) if attempt == 0 => {
                    self.fetch_group(gid).await?;
                }
                Ok(other) => {
                    return Err(CoreError::Net(NetError::Unexpected(format!("{other:?}"))))
                }
                Err(e) => return Err(e),
            }
        }
        Err(CoreError::Other(
            "the server would not take the message".into(),
        ))
    }

    /// Posts a commit the group has staged. On a lost race, catches up and
    /// returns `Ok(None)` so the caller can decide whether to try again.
    async fn post_commit(
        &mut self,
        gid: GroupId,
        commit: MlsMessageOut,
        welcome: Option<WelcomeOut>,
    ) -> Result<Option<u64>, CoreError> {
        let server_id = self.server_of(&gid)?;
        let bytes = ser(&commit)?;
        let too_big = bytes.len() > MAX_MLS_BYTES
            || welcome
                .as_ref()
                .is_some_and(|w| w.welcome.len() + w.voucher.len() > MAX_MLS_BYTES);
        if too_big {
            let live = self.groups.get_mut(&gid).expect("checked by server_of");
            live.mls
                .clear_pending_commit(self.prov.storage())
                .map_err(mls_err)?;
            return Err(too_large());
        }
        let r = self
            .request(
                server_id,
                Request::Post {
                    group: gid,
                    mls: bytes,
                    welcome,
                },
            )
            .await;
        let now = self.now();
        let live = self.groups.get_mut(&gid).expect("checked by server_of");
        match r {
            Ok(Response::Posted { seq }) => {
                live.mls.merge_pending_commit(&self.prov).map_err(mls_err)?;
                live.row.last_update_unix = now;
                self.store.set_last_update(&gid, now)?;
                Ok(Some(seq))
            }
            Err(CoreError::Net(
                e @ (NetError::Disconnected | NetError::Timeout | NetError::Io(_)),
            )) => {
                // The server may have taken it. It stays staged, on disk too,
                // until the log shows whether it landed. After a timeout the
                // server may still be working on it: this connection closes,
                // and the commit stays staged through one more sync round
                // even if the log ends without it.
                if matches!(e, NetError::Timeout) {
                    self.conns.remove(&server_id);
                    self.commit_grace.insert(gid);
                }
                Err(CoreError::Net(e))
            }
            Ok(Response::Conflict { .. }) => {
                live.mls
                    .clear_pending_commit(self.prov.storage())
                    .map_err(mls_err)?;
                self.fetch_group(gid).await?;
                Ok(None)
            }
            Ok(other) => {
                live.mls
                    .clear_pending_commit(self.prov.storage())
                    .map_err(mls_err)?;
                Err(CoreError::Net(NetError::Unexpected(format!("{other:?}"))))
            }
            Err(e) => {
                live.mls
                    .clear_pending_commit(self.prov.storage())
                    .map_err(mls_err)?;
                Err(e)
            }
        }
    }

    /// Makes another member an admin.
    pub async fn make_admin(&mut self, gid: GroupId, member: &Key) -> Result<(), CoreError> {
        self.settle_sent(gid).await?;
        for _ in 0..3 {
            let live = self
                .groups
                .get_mut(&gid)
                .ok_or_else(|| CoreError::Other("no such group".into()))?;
            let mut admins = admins_from(live.mls.extensions());
            if admins.contains(member) {
                return Ok(());
            }
            admins.push(*member);
            let bundle = live
                .mls
                .commit_builder()
                .propose_group_context_extensions(group_context_extensions(&admins))
                .map_err(mls_err)?
                .load_psks(self.prov.storage())
                .map_err(mls_err)?
                .build(self.prov.rand(), self.prov.crypto(), &live.row.key, |_| {
                    true
                })
                .map_err(mls_err)?
                .stage_commit(&self.prov)
                .map_err(mls_err)?;
            let (commit, _, _) = bundle.into_messages();
            if self.post_commit(gid, commit, None).await?.is_some() {
                self.emit(Event::MembersChanged { group: gid });
                return Ok(());
            }
        }
        Err(CoreError::Other(
            "the group kept changing; try again".into(),
        ))
    }

    /// Makes an invite link and returns it with the Unix time it expires.
    /// `group: None` makes a server invite.
    pub async fn invite(
        &mut self,
        group: Option<GroupId>,
        dm: bool,
    ) -> Result<(InviteLink, u64), CoreError> {
        let gid = match (group, dm) {
            (_, true) => Some(
                self.create_group_on(self.account_server()?, "", true)
                    .await?,
            ),
            (g, false) => g,
        };
        let server_id = match gid {
            Some(g) => self.server_of(&g)?,
            None => self.account_server()?,
        };
        let row = self
            .store
            .servers()?
            .into_iter()
            .find(|s| s.id == server_id)
            .expect("server_of found it");
        let Response::Invite {
            token,
            expires_unix,
        } = self
            .request(server_id, Request::CreateInvite { group: gid })
            .await?
        else {
            return Err(CoreError::Net(NetError::Unexpected("no invite".into())));
        };
        let mut link = InviteLink {
            host: row.host,
            port: row.port,
            token,
            cert_fpr: row.cert_fpr,
            inviter_fpr: None,
            secret: None,
        };
        if let Some(gid) = gid {
            let mut secret = [0u8; 32];
            OsRng.fill_bytes(&mut secret);
            let my_key = self.groups[&gid].row.key.public();
            let voucher = Voucher::new(
                &self.profile.identity,
                token,
                &secret,
                gid,
                my_key,
                expires_unix,
            );
            let request_key = invite_signing_key(&secret).public();
            let seal_key = voucher_seal_key(&secret);
            self.store.save_voucher(
                &gid,
                &token,
                &StoredVoucher {
                    voucher: postcard::to_stdvec(&voucher)?,
                    request_key,
                    seal_key,
                    secret: Some(secret),
                },
            )?;
            // Members get a public key and a key derived from the secret,
            // never the secret: they can check and complete the join, but
            // only the person holding the link can sign a request or prove
            // it to this client.
            self.send_app(
                gid,
                &AppMsg::Voucher {
                    voucher,
                    request_key,
                    seal_key,
                },
            )
            .await?;
            link.inviter_fpr = Some(fingerprint(&self.profile.identity.public()));
            link.secret = Some(secret);
        }
        Ok((link, expires_unix))
    }

    /// Whole hours from now until `expires_unix`, for telling someone when
    /// an invite link stops working.
    pub fn hours_until(&self, expires_unix: u64) -> u64 {
        crate::invite::hours_left(expires_unix, self.now())
    }

    async fn handle_join_request(
        &mut self,
        gid: GroupId,
        token: Token,
        blob: Vec<u8>,
    ) -> Result<(), CoreError> {
        let Some(stored) = self.store.voucher(&gid, &token)? else {
            return Ok(());
        };
        let Some(suite) = self.groups.get(&gid).map(|l| l.mls.ciphersuite()) else {
            return Ok(());
        };
        // The request must be signed, with the key only the link's holder
        // can derive, over this token and the mailbox the KeyPackage is for.
        let checked = pick_key_package(&self.prov, &blob, suite).and_then(|kp| {
            let joiner = key_of(kp.leaf_node().signature_key().as_slice())?;
            let sig = join_sig(&kp)?;
            join_request_ok(&stored.request_key, &token, &joiner, &sig).then_some((kp, joiner))
        });
        let Some((kp, joiner)) = checked else {
            if self.bad_requests.insert(token) {
                self.emit(Event::Warning(
                    "A request to join one of your groups failed its check and was ignored.".into(),
                ));
            }
            return Ok(());
        };
        let Ok(voucher) = postcard::from_bytes::<Voucher>(&stored.voucher) else {
            return Ok(());
        };
        // The verified mark for the joiner comes later, from their proof
        // that they hold the link itself (see `AppMsg::InviteProof`).
        let mine = stored.secret.is_some();
        self.settle_sent(gid).await?;
        for _ in 0..3 {
            let live = self
                .groups
                .get_mut(&gid)
                .ok_or_else(|| CoreError::Other("no such group".into()))?;
            let my_key = live.row.key.public();
            let is_admin = admins_from(live.mls.extensions()).contains(&my_key);
            if !is_admin && !mine {
                return Ok(());
            }
            if live.mls.members().any(|m| m.signature_key == joiner.0) {
                return Ok(());
            }
            let (commit, welcome, _) = live
                .mls
                .add_members(&self.prov, &live.row.key, std::slice::from_ref(&kp))
                .map_err(mls_err)?;
            let welcome = WelcomeOut {
                token,
                welcome: ser(&welcome)?,
                // Sealed under the invite secret: the server stores it but
                // cannot read the inviter's identity key inside.
                voucher: seal_voucher(&stored.seal_key, &voucher),
            };
            match self.post_commit(gid, commit, Some(welcome)).await {
                Ok(Some(seq)) => {
                    self.store.upsert_member(&gid, &joiner, Some(seq))?;
                    self.after_add(gid).await?;
                    self.emit(Event::JoinRequestHandled { group: gid });
                    self.emit(Event::MembersChanged { group: gid });
                    return Ok(());
                }
                Ok(None) => continue,
                Err(CoreError::Net(NetError::Refused(_))) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// After someone joins, repeat this member's profile (and the group's
    /// name, if this member knows it) so the newcomer can read them.
    async fn after_add(&mut self, gid: GroupId) -> Result<(), CoreError> {
        self.post_profile(gid).await?;
        if self.groups[&gid].row.is_dm {
            self.send_app(gid, &AppMsg::IsDm).await?;
        }
        let name = self.groups[&gid].row.name.clone();
        if !name.is_empty() {
            self.send_app(gid, &AppMsg::GroupName { name }).await?;
        }
        Ok(())
    }

    // ---------- receiving ----------

    /// Fetches and applies everything new from every server. A dropped
    /// connection shows as [`Event::Disconnected`] and the next sync
    /// reconnects; a problem with one group or one request shows as a
    /// warning and the others carry on.
    pub async fn sync(&mut self) -> Result<(), CoreError> {
        let mut servers: Vec<i64> = self.groups.values().map(|g| g.row.server_id).collect();
        servers.extend(self.store.pending_joins()?.iter().map(|p| p.server_id));
        servers.extend(
            self.store
                .servers()?
                .iter()
                .filter(|s| s.account.is_some())
                .map(|s| s.id),
        );
        servers.sort_unstable();
        servers.dedup();
        for server_id in servers {
            if let Err(e) = self.sync_server(server_id).await {
                if !connection_lost(&e) {
                    return Err(e);
                }
                self.conns.remove(&server_id);
                self.emit(Event::Disconnected);
            }
        }
        Ok(())
    }

    /// "Book club", or a plain description for a chat with no name yet.
    fn label(&self, gid: &GroupId) -> String {
        match self.groups.get(gid) {
            Some(l) if !l.row.name.is_empty() => l.row.name.clone(),
            Some(l) if l.row.is_dm => "a direct message".into(),
            _ => "a chat".into(),
        }
    }

    /// Passes on a dropped connection, and turns any other error from one
    /// group's step into a warning so the other groups carry on.
    fn group_step(&mut self, r: Result<(), CoreError>, what: &str) -> Result<(), CoreError> {
        match r {
            Err(e) if connection_lost(&e) => Err(e),
            Err(e) => {
                self.emit(Event::Warning(format!("{what}: {e}")));
                Ok(())
            }
            Ok(()) => Ok(()),
        }
    }

    async fn sync_server(&mut self, server_id: i64) -> Result<(), CoreError> {
        // Commits that timed out before this round stay staged through it;
        // the round after this one drops them if the log still ends without.
        let graced: Vec<GroupId> = self
            .commit_grace
            .iter()
            .filter(|g| {
                self.groups
                    .get(g)
                    .is_some_and(|l| l.row.server_id == server_id)
            })
            .copied()
            .collect();
        self.sync_server_round(server_id).await?;
        for g in graced {
            self.commit_grace.remove(&g);
        }
        Ok(())
    }

    /// Whether a commit of this client's own is still staged in a group,
    /// which holds back any new commit there.
    fn holds_commit(&self, gid: &GroupId) -> bool {
        self.groups
            .get(gid)
            .is_some_and(|g| g.mls.pending_commit().is_some())
    }

    async fn sync_server_round(&mut self, server_id: i64) -> Result<(), CoreError> {
        let mut pushed: Vec<(GroupId, socketchat_proto::msg::JoinRequest)> = Vec::new();
        {
            let c = self.conn(server_id).await?;
            while let Some(p) = c.try_push() {
                if let Push::JoinRequest { group, request } = p {
                    pushed.push((group, request));
                }
            }
        }
        if let Response::Welcomes(ws) = self.request(server_id, Request::FetchWelcomes).await? {
            for w in ws {
                if let Err(e) = self.handle_welcome(w).await {
                    if connection_lost(&e) {
                        return Err(e);
                    }
                    self.emit(Event::Warning(format!("Could not join a group: {e}")));
                }
            }
        }
        let gids: Vec<GroupId> = self
            .groups
            .values()
            .filter(|g| g.row.server_id == server_id)
            .map(|g| g.row.id)
            .collect();
        for gid in &gids {
            if self.groups.contains_key(gid) {
                let r = self.fetch_group(*gid).await;
                let what = format!("Could not fetch new messages in {}", self.label(gid));
                self.group_step(r, &what)?;
            }
        }
        let todo: Vec<DmTodo> = std::mem::take(&mut self.dm_todo);
        for t in todo {
            let r = match t {
                DmTodo::Accept {
                    shared,
                    from,
                    group,
                    token,
                    dm_key,
                } => self.accept_dm(shared, from, group, token, dm_key).await,
                DmTodo::Complete {
                    group,
                    token,
                    key_packages,
                } => self.complete_dm(group, token, key_packages).await,
            };
            self.group_step(r, "Could not open the direct message")?;
        }
        let leaving: Vec<GroupId> = self.leaves.drain().collect();
        for gid in leaving {
            if self.holds_commit(&gid) {
                self.leaves.insert(gid);
                continue;
            }
            if self.groups.contains_key(&gid) {
                let r = self.commit_leaves(gid).await;
                let what = format!("Could not let someone leave {}", self.label(&gid));
                self.group_step(r, &what)?;
            }
        }
        let now = self.now();
        let stale: Vec<GroupId> = self
            .groups
            .values()
            .filter(|g| g.row.server_id == server_id)
            .filter(|g| now.saturating_sub(g.row.last_update_unix) > KEY_REFRESH_SECS)
            .filter(|g| g.mls.pending_commit().is_none())
            .map(|g| g.row.id)
            .collect();
        for gid in stale {
            let r = self.update_keys(gid).await;
            let what = format!("Could not refresh your keys in {}", self.label(&gid));
            self.group_step(r, &what)?;
        }
        // Someone joined, or this client's own add went through without a
        // reply: the newcomer needs this member's name, and the chat's name
        // and kind.
        let owed: Vec<GroupId> = self.repost.drain().collect();
        for gid in owed {
            if self
                .groups
                .get(&gid)
                .is_some_and(|g| g.row.server_id == server_id)
            {
                self.repost.insert(gid);
                let r = self.after_add(gid).await;
                if r.is_ok() {
                    self.repost.remove(&gid);
                }
                let what = format!("Could not share your name in {}", self.label(&gid));
                self.group_step(r, &what)?;
            } else if self.groups.contains_key(&gid) {
                self.repost.insert(gid);
            }
        }
        for gid in self.store.groups_owing_proofs()? {
            match self.groups.get(&gid) {
                None => self.store.forget_proofs(&gid)?,
                Some(l) if l.row.server_id == server_id => {
                    let r = self.send_owed_proofs(gid).await;
                    let what = format!("Could not confirm your invite in {}", self.label(&gid));
                    self.group_step(r, &what)?;
                }
                Some(_) => {}
            }
        }
        // Join requests: the ones pushed live, then each group's waiting
        // list one page at a time. A request this client cannot or will not
        // complete stays on the server's list, so each token is tried once
        // per sync and a page with nothing new ends the loop.
        let mut seen = HashSet::new();
        for (gid, j) in pushed {
            if self.holds_commit(&gid) {
                continue;
            }
            if seen.insert(j.token) && self.groups.contains_key(&gid) {
                let r = self.handle_join_request(gid, j.token, j.key_package).await;
                self.group_step(r, "Could not let someone in")?;
            }
        }
        for gid in gids {
            if self.holds_commit(&gid) {
                continue;
            }
            let r = self.handle_waiting_joins(server_id, gid, &mut seen).await;
            let what = format!(
                "Could not check who is waiting to join {}",
                self.label(&gid)
            );
            self.group_step(r, &what)?;
        }
        Ok(())
    }

    /// Works through a group's waiting join requests, a page at a time,
    /// each page starting after the last request of the one before.
    async fn handle_waiting_joins(
        &mut self,
        server_id: i64,
        gid: GroupId,
        seen: &mut HashSet<Token>,
    ) -> Result<(), CoreError> {
        /// More pages than this in one sync wait for the next one.
        const MAX_PAGES: usize = 20;
        let mut after: Option<(u64, Token)> = None;
        for _ in 0..MAX_PAGES {
            if !self.groups.contains_key(&gid) {
                return Ok(());
            }
            let Response::Joins(js) = self
                .request(server_id, Request::PendingJoins { group: gid, after })
                .await?
            else {
                return Ok(());
            };
            let Some(last) = js.last().map(|j| (j.lodged_unix, j.token)) else {
                return Ok(());
            };
            // A page that does not move forward would repeat forever.
            let pos = |c: &(u64, Token)| (c.0, c.1 .0);
            if after.is_some_and(|a| pos(&last) <= pos(&a)) {
                return Ok(());
            }
            after = Some(last);
            for j in js {
                if !self.groups.contains_key(&gid) {
                    return Ok(());
                }
                if !seen.insert(j.token) {
                    continue;
                }
                let r = self.handle_join_request(gid, j.token, j.key_package).await;
                self.group_step(r, "Could not let someone in")?;
            }
        }
        Ok(())
    }

    /// Fetches a group's new log entries and applies them in order, until
    /// the server has nothing more. A commit of this client's own still
    /// staged once the log runs out never reached the server, so it goes.
    pub(crate) async fn fetch_group(&mut self, gid: GroupId) -> Result<(), CoreError> {
        let server_id = self.server_of(&gid)?;
        loop {
            let after = self.groups[&gid].row.last_seq;
            #[cfg(feature = "test-hooks")]
            let fault = self.hooks.fetch_fault(gid);
            #[cfg(not(feature = "test-hooks"))]
            let fault: Option<CoreError> = None;
            #[cfg(feature = "test-hooks")]
            let stale = self.hooks.stale_pages.contains(&gid);
            #[cfg(not(feature = "test-hooks"))]
            let stale = false;
            let fetched = match fault {
                Some(e) => Err(e),
                None if stale => Ok(Response::Entries(vec![Entry {
                    seq: after,
                    mls: vec![],
                }])),
                None => {
                    self.request(
                        server_id,
                        Request::Fetch {
                            group: gid,
                            after,
                            limit: 500,
                        },
                    )
                    .await
                }
            };
            let es = match fetched {
                Ok(Response::Entries(es)) => es,
                Ok(_) => return Ok(()),
                Err(CoreError::Net(NetError::Refused(why))) if why == NOT_A_MEMBER => {
                    return self.forget_group(gid);
                }
                Err(CoreError::Net(NetError::Refused(why))) => {
                    let label = self.label(&gid);
                    self.emit(Event::Warning(format!(
                        "The server would not send new messages in {label}: {why}"
                    )));
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            let Some(last) = es.last().map(|e| e.seq) else {
                // The log ends here. A commit still staged never reached the
                // server, unless its post timed out this round or the last.
                let keep = self.commit_grace.contains(&gid);
                let live = self.groups.get_mut(&gid).expect("caller checked");
                if live.mls.pending_commit().is_some() && !keep {
                    live.mls
                        .clear_pending_commit(self.prov.storage())
                        .map_err(mls_err)?;
                }
                return Ok(());
            };
            // A page that ends at or before where it started would come back
            // the same forever: a broken or hostile server.
            if last <= after {
                return Ok(());
            }
            for e in es {
                self.apply_entry(gid, e).await?;
                if !self.groups.contains_key(&gid) {
                    return Ok(());
                }
            }
            let _ = self
                .request(
                    server_id,
                    Request::Ack {
                        group: gid,
                        seq: last,
                    },
                )
                .await;
        }
    }

    async fn apply_entry(&mut self, gid: GroupId, e: Entry) -> Result<(), CoreError> {
        let now = self.now();
        let live = self.groups.get_mut(&gid).expect("caller checked");
        if e.seq <= live.row.last_seq {
            return Ok(());
        }
        live.row.last_seq = e.seq;
        self.store.set_last_seq(&gid, e.seq)?;
        let Ok(pm) =
            MlsMessageIn::tls_deserialize_exact(&e.mls).map(|m| m.try_into_protocol_message())
        else {
            return Ok(());
        };
        let Ok(pm) = pm else { return Ok(()) };
        let local = live.mls.epoch().as_u64();
        let epoch = pm.epoch().as_u64();
        let is_commit = pm.content_type() == ContentType::Commit;
        let processed = match live.mls.process_message(&self.prov, pm) {
            Ok(p) => p,
            Err(_) => {
                // Anything from before this member joined, or already
                // applied, does not open and needs nothing. A commit for the
                // current epoch, or any message from a later one, means this
                // app missed a change the others made.
                if epoch > local || (is_commit && epoch == local) {
                    self.report_drift(gid);
                }
                return Ok(());
            }
        };
        let sender = match processed.sender() {
            Sender::Member(i) => live
                .mls
                .member_at(*i)
                .and_then(|m| key_of(&m.signature_key)),
            _ => None,
        };
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(am) => {
                if let (Some(sender), Some(msg)) = (sender, AppMsg::decode(&am.into_bytes())) {
                    self.apply_app(gid, e.seq, sender, msg).await?;
                }
            }
            ProcessedMessageContent::ProposalMessage(qp) => {
                live.mls
                    .store_pending_proposal(self.prov.storage(), *qp)
                    .map_err(mls_err)?;
                self.leaves.insert(gid);
            }
            ProcessedMessageContent::StagedCommitMessage(sc) => {
                // Someone else's commit for this epoch: merging it also drops
                // any commit of this client's own still staged.
                self.apply_commit(gid, e.seq, *sc).await?;
            }
            ProcessedMessageContent::OwnPendingCommit => {
                // This client's own commit, whose reply never came. It gets
                // the same bookkeeping as anyone else's, and a newcomer it
                // added still gets this member's name and the chat's.
                let (added, removed) = live
                    .mls
                    .pending_commit()
                    .map(|sc| commit_changes(&live.mls, sc))
                    .unwrap_or_default();
                live.mls.merge_pending_commit(&self.prov).map_err(mls_err)?;
                live.row.last_update_unix = now;
                self.store.set_last_update(&gid, now)?;
                self.commit_grace.remove(&gid);
                self.record_changes(gid, e.seq, &added, &removed)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Says once per session that a group fell out of step with the others.
    fn report_drift(&mut self, gid: GroupId) {
        if !self.drifted.insert(gid) {
            return;
        }
        let what = match self.groups.get(&gid) {
            Some(l) if !l.row.name.is_empty() => format!("The chat {}", l.row.name),
            Some(l) if l.row.is_dm => "A direct message".into(),
            _ => "A chat".into(),
        };
        self.emit(Event::Warning(format!(
            "{what} fell out of step. Ask an admin to remove you and invite you again."
        )));
    }

    async fn apply_commit(
        &mut self,
        gid: GroupId,
        seq: u64,
        sc: StagedCommit,
    ) -> Result<(), CoreError> {
        let live = self.groups.get_mut(&gid).expect("caller checked");
        let (added, removed) = commit_changes(&live.mls, &sc);
        let me_out = sc.self_removed();
        live.mls
            .merge_staged_commit(&self.prov, sc)
            .map_err(mls_err)?;
        if me_out {
            for k in &removed {
                self.store.remove_member(&gid, k)?;
            }
            self.store.set_left(&gid)?;
            let live = self.groups.remove(&gid).expect("present");
            if let Some(c) = self.conns.get(&live.row.server_id) {
                c.forget(&live.row.key.public());
            }
            self.emit(Event::Left { group: gid });
            return Ok(());
        }
        self.record_changes(gid, seq, &added, &removed)
    }

    /// Records who a merged commit added and removed. Each newcomer is owed
    /// this member's profile, and the chat's name and kind.
    fn record_changes(
        &mut self,
        gid: GroupId,
        seq: u64,
        added: &[Key],
        removed: &[Key],
    ) -> Result<(), CoreError> {
        for k in added {
            self.store.upsert_member(&gid, k, Some(seq))?;
        }
        for k in removed {
            self.store.remove_member(&gid, k)?;
        }
        if !added.is_empty() || !removed.is_empty() {
            self.emit(Event::MembersChanged { group: gid });
        }
        if !added.is_empty() {
            self.repost.insert(gid);
        }
        Ok(())
    }

    async fn apply_app(
        &mut self,
        gid: GroupId,
        seq: u64,
        sender: Key,
        msg: AppMsg,
    ) -> Result<(), CoreError> {
        match msg {
            AppMsg::Text { body } => {
                let text = crate::sanitize::clean_text(&body);
                let now = self.now();
                self.store
                    .add_message(&gid, seq, Some(&sender), kind::TEXT, &text, now)?;
                let line = self.line(&gid, seq, Some(sender), text, now, false);
                self.emit(Event::Message { group: gid, line });
            }
            AppMsg::Profile {
                display_name,
                binding,
            } => {
                if binding.group != gid || binding.group_key != sender || !binding.verify() {
                    return Ok(());
                }
                let name = crate::sanitize::clean_name(&display_name);
                let old = self
                    .store
                    .members(&gid)?
                    .into_iter()
                    .find(|m| m.key == sender)
                    .map(|m| m.display_name)
                    .unwrap_or_default();
                self.store
                    .set_member_profile(&gid, &sender, &binding.identity, &name)?;
                if self.store.take_expected_joiner(&gid, &sender)? {
                    self.store.trust(&binding.identity)?;
                }
                if !old.is_empty() && old != name {
                    let now = self.now();
                    let text = format!("{old} is now called {name}");
                    self.store
                        .add_message(&gid, seq, None, kind::NOTICE, &text, now)?;
                    self.emit(Event::NameChanged {
                        group: gid,
                        old,
                        new: name,
                    });
                }
                self.emit(Event::MembersChanged { group: gid });
            }
            AppMsg::GroupName { name } => {
                let name = crate::sanitize::clean_name(&name);
                self.store.set_group_name(&gid, &name)?;
                if let Some(l) = self.groups.get_mut(&gid) {
                    l.row.name = name;
                }
                self.emit(Event::GroupRenamed { group: gid });
            }
            AppMsg::Voucher {
                voucher,
                request_key,
                seal_key,
            } => {
                // Only the inviter can post their own voucher: it must be
                // signed by the identity this sender proved in their profile,
                // and name this sender's key in this group.
                let bound = self
                    .store
                    .members(&gid)?
                    .into_iter()
                    .find(|m| m.key == sender)
                    .and_then(|m| m.identity);
                let genuine = voucher.group == gid
                    && voucher.inviter_group_key == sender
                    && bound == Some(voucher.inviter_identity)
                    && voucher
                        .verify(&fingerprint(&voucher.inviter_identity), self.now())
                        .is_ok();
                if genuine {
                    self.store.save_voucher(
                        &gid,
                        &voucher.token,
                        &StoredVoucher {
                            voucher: postcard::to_stdvec(&voucher)?,
                            request_key,
                            seal_key,
                            secret: None,
                        },
                    )?;
                }
            }
            AppMsg::InviteProof { token, proof } => {
                // Only a link this client made holds the secret to check it.
                let secret = self.store.voucher(&gid, &token)?.and_then(|v| v.secret);
                if let Some(secret) = secret {
                    if proof_matches(&secret, &gid, &sender, &proof) {
                        let identity = self
                            .store
                            .members(&gid)?
                            .into_iter()
                            .find(|m| m.key == sender)
                            .and_then(|m| m.identity);
                        match identity {
                            Some(id) => self.store.trust(&id)?,
                            // Their profile has not arrived: trust it when it does.
                            None => self.store.expect_joiner(&gid, &sender)?,
                        }
                        self.emit(Event::MembersChanged { group: gid });
                    }
                }
            }
            AppMsg::File(offer) => {
                let mut offer = offer;
                offer.name = crate::files::safe_name(&offer.name);
                self.store.add_file(&gid, &offer)?;
                let now = self.now();
                let who = self.name_for(&gid, &sender);
                let text = format!("{who} sent {} ({})", offer.name, human_size(offer.size));
                self.store
                    .add_message(&gid, seq, Some(&sender), kind::FILE, &text, now)?;
                self.emit(Event::FileOffered {
                    group: gid,
                    file: offer,
                });
            }
            AppMsg::IsDm => {
                self.store.set_is_dm(&gid)?;
                if let Some(l) = self.groups.get_mut(&gid) {
                    l.row.is_dm = true;
                }
            }
            AppMsg::DmRequest {
                to,
                group,
                token,
                dm_key,
            } => {
                if self.my_group_key(gid) == Some(to) {
                    self.dm_todo.push(DmTodo::Accept {
                        shared: gid,
                        from: sender,
                        group,
                        token,
                        dm_key,
                    });
                }
            }
            AppMsg::DmAccept {
                to,
                group,
                token,
                key_packages,
            } => {
                #[cfg(feature = "test-hooks")]
                if self.my_group_key(gid) != Some(to) {
                    self.hooks.dm_accepts_seen.push(key_packages.clone());
                }
                if self.my_group_key(gid) == Some(to)
                    && self.dm_offers.get(&token) == Some(&(group, sender))
                {
                    self.dm_offers.remove(&token);
                    self.dm_todo.push(DmTodo::Complete {
                        group,
                        token,
                        key_packages,
                    });
                }
            }
        }
        Ok(())
    }

    // ---------- views ----------

    fn name_for(&self, gid: &GroupId, key: &Key) -> String {
        if self
            .groups
            .get(gid)
            .is_some_and(|g| g.row.key.public() == *key)
        {
            return self.profile.display_name.clone();
        }
        let m = self
            .store
            .members(gid)
            .ok()
            .and_then(|ms| ms.into_iter().find(|m| m.key == *key));
        match m {
            Some(m) if m.local_name.is_some() => m.local_name.unwrap_or_default(),
            Some(m) if !m.display_name.is_empty() => m.display_name,
            _ => format!("someone ({})", short(key)),
        }
    }

    fn line(
        &self,
        gid: &GroupId,
        seq: u64,
        sender: Option<Key>,
        text: String,
        sent_unix: u64,
        notice: bool,
    ) -> ChatLine {
        ChatLine {
            seq,
            sender: sender.map(|k| self.name_for(gid, &k)).unwrap_or_default(),
            sender_key: sender,
            text,
            sent_unix,
            notice,
        }
    }

    pub fn groups(&self) -> Vec<GroupSummary> {
        self.store
            .groups()
            .unwrap_or_default()
            .into_iter()
            .map(|g| GroupSummary {
                id: g.id,
                name: g.name,
                is_dm: g.is_dm,
                left: g.left,
            })
            .collect()
    }

    pub fn members(&self, gid: GroupId) -> Vec<MemberView> {
        let Some(live) = self.groups.get(&gid) else {
            return vec![];
        };
        let admins = admins_from(live.mls.extensions());
        let mine = live.row.key.public();
        let present: HashSet<Key> = live
            .mls
            .members()
            .filter_map(|m| key_of(&m.signature_key))
            .collect();
        self.store
            .members(&gid)
            .unwrap_or_default()
            .into_iter()
            .filter(|m| present.contains(&m.key))
            .map(|m| MemberView {
                name: self.name_for(&gid, &m.key),
                verified: m.verified,
                admin: admins.contains(&m.key),
                me: m.key == mine,
                key: m.key,
            })
            .collect()
    }

    pub fn messages(&self, gid: GroupId, limit: usize) -> Vec<ChatLine> {
        self.store
            .messages(&gid, limit)
            .unwrap_or_default()
            .into_iter()
            .map(|m| {
                self.line(
                    &gid,
                    m.seq,
                    m.sender,
                    m.body,
                    m.sent_unix,
                    m.kind != kind::TEXT,
                )
            })
            .collect()
    }

    /// This client's own key in a group.
    pub fn my_group_key(&self, gid: GroupId) -> Option<Key> {
        self.groups.get(&gid).map(|g| g.row.key.public())
    }

    // ---------- chatting ----------

    /// Sends a text message to a group.
    pub async fn send_text(&mut self, gid: GroupId, text: &str) -> Result<(), CoreError> {
        let text = crate::sanitize::clean_text(text);
        if text.trim().is_empty() {
            return Ok(());
        }
        // A message can go out while a commit waits to be confirmed.
        if self.holds_commit(&gid) {
            self.resolve_pending(gid).await?;
        }
        let seq = self
            .send_app(gid, &AppMsg::Text { body: text.clone() })
            .await?;
        let me = self.my_group_key(gid);
        let now = self.now();
        self.store
            .add_message(&gid, seq, me.as_ref(), kind::TEXT, &text, now)?;
        Ok(())
    }

    /// Changes this person's display name everywhere and tells every group.
    pub async fn set_display_name(&mut self, name: &str) -> Result<(), CoreError> {
        let name = crate::sanitize::clean_name(name);
        if name.is_empty() {
            return Err(CoreError::Other(
                "a name needs at least one visible character".into(),
            ));
        }
        self.profile.display_name = name;
        self.store.set_profile(&self.profile)?;
        let gids: Vec<GroupId> = self.groups.keys().copied().collect();
        for gid in gids {
            self.post_profile(gid).await?;
        }
        Ok(())
    }

    /// Renames a member on this screen only. `None` goes back to their own name.
    pub fn rename_local(
        &mut self,
        gid: GroupId,
        member: &Key,
        name: &str,
    ) -> Result<(), CoreError> {
        let name = crate::sanitize::clean_name(name);
        let name = (!name.is_empty()).then_some(name);
        self.store.set_local_name(&gid, member, name.as_deref())
    }

    /// The safety number to compare with a member in person.
    pub fn safety_number(&self, gid: GroupId, member: &Key) -> Option<String> {
        let them = self
            .store
            .members(&gid)
            .ok()?
            .into_iter()
            .find(|m| m.key == *member)?
            .identity?;
        Some(crate::keys::display_safety_number(
            &crate::keys::safety_number(&self.profile.identity.public(), &them),
        ))
    }

    /// Marks a member's identity as checked in person.
    pub fn mark_verified(&mut self, gid: GroupId, member: &Key) -> Result<bool, CoreError> {
        let id = self
            .store
            .members(&gid)?
            .into_iter()
            .find(|m| m.key == *member)
            .and_then(|m| m.identity);
        match id {
            Some(id) => {
                self.store.trust(&id)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// The group's current epoch, for tests and status lines.
    pub fn epoch(&self, gid: GroupId) -> Option<u64> {
        self.groups.get(&gid).map(|g| g.mls.epoch().as_u64())
    }

    /// Settles a commit whose reply was lost: reads the log to its end. If
    /// the server took the commit, it is applied on the way; if another
    /// commit for that epoch came first, that one wins; if the log ends
    /// without it, it is dropped.
    pub async fn resolve_pending(&mut self, gid: GroupId) -> Result<(), CoreError> {
        self.fetch_group(gid).await
    }

    /// Settles any commit still staged before making a new one in the
    /// group. One whose post timed out may stay staged for a sync round
    /// while the server finishes with it; until then no new commit can go.
    async fn settle_sent(&mut self, gid: GroupId) -> Result<(), CoreError> {
        if self.holds_commit(&gid) {
            self.resolve_pending(gid).await?;
        }
        if self.holds_commit(&gid) {
            return Err(CoreError::Other(format!(
                "a change you made in {} is not confirmed yet; try again in a moment",
                self.label(&gid)
            )));
        }
        Ok(())
    }

    /// Refreshes this member's own encryption keys in a group.
    pub async fn update_keys(&mut self, gid: GroupId) -> Result<(), CoreError> {
        self.settle_sent(gid).await?;
        for _ in 0..3 {
            let live = self
                .groups
                .get_mut(&gid)
                .ok_or_else(|| CoreError::Other("no such group".into()))?;
            let (commit, _, _) = live
                .mls
                .self_update(&self.prov, &live.row.key, LeafNodeParameters::default())
                .map_err(mls_err)?
                .into_messages();
            if self.post_commit(gid, commit, None).await?.is_some() {
                return Ok(());
            }
        }
        Err(CoreError::Other(
            "the group kept changing; try again".into(),
        ))
    }

    /// Removes a member. Needs an admin.
    pub async fn remove_member(&mut self, gid: GroupId, member: &Key) -> Result<(), CoreError> {
        self.settle_sent(gid).await?;
        for _ in 0..3 {
            let live = self
                .groups
                .get_mut(&gid)
                .ok_or_else(|| CoreError::Other("no such group".into()))?;
            let Some(idx) = live
                .mls
                .members()
                .find(|m| m.signature_key == member.0)
                .map(|m| m.index)
            else {
                return Ok(());
            };
            let (commit, _, _) = live
                .mls
                .remove_members(&self.prov, &live.row.key, &[idx])
                .map_err(mls_err)?;
            if self.post_commit(gid, commit, None).await?.is_some() {
                self.store.remove_member(&gid, member)?;
                self.emit(Event::MembersChanged { group: gid });
                return Ok(());
            }
        }
        Err(CoreError::Other(
            "the group kept changing; try again".into(),
        ))
    }

    /// Leaves a group: asks the others to remove this member. The next
    /// member online makes it happen.
    pub async fn leave(&mut self, gid: GroupId) -> Result<(), CoreError> {
        self.settle_sent(gid).await?;
        let alone = self
            .groups
            .get(&gid)
            .is_some_and(|g| g.mls.members().count() <= 1);
        if alone {
            return self.forget_group(gid);
        }
        let server_id = self.server_of(&gid)?;
        let live = self.groups.get_mut(&gid).expect("checked by server_of");
        let proposal = live
            .mls
            .leave_group(&self.prov, &live.row.key)
            .map_err(mls_err)?;
        self.request(
            server_id,
            Request::Post {
                group: gid,
                mls: ser(&proposal)?,
                welcome: None,
            },
        )
        .await?;
        Ok(())
    }

    fn forget_group(&mut self, gid: GroupId) -> Result<(), CoreError> {
        self.store.set_left(&gid)?;
        if let Some(live) = self.groups.remove(&gid) {
            if let Some(c) = self.conns.get(&live.row.server_id) {
                c.forget(&live.row.key.public());
            }
        }
        self.emit(Event::Left { group: gid });
        Ok(())
    }

    /// Commits members' requests to leave. When the last admin leaves, the
    /// commit hands the role to the longest-standing remaining member, as
    /// the server requires.
    async fn commit_leaves(&mut self, gid: GroupId) -> Result<(), CoreError> {
        let server_id = self.server_of(&gid)?;
        self.settle_sent(gid).await?;
        for _ in 0..3 {
            let live = self
                .groups
                .get(&gid)
                .ok_or_else(|| CoreError::Other("no such group".into()))?;
            let me = live.row.key.public();
            let leaving: Vec<Key> = live
                .mls
                .pending_proposals()
                .filter_map(|q| match q.proposal() {
                    Proposal::Remove(r) => live.mls.member_at(r.removed()),
                    _ => None,
                })
                .filter_map(|m| key_of(&m.signature_key))
                .collect();
            if leaving.is_empty() || leaving.contains(&me) {
                return Ok(());
            }
            let admins = admins_from(live.mls.extensions());
            let remaining: Vec<Key> = live
                .mls
                .members()
                .filter_map(|m| key_of(&m.signature_key))
                .filter(|k| !leaving.contains(k))
                .collect();
            let promote = if remaining.iter().any(|k| admins.contains(k)) {
                None
            } else {
                let Response::Members(ms) = self
                    .request(server_id, Request::Members { group: gid })
                    .await?
                else {
                    return Ok(());
                };
                ms.into_iter()
                    .filter(|m| remaining.contains(&m.key))
                    .min_by_key(|m| (m.joined_seq, m.key.0))
                    .map(|m| m.key)
            };
            let live = self.groups.get_mut(&gid).expect("checked above");
            let mut builder = live.mls.commit_builder().consume_proposal_store(true);
            if let Some(p) = promote {
                builder = builder
                    .propose_group_context_extensions(group_context_extensions(&[p]))
                    .map_err(mls_err)?;
            }
            let bundle = builder
                .load_psks(self.prov.storage())
                .map_err(mls_err)?
                .build(self.prov.rand(), self.prov.crypto(), &live.row.key, |_| {
                    true
                })
                .map_err(mls_err)?
                .stage_commit(&self.prov)
                .map_err(mls_err)?;
            let (commit, _, _) = bundle.into_messages();
            match self.post_commit(gid, commit, None).await {
                Ok(Some(_)) => {
                    for k in &leaving {
                        self.store.remove_member(&gid, k)?;
                    }
                    self.emit(Event::MembersChanged { group: gid });
                    return Ok(());
                }
                Ok(None) => continue,
                Err(CoreError::Net(NetError::Refused(_))) => {
                    // Someone else committed first; catch up.
                    self.fetch_group(gid).await?;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    // ---------- direct messages ----------

    /// Opens a direct message with a member of a shared group. The two apps
    /// arrange it inside the shared group's encrypted messages, so the
    /// server's records do not link the two chats.
    pub async fn dm(&mut self, shared: GroupId, member: &Key) -> Result<GroupId, CoreError> {
        let server_id = self.server_of(&shared)?;
        let dm = self.create_group_on(server_id, "", true).await?;
        let Response::Invite { token, .. } = self
            .request(server_id, Request::CreateInvite { group: Some(dm) })
            .await?
        else {
            return Err(CoreError::Net(NetError::Unexpected("no invite".into())));
        };
        self.dm_offers.insert(token, (dm, *member));
        let dm_key = self.groups[&dm].row.key.public();
        self.send_app(
            shared,
            &AppMsg::DmRequest {
                to: *member,
                group: dm,
                token,
                dm_key,
            },
        )
        .await?;
        Ok(dm)
    }

    async fn accept_dm(
        &mut self,
        shared: GroupId,
        from: Key,
        group: GroupId,
        token: Token,
        dm_key: Key,
    ) -> Result<(), CoreError> {
        let server_id = self.server_of(&shared)?;
        let from_identity = self
            .store
            .members(&shared)?
            .into_iter()
            .find(|m| m.key == from)
            .and_then(|m| m.identity)
            .ok_or_else(|| {
                CoreError::Other("the request came from someone with no profile yet".into())
            })?;
        let key = KeyPair::generate();
        self.conn(server_id)
            .await?
            .register_mailbox(Some(token), &key)
            .await?;
        let key_packages = key_package_blob(&self.prov, &key)?;
        self.store.save_pending_join(&PendingJoin {
            token,
            server_id,
            link: DmAsk {
                identity: from_identity,
                dm_key,
                group,
            }
            .to_link(),
            key,
            lodged_unix: self.now(),
        })?;
        self.send_app(
            shared,
            &AppMsg::DmAccept {
                to: from,
                group,
                token,
                key_packages,
            },
        )
        .await?;
        Ok(())
    }

    async fn complete_dm(
        &mut self,
        group: GroupId,
        token: Token,
        key_packages: Vec<u8>,
    ) -> Result<(), CoreError> {
        if !self.groups.contains_key(&group) {
            return Err(CoreError::Other("the direct message is gone".into()));
        }
        self.settle_sent(group).await?;
        let live = self
            .groups
            .get_mut(&group)
            .ok_or_else(|| CoreError::Other("the direct message is gone".into()))?;
        let Some(kp) = pick_key_package(&self.prov, &key_packages, live.mls.ciphersuite()) else {
            return Ok(());
        };
        let joiner = key_of(kp.leaf_node().signature_key().as_slice());
        let (commit, welcome, _) = live
            .mls
            .add_members(&self.prov, &live.row.key, &[kp])
            .map_err(mls_err)?;
        let welcome = WelcomeOut {
            token,
            welcome: ser(&welcome)?,
            voucher: vec![],
        };
        if let Some(seq) = self.post_commit(group, commit, Some(welcome)).await? {
            if let Some(j) = joiner {
                self.store.upsert_member(&group, &j, Some(seq))?;
            }
            self.after_add(group).await?;
            self.emit(Event::MembersChanged { group });
        }
        Ok(())
    }

    // ---------- files ----------

    /// Files offered in a group, oldest first.
    pub fn files(&self, gid: GroupId) -> Vec<crate::files::FileOffer> {
        self.store.files(&gid).unwrap_or_default()
    }

    /// Sends a file, photo or video to a group. Photos lose their location
    /// and device data first. A video keeps its own, so it needs
    /// `video_ok`. Returns the offer the group received.
    pub async fn send_file(
        &mut self,
        gid: GroupId,
        path: &Path,
        video_ok: bool,
    ) -> Result<crate::files::FileOffer, CoreError> {
        use crate::files::*;
        let server_id = self.server_of(&gid)?;
        let mut head = [0u8; 16];
        let n = fill(&mut std::fs::File::open(path)?, &mut head)?;
        let kind = sniff(&head[..n]);
        if kind == Kind::Video && !video_ok {
            return Err(CoreError::VideoNeedsConfirm);
        }
        let name = safe_name(
            &path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        );
        // Photos are small enough to clean in memory; everything else
        // streams from disk a chunk at a time.
        let (mut source, size): (Box<dyn std::io::Read + Send>, u64) = match kind {
            Kind::Jpeg | Kind::Png | Kind::WebP => {
                let bytes = strip_image(kind, std::fs::read(path)?)?;
                let len = bytes.len() as u64;
                (Box::new(std::io::Cursor::new(bytes)), len)
            }
            _ => (
                Box::new(std::fs::File::open(path)?),
                std::fs::metadata(path)?.len(),
            ),
        };
        let Response::File(id) = self
            .request(server_id, Request::FileBegin { group: gid, size })
            .await?
        else {
            return Err(CoreError::Net(NetError::Unexpected("no file ID".into())));
        };
        let mut key = [0u8; 32];
        let mut prefix = [0u8; 19];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut prefix);
        let mut enc = Some(encryptor(&key, &prefix));
        let mut hash = sha2::Sha256::default();
        let total = chunk_count(size);
        let mut cur = vec![0u8; CHUNK];
        for index in 0..total {
            let len = fill(&mut source, &mut cur)?;
            let last = index + 1 == total;
            sha2::Digest::update(&mut hash, &cur[..len]);
            let sealed = if last {
                enc.take()
                    .expect("one last chunk")
                    .encrypt_last(&cur[..len])
            } else {
                enc.as_mut()
                    .expect("before the last chunk")
                    .encrypt_next(&cur[..len])
            }
            .map_err(|_| CoreError::Other("could not encrypt the file".into()))?;
            self.request(
                server_id,
                Request::FileChunk {
                    file: id,
                    index,
                    data: sealed,
                },
            )
            .await?;
        }
        self.request(server_id, Request::FileEnd { file: id })
            .await?;
        let offer = FileOffer {
            id,
            name,
            size,
            mime: mime(kind).into(),
            sha256: sha2::Digest::finalize(hash).into(),
            key,
            nonce_prefix: prefix,
        };
        let seq = self.send_app(gid, &AppMsg::File(offer.clone())).await?;
        self.store.add_file(&gid, &offer)?;
        let me = self.my_group_key(gid);
        let text = format!("You sent {} ({})", offer.name, human_size(size));
        let now = self.now();
        self.store
            .add_message(&gid, seq, me.as_ref(), kind::FILE, &text, now)?;
        Ok(offer)
    }

    /// Downloads, opens and checks a file, then saves it in `dir` under a
    /// name that never replaces an existing file.
    pub async fn save_file(
        &mut self,
        gid: GroupId,
        id: socketchat_proto::msg::FileId,
        dir: &Path,
    ) -> Result<std::path::PathBuf, CoreError> {
        use crate::files::*;
        use std::io::Write;
        let server_id = self.server_of(&gid)?;
        let offer = self
            .store
            .files(&gid)?
            .into_iter()
            .find(|f| f.id == id)
            .ok_or_else(|| CoreError::Other("no such file in this chat".into()))?;
        std::fs::create_dir_all(dir)?;
        let part = dir.join(format!(".socketchat-{}.part", hex(&id.0)));
        let tampered =
            || CoreError::Other("the file was changed on its way; nothing was saved".into());
        let mut out = std::fs::File::create(&part)?;
        let mut dec = Some(decryptor(&offer.key, &offer.nonce_prefix));
        let mut hash = sha2::Sha256::default();
        let total = chunk_count(offer.size);
        let mut failed = None;
        for index in 0..total {
            let data = match self
                .request(server_id, Request::FileGet { file: id, index })
                .await
            {
                Ok(Response::Chunk(d)) => d,
                Ok(_) => {
                    failed = Some(CoreError::Net(NetError::Unexpected("no chunk".into())));
                    break;
                }
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            };
            let plain = if index + 1 == total {
                dec.take()
                    .expect("one last chunk")
                    .decrypt_last(data.as_slice())
            } else {
                dec.as_mut()
                    .expect("before the last chunk")
                    .decrypt_next(data.as_slice())
            };
            let Ok(plain) = plain else {
                failed = Some(tampered());
                break;
            };
            sha2::Digest::update(&mut hash, &plain);
            if let Err(e) = out.write_all(&plain) {
                failed = Some(e.into());
                break;
            }
        }
        if failed.is_none() && <[u8; 32]>::from(sha2::Digest::finalize(hash)) != offer.sha256 {
            failed = Some(tampered());
        }
        if failed.is_none() {
            if let Err(e) = out.sync_all() {
                failed = Some(e.into());
            }
        }
        drop(out);
        if let Some(e) = failed {
            let _ = std::fs::remove_file(&part);
            return Err(e);
        }
        let saved = match publish(&part, dir, &offer.name) {
            Ok(saved) => saved,
            Err(e) => {
                let _ = std::fs::remove_file(&part);
                return Err(e.into());
            }
        };
        let _ = self
            .request(server_id, Request::FileDone { file: id })
            .await;
        Ok(saved)
    }
}

#[cfg(feature = "test-hooks")]
impl Hooks {
    /// The failure a test set up for this group's next fetch, if any.
    fn fetch_fault(&mut self, gid: GroupId) -> Option<CoreError> {
        if self.broken.contains(&gid) {
            return Some(CoreError::Other("this group was broken for a test".into()));
        }
        self.refuse_fetch
            .remove(&gid)
            .map(|why| CoreError::Net(NetError::Refused(why)))
    }
}

/// Hooks for tests that play a hostile member or a failing server. Only
/// built with the `test-hooks` feature, which the shipped binary never has.
#[cfg(feature = "test-hooks")]
impl Client {
    /// Posts any application message, as a hostile member could.
    pub async fn test_send_app(&mut self, gid: GroupId, msg: &AppMsg) -> Result<u64, CoreError> {
        self.send_app(gid, msg).await
    }

    /// The public key this client checks join requests for `token` with.
    pub fn test_invite_request_key(&self, gid: GroupId, token: Token) -> Option<Key> {
        self.store
            .voucher(&gid, &token)
            .ok()
            .flatten()
            .map(|v| v.request_key)
    }

    /// Joins with a group link, signing the request with the key whose seed
    /// is `seed` instead of the one the link gives.
    pub async fn test_join_signing_with(
        &mut self,
        link: &InviteLink,
        seed: [u8; 32],
    ) -> Result<JoinStatus, CoreError> {
        self.join_with(link, Some(KeyPair::from_seed(&seed)), false)
            .await
    }

    /// Makes every fetch of this group come back as one page that ends where
    /// it started, as a hostile server could answer.
    pub fn test_serve_stale_pages(&mut self, gid: GroupId) {
        self.hooks.stale_pages.insert(gid);
    }

    /// Forgets a staged commit without looking at the log, the way an old
    /// bug did.
    pub fn test_drop_pending_commit(&mut self, gid: GroupId) {
        if let Some(live) = self.groups.get_mut(&gid) {
            let _ = live.mls.clear_pending_commit(self.prov.storage());
        }
    }

    /// Makes every fetch of this group fail.
    pub fn test_break_group(&mut self, gid: GroupId) {
        self.hooks.broken.insert(gid);
    }

    /// Makes the server's next fetch of this group come back refused.
    pub fn test_refuse_next_fetch(&mut self, gid: GroupId, why: &str) {
        self.hooks.refuse_fetch.insert(gid, why.to_string());
    }

    /// KeyPackages this client saw in direct-message answers meant for
    /// someone else.
    pub fn test_dm_accepts_seen(&self) -> Vec<Vec<u8>> {
        self.hooks.dm_accepts_seen.clone()
    }

    /// Adds the owner of a KeyPackage blob to one of this client's groups
    /// and returns the Welcome instead of sending it.
    pub async fn test_add_and_keep_welcome(
        &mut self,
        gid: GroupId,
        blob: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        let live = self
            .groups
            .get_mut(&gid)
            .ok_or_else(|| CoreError::Other("no such group".into()))?;
        let kp = pick_key_package(&self.prov, blob, live.mls.ciphersuite())
            .ok_or_else(|| CoreError::Other("no usable KeyPackage".into()))?;
        let (commit, welcome, _) = live
            .mls
            .add_members(&self.prov, &live.row.key, &[kp])
            .map_err(mls_err)?;
        let welcome = ser(&welcome)?;
        self.post_commit(gid, commit, None)
            .await?
            .ok_or_else(|| CoreError::Other("the group moved on".into()))?;
        Ok(welcome)
    }
}
