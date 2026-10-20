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
use crate::invite::{key_package_blob, pick_key_package};
use crate::keys::{fingerprint, invite_mac, mac_matches, Binding, GroupId, Key, KeyPair, Voucher};
use crate::net::{Conn, NetError};
use crate::provider::Provider;
use crate::store::{GroupRow, PendingJoin, Profile, Store};
use crate::suite::{
    admins_from, group_context_extensions, group_create_config, group_join_config, SUITE,
};
use crate::CoreError;

/// Kinds of stored message line.
pub mod kind {
    pub const TEXT: i64 = 0;
    pub const NOTICE: i64 = 1;
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
    Warning(String),
    Disconnected,
    Reconnected,
}

struct Live {
    row: GroupRow,
    mls: MlsGroup,
}

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

fn ser(m: &MlsMessageOut) -> Result<Vec<u8>, CoreError> {
    m.tls_serialize_detached().map_err(mls_err)
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
            if let Some(a) = &row.account {
                c.prove(a).await?;
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
    /// invite lodges a join request.
    pub async fn join(&mut self, link: &InviteLink) -> Result<JoinStatus, CoreError> {
        let server_id = self
            .store
            .add_server(&link.host, link.port, &link.cert_fpr)?;
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
        let blob = key_package_blob(&self.prov, &key)?;
        let mac = invite_mac(&secret, &blob);
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
                mac,
            })
            .await?
        {
            Response::JoinLodged => Ok(JoinStatus::Waiting {
                for_name: "the person who invited you, or a group admin".into(),
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
        let link =
            InviteLink::from_str(&pending.link).map_err(|e| CoreError::Other(e.to_string()))?;
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
        let voucher: Option<Voucher> = postcard::from_bytes(&w.voucher).ok();
        let now = self.now();
        let verification = match (&voucher, link.inviter_fpr, link.secret, adder) {
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
            is_dm: false,
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
        self.store.delete_pending_join(&pending.token)?;
        self.groups.insert(gid, Live { row, mls });
        self.post_profile(gid).await?;
        self.emit(Event::Joined {
            group: gid,
            verification,
        });
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
        let r = self
            .request(
                server_id,
                Request::Post {
                    group: gid,
                    mls: ser(&commit)?,
                    welcome,
                },
            )
            .await;
        let live = self.groups.get_mut(&gid).expect("checked by server_of");
        match r {
            Ok(Response::Posted { seq }) => {
                live.mls.merge_pending_commit(&self.prov).map_err(mls_err)?;
                Ok(Some(seq))
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

    /// Makes an invite link. `group: None` makes a server invite.
    pub async fn invite(
        &mut self,
        group: Option<GroupId>,
        dm: bool,
    ) -> Result<InviteLink, CoreError> {
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
            self.store
                .save_voucher(&gid, &token, &postcard::to_stdvec(&voucher)?, &secret)?;
            self.send_app(gid, &AppMsg::Voucher { voucher, secret })
                .await?;
            link.inviter_fpr = Some(fingerprint(&self.profile.identity.public()));
            link.secret = Some(secret);
        }
        Ok(link)
    }

    async fn handle_join_request(
        &mut self,
        gid: GroupId,
        token: Token,
        blob: Vec<u8>,
        mac: [u8; 32],
    ) -> Result<(), CoreError> {
        let Some((vbytes, secret)) = self.store.voucher(&gid, &token)? else {
            return Ok(());
        };
        if !mac_matches(&secret, &blob, &mac) {
            self.emit(Event::Warning(
                "A request to join one of your groups failed its check and was ignored.".into(),
            ));
            return Ok(());
        }
        let Ok(voucher) = postcard::from_bytes::<Voucher>(&vbytes) else {
            return Ok(());
        };
        for _ in 0..3 {
            let me = self.profile.identity.public();
            let live = self
                .groups
                .get_mut(&gid)
                .ok_or_else(|| CoreError::Other("no such group".into()))?;
            let my_key = live.row.key.public();
            let is_admin = admins_from(live.mls.extensions()).contains(&my_key);
            if !is_admin && voucher.inviter_identity != me {
                return Ok(());
            }
            let Some(kp) = pick_key_package(&self.prov, &blob, live.mls.ciphersuite()) else {
                return Ok(());
            };
            let Some(joiner) = key_of(kp.leaf_node().signature_key().as_slice()) else {
                return Ok(());
            };
            if live.mls.members().any(|m| m.signature_key == joiner.0) {
                return Ok(());
            }
            let (commit, welcome, _) = live
                .mls
                .add_members(&self.prov, &live.row.key, &[kp])
                .map_err(mls_err)?;
            let welcome = WelcomeOut {
                token,
                welcome: ser(&welcome)?,
                voucher: vbytes.clone(),
            };
            match self.post_commit(gid, commit, Some(welcome)).await {
                Ok(Some(seq)) => {
                    self.store.upsert_member(&gid, &joiner, Some(seq))?;
                    self.store.expect_joiner(&gid, &joiner)?;
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
        let name = self.groups[&gid].row.name.clone();
        if !name.is_empty() {
            self.send_app(gid, &AppMsg::GroupName { name }).await?;
        }
        Ok(())
    }

    // ---------- receiving ----------

    /// Fetches and applies everything new from every server.
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
                match e {
                    CoreError::Net(
                        NetError::Disconnected | NetError::Io(_) | NetError::Timeout,
                    ) => {
                        self.conns.remove(&server_id);
                        self.emit(Event::Disconnected);
                    }
                    e => return Err(e),
                }
            }
        }
        Ok(())
    }

    async fn sync_server(&mut self, server_id: i64) -> Result<(), CoreError> {
        let mut join_requests = Vec::new();
        {
            let c = self.conn(server_id).await?;
            while let Some(p) = c.try_push() {
                if let Push::JoinRequest { group, request } = p {
                    join_requests.push((group, request));
                }
            }
        }
        if let Response::Welcomes(ws) = self.request(server_id, Request::FetchWelcomes).await? {
            for w in ws {
                if let Err(e) = self.handle_welcome(w).await {
                    self.emit(Event::Warning(format!("could not join a group: {e}")));
                }
            }
        }
        let gids: Vec<GroupId> = self
            .groups
            .values()
            .filter(|g| g.row.server_id == server_id)
            .map(|g| g.row.id)
            .collect();
        for gid in gids {
            self.fetch_group(gid).await?;
            if !self.groups.contains_key(&gid) {
                continue;
            }
            if let Response::Joins(js) = self
                .request(server_id, Request::PendingJoins { group: gid })
                .await?
            {
                join_requests.extend(js.into_iter().map(|j| (gid, j)));
            }
        }
        let owed: Vec<GroupId> = self.repost.drain().collect();
        for gid in owed {
            if self.groups.contains_key(&gid) {
                self.post_profile(gid).await?;
            }
        }
        let mut seen = HashSet::new();
        for (gid, j) in join_requests {
            if seen.insert(j.token) && self.groups.contains_key(&gid) {
                self.handle_join_request(gid, j.token, j.key_package, j.mac)
                    .await?;
            }
        }
        Ok(())
    }

    /// Fetches a group's new log entries and applies them in order.
    pub(crate) async fn fetch_group(&mut self, gid: GroupId) -> Result<(), CoreError> {
        let server_id = self.server_of(&gid)?;
        loop {
            let after = self.groups[&gid].row.last_seq;
            let Response::Entries(es) = self
                .request(
                    server_id,
                    Request::Fetch {
                        group: gid,
                        after,
                        limit: 500,
                    },
                )
                .await?
            else {
                return Ok(());
            };
            let Some(last) = es.last().map(|e| e.seq) else {
                return Ok(());
            };
            let full = es.len() == 500;
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
            if !full {
                return Ok(());
            }
        }
    }

    async fn apply_entry(&mut self, gid: GroupId, e: Entry) -> Result<(), CoreError> {
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
        // Our own messages and anything from before we joined do not open.
        let Ok(processed) = live.mls.process_message(&self.prov, pm) else {
            return Ok(());
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
            }
            ProcessedMessageContent::StagedCommitMessage(sc) => {
                self.apply_commit(gid, e.seq, *sc).await?;
            }
            _ => {}
        }
        Ok(())
    }

    async fn apply_commit(
        &mut self,
        gid: GroupId,
        seq: u64,
        sc: StagedCommit,
    ) -> Result<(), CoreError> {
        let live = self.groups.get_mut(&gid).expect("caller checked");
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
        let removed: Vec<Key> = sc
            .remove_proposals()
            .filter_map(|r| live.mls.member_at(r.remove_proposal().removed()))
            .filter_map(|m| key_of(&m.signature_key))
            .collect();
        let me_out = sc.self_removed();
        live.mls
            .merge_staged_commit(&self.prov, sc)
            .map_err(mls_err)?;
        for k in &added {
            self.store.upsert_member(&gid, k, Some(seq))?;
        }
        for k in &removed {
            self.store.remove_member(&gid, k)?;
        }
        if me_out {
            self.store.set_left(&gid)?;
            let live = self.groups.remove(&gid).expect("present");
            if let Some(c) = self.conns.get(&live.row.server_id) {
                c.forget(&live.row.key.public());
            }
            self.emit(Event::Left { group: gid });
            return Ok(());
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
            AppMsg::Voucher { voucher, secret } => {
                if voucher.group == gid && voucher.secret_matches(&secret) {
                    self.store.save_voucher(
                        &gid,
                        &voucher.token,
                        &postcard::to_stdvec(&voucher)?,
                        &secret,
                    )?;
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
                    m.kind == kind::NOTICE,
                )
            })
            .collect()
    }

    /// This client's own key in a group.
    pub fn my_group_key(&self, gid: GroupId) -> Option<Key> {
        self.groups.get(&gid).map(|g| g.row.key.public())
    }
}
