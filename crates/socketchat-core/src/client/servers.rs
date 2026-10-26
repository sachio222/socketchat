//! The servers a profile knows: how each is written on screen, its state,
//! which one new rooms go on, and forgetting one.

use openmls_traits::OpenMlsProvider as _;
use socketchat_proto::msg::GroupId;
use socketchat_proto::DEFAULT_PORT;

use super::{Client, DmTodo, Event};
use crate::net::NetError;
use crate::store::ServerRow;
use crate::CoreError;

/// How a server is written for people: its host, with `:port` only when
/// the port is not the usual one. Every host shown goes through here, and
/// the host is cleaned first: it comes from an invite link.
pub fn server_text(host: &str, port: u16) -> String {
    let host = crate::sanitize::clean_host(host);
    if port == DEFAULT_PORT {
        host
    } else {
        format!("{host}:{port}")
    }
}

/// Why a connection failed, in a few plain words: "connection refused".
fn reason(e: &NetError) -> String {
    match e {
        NetError::Io(s) => {
            // "Connection refused (os error 61)" reads as "connection refused".
            let s = match s.rfind(" (os error ") {
                Some(i) if s.ends_with(')') => &s[..i],
                _ => s.as_str(),
            };
            let mut c = s.chars();
            match c.next() {
                Some(first) => first.to_lowercase().chain(c).collect(),
                None => "no reason given".into(),
            }
        }
        NetError::Timeout => "it took too long to answer".into(),
        e => e.to_string(),
    }
}

/// Whether this client can talk to a server right now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerState {
    /// This client holds a live connection to it now.
    Connected,
    /// The last try failed, for this reason.
    Unreachable(String),
    /// Not tried since this profile opened, or the connection dropped
    /// without a failed try since.
    NotYet,
}

/// One server, as `/servers` lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerView {
    pub id: i64,
    /// From [`server_text`].
    pub text: String,
    /// Rooms this person is in there.
    pub rooms: usize,
    pub state: ServerState,
    /// New rooms go on this server.
    pub new_rooms: bool,
}

impl Client {
    /// Turns a failure to connect to (or sign in on) `row` into the error
    /// to show, and remembers its reason for [`Client::servers`]. A server
    /// that cannot be reached at all is named in the error.
    pub(super) fn connect_failed(&mut self, row: &ServerRow, e: NetError) -> CoreError {
        let why = reason(&e);
        self.last_error.insert(row.id, why.clone());
        match e {
            NetError::Io(_) | NetError::Timeout => CoreError::Unreachable {
                server: server_text(&row.host, row.port),
                why,
            },
            e => e.into(),
        }
    }

    /// Remembers why the connection to a server was lost during a sync.
    pub(super) fn note_lost(&mut self, server_id: i64, e: &CoreError) {
        let why = match e {
            CoreError::Unreachable { why, .. } => why.clone(),
            CoreError::Net(n) => reason(n),
            e => e.to_string(),
        };
        self.last_error.insert(server_id, why);
    }

    /// A server's name for people, or "a server" for one this profile no
    /// longer knows.
    pub(super) fn server_name(&self, server_id: i64) -> String {
        self.store
            .servers()
            .ok()
            .and_then(|v| v.into_iter().find(|s| s.id == server_id))
            .map(|s| server_text(&s.host, s.port))
            .unwrap_or_else(|| "a server".into())
    }

    /// The server new rooms go on: the open room's server when this
    /// person has an account there, else the newest server they have an
    /// account on.
    pub(super) fn pick_server(&self, open: Option<GroupId>) -> Result<Option<i64>, CoreError> {
        let servers = self.store.servers()?;
        let account = |id: i64| servers.iter().any(|s| s.id == id && s.account.is_some());
        let here = open
            .and_then(|g| self.groups.get(&g))
            .map(|l| l.row.server_id)
            .filter(|id| account(*id));
        Ok(here.or_else(|| {
            servers
                .iter()
                .rev()
                .find(|s| s.account.is_some())
                .map(|s| s.id)
        }))
    }

    /// The server [`Client::create_group`] would use with `open` on
    /// screen; `None` before this person has an account anywhere.
    pub fn new_room_server(&self, open: Option<GroupId>) -> Option<i64> {
        self.pick_server(open).ok().flatten()
    }

    /// Every server this profile knows, oldest first: the order
    /// `socketchat servers` numbers them in. `open` is the room on screen,
    /// which decides where new rooms go.
    pub fn servers(&self, open: Option<GroupId>) -> Vec<ServerView> {
        let new_rooms = self.new_room_server(open);
        self.store
            .servers()
            .unwrap_or_default()
            .into_iter()
            .map(|s| {
                let state = if self.conns.get(&s.id).is_some_and(|c| c.is_alive()) {
                    ServerState::Connected
                } else if let Some(why) = self.last_error.get(&s.id) {
                    ServerState::Unreachable(why.clone())
                } else {
                    ServerState::NotYet
                };
                ServerView {
                    id: s.id,
                    text: server_text(&s.host, s.port),
                    rooms: self
                        .groups
                        .values()
                        .filter(|g| g.row.server_id == s.id)
                        .count(),
                    state,
                    new_rooms: new_rooms == Some(s.id),
                }
            })
            .collect()
    }

    /// The server room `gid` is on, as people read it.
    pub fn room_server(&self, gid: GroupId) -> Option<String> {
        let id = self.groups.get(&gid)?.row.server_id;
        Some(self.server_name(id))
    }

    /// A server whose connection dropped, as people read it, if any.
    pub fn dropped_server(&self) -> Option<String> {
        let (id, _) = self.conns.iter().find(|(_, c)| !c.is_alive())?;
        Some(self.server_name(*id))
    }

    /// Makes a new group on server `server_id`, where this person needs an
    /// account.
    pub async fn create_group_at(
        &mut self,
        server_id: i64,
        name: &str,
    ) -> Result<GroupId, CoreError> {
        let row = self
            .store
            .servers()?
            .into_iter()
            .find(|s| s.id == server_id)
            .ok_or_else(|| CoreError::Other("this profile does not know that server".into()))?;
        if row.account.is_none() {
            return Err(CoreError::Other(format!(
                "you have no account on {} yet; join it with a server invite first",
                server_text(&row.host, row.port)
            )));
        }
        self.create_group_on(server_id, name, false).await
    }

    /// Deletes a server from this computer without asking it anything:
    /// every room on it with its keys and messages, the joins waiting
    /// there, the links made there, and its pinned certificate and account
    /// key. The server is not told, so the others in those rooms still see
    /// this person as a member. Returns how many rooms went.
    pub fn forget_server(&mut self, server_id: i64) -> Result<usize, CoreError> {
        let name = self.server_name(server_id);
        if !self.store.servers()?.iter().any(|s| s.id == server_id) {
            return Err(CoreError::Other(
                "this profile does not know that server".into(),
            ));
        }
        let key_packages: Vec<Vec<u8>> = self
            .store
            .pending_joins()?
            .into_iter()
            .filter(|p| p.server_id == server_id)
            .flat_map(|p| p.key_package_refs)
            .collect();
        let gone = self.store.forget_server(server_id)?;
        self.conns.remove(&server_id);
        self.last_error.remove(&server_id);
        self.connected_at.remove(&server_id);
        let mut rooms = 0;
        for gid in &gone {
            if let Some(mut live) = self.groups.remove(gid) {
                rooms += 1;
                // The store already deleted its rows; this clears anything
                // OpenMLS keeps elsewhere.
                let _ = live.mls.delete(self.prov.storage());
            }
            self.leaves.remove(gid);
            self.repost.remove(gid);
            self.commit_grace.remove(gid);
            self.pushed.remove(gid);
            self.drifted.remove(gid);
            self.outsiders.remove(gid);
            self.overreach.remove(gid);
            self.version_unshared.remove(gid);
            self.dm_offers.retain(|_, (dm, _)| dm != gid);
            self.dm_todo.retain(|t| match t {
                DmTodo::Accept { shared, group, .. } => shared != gid && group != gid,
                DmTodo::Complete { group, .. } => group != gid,
            });
        }
        if let Err(e) = self.delete_key_packages(&key_packages) {
            self.emit(Event::Warning(format!(
                "Forgot {name}, but some keys for joins there are still on this computer: {e}"
            )));
        }
        self.tidy_log(&name);
        Ok(rooms)
    }
}
