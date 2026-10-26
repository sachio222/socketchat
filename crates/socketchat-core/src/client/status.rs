//! What `/status` and `socketchat status` show: the server and the
//! connection to it, this profile, and the open room, read from what this
//! client already holds.

use socketchat_proto::msg::{GroupId, Request, Response};

use super::Client;
use crate::settings::{WhoCanInvite, WhoCanSetTopic};

/// How the connection to a server stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Link {
    /// Connected since `since_unix`, on this client's clock, speaking
    /// `protocol`.
    Connected { since_unix: u64, protocol: u16 },
    /// The connection dropped and has not been tried again yet; the next
    /// sync reconnects.
    Lost,
    /// The last try failed, for this reason.
    Unreachable(String),
    /// Not tried since this profile opened.
    NotYet,
}

/// One server, as `/status` shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerStatus {
    /// The host, cleaned as [`super::server_text`] cleans it.
    pub host: String,
    pub port: u16,
    /// The SHA-256 fingerprint of the certificate this profile pins.
    pub cert_fpr: [u8; 32],
    pub link: Link,
    /// Rooms this person is in there.
    pub rooms: usize,
    /// The server's own rule on members inviting into rooms: `Some(false)`
    /// when only admins invite, in every room. `None` when it was not
    /// asked: not connected, or a server too old to say.
    pub members_invite: Option<bool>,
}

/// The open room, as `/status` shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomStatus {
    pub is_dm: bool,
    pub members: usize,
    /// Members with the verified mark, this person included, as the People
    /// title counts them.
    pub verified: usize,
    pub admins: usize,
    /// Whether this person is one of the admins.
    pub admin: bool,
    pub invite: WhoCanInvite,
    /// Seconds each member who is not an admin waits between posts; 0 is
    /// off.
    pub slow_secs: u32,
    pub topic_who: WhoCanSetTopic,
    /// Whether the room has a topic.
    pub topic: bool,
    /// The room's MLS suite, by name and number.
    pub suite: String,
    /// Whether that suite has post-quantum key exchange (see
    /// [`crate::suite::post_quantum`]).
    pub post_quantum: bool,
}

/// Everything `/status` shows that this client knows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusView {
    /// The name others see for this person.
    pub name: String,
    /// The digits this person's identity key adds to each safety number
    /// (see [`crate::keys::safety_digits`]).
    pub safety_digits: String,
    /// The open room's server, or with no room open the one new rooms go
    /// on; `None` before this profile knows any server.
    pub server: Option<ServerStatus>,
    /// How many other servers this profile knows.
    pub other_servers: usize,
    /// The open room, while this person is in it.
    pub room: Option<RoomStatus>,
}

/// A suite as people can look it up: its name and its number, such as
/// "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001)".
pub fn suite_text(suite: openmls::prelude::Ciphersuite) -> String {
    format!("{suite} (0x{:04X})", u16::from(suite))
}

impl Client {
    /// What `/status` shows with `open` on screen. Nothing here connects:
    /// a server is asked for its rule on inviting only over a connection
    /// that is up already.
    pub async fn status(&mut self, open: Option<GroupId>) -> StatusView {
        let open = open.filter(|g| self.groups.contains_key(g));
        let servers = self.store.servers().unwrap_or_default();
        let shown = open
            .map(|g| self.groups[&g].row.server_id)
            .or_else(|| self.new_room_server(None))
            .or_else(|| servers.first().map(|s| s.id));
        let mut server = None;
        if let Some(row) = servers.iter().find(|s| Some(s.id) == shown) {
            let link = match self.conns.get(&row.id) {
                Some(c) if c.is_alive() => Link::Connected {
                    since_unix: self.connected_at.get(&row.id).copied().unwrap_or(0),
                    protocol: c.protocol(),
                },
                Some(_) => Link::Lost,
                None => match self.last_error.get(&row.id) {
                    Some(why) => Link::Unreachable(why.clone()),
                    None => Link::NotYet,
                },
            };
            let members_invite = match link {
                Link::Connected { protocol, .. } if protocol >= 3 => {
                    match self.request(row.id, Request::ServerRules).await {
                        Ok(Response::ServerRules {
                            members_can_invite_to_rooms,
                        }) => Some(members_can_invite_to_rooms),
                        _ => None,
                    }
                }
                _ => None,
            };
            server = Some(ServerStatus {
                host: crate::sanitize::clean_host(&row.host),
                port: row.port,
                cert_fpr: row.cert_fpr,
                link,
                rooms: self
                    .groups
                    .values()
                    .filter(|g| g.row.server_id == row.id)
                    .count(),
                members_invite,
            });
        }
        let room = open.map(|g| {
            let members = self.members(g);
            let settings = self.room_settings(g).unwrap_or_default();
            let suite = self.room_suite(g);
            RoomStatus {
                is_dm: self.groups[&g].row.is_dm,
                members: members.len(),
                verified: members.iter().filter(|m| m.verified).count(),
                admins: members.iter().filter(|m| m.admin).count(),
                admin: members.iter().any(|m| m.me && m.admin),
                invite: settings.invite,
                slow_secs: settings.slow_secs,
                topic_who: settings.topic,
                topic: self.topic(g).is_some(),
                suite: suite.map(suite_text).unwrap_or_default(),
                post_quantum: suite.is_some_and(crate::suite::post_quantum),
            }
        });
        StatusView {
            name: self.profile.display_name.clone(),
            safety_digits: crate::keys::safety_digits(&self.profile.identity.public()),
            other_servers: servers.len().saturating_sub(usize::from(server.is_some())),
            server,
            room,
        }
    }
}
