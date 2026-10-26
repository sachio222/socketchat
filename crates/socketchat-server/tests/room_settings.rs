//! Each room's own settings, as the server reads and enforces them from
//! signed group changes: who can bring people in, and slow mode.

mod common;

use common::*;
use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;
use socketchat_core::settings::{RoomSettings, WhoCanInvite};
use socketchat_core::suite::{
    admins_extension, admins_from, capabilities_0_5_1, group_context_extensions, ADMINS_EXT,
    ROOM_SETTINGS_EXT, SUITE,
};
use socketchat_proto::msg::{Request, Response};
use socketchat_server::{init, make_server_invite, Config, Server, ServerHandle};

struct Env {
    d: tempfile::TempDir,
    h: ServerHandle,
}

async fn env_with(f: impl FnOnce(&mut Config)) -> Env {
    let d = tempfile::tempdir().unwrap();
    init(d.path(), "localhost").unwrap();
    let mut cfg = Config::load(d.path()).unwrap();
    cfg.listen = "127.0.0.1:0".parse().unwrap();
    f(&mut cfg);
    let h = Server::start(cfg).await.unwrap();
    Env { d, h }
}

async fn env() -> Env {
    env_with(|_| {}).await
}

/// A server whose config file holds `lines`, as an operator wrote it.
async fn env_from_file(lines: &str) -> Env {
    let d = tempfile::tempdir().unwrap();
    init(d.path(), "localhost").unwrap();
    let path = d.path().join(socketchat_server::config::CONFIG_FILE);
    let mut text = std::fs::read_to_string(&path).unwrap();
    for key in ["members_make_accounts", "members_can_invite_to_rooms"] {
        text = text
            .lines()
            .filter(|l| !l.starts_with(key))
            .collect::<Vec<_>>()
            .join("\n");
    }
    std::fs::write(&path, format!("{lines}\n{text}\n")).unwrap();
    let mut cfg = Config::load(d.path()).unwrap();
    cfg.listen = "127.0.0.1:0".parse().unwrap();
    let h = Server::start(cfg).await.unwrap();
    Env { d, h }
}

/// What the server says about members inviting into its rooms.
async fn server_rules(p: &mut Person) -> Response {
    p.conn.req(Request::ServerRules).await
}

/// Under the server's rule, a member's room link and add are refused in
/// every room, whatever the room's setting; an admin's still work.
async fn members_kept_out_by_the_server(e: &Env) {
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    assert_eq!(
        server_rules(&mut b).await,
        Response::ServerRules {
            members_can_invite_to_rooms: false
        }
    );
    assert!(posted(
        &set(&mut a, RoomSettings::new(WhoCanInvite::Anyone, 10)).await
    ));
    b.catch_up().await;
    let r = b.conn.req(Request::CreateInvite { group: b.gid }).await;
    assert!(
        matches!(r, Response::Refused(ref s) if s.contains("on this server only admins")),
        "{r:?}"
    );
    let mut c = e.person().await;
    let t = a.invite().await;
    assert_eq!(c.redeem_mailbox(t).await, Response::Ok);
    let r = b.add(c.key_package(), t).await;
    assert!(
        matches!(r, Response::Refused(ref s) if s.contains("on this server only admins")),
        "{r:?}"
    );
    assert!(posted(&a.add(c.key_package(), t).await));
}

/// An operator who set `members_can_invite = false` before 0.5.2 keeps
/// members from bringing people into rooms after the upgrade.
#[tokio::test]
async fn the_old_switch_still_keeps_members_from_inviting_into_rooms() {
    let e = env_from_file("members_can_invite = false").await;
    members_kept_out_by_the_server(&e).await;
}

#[tokio::test]
async fn the_new_key_keeps_members_from_inviting_into_rooms() {
    let e = env_from_file("members_can_invite_to_rooms = false").await;
    members_kept_out_by_the_server(&e).await;
}

/// On the default, each room's own setting decides.
#[tokio::test]
async fn by_default_each_room_decides() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    assert_eq!(
        server_rules(&mut b).await,
        Response::ServerRules {
            members_can_invite_to_rooms: true
        }
    );
    let t = b.invite().await;
    let mut c = e.person().await;
    assert_eq!(c.redeem_mailbox(t).await, Response::Ok);
    assert!(posted(&b.add(c.key_package(), t).await));
}

impl Env {
    async fn person(&self) -> Person {
        Person::new(self.h.addr, self.h.cert_fpr).await
    }
    async fn admin(&self) -> Person {
        let mut a = self.person().await;
        let inv = make_server_invite(self.d.path()).unwrap().token;
        assert_eq!(a.create_group(inv, SUITE).await, Response::Ok);
        a
    }
    /// A member added by `admin`, already joined.
    async fn member(&self, admin: &mut Person) -> Person {
        let mut b = self.person().await;
        let t = admin.invite().await;
        assert_eq!(b.redeem_mailbox(t).await, Response::Ok);
        let r = admin.add(b.key_package(), t).await;
        assert!(matches!(r, Response::Posted { .. }), "{r:?}");
        b.join_from_welcome(admin.gid.unwrap()).await;
        b
    }
}

/// `p` commits these GroupContext extensions and posts the commit. The
/// commit is merged or dropped by what the server says.
async fn commit_context(p: &mut Person, exts: Extensions<GroupContext>) -> Response {
    let g = p.group.as_mut().unwrap();
    let bundle = g
        .commit_builder()
        .propose_group_context_extensions(exts)
        .unwrap()
        .load_psks(p.prov.storage())
        .unwrap()
        .build(p.prov.rand(), p.prov.crypto(), &p.key, |_| true)
        .unwrap()
        .stage_commit(&p.prov)
        .unwrap();
    let (msg, _, _) = bundle.into_messages();
    let r = p.post(ser(&msg), None).await;
    p.settle(&r);
    r
}

/// `p` sets the room's settings, keeping its admins.
async fn set(p: &mut Person, s: RoomSettings) -> Response {
    let admins = admins_from(p.group.as_ref().unwrap().extensions());
    commit_context(p, group_context_extensions(&admins, &s)).await
}

fn admins_only() -> RoomSettings {
    RoomSettings::new(WhoCanInvite::Admins, 0)
}

fn posted(r: &Response) -> bool {
    matches!(r, Response::Posted { .. })
}

#[tokio::test]
async fn any_member_room_lets_a_member_link_and_add() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let mut c = e.person().await;
    let t = b.invite().await;
    assert_eq!(c.redeem_mailbox(t).await, Response::Ok);
    let r = b.add(c.key_package(), t).await;
    assert!(posted(&r), "{r:?}");
}

#[tokio::test]
async fn admins_only_room_refuses_a_members_link_and_add() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let r = set(&mut a, admins_only()).await;
    assert!(posted(&r), "{r:?}");
    b.catch_up().await;
    let r = b.conn.req(Request::CreateInvite { group: b.gid }).await;
    assert!(
        matches!(r, Response::Refused(ref s) if s.contains("only admins")),
        "{r:?}"
    );
    // An admin's link, used by Cy; Bo's add of Cy is refused, Ada's goes.
    let mut c = e.person().await;
    let t = a.invite().await;
    assert_eq!(c.redeem_mailbox(t).await, Response::Ok);
    let r = b.add(c.key_package(), t).await;
    assert!(
        matches!(r, Response::Refused(ref s) if s.contains("only admins")),
        "{r:?}"
    );
    let r = a.add(c.key_package(), t).await;
    assert!(posted(&r), "{r:?}");
}

/// Back to anyone: members link and add again.
#[tokio::test]
async fn turning_admins_only_off_lets_members_invite_again() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    assert!(posted(&set(&mut a, admins_only()).await));
    assert!(posted(&set(&mut a, RoomSettings::default()).await));
    b.catch_up().await;
    let mut c = e.person().await;
    let t = b.invite().await;
    assert_eq!(c.redeem_mailbox(t).await, Response::Ok);
    assert!(posted(&b.add(c.key_package(), t).await));
}

#[tokio::test]
async fn a_member_cannot_change_the_settings() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let r = set(&mut b, admins_only()).await;
    assert!(
        matches!(r, Response::Refused(ref s) if s.contains("admin")),
        "{r:?}"
    );
    // Nor turn off what an admin turned on.
    assert!(posted(
        &set(&mut a, RoomSettings::new(WhoCanInvite::Admins, 30)).await
    ));
    b.catch_up().await;
    let r = set(&mut b, RoomSettings::default()).await;
    assert!(
        matches!(r, Response::Refused(ref s) if s.contains("admin")),
        "{r:?}"
    );
    let r = set(&mut b, RoomSettings::new(WhoCanInvite::Admins, 0)).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
}

/// A settings extension that does not read is refused, from an admin too.
#[tokio::test]
async fn malformed_settings_are_refused() {
    let e = env().await;
    let mut a = e.admin().await;
    let exts = Extensions::from_vec(vec![
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[
                ExtensionType::Unknown(ADMINS_EXT),
                ExtensionType::Unknown(ROOM_SETTINGS_EXT),
            ],
            &[],
            &[CredentialType::Basic],
        )),
        admins_extension(&[a.key.public()]),
        Extension::Unknown(ROOM_SETTINGS_EXT, UnknownExtension(vec![0, 1, 0, 1, 9])),
    ])
    .unwrap();
    let r = commit_context(&mut a, exts).await;
    assert!(
        matches!(r, Response::Refused(ref s) if s.contains("settings")),
        "{r:?}"
    );
}

/// When the last admin leaves, the member who hands the role on cannot
/// change the settings on the way.
#[tokio::test]
async fn handing_over_admin_keeps_the_settings() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let mut c = e.member(&mut a).await;
    assert!(posted(&set(&mut a, admins_only()).await));
    b.catch_up().await;
    c.catch_up().await;
    let leave = a
        .group
        .as_mut()
        .unwrap()
        .leave_group(&a.prov, &a.key)
        .unwrap();
    assert!(posted(&a.post(ser(&leave), None).await));
    b.catch_up().await;
    c.catch_up().await;
    let bk = b.key.public();
    let r = commit_context(
        &mut c,
        group_context_extensions(&[bk], &RoomSettings::default()),
    )
    .await;
    assert!(
        matches!(r, Response::Refused(ref s) if s.contains("settings")),
        "{r:?}"
    );
    let r = commit_context(&mut c, group_context_extensions(&[bk], &admins_only())).await;
    assert!(posted(&r), "{r:?}");
}

/// Links members made before the room went admins-only stop working.
#[tokio::test]
async fn admins_only_cancels_the_links_members_made() {
    let e = env().await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let members_link = b.invite().await;
    let admins_link = a.invite().await;
    assert!(posted(&set(&mut a, admins_only()).await));
    let mut c = e.person().await;
    let r = c.redeem_mailbox(members_link).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
    let mut d = e.person().await;
    assert_eq!(d.redeem_mailbox(admins_link).await, Response::Ok);
}

/// Someone whose app predates room settings hears at once that this room
/// needs a newer one, rather than waiting for an add that cannot happen.
#[tokio::test]
async fn an_old_app_cannot_lodge_a_join_in_a_room_with_settings() {
    let e = env().await;
    let mut a = e.admin().await;
    assert!(posted(&set(&mut a, admins_only()).await));
    let t = a.invite().await;
    let mut c = e.person().await;
    assert_eq!(c.redeem_mailbox(t).await, Response::Ok);
    let old = KeyPackage::builder()
        .leaf_node_capabilities(capabilities_0_5_1())
        .build(SUITE, &c.prov, &c.key, c.key.credential())
        .unwrap();
    let blob = blob_of(&[old.key_package().clone()]);
    let r = c
        .conn
        .req(Request::RedeemInvite {
            token: t,
            key_package: blob,
            mac: [0; 32],
        })
        .await;
    assert!(
        matches!(r, Response::Refused(ref s) if s.contains("0.5.2")),
        "{r:?}"
    );
    let blob = blob_of(&[c.key_package()]);
    let r = c
        .conn
        .req(Request::RedeemInvite {
            token: t,
            key_package: blob,
            mac: [0; 32],
        })
        .await;
    assert_eq!(r, Response::JoinLodged);
}

/// A room on the defaults still takes an old app's join.
#[tokio::test]
async fn an_old_app_can_join_a_room_on_the_defaults() {
    let e = env().await;
    let mut a = e.admin().await;
    let t = a.invite().await;
    let mut c = e.person().await;
    assert_eq!(c.redeem_mailbox(t).await, Response::Ok);
    let old = KeyPackage::builder()
        .leaf_node_capabilities(capabilities_0_5_1())
        .build(SUITE, &c.prov, &c.key, c.key.credential())
        .unwrap();
    let r = c
        .conn
        .req(Request::RedeemInvite {
            token: t,
            key_package: blob_of(&[old.key_package().clone()]),
            mac: [0; 32],
        })
        .await;
    assert_eq!(r, Response::JoinLodged);
}

/// KeyPackages encoded as apps lodge them.
fn blob_of(kps: &[KeyPackage]) -> Vec<u8> {
    let list: Vec<Vec<u8>> = kps
        .iter()
        .map(|k| k.tls_serialize_detached().unwrap())
        .collect();
    let frame = socketchat_proto::msg::to_frame(&list).unwrap();
    frame[4..].to_vec()
}
