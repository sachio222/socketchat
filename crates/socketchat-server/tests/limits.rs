//! How many new accounts one account can bring onto a server through the
//! room links it makes.

mod common;

use common::*;
use socketchat_core::keys::KeyPair;
use socketchat_core::suite::SUITE;
use socketchat_proto::msg::{Request, Response};
use socketchat_proto::Token;
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

impl Env {
    async fn person(&self) -> Person {
        Person::new(self.h.addr, self.h.cert_fpr).await
    }
    /// Someone with a server account and a room they made.
    async fn admin(&self) -> Person {
        let mut a = self.person().await;
        let inv = make_server_invite(self.d.path()).unwrap().token;
        assert_eq!(a.create_group(inv, SUITE).await, Response::Ok);
        a
    }
    /// A member added by `admin` who has no account on this server.
    async fn member(&self, admin: &mut Person) -> Person {
        let mut b = self.person().await;
        let t = admin.invite().await;
        assert_eq!(b.redeem_mailbox(t).await, Response::Ok);
        let r = admin.add(b.key_package(), t).await;
        assert!(matches!(r, Response::Posted { .. }), "{r:?}");
        b.join_from_welcome(admin.gid.unwrap()).await;
        b
    }
    /// Registers a new account with `token` on a fresh connection.
    async fn account_from(&self, token: Token) -> Response {
        let mut x = Raw::connect(self.h.addr, self.h.cert_fpr).await;
        x.hello().await;
        let k = KeyPair::generate();
        let ch = x.challenge().await;
        x.req(Request::RegisterAccount {
            token,
            key: k.public(),
            sig: auth_sig(&k, &ch),
        })
        .await
    }
}

const DAY: u64 = 24 * 3600;

/// One account's room links register at most the configured number of new
/// accounts in a window; links past that still bring people into the room.
#[tokio::test]
async fn room_links_register_a_limited_number_of_accounts() {
    let e = env_with(|c| c.max_accounts_from_room_links = 5).await;
    let mut a = e.admin().await;
    let mut minted = 0;
    let mut spare = vec![];
    for _ in 0..20 {
        let t = a.invite().await;
        match e.account_from(t).await {
            Response::Ok => minted += 1,
            Response::Refused(_) => spare.push(t),
            r => panic!("{r:?}"),
        }
    }
    assert_eq!(minted, 5, "one account's room links made {minted} accounts");

    // A link past the limit still lets someone into the room.
    let mut b = e.person().await;
    assert_eq!(b.redeem_mailbox(spare[0]).await, Response::Ok);
    let r = a.add(b.key_package(), spare[0]).await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
    b.join_from_welcome(a.gid.unwrap()).await;

    // In the next window the account's links make accounts again.
    e.h.advance_clock(2 * DAY);
    let t = a.invite().await;
    assert_eq!(e.account_from(t).await, Response::Ok);
}

/// With the default settings an admin brings 20 people who are new to the
/// server into a room on one day and 20 more the next, and every one of
/// them gets an account.
#[tokio::test]
async fn an_admin_brings_twenty_new_people_a_day_with_the_defaults() {
    let e = env_with(|_| {}).await;
    let mut a = e.admin().await;
    for day in 0..2 {
        for i in 0..20 {
            let t = a.invite().await;
            assert_eq!(
                e.account_from(t).await,
                Response::Ok,
                "day {day}, person {i}"
            );
        }
        // The day's links expire, which frees room for 20 more open links.
        e.h.advance_clock(DAY + 3600);
    }
}

/// A room link made on a connection that holds no account registers no
/// account, so the limit cannot be stepped around; the link still lets
/// someone into the room.
#[tokio::test]
async fn links_made_without_an_account_register_none() {
    let e = env_with(|_| {}).await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    let t = b.invite().await;
    let r = e.account_from(t).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");

    let mut c = e.person().await;
    assert_eq!(c.redeem_mailbox(t).await, Response::Ok);
    let r = b.add(c.key_package(), t).await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
    c.join_from_welcome(b.gid.unwrap()).await;
}

/// Room links are counted apart from server invite links: making room
/// links leaves the account its 5 server invites.
#[tokio::test]
async fn room_links_leave_server_invites_alone() {
    let e = env_with(|c| c.max_accounts_from_room_links = 2).await;
    let mut a = e.admin().await;
    for _ in 0..3 {
        a.invite().await;
    }
    for i in 0..5 {
        let r = a.conn.req(Request::CreateInvite { group: None }).await;
        assert!(matches!(r, Response::Invite { .. }), "invite {i}: {r:?}");
    }
}
