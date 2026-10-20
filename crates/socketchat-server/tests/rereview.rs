//! Findings from the re-review of 4077bf8: slow and silent readers, the
//! per-address limit, and the Windows stall on big replies.

mod common;

use std::time::Duration;

use common::*;
use socketchat_core::suite::SUITE;
use socketchat_proto::msg::{to_frame, Busy, ClientFrame, Request, Response, ServerFrame};
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
    async fn admin(&self) -> Person {
        let mut a = Person::new(self.h.addr, self.h.cert_fpr).await;
        let inv = make_server_invite(self.d.path()).unwrap().token;
        assert_eq!(a.create_group(inv, SUITE).await, Response::Ok);
        a
    }
}

/// Posts a group message of `len` bytes of `fill` from `a`.
async fn post_big(a: &mut Person, fill: u8, len: usize) {
    let m = a
        .group
        .as_mut()
        .unwrap()
        .create_message(&a.prov, &a.key, &vec![fill; len])
        .unwrap();
    let r = a.post(ser(&m), None).await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
}

/// A new connection signed in as `a`'s group key.
async fn signed_in_as(e: &Env, a: &Person, c: &mut Raw) {
    c.hello().await;
    let ch = c.challenge().await;
    let r = c
        .req(Request::Prove {
            key: a.key.public(),
            sig: auth_sig(&a.key, &ch),
        })
        .await;
    assert_eq!(r, Response::Ok);
    let _ = e;
}

// ---------- Windows CI stall: the last bytes of a reply ----------

/// The writer handed each frame to TLS and moved on without flushing. When
/// the socket was full, the frame's last TLS records stayed in the TLS
/// buffer until the next frame came, so a reply with nothing after it never
/// arrived whole. Windows loopback buffers are small, so CI saw it there;
/// eight 1 MB replies outrun the largest send buffer macOS and Linux grow.
#[tokio::test]
async fn big_replies_reach_a_slow_reader_whole() {
    let e = env_with(|_| {}).await;
    let mut a = e.admin().await;
    let gid = a.gid.unwrap();
    post_big(&mut a, 1, 1_000_000).await;
    let mut c = Raw::connect_small(e.h.addr, e.h.cert_fpr, 4096).await;
    signed_in_as(&e, &a, &mut c).await;
    let mut req = Vec::new();
    for id in 0..8u32 {
        req.extend(
            to_frame(&ClientFrame::Req {
                id: 100 + id,
                body: Request::Fetch {
                    group: gid,
                    after: 0,
                    limit: 1,
                },
            })
            .unwrap(),
        );
    }
    c.send_raw(&req).await.unwrap();
    for n in 0..8u32 {
        match c.recv_slowly(16 * 1024, Duration::from_millis(1)).await {
            Some(ServerFrame::Resp {
                id,
                body: Response::Entries(es),
            }) => assert_eq!((id, es.len()), (100 + n, 1)),
            other => panic!("reply {n}: {other:?}"),
        }
    }
}

// ---------- R1: a client that stops reading ----------

/// A client that stops reading kept its connection slot after the idle
/// limit, because the task waited forever on a writer stuck writing to a
/// full socket. With max_connections = 1, nobody else got in.
#[tokio::test]
async fn rr_non_reading_client_frees_its_slot_after_idle() {
    let e = env_with(|c| {
        c.max_connections = 1;
        c.timing.idle = Duration::from_millis(500);
    })
    .await;
    let mut c = Raw::connect(e.h.addr, e.h.cert_fpr).await;
    c.hello().await;
    let mut batch = Vec::new();
    for id in 0..10_000u32 {
        batch.extend(
            to_frame(&ClientFrame::Req {
                id,
                body: Request::Challenge,
            })
            .unwrap(),
        );
    }
    // Flood without reading until the server stops taking bytes.
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        for _ in 0..100 {
            if c.send_raw(&batch).await.is_err() {
                break;
            }
        }
    })
    .await;
    // Well past the idle limit and the writer's grace: the slot is free.
    tokio::time::sleep(Duration::from_secs(12)).await;
    let mut other = Raw::connect(e.h.addr, e.h.cert_fpr).await;
    other
        .send(&ClientFrame::Hello {
            version: socketchat_proto::PROTOCOL_VERSION,
        })
        .await;
    let got = other.recv().await;
    drop(c);
    assert!(
        got.is_some(),
        "slot still held by a connection that stopped reading 12 s after the 0.5 s idle limit"
    );
}

/// One address may hold only as many connections as `max_per_ip` in the
/// config file says; the next one hears why and is closed, and a freed slot
/// can be used again.
#[tokio::test]
async fn connections_per_address_are_capped() {
    let d = tempfile::tempdir().unwrap();
    init(d.path(), "localhost").unwrap();
    let file = d.path().join(socketchat_server::config::CONFIG_FILE);
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.contains("max_per_ip = 256"), "{text}");
    std::fs::write(
        &file,
        text.replace("max_per_ip = 256", "max_per_ip = 2")
            .replace("0.0.0.0:7444", "127.0.0.1:0"),
    )
    .unwrap();
    let h = Server::start(Config::load(d.path()).unwrap())
        .await
        .unwrap();
    let e = Env { d, h };
    let mut one = Raw::connect(e.h.addr, e.h.cert_fpr).await;
    one.hello().await;
    let mut two = Raw::connect(e.h.addr, e.h.cert_fpr).await;
    two.hello().await;
    // The third is told why at Hello, then closed.
    let mut third = Raw::connect(e.h.addr, e.h.cert_fpr).await;
    third
        .send(&ClientFrame::Hello {
            version: socketchat_proto::PROTOCOL_VERSION,
        })
        .await;
    assert_eq!(third.recv().await, Some(ServerFrame::Busy(Busy::Network)));
    assert_eq!(third.recv().await, None);
    // Closing one frees its slot.
    drop(two);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut again = Raw::connect(e.h.addr, e.h.cert_fpr).await;
    again.hello().await;
    one.challenge().await;
}

// ---------- R2: replies a member never reads, counted in bytes ----------

/// The queue was bounded in frames, not bytes: a member who never reads
/// parked 64 near-1 MiB fetch replies per connection.
#[tokio::test]
async fn rr_unread_big_replies_bounded_in_bytes() {
    let e = env_with(|_| {}).await;
    let mut a = e.admin().await;
    let gid = a.gid.unwrap();
    for fill in 1u8..=3 {
        post_big(&mut a, fill, 1_000_000).await;
    }
    let mut req = Vec::new();
    for id in 0..200u32 {
        req.extend(
            to_frame(&ClientFrame::Req {
                id: 1000 + id,
                body: Request::Fetch {
                    group: gid,
                    after: 0,
                    limit: 1,
                },
            })
            .unwrap(),
        );
    }
    let mut held = Vec::new();
    for _ in 0..6 {
        let mut c = Raw::connect(e.h.addr, e.h.cert_fpr).await;
        signed_in_as(&e, &a, &mut c).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), c.send_raw(&req)).await;
        held.push(c);
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let bytes = e.h.queued_bytes();
    let frames = e.h.queued_frames();
    eprintln!("queued: {frames} frames, {bytes} bytes");
    assert!(frames > 0, "nothing queued; the test did not fill anything");
    assert!(
        bytes <= 6 * socketchat_server::QUEUE_BYTES,
        "6 members who never read have {bytes} bytes queued ({frames} frames)"
    );
}

// ---------- R9: join requests past the first page; open invite links ----------

/// Seconds since the Unix epoch.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Join requests nobody completes filled the first page, and the requests
/// after them never came back. Paging by (lodged time, token) reaches all.
#[tokio::test]
async fn pending_joins_page_past_requests_nobody_completes() {
    let e = env_with(|_| {}).await;
    let mut a = e.admin().await;
    let gid = a.gid.unwrap();
    let db = rusqlite::Connection::open(e.d.path().join("server.db")).unwrap();
    let now = unix_now();
    // 150 requests of 8 KB, three to a second, tokens in no time order:
    // more than one reply holds.
    let mut all = Vec::new();
    for i in 0..150u32 {
        let mut token = [0u8; 16];
        token[..4].copy_from_slice(&(i.wrapping_mul(2_654_435_761)).to_be_bytes());
        let at = now - 1000 + (i / 3) as i64;
        db.execute(
            "INSERT INTO joins (token, group_id, mailbox, key_package, mac, lodged_unix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                token.as_slice(),
                gid.0.as_slice(),
                [i as u8; 32].as_slice(),
                vec![7u8; 8 * 1024],
                [0u8; 32].as_slice(),
                at
            ],
        )
        .unwrap();
        all.push((at as u64, token));
    }
    all.sort();
    let mut seen = Vec::new();
    let mut pages = 0;
    let mut after = None;
    for _ in 0..10 {
        let r = a
            .conn
            .req(Request::PendingJoins { group: gid, after })
            .await;
        let Response::Joins(js) = r else {
            panic!("{r:?}")
        };
        let Some(last) = js.last() else {
            break;
        };
        after = Some((last.lodged_unix, last.token));
        pages += 1;
        seen.extend(js.iter().map(|j| (j.lodged_unix, j.token.0)));
    }
    assert!(pages >= 2, "{pages} pages");
    let missed = all.iter().filter(|x| !seen.contains(x)).count();
    assert!(
        missed == 0 && seen.len() == all.len(),
        "{missed} of {} requests never came back; {} came back in all",
        all.len(),
        seen.len()
    );
    assert_eq!(seen, all, "out of order");
}

/// One member may hold only so many unused, unexpired invite links in a
/// group. A used or expired link frees its place.
#[tokio::test]
async fn open_group_invites_are_capped_per_member() {
    let e = env_with(|_| {}).await;
    let mut a = e.admin().await;
    let mut links = Vec::new();
    for _ in 0..20 {
        links.push(a.invite().await);
    }
    let full = "you have 20 open invite links in this group; wait for some to be used or expire";
    let r = a.conn.req(Request::CreateInvite { group: a.gid }).await;
    assert_eq!(r, Response::Refused(full.into()));
    // Someone uses one: that frees a place, and only one.
    let mut j = Person::new(e.h.addr, e.h.cert_fpr).await;
    assert_eq!(j.redeem_mailbox(links[0]).await, Response::Ok);
    a.invite().await;
    let r = a.conn.req(Request::CreateInvite { group: a.gid }).await;
    assert_eq!(r, Response::Refused(full.into()));
    // Once they expire, all the places are free again.
    e.h.advance_clock(e.h.config().invite_ttl_hours as u64 * 3600 + 60);
    for _ in 0..20 {
        a.invite().await;
    }
}
