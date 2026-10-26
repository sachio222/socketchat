//! Storage limits per member, per room and for the whole server, and how
//! fetched, expired and abandoned data frees room under them.

mod common;

use common::*;
use socketchat_core::suite::SUITE;
use socketchat_proto::msg::{FileId, Request, Response};
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
    // These tests post faster than any person would; the pace limit has
    // its own tests in rate_limit.rs.
    cfg.rate_burst_messages = 0;
    f(&mut cfg);
    let h = Server::start(cfg).await.unwrap();
    Env { d, h }
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
    async fn member(&self, admin: &mut Person) -> Person {
        let mut b = self.person().await;
        let t = admin.invite().await;
        assert_eq!(b.redeem_mailbox(t).await, Response::Ok);
        let r = admin.add(b.key_package(), t).await;
        assert!(matches!(r, Response::Posted { .. }), "{r:?}");
        b.join_from_welcome(admin.gid.unwrap()).await;
        b
    }
    /// Uploads begun and not finished, over the whole server.
    fn open_uploads(&self) -> i64 {
        let db = rusqlite::Connection::open(self.d.path().join("server.db")).unwrap();
        db.query_row("SELECT COUNT(*) FROM files WHERE complete = 0", [], |r| {
            r.get(0)
        })
        .unwrap()
    }
    /// Bytes of messages the server counts for `p`'s room.
    fn room_bytes(&self, p: &Person) -> u64 {
        let db = rusqlite::Connection::open(self.d.path().join("server.db")).unwrap();
        db.query_row(
            "SELECT log_bytes FROM groups WHERE id = ?1",
            [p.gid.unwrap().0.as_slice()],
            |r| r.get::<_, i64>(0),
        )
        .unwrap() as u64
    }
}

const MB: u64 = 1_000_000;
const DAY: u64 = 24 * 3600;
const CHUNK: usize = 64 * 1024;
/// What the server counts for each log entry besides its MLS bytes.
const ROW: u64 = 64;

async fn begin(p: &mut Person, size: u64) -> Response {
    let group = p.gid.unwrap();
    p.conn.req(Request::FileBegin { group, size }).await
}

/// Uploads a whole file of `size` bytes.
async fn upload(p: &mut Person, size: u64) -> Response {
    let file: FileId = match begin(p, size).await {
        Response::File(id) => id,
        r => return r,
    };
    let chunks = (size as usize).div_ceil(CHUNK).max(1);
    for index in 0..chunks {
        let len = (size as usize - index * CHUNK).min(CHUNK) + 16;
        let r = p
            .conn
            .req(Request::FileChunk {
                file,
                index: index as u32,
                data: vec![7; len],
            })
            .await;
        if r != Response::Ok {
            return r;
        }
    }
    p.conn.req(Request::FileEnd { file }).await
}

/// A chat message with `size` bytes of text from `p`.
fn message(p: &mut Person, size: usize) -> Vec<u8> {
    let (prov, key) = (&p.prov, &p.key);
    let m = p
        .group
        .as_mut()
        .unwrap()
        .create_message(prov, key, &vec![1u8; size])
        .unwrap();
    ser(&m)
}

/// `p`'s request to leave, with `aad` bytes of extra data.
fn leave(p: &mut Person, aad: usize) -> Vec<u8> {
    let (prov, key) = (&p.prov, &p.key);
    let g = p.group.as_mut().unwrap();
    g.set_aad(vec![0; aad]);
    let m = g.leave_group(prov, key).unwrap();
    g.set_aad(vec![]);
    ser(&m)
}

/// Fetches until nothing new comes; one reply carries at most 900 KB.
async fn catch_up_all(p: &mut Person) {
    loop {
        let before = p.last_seq;
        p.catch_up().await;
        if p.last_seq == before {
            return;
        }
    }
}

/// Posts chat messages from `p` until the room's messages sit within 100
/// bytes of `limit`: too close for anything but a leave request.
async fn fill_room(e: &Env, p: &mut Person, limit: u64) {
    loop {
        let left = limit - e.room_bytes(p);
        // The bytes a chat message adds besides its text, measured.
        let overhead = message(p, 1000).len() as u64 - 1000 + ROW;
        if left < 100 + overhead {
            return;
        }
        let text = (left - 100 - overhead).min(200_000);
        let m = message(p, text as usize);
        let r = p.post(m, None).await;
        assert!(matches!(r, Response::Posted { .. }), "{r:?}");
    }
}

fn refused_saying(r: &Response, words: &str) -> bool {
    matches!(r, Response::Refused(why) if why.contains(words))
}

/// One member cannot keep uploading files without end: the server refuses
/// the next file once that member's files reach the limit.
#[tokio::test]
async fn member_cannot_store_unbounded_files() {
    let e = env_with(|c| {
        c.max_file_mb = 1;
        c.max_member_files_mb = 5;
    })
    .await;
    let mut a = e.admin().await;
    let mut stored = 0;
    let mut last = Response::Ok;
    for _ in 0..20 {
        last = upload(&mut a, MB).await;
        if last != Response::Ok {
            break;
        }
        stored += 1;
    }
    assert_eq!(stored, 5, "one member stored {stored} MB ({last:?})");
    assert!(refused_saying(&last, "5 MB"), "{last:?}");
}

/// Members who each stay under their own limit still cannot take a room
/// past its limit.
#[tokio::test]
async fn room_files_are_capped_across_members() {
    let e = env_with(|c| {
        c.max_file_mb = 1;
        c.max_member_files_mb = 3;
        c.max_room_files_mb = 5;
    })
    .await;
    let mut a = e.admin().await;
    let mut b = e.member(&mut a).await;
    for _ in 0..3 {
        assert_eq!(upload(&mut a, MB).await, Response::Ok);
    }
    for _ in 0..2 {
        assert_eq!(upload(&mut b, MB).await, Response::Ok);
    }
    let r = begin(&mut b, MB).await;
    assert!(refused_saying(&r, "this room"), "{r:?}");
}

/// Unfinished uploads a member's app left behind never stop them sending:
/// starting a fourth drops the oldest, so at most three stay open.
#[tokio::test]
async fn a_fourth_upload_drops_the_oldest_unfinished_one() {
    let e = env_with(|c| c.max_file_mb = 1).await;
    let mut a = e.admin().await;
    let mut abandoned = vec![];
    for _ in 0..3 {
        match begin(&mut a, MB).await {
            Response::File(id) => abandoned.push(id),
            r => panic!("{r:?}"),
        }
    }
    assert_eq!(upload(&mut a, MB).await, Response::Ok);
    let r = a
        .conn
        .req(Request::FileChunk {
            file: abandoned[0],
            index: 0,
            data: vec![7; 16],
        })
        .await;
    assert!(refused_saying(&r, "no such upload"), "{r:?}");
    assert_eq!(e.open_uploads(), 2);
    for _ in 0..3 {
        assert!(matches!(begin(&mut a, MB).await, Response::File(_)));
        assert!(e.open_uploads() <= 3);
    }
}

/// Unfinished uploads go six hours after they began.
#[tokio::test]
async fn unfinished_uploads_go_after_six_hours() {
    let e = env_with(|c| c.max_file_mb = 1).await;
    let mut a = e.admin().await;
    for _ in 0..3 {
        assert!(matches!(begin(&mut a, MB).await, Response::File(_)));
    }
    assert_eq!(e.open_uploads(), 3);
    e.h.advance_clock(7 * 3600);
    e.h.sweep_now();
    assert_eq!(e.open_uploads(), 0);
}

/// Uploads that are announced but never sent take no room from anyone.
#[tokio::test]
async fn announced_uploads_do_not_fill_the_server() {
    let e = env_with(|c| {
        c.max_file_mb = 1;
        c.max_stored_mb = 10;
    })
    .await;
    let mut a = e.admin().await;
    let mut c = e.admin().await;
    for p in [&mut a, &mut c] {
        for _ in 0..3 {
            assert!(matches!(begin(p, MB).await, Response::File(_)));
        }
    }
    let mut b = e.admin().await;
    for i in 0..5 {
        assert_eq!(upload(&mut b, MB).await, Response::Ok, "file {i}");
    }
    let m = message(&mut b, 100_000);
    assert!(matches!(b.post(m, None).await, Response::Posted { .. }));
}

/// Files may fill only nine tenths of the server's limit, so chat goes on
/// when files are at theirs.
#[tokio::test]
async fn chat_posts_when_files_are_at_their_cap() {
    let e = env_with(|c| {
        c.max_file_mb = 1;
        c.max_stored_mb = 2;
    })
    .await;
    let mut a = e.admin().await;
    assert_eq!(upload(&mut a, MB).await, Response::Ok);
    assert_eq!(upload(&mut a, 800_000).await, Response::Ok);
    let r = begin(&mut a, 200_000).await;
    assert!(refused_saying(&r, "this server"), "{r:?}");
    let m = message(&mut a, 100_000);
    let r = a.post(m, None).await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
}

/// The whole server has a limit too, over every room.
#[tokio::test]
async fn server_total_is_capped_across_rooms() {
    let e = env_with(|c| {
        c.max_file_mb = 1;
        c.max_stored_mb = 3;
    })
    .await;
    let mut a = e.admin().await;
    let mut c = e.admin().await;
    for _ in 0..2 {
        assert_eq!(upload(&mut a, MB).await, Response::Ok);
    }
    assert_eq!(upload(&mut c, 600_000).await, Response::Ok);
    let r = begin(&mut c, MB).await;
    assert!(refused_saying(&r, "this server"), "{r:?}");
    // A small message still goes while there is room for it.
    let m = message(&mut c, 100);
    assert!(matches!(c.post(m, None).await, Response::Posted { .. }));
}

/// Removing a member who stays away frees the files only they were
/// waiting for, at once.
#[tokio::test]
async fn removing_an_away_member_frees_their_files() {
    let e = env_with(|c| {
        c.max_file_mb = 1;
        c.max_room_files_mb = 1;
    })
    .await;
    let mut a = e.admin().await;
    let b = e.member(&mut a).await;
    assert_eq!(upload(&mut a, MB).await, Response::Ok);
    let r = begin(&mut a, MB).await;
    assert!(refused_saying(&r, "this room"), "{r:?}");

    let idx = a
        .g()
        .members()
        .find(|m| m.signature_key == b.key.public().0)
        .unwrap()
        .index;
    let (prov, key) = (&a.prov, &a.key);
    let (c, _, _) = a
        .group
        .as_mut()
        .unwrap()
        .remove_members(prov, key, &[idx])
        .unwrap();
    let r = a.post(ser(&c), None).await;
    a.settle(&r);
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
    assert!(matches!(begin(&mut a, MB).await, Response::File(_)));
}

/// A full room takes only what lets it shrink, at the size apps send it:
/// each member's first request to leave and a removal with no extra data,
/// and never more than a tenth past its limit. Padded copies of either are
/// refused. Once everyone left has fetched, chat goes again.
#[tokio::test]
async fn a_full_room_takes_only_small_leaves_and_removals() {
    let e = env_with(|c| c.max_room_messages_mb = 1).await;
    let mut a = e.admin().await;
    let mut others = vec![];
    for _ in 0..3 {
        others.push(e.member(&mut a).await);
    }
    fill_room(&e, &mut a, MB).await;
    let m = message(&mut a, 100);
    assert!(refused_saying(&a.post(m, None).await, "1 MB"));

    for b in others.iter_mut() {
        catch_up_all(b).await;
    }
    // Padded to carry data: refused, on its own and as a second try.
    let padded = leave(&mut others[0], 300_000);
    let r = others[0].post(padded, None).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
    let padded = leave(&mut others[0], 2_000);
    let r = others[0].post(padded, None).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");
    // The size apps send: taken once per member.
    for b in others.iter_mut() {
        let l = leave(b, 0);
        let r = b.post(l, None).await;
        assert!(matches!(r, Response::Posted { .. }), "{r:?}");
    }
    let again = leave(&mut others[0], 0);
    let r = others[0].post(again, None).await;
    assert!(matches!(r, Response::Refused(_)), "{r:?}");

    // A removal padded with extra data is refused; the plain one goes.
    catch_up_all(&mut a).await;
    for (aad, want) in [(300_000, false), (0, true)] {
        a.g().set_aad(vec![0; aad]);
        let (prov, key) = (&a.prov, &a.key);
        let (c, _, _) = a
            .group
            .as_mut()
            .unwrap()
            .commit_to_pending_proposals(prov, key)
            .unwrap();
        let r = a.post(ser(&c), None).await;
        a.settle(&r);
        assert_eq!(matches!(r, Response::Posted { .. }), want, "{r:?}");
        if want {
            let Response::Posted { seq } = r else {
                unreachable!()
            };
            assert!(e.room_bytes(&a) <= MB + MB / 10);
            let gid = a.gid.unwrap();
            assert_eq!(
                a.conn.req(Request::Ack { group: gid, seq }).await,
                Response::Ok
            );
        }
    }
    a.g().set_aad(vec![]);
    let m = message(&mut a, 200_000);
    assert!(matches!(a.post(m, None).await, Response::Posted { .. }));
}

/// Messages that outlive the retention time free their room's space.
#[tokio::test]
async fn expired_messages_free_space() {
    let e = env_with(|c| c.max_room_messages_mb = 1).await;
    let mut a = e.admin().await;
    let _b = e.member(&mut a).await;
    let mut full = false;
    for _ in 0..20 {
        let m = message(&mut a, 200_000);
        match a.post(m, None).await {
            Response::Posted { .. } => continue,
            r => {
                assert!(matches!(r, Response::Refused(_)), "{r:?}");
                full = true;
                break;
            }
        }
    }
    assert!(full, "the room never filled");
    e.h.advance_clock(31 * DAY);
    e.h.sweep_now();
    let m = message(&mut a, 200_000);
    assert!(matches!(a.post(m, None).await, Response::Posted { .. }));
}

/// A room may have only so many joins waiting. The next joiner hears it
/// when they redeem the link, which stays unused; once someone opens their
/// invitation, the link works.
#[tokio::test]
async fn joins_past_the_waiting_limit_are_turned_away_at_the_link() {
    let e = env_with(|c| c.max_room_welcomes = 2).await;
    let mut a = e.admin().await;
    let mut waiting = vec![];
    for _ in 0..2 {
        let mut p = e.person().await;
        let t = a.invite().await;
        assert_eq!(p.redeem_mailbox(t).await, Response::Ok);
        let r = a.add(p.key_package(), t).await;
        assert!(matches!(r, Response::Posted { .. }), "{r:?}");
        waiting.push(p);
    }
    let mut d = e.person().await;
    let t = a.invite().await;
    let r = d.redeem_mailbox(t).await;
    assert!(refused_saying(&r, "2 people"), "{r:?}");

    let gid = a.gid.unwrap();
    waiting[0].join_from_welcome(gid).await;
    assert_eq!(d.redeem_mailbox(t).await, Response::Ok);
    let r = a.add(d.key_package(), t).await;
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
}

/// Links redeemed but not yet acted on count as waiting joins too.
#[tokio::test]
async fn redeemed_links_count_as_waiting_joins() {
    let e = env_with(|c| c.max_room_welcomes = 2).await;
    let mut a = e.admin().await;
    for _ in 0..2 {
        let mut p = e.person().await;
        let t = a.invite().await;
        assert_eq!(p.redeem_mailbox(t).await, Response::Ok);
    }
    let mut d = e.person().await;
    let t = a.invite().await;
    let r = d.redeem_mailbox(t).await;
    assert!(refused_saying(&r, "2 people"), "{r:?}");
}

/// A room whose messages are full turns a joiner away at the link, where
/// their app shows it, instead of at the add, which apps do not show.
#[tokio::test]
async fn a_full_room_turns_joiners_away_at_the_link() {
    let e = env_with(|c| c.max_room_messages_mb = 1).await;
    let mut a = e.admin().await;
    let _b = e.member(&mut a).await;
    fill_room(&e, &mut a, MB).await;
    let mut d = e.person().await;
    let t = a.invite().await;
    let r = d.redeem_mailbox(t).await;
    assert!(refused_saying(&r, "1 MB"), "{r:?}");
}

/// Expired messages and files also leave the server's own total.
#[tokio::test]
async fn stored_total_frees_with_retention() {
    let e = env_with(|c| {
        c.max_file_mb = 1;
        c.max_stored_mb = 3;
    })
    .await;
    let mut a = e.admin().await;
    for _ in 0..2 {
        assert_eq!(upload(&mut a, MB).await, Response::Ok);
    }
    assert!(matches!(begin(&mut a, MB).await, Response::Refused(_)));
    e.h.advance_clock(31 * DAY);
    e.h.sweep_now();
    assert!(matches!(begin(&mut a, MB).await, Response::File(_)));
}

/// Removes `who` from `a`'s room with no extra data and returns the answer.
async fn remove(a: &mut Person, who: &socketchat_core::keys::KeyPair, aad: usize) -> Response {
    let idx = a
        .g()
        .members()
        .find(|m| m.signature_key == who.public().0)
        .unwrap()
        .index;
    a.g().set_aad(vec![0; aad]);
    let (prov, key) = (&a.prov, &a.key);
    let (c, _, _) = a
        .group
        .as_mut()
        .unwrap()
        .remove_members(prov, key, &[idx])
        .unwrap();
    let r = a.post(ser(&c), None).await;
    a.settle(&r);
    a.g().set_aad(vec![]);
    r
}

/// Changes that only shrink a full room stop at a tenth past its limit.
/// Removals from a room whose members never refreshed their keys are the
/// largest honest ones, about 25 KB each here, so a few fit and then the
/// server refuses.
#[tokio::test]
async fn shrinking_changes_stop_a_tenth_past_the_limit() {
    let e = env_with(|c| c.max_room_messages_mb = 1).await;
    let mut a = e.admin().await;
    let mut others = vec![];
    for _ in 0..20 {
        let mut p = e.person().await;
        let t = a.invite().await;
        assert_eq!(p.redeem_mailbox(t).await, Response::Ok);
        let r = a.add(p.key_package(), t).await;
        assert!(matches!(r, Response::Posted { .. }), "{r:?}");
        others.push(p);
    }
    fill_room(&e, &mut a, MB).await;
    let mut taken = 0;
    let mut last = Response::Ok;
    for p in &others {
        last = remove(&mut a, &p.key, 0).await;
        if !matches!(last, Response::Posted { .. }) {
            break;
        }
        taken += 1;
        assert!(e.room_bytes(&a) <= MB + MB / 10, "{}", e.room_bytes(&a));
    }
    eprintln!(
        "{taken} removals taken past the limit; room at {} bytes; then {last:?}",
        e.room_bytes(&a)
    );
    assert!(taken >= 2, "{taken}");
    assert!(refused_saying(&last, "1 MB"), "{last:?}");
    assert!(e.room_bytes(&a) > MB);
    assert!(e.room_bytes(&a) <= MB + MB / 10);
}

/// A change too large for even a full room's spare tenth is refused before
/// the server checks it: with the check made to take 3 seconds, the answer
/// comes in under half that, which leaves room for a slow test machine.
/// The pause starts only after the room is set up, so no setup step waits
/// on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_past_the_ceiling_is_refused_before_its_check() {
    let delay = socketchat_server::config::CheckDelay::default();
    let e = env_with(|c| {
        c.max_room_messages_mb = 1;
        c.commit_check_delay = delay.clone();
    })
    .await;
    let mut a = e.admin().await;
    let b = e.member(&mut a).await;
    let c = e.member(&mut a).await;
    fill_room(&e, &mut a, MB).await;
    delay.set(std::time::Duration::from_secs(3));
    let t = std::time::Instant::now();
    let r = remove(&mut a, &b.key, 0).await;
    let plain = t.elapsed();
    assert!(matches!(r, Response::Posted { .. }), "{r:?}");
    assert!(plain >= std::time::Duration::from_secs(3), "{plain:?}");
    // A second removal padded past the spare tenth never reaches the check.
    let t = std::time::Instant::now();
    let r = remove(&mut a, &c.key, 200_000).await;
    let padded = t.elapsed();
    assert!(refused_saying(&r, "1 MB"), "{r:?}");
    assert!(
        padded < std::time::Duration::from_millis(1500),
        "the refusal took {padded:?}"
    );
}
