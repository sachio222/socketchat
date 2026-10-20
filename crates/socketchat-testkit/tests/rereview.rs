//! Re-review reproductions (4077bf8). Each test states the correct
//! behavior; a failure confirms the finding.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use socketchat_core::client::{Client, Event};
use socketchat_proto::msg::GroupId;
use socketchat_testkit::{drain, passphrase, settle, TestClient, TestServer};

// ---------- names owed after an add ----------

/// Ada lets Bo in, but sharing her name and the group's name fails right
/// after the server took the add. She still owes them to Bo, and a later
/// sync sends them.
#[tokio::test]
async fn names_owed_after_a_join_request_add_go_out_later() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Crew").await.unwrap();
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    a.test_fail_next_after_add(g);
    settle(&mut [&mut a, &mut b]).await;
    let name = b.groups().into_iter().find(|x| x.id == g).map(|x| x.name);
    assert_eq!(
        name.as_deref(),
        Some("Crew"),
        "Bo never learns the group's name"
    );
    assert!(
        b.members(g).iter().any(|m| m.name == "Ada"),
        "Bo never learns Ada's name: {:?}",
        b.members(g)
    );
}

/// The same for a direct message: the add went through, sharing Ada's name
/// failed once, and Bo still gets it.
#[tokio::test]
async fn names_owed_after_a_dm_add_go_out_later() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Crew").await.unwrap();
    let mut b = TestClient::profile_only("Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let bk = b.my_group_key(g).unwrap();
    let dm = a.dm(g, &bk).await.unwrap();
    a.test_fail_next_after_add(dm);
    settle(&mut [&mut a, &mut b]).await;
    assert!(
        b.groups().iter().any(|x| x.id == dm && x.is_dm),
        "Bo is not in the direct message"
    );
    assert!(
        b.members(dm).iter().any(|m| m.name == "Ada"),
        "Bo never learns Ada's name in the direct message: {:?}",
        b.members(dm)
    );
}

fn warnings(events: &[Event]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Warning(w) => Some(w.clone()),
            _ => None,
        })
        .collect()
}

/// A relay that, once armed, forwards the client's first chunk larger than
/// `min` bytes (a Post carrying a Commit and Welcome), throws away every
/// server byte from then on, and closes both sides 300 ms later.
struct BigCut {
    port: u16,
    armed: Arc<AtomicBool>,
}

impl BigCut {
    async fn start(target: std::net::SocketAddr, min: usize) -> BigCut {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let armed = Arc::new(AtomicBool::new(false));
        let armed2 = armed.clone();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let Ok(server) = tokio::net::TcpStream::connect(target).await else {
                    continue;
                };
                let (mut cr, mut cw) = client.into_split();
                let (mut sr, mut sw) = server.into_split();
                let armed = armed2.clone();
                let dropping = Arc::new(AtomicBool::new(false));
                let cut = Arc::new(tokio::sync::Notify::new());
                let (d1, c1, a1) = (dropping.clone(), cut.clone(), armed.clone());
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 256 * 1024];
                    loop {
                        let n = match cr.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if a1.load(Ordering::SeqCst) && n > min {
                            d1.store(true, Ordering::SeqCst);
                            a1.store(false, Ordering::SeqCst);
                            let _ = sw.write_all(&buf[..n]).await;
                            // Let the rest of the request through.
                            let _ = tokio::time::timeout(Duration::from_millis(300), async {
                                loop {
                                    match cr.read(&mut buf).await {
                                        Ok(0) | Err(_) => break,
                                        Ok(n) => {
                                            let _ = sw.write_all(&buf[..n]).await;
                                        }
                                    }
                                }
                            })
                            .await;
                            c1.notify_waiters();
                            break;
                        }
                        if sw.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 256 * 1024];
                    loop {
                        tokio::select! {
                            _ = cut.notified() => break,
                            r = sr.read(&mut buf) => {
                                let n = match r { Ok(0) | Err(_) => break, Ok(n) => n };
                                if dropping.load(Ordering::SeqCst) { continue; }
                                if cw.write_all(&buf[..n]).await.is_err() { break; }
                            }
                        }
                    }
                    let _ = cw.shutdown().await;
                });
            }
        });
        BigCut { port, armed }
    }
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }
}

/// R3: with member invites turned off, a non-admin member tries to get a
/// puppet of their own into the group through an admin's open link, using
/// what every member receives about it. Members hold only the public key
/// that checks a join request, so the best they can do is sign with
/// something they hold; the admin's app must ignore the request.
#[tokio::test]
async fn rr_member_cannot_add_puppet_when_member_invites_are_off() {
    let s = TestServer::start_with(|c| c.members_can_invite = false).await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut m = TestClient::profile_only("Mal").await;
    m.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut m]).await;
    let (link, _) = a.invite(Some(g), false).await.unwrap();
    settle(&mut [&mut a, &mut m]).await;
    let request_key = m.test_invite_request_key(g, link.token).unwrap();
    let mut puppet_link = link.clone();
    puppet_link.secret = Some([9; 32]);
    let mut p = TestClient::profile_only("Pup").await;
    p.test_join_signing_with(&puppet_link, request_key.0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut m, &mut p]).await;
    let mut cy = TestClient::profile_only("Cy").await;
    let cy_join = cy.join(&link).await;
    let am = a.members(g);
    eprintln!("Cy's join with Ada's real link: {cy_join:?}");
    assert!(
        !am.iter().any(|x| x.name == "Pup"),
        "Mal's puppet is in a group where only admins may invite: {am:?}"
    );
}

/// R4: any link naming a known server with a different certificate re-pins
/// it before the server is even reached, so a bogus link cuts the person
/// off from every chat on that server.
#[tokio::test]
async fn rr_bogus_link_does_not_repin_a_server_in_use() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut bogus = s.server_invite();
    bogus.cert_fpr = [7; 32];
    let r = a.join(&bogus).await;
    let w = warnings(&drain(&mut a).await);
    eprintln!("join with bogus link: {r:?}; warnings: {w:?}");
    let sent = a.send_text(g, "still here?").await;
    assert!(
        sent.is_ok(),
        "after one bogus link Ada can no longer use her chat: {sent:?}"
    );
}

/// R5: the reply to an add commit is lost; Ada later merges it as
/// OwnPendingCommit but never reposts her name or the group name, so the
/// newcomer sees neither.
#[tokio::test]
async fn rr_lost_reply_to_add_still_welcomes_newcomer_properly() {
    let s = TestServer::start().await;
    let proxy = BigCut::start(s.addr(), 1500).await;
    let mut link = s.server_invite();
    link.port = proxy.port;
    let mut a = TestClient::profile_only("Ada").await;
    a.join(&link).await.unwrap();
    let g = a.create_group("Book club").await.unwrap();
    let mut inv = a.invite(Some(g), false).await.unwrap().0;
    inv.port = s.addr().port();
    let mut c = TestClient::profile_only("Cy").await;
    c.join(&inv).await.unwrap();
    proxy.arm();
    a.sync().await.unwrap();
    let ev = drain(&mut a).await;
    assert!(
        ev.iter().any(|e| matches!(e, Event::Disconnected)),
        "the cut did not hit the Post: {ev:?}"
    );
    for _ in 0..3 {
        a.sync().await.unwrap();
        c.sync().await.unwrap();
    }
    settle(&mut [&mut a, &mut c]).await;
    assert_eq!(a.epoch(g), c.epoch(g), "Cy did not join");
    let name = c
        .groups()
        .into_iter()
        .find(|x| x.id == g)
        .map(|x| x.name)
        .unwrap_or_default();
    let cm: Vec<String> = c.members(g).into_iter().map(|m| m.name).collect();
    assert!(
        name == "Book club" && cm.iter().any(|n| n == "Ada"),
        "Cy sees group name {name:?} and members {cm:?}"
    );
}

/// R6: message text keeps emoji ZWJ sequences, ZWNJ and flag tag sequences.
#[test]
fn rr_text_keeps_joiners_and_emoji_tags() {
    use socketchat_core::sanitize::clean_text;
    let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}";
    let persian = "\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}";
    let scotland = "\u{1F3F4}\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}";
    let mut broken = Vec::new();
    for t in [family, persian, scotland] {
        if clean_text(t) != t {
            broken.push(format!("{t:?} -> {:?}", clean_text(t)));
        }
    }
    assert!(broken.is_empty(), "{broken:?}");
}

/// R7: a salt file asking for 2^32-1 Argon2 passes hangs the app on open
/// instead of being refused.
#[tokio::test]
async fn rr_tampered_kdf_params_are_refused_quickly() {
    let dir = tempfile::tempdir().unwrap();
    drop(
        Client::create_profile(dir.path(), passphrase(), "Ada")
            .await
            .unwrap(),
    );
    let salt_path = dir.path().join("salt");
    let mut f = std::fs::read(&salt_path).unwrap();
    assert!(f.starts_with(b"sckdf\x01"));
    f[6..10].copy_from_slice(&8u32.to_be_bytes());
    f[10..14].copy_from_slice(&u32::MAX.to_be_bytes());
    std::fs::write(&salt_path, &f).unwrap();
    let p = dir.path().to_path_buf();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let r = rt.block_on(Client::open(&p, passphrase()));
        let _ = tx.send(r.is_ok());
    });
    let done = rx.recv_timeout(Duration::from_secs(10));
    assert!(
        done.is_ok(),
        "opening a profile whose salt file asks for 2^32-1 passes still runs after 10 s"
    );
    let _ = GroupId([0; 16]);
}

/// Control for R5: the same steps with no reply lost.
#[tokio::test]
async fn rr_control_add_without_lost_reply() {
    let s = TestServer::start().await;
    let proxy = BigCut::start(s.addr(), 1500).await;
    let mut link = s.server_invite();
    link.port = proxy.port;
    let mut a = TestClient::profile_only("Ada").await;
    a.join(&link).await.unwrap();
    let g = a.create_group("Book club").await.unwrap();
    let mut inv = a.invite(Some(g), false).await.unwrap().0;
    inv.port = s.addr().port();
    let mut c = TestClient::profile_only("Cy").await;
    c.join(&inv).await.unwrap();
    for _ in 0..4 {
        a.sync().await.unwrap();
        c.sync().await.unwrap();
    }
    settle(&mut [&mut a, &mut c]).await;
    let name = c
        .groups()
        .into_iter()
        .find(|x| x.id == g)
        .map(|x| x.name)
        .unwrap_or_default();
    let cm: Vec<String> = c.members(g).into_iter().map(|m| m.name).collect();
    assert!(
        name == "Book club" && cm.iter().any(|n| n == "Ada"),
        "{name:?} {cm:?}"
    );
}

/// R8: the joiner's connection drops right after the Welcome is taken, on
/// the post of its Profile. The Profile and the InviteProof are never sent
/// again, so the inviter never learns the newcomer's name or verifies them.
#[tokio::test]
async fn rr_joiner_drop_after_welcome_still_sends_profile_and_proof() {
    let s = TestServer::start().await;
    let proxy = BigCut::start(s.addr(), 150).await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut inv = a.invite(Some(g), false).await.unwrap().0;
    inv.port = proxy.port;
    let mut c = TestClient::profile_only("Cy").await;
    c.join(&inv).await.unwrap();
    a.sync().await.unwrap();
    proxy.arm();
    c.sync().await.unwrap();
    let ev = drain(&mut c).await;
    eprintln!("Cy's first sync: {ev:?}");
    for _ in 0..4 {
        a.sync().await.unwrap();
        c.sync().await.unwrap();
    }
    settle(&mut [&mut a, &mut c]).await;
    assert_eq!(a.epoch(g), c.epoch(g), "Cy did not join");
    let am: Vec<(String, bool)> = a
        .members(g)
        .into_iter()
        .filter(|m| !m.me)
        .map(|m| (m.name, m.verified))
        .collect();
    assert!(
        am.iter().any(|(n, v)| n == "Cy" && *v),
        "Ada sees the newcomer as {am:?}"
    );
}

/// R10: a server that answers every fetch with the same page, ending where
/// it started, must not hold the app in a loop.
#[tokio::test]
async fn rr_stale_pages_from_server_do_not_freeze_sync() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    a.test_serve_stale_pages(g);
    let r = tokio::time::timeout(Duration::from_secs(10), a.sync()).await;
    assert!(
        r.is_ok(),
        "sync still running after 10 s against a server that repeats one page"
    );
}

/// R11: a join request that fails its check stays on the server's list, so
/// every sync reads it again. The app says so once per session.
#[tokio::test]
async fn rr_bad_join_request_warns_once() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let (link, _) = a.invite(Some(g), false).await.unwrap();
    let mut p = TestClient::profile_only("Pup").await;
    p.test_join_signing_with(&link, [9; 32]).await.unwrap();
    for _ in 0..4 {
        a.sync().await.unwrap();
    }
    let said = warnings(&drain(&mut a).await);
    let n = said
        .iter()
        .filter(|w| w.contains("failed its check"))
        .count();
    assert_eq!(n, 1, "{said:?}");
}
