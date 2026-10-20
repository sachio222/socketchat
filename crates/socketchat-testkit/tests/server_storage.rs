use std::path::Path;

use socketchat_proto::msg::GroupId;
use socketchat_testkit::{open_server_db, settle, TestClient, TestServer};

fn texts(c: &TestClient, g: GroupId) -> Vec<String> {
    c.messages(g, 100)
        .into_iter()
        .filter(|l| !l.notice)
        .map(|l| l.text)
        .collect()
}

/// Every byte under `dir`, file by file.
fn all_bytes(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = vec![];
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(all_bytes(&p));
        } else {
            out.push((p.display().to_string(), std::fs::read(&p).unwrap()));
        }
    }
    out
}

fn has(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

#[tokio::test]
async fn server_restart_keeps_all_state() {
    let mut s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut b = TestClient::new(&s, "Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    let mut c = TestClient::new(&s, "Cy").await;
    c.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    a.send_text(g, "before").await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    s.restart().await;
    // Clients notice the drop on their next sync and reconnect after it.
    settle(&mut [&mut a, &mut b, &mut c]).await;
    b.send_text(g, "after").await.unwrap();
    c.send_text(g, "me too").await.unwrap();
    settle(&mut [&mut a, &mut b, &mut c]).await;
    for x in [&a, &b, &c] {
        assert_eq!(
            texts(x, g),
            vec!["before", "after", "me too"],
            "{}",
            x.display_name()
        );
        assert_eq!(x.members(g).len(), 3);
    }
}

#[tokio::test]
async fn retention_sweep_deletes_old_entries() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut b = TestClient::new(&s, "Bo").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let _unused = a.invite(Some(g), false).await.unwrap().0;
    a.send_text(g, "Bo never reads this").await.unwrap();
    let db = open_server_db(&s);
    let count = |sql: &str| -> i64 { db.query_row(sql, [], |r| r.get(0)).unwrap() };
    assert!(count("SELECT count(*) FROM log") > 0);
    assert!(count("SELECT count(*) FROM invites") > 0);
    s.handle.advance_clock(31 * 24 * 3600);
    s.handle.sweep_now();
    assert_eq!(count("SELECT count(*) FROM log"), 0);
    assert_eq!(count("SELECT count(*) FROM invites"), 0);
    assert_eq!(count("SELECT count(*) FROM welcomes"), 0);
}

#[tokio::test]
async fn server_bytes_hold_no_plaintext() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Zelda Quixote").await;
    let g = a.create_group("Velvet Harbor Society").await.unwrap();
    let mut b = TestClient::new(&s, "Ignatius Plumtree").await;
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    a.send_text(g, "the eagle lands at midnight 7731")
        .await
        .unwrap();
    b.send_text(g, "copy that, bring the kumquats")
        .await
        .unwrap();
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("ledger-of-secrets.txt");
    std::fs::write(&f, "file-secret-content-9981 ".repeat(200)).unwrap();
    a.send_file(g, &f, false).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert!(
        texts(&b, g).iter().any(|t| t.contains("eagle")),
        "the chat really happened"
    );
    let secrets = [
        "Zelda Quixote",
        "Ignatius Plumtree",
        "Velvet Harbor Society",
        "the eagle lands at midnight 7731",
        "bring the kumquats",
        "file-secret-content-9981",
        "ledger-of-secrets",
    ];
    for (path, bytes) in all_bytes(s.dir.path()) {
        for secret in secrets {
            assert!(
                !has(&bytes, secret.as_bytes()),
                "{secret:?} found in {path}"
            );
            assert!(
                !has(&bytes, &utf16(secret)),
                "{secret:?} (UTF-16) found in {path}"
            );
        }
    }
}

#[tokio::test]
async fn server_cannot_link_person_across_groups() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g1 = a.create_group("One").await.unwrap();
    let mut c = TestClient::new(&s, "Cy").await;
    let g2 = c.create_group("Two").await.unwrap();
    let mut p = TestClient::new(&s, "Pat").await;
    p.join(&a.invite(Some(g1), false).await.unwrap().0)
        .await
        .unwrap();
    p.join(&c.invite(Some(g2), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut c, &mut p]).await;
    let (k1, k2) = (p.my_group_key(g1).unwrap(), p.my_group_key(g2).unwrap());
    assert_ne!(k1, k2, "a fresh key in each group");
    // No identity key reaches the server: not the joiner's, and not the
    // inviters' either, whose signed vouchers travel with each Welcome.
    let identities = [
        ("Ada", a.identity()),
        ("Cy", c.identity()),
        ("Pat", p.identity()),
    ];
    let files = all_bytes(s.dir.path());
    assert!(
        files.iter().any(|(path, _)| path.ends_with("-wal")),
        "the scan covers the write-ahead log"
    );
    for (path, bytes) in files {
        for (who, identity) in &identities {
            assert!(
                !has(&bytes, &identity.0),
                "{who}'s identity key found in {path}"
            );
        }
    }
    let db = open_server_db(&s);
    let group_of = |k: &[u8]| -> Vec<u8> {
        db.query_row("SELECT group_id FROM mailboxes WHERE key = ?1", [k], |r| {
            r.get(0)
        })
        .unwrap()
    };
    assert_eq!(group_of(&k1.0), g1.0.to_vec());
    assert_eq!(group_of(&k2.0), g2.0.to_vec());
    let cols: Vec<String> = db
        .prepare("SELECT name FROM pragma_table_info('accounts')")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        cols,
        vec!["key", "created_unix"],
        "accounts link to nothing"
    );
    let joins: i64 = db
        .query_row("SELECT count(*) FROM joins", [], |r| r.get(0))
        .unwrap();
    assert_eq!(joins, 0, "finished joins leave no token-to-mailbox record");
}

#[tokio::test]
async fn account_and_mailbox_times_are_whole_days() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    // Pat has no account yet, so the group invite registers an account and
    // a mailbox together.
    let mut p = TestClient::profile_only("Pat").await;
    p.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut p]).await;
    let db = open_server_db(&s);
    let times = |sql: &str| -> Vec<i64> {
        db.prepare(sql)
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    let accounts = times("SELECT created_unix FROM accounts");
    let mailboxes = times("SELECT created_unix FROM mailboxes");
    assert_eq!(accounts.len(), 2, "Ada's and Pat's");
    assert_eq!(mailboxes.len(), 2, "one in G for each");
    for t in accounts.iter().chain(&mailboxes) {
        assert_eq!(t % 86400, 0, "{t} is not a whole day");
    }
}

#[tokio::test]
async fn unfinished_join_mailbox_lasts_at_least_seven_days() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("G").await.unwrap();
    let mut p = TestClient::new(&s, "Pat").await;
    // Nobody lets Pat in, so the mailbox stays unjoined.
    p.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    let db = open_server_db(&s);
    let waiting = || -> i64 {
        db.query_row(
            "SELECT count(*) FROM mailboxes WHERE joined_seq IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(waiting(), 1);
    s.handle.advance_clock(7 * 24 * 3600 - 3600);
    s.handle.sweep_now();
    assert_eq!(waiting(), 1, "kept for the full seven-day wait");
    s.handle.advance_clock(24 * 3600 + 7200);
    s.handle.sweep_now();
    assert_eq!(waiting(), 0, "gone a day later");
}

#[test]
fn scanner_finds_planted_secrets() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir(d.path().join("files")).unwrap();
    std::fs::write(
        d.path().join("files/x"),
        [b"..".as_slice(), &utf16("Zelda Quixote"), b".."].concat(),
    )
    .unwrap();
    std::fs::write(
        d.path().join("server.db-wal"),
        b"xx the eagle lands at midnight 7731 xx",
    )
    .unwrap();
    let found: Vec<bool> = all_bytes(d.path())
        .iter()
        .map(|(_, b)| {
            has(b, b"the eagle lands at midnight 7731") || has(b, &utf16("Zelda Quixote"))
        })
        .collect();
    assert_eq!(found, vec![true, true]);
}
