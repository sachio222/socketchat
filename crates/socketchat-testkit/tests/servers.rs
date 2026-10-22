//! A profile on more than one server: which server new rooms go on, what
//! each server's state is, errors that name the server, and forgetting a
//! server this computer can no longer use.

use std::time::Duration;

use socketchat_core::client::{server_text, ServerState};
use socketchat_testkit::{settle, TestClient, TestServer};

/// The server ID behind the `n`th row (from 1) of `servers()`.
fn nth(c: &TestClient, n: usize) -> i64 {
    c.servers(None)[n - 1].id
}

/// Stops a server and waits for its port to close.
async fn stop(s: &TestServer) {
    s.handle.shutdown();
    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[test]
fn server_text_leaves_out_the_usual_port_and_cleans_the_host() {
    assert_eq!(
        server_text("chat.socketchat.org", 7444),
        "chat.socketchat.org"
    );
    assert_eq!(
        server_text("Jacobs-MacBook-Pro-2.local", 9000),
        "Jacobs-MacBook-Pro-2.local:9000"
    );
    assert_eq!(server_text("evil\x1b[31m.host", 7444), "evil[31m.host");
}

#[tokio::test]
async fn new_rooms_go_on_the_server_joined_last() {
    let (s1, s2) = (TestServer::start().await, TestServer::start().await);
    let mut a = TestClient::new(&s1, "Ada").await;
    a.join(&s2.server_invite()).await.unwrap();
    let second = nth(&a, 2);
    assert_eq!(a.new_room_server(None), Some(second));
    let g = a.create_group("Book club").await.unwrap();
    assert_eq!(a.test_server_of(g), second, "the newest server");
    let rows = a.servers(None);
    assert!(!rows[0].new_rooms && rows[1].new_rooms, "{rows:?}");
}

#[tokio::test]
async fn new_rooms_follow_the_open_room() {
    let (s1, s2) = (TestServer::start().await, TestServer::start().await);
    let mut a = TestClient::new(&s1, "Ada").await;
    a.join(&s2.server_invite()).await.unwrap();
    let first = nth(&a, 1);
    let old = a.create_group_at(first, "Old crew").await.unwrap();
    assert_eq!(a.test_server_of(old), first);
    assert_eq!(a.new_room_server(Some(old)), Some(first));
    let rows = a.servers(Some(old));
    assert!(rows[0].new_rooms && !rows[1].new_rooms, "{rows:?}");
    assert_eq!(rows[0].rooms, 1);
    assert_eq!(rows[1].rooms, 0);
}

#[tokio::test]
async fn each_server_says_whether_it_is_connected() {
    let (s1, s2) = (TestServer::start().await, TestServer::start().await);
    let mut a = TestClient::new(&s1, "Ada").await;
    a.join(&s2.server_invite()).await.unwrap();
    let (one, two) = (nth(&a, 1), nth(&a, 2));
    a.create_group_at(one, "Old crew").await.unwrap();
    a.create_group_at(two, "New crew").await.unwrap();

    // A profile just opened has not tried yet.
    let mut a = a.reopen().await;
    let states: Vec<ServerState> = a.servers(None).into_iter().map(|s| s.state).collect();
    assert_eq!(states, [ServerState::NotYet, ServerState::NotYet]);

    a.sync().await.unwrap();
    let states: Vec<ServerState> = a.servers(None).into_iter().map(|s| s.state).collect();
    assert_eq!(states, [ServerState::Connected, ServerState::Connected]);

    stop(&s1).await;
    a.test_drop_connections();
    a.sync().await.unwrap();
    let rows = a.servers(None);
    assert_eq!(
        rows[0].state,
        ServerState::Unreachable("connection refused".into()),
        "{rows:?}"
    );
    assert_eq!(rows[1].state, ServerState::Connected, "{rows:?}");
}

#[tokio::test]
async fn a_dead_server_is_named_in_the_error() {
    let s1 = TestServer::start().await;
    let mut a = TestClient::new(&s1, "Ada").await;
    let g = a.create_group("Old crew").await.unwrap();
    stop(&s1).await;
    let mut a = a.reopen().await;
    let e = a.send_text(g, "hello?").await.unwrap_err();
    assert_eq!(
        e.to_string(),
        format!(
            "Could not reach 127.0.0.1:{}: connection refused.",
            s1.addr().port()
        )
    );
}

#[tokio::test]
async fn a_dead_server_does_not_stop_rooms_on_a_live_one() {
    let (s1, s2) = (TestServer::start().await, TestServer::start().await);
    let mut a = TestClient::new(&s1, "Ada").await;
    a.create_group("Old crew").await.unwrap();
    stop(&s1).await;
    let mut a = a.reopen().await;
    // Joining the new server works, and new rooms go there.
    a.join(&s2.server_invite()).await.unwrap();
    let g = a.create_group("Book club").await.unwrap();
    assert_eq!(a.test_server_of(g), nth(&a, 2));
    a.sync().await.unwrap();
}

#[tokio::test]
async fn forgetting_a_server_deletes_only_what_is_on_it() {
    let (s1, s2) = (TestServer::start().await, TestServer::start().await);
    let mut a = TestClient::new(&s1, "Ada").await;
    a.join(&s2.server_invite()).await.unwrap();
    let (one, two) = (nth(&a, 1), nth(&a, 2));

    // On the first server: a room with Bo in it and its history, an open
    // room link, and a join Ada asked for and that nobody let in yet.
    let mut bo = TestClient::new(&s1, "Bo").await;
    let old = a.create_group_at(one, "Old crew").await.unwrap();
    let link = a.invite(Some(old), false).await.unwrap().0;
    bo.join(&link).await.unwrap();
    settle(&mut [&mut a, &mut bo]).await;
    bo.send_text(old, "see you there").await.unwrap();
    a.sync().await.unwrap();
    a.invite(Some(old), false).await.unwrap();
    let cy_room = bo.create_group("Cy's room").await.unwrap();
    a.join(&bo.invite(Some(cy_room), false).await.unwrap().0)
        .await
        .unwrap();
    assert_eq!(a.test_pending_joins(), 1);

    // On the second server: a room with Di in it, and an open link.
    let mut di = TestClient::new(&s2, "Di").await;
    let new = a.create_group_at(two, "New crew").await.unwrap();
    di.join(&a.invite(Some(new), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut di]).await;
    a.invite(Some(new), false).await.unwrap();
    // Two links recorded on each server: the one used to join, and the
    // open one.
    assert_eq!(a.test_invite_rows(), 4);

    let s1_addr = s1.addr();
    stop(&s1).await;
    assert_eq!(a.forget_server(one).unwrap(), 1);

    assert!(a.test_traces(old).is_empty(), "{:?}", a.test_traces(old));
    assert!(!a.groups().iter().any(|g| g.id == old));
    assert_eq!(a.test_pending_joins(), 0);
    assert_eq!(a.test_invite_rows(), 2, "only the second server's links");
    assert_eq!(
        a.trusted_certificate(&s1_addr.ip().to_string(), s1_addr.port())
            .unwrap(),
        None,
        "the pin went with the row"
    );
    let rows = a.servers(None);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, two);
    assert_eq!(rows[0].rooms, 1);

    // The second server's room still works, and stays after a reopen.
    di.send_text(new, "still here").await.unwrap();
    a.sync().await.unwrap();
    assert!(a.messages(new, 10).iter().any(|l| l.text == "still here"));
    let mut a = a.reopen().await;
    a.sync().await.unwrap();
    assert!(a.groups().iter().any(|g| g.id == new));
    assert_eq!(a.servers(None).len(), 1);
    assert!(a.test_traces(old).is_empty());

    // New rooms fall back to the server that is left.
    assert_eq!(a.new_room_server(None), Some(two));
}

#[tokio::test]
async fn forgetting_the_newest_server_moves_new_rooms_back() {
    let (s1, s2) = (TestServer::start().await, TestServer::start().await);
    let mut a = TestClient::new(&s1, "Ada").await;
    a.join(&s2.server_invite()).await.unwrap();
    let (one, two) = (nth(&a, 1), nth(&a, 2));
    a.forget_server(two).unwrap();
    assert_eq!(a.new_room_server(None), Some(one));
    let g = a.create_group("Book club").await.unwrap();
    assert_eq!(a.test_server_of(g), one);
}

/// The profile's own files, each with its contents and, on Unix, its
/// mode. SQLite's database and log files change with every write, so only
/// their names count.
fn profile_files(c: &TestClient) -> Vec<(String, Option<Vec<u8>>, u32)> {
    let mut out: Vec<_> = std::fs::read_dir(c.dir.path())
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            let name = e.file_name().to_string_lossy().into_owned();
            #[cfg(unix)]
            let mode =
                std::os::unix::fs::PermissionsExt::mode(&e.metadata().unwrap().permissions());
            #[cfg(not(unix))]
            let mode = 0;
            let body = (!name.contains(".db")).then(|| std::fs::read(e.path()).unwrap());
            (name, body, mode)
        })
        .filter(|(name, _, _)| !name.ends_with("-wal") && !name.ends_with("-shm"))
        .collect();
    out.sort();
    out
}

#[tokio::test]
async fn forgetting_a_server_leaves_the_profile_files_alone() {
    let (s1, s2) = (TestServer::start().await, TestServer::start().await);
    let mut a = TestClient::new(&s1, "Ada").await;
    a.join(&s2.server_invite()).await.unwrap();
    let one = nth(&a, 1);
    a.create_group_at(one, "Old crew").await.unwrap();
    let before = profile_files(&a);
    assert!(before.iter().any(|(n, b, _)| n == "salt" && b.is_some()));
    a.forget_server(one).unwrap();
    assert_eq!(profile_files(&a), before);
    let a = a.reopen().await;
    assert_eq!(a.servers(None).len(), 1);
}

/// A server address with letters outside ASCII, kept from a link that an
/// app taking any address accepted, makes no invite link: apps refuse such
/// an address. Socketchat says what the owner can change instead, and asks
/// nothing of the server.
#[tokio::test]
async fn no_invite_link_names_a_server_address_apps_refuse() {
    let s = TestServer::start().await;
    let mut a = TestClient::new(&s, "Ada").await;
    let g = a.create_group("Crew").await.unwrap();
    a.test_store_server_host(nth(&a, 1), "bücher.example");
    let rooms = a.groups().len();
    for (group, dm) in [(Some(g), false), (None, false), (None, true)] {
        let said = match a.invite(group, dm).await {
            Ok((link, _)) => panic!("made {link}"),
            Err(e) => e.to_string(),
        };
        assert!(said.contains("bücher.example"), "{said}");
        assert!(said.contains("public_host"), "{said}");
        assert!(said.contains("new server invite"), "{said}");
    }
    assert_eq!(a.groups().len(), rooms, "no direct chat made for it");
    assert_eq!(a.test_invite_rows(), 0, "no link asked of the server");
}

/// Ada's room `name`, made by `owner`, with a message she has not read
/// when `owner` removes her: an ended room still on her computer.
async fn removed_with_unread(
    a: &mut TestClient,
    owner: &mut TestClient,
    name: &str,
) -> socketchat_proto::msg::GroupId {
    let g = owner.create_group(name).await.unwrap();
    a.join(&owner.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut *a, &mut *owner]).await;
    owner.send_text(g, "read me").await.unwrap();
    settle(&mut [&mut *a, &mut *owner]).await;
    let ak = a.my_group_key(g).unwrap();
    owner.remove_member(g, &ak).await.unwrap();
    settle(&mut [&mut *a, &mut *owner]).await;
    let row = a.groups().into_iter().find(|x| x.id == g).expect("listed");
    assert!(row.ended.is_some() && row.unseen > 0, "{row:?}");
    g
}

/// Forgetting a server deletes the rooms there that ended for this person
/// and still wait to be read, with their messages. An ended room on
/// another server stays.
#[tokio::test]
async fn forgetting_a_server_deletes_its_ended_rooms_too() {
    let (s1, s2) = (TestServer::start().await, TestServer::start().await);
    let mut a = TestClient::new(&s1, "Ada").await;
    a.join(&s2.server_invite()).await.unwrap();
    let one = nth(&a, 1);
    let mut bo = TestClient::new(&s1, "Bo").await;
    let mut cy = TestClient::new(&s2, "Cy").await;
    let there = removed_with_unread(&mut a, &mut bo, "Bo's room").await;
    let elsewhere = removed_with_unread(&mut a, &mut cy, "Cy's room").await;

    a.forget_server(one).unwrap();
    assert!(!a.groups().iter().any(|g| g.id == there));
    assert!(a.messages(there, 10).is_empty());
    assert!(
        a.test_traces(there).is_empty(),
        "{:?}",
        a.test_traces(there)
    );
    assert!(a.groups().iter().any(|g| g.id == elsewhere));
    assert!(!a.messages(elsewhere, 10).is_empty());
    let a = a.reopen().await;
    assert!(!a.groups().iter().any(|g| g.id == there));
}
