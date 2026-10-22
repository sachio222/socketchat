use socketchat_core::net::{Conn, NetError};
use socketchat_proto::msg::{GroupId, Request, Response};
use socketchat_testkit::{settle, TestClient, TestServer};

fn texts(c: &TestClient, g: GroupId) -> Vec<String> {
    c.messages(g, 100)
        .into_iter()
        .filter(|l| !l.notice)
        .map(|l| format!("{}: {}", l.sender, l.text))
        .collect()
}

async fn pair(s: &TestServer, bo_cap: Option<u16>) -> (GroupId, TestClient, TestClient) {
    let mut a = TestClient::new(s, "Ada").await;
    let g = a.create_group("Crew").await.unwrap();
    let mut b = TestClient::profile_only("Bo").await;
    if let Some(cap) = bo_cap {
        b.test_cap_protocol(cap);
    }
    b.join(&s.server_invite()).await.unwrap();
    b.join(&a.invite(Some(g), false).await.unwrap().0)
        .await
        .unwrap();
    settle(&mut [&mut a, &mut b]).await;
    (g, a, b)
}

async fn chat_both_ways(g: GroupId, a: &mut TestClient, b: &mut TestClient) {
    a.send_text(g, "hi Bo").await.unwrap();
    b.send_text(g, "hi Ada").await.unwrap();
    settle(&mut [a, b]).await;
    for c in [&*a, &*b] {
        let t = texts(c, g);
        assert!(t.contains(&"Ada: hi Bo".to_string()), "{t:?}");
        assert!(t.contains(&"Bo: hi Ada".to_string()), "{t:?}");
    }
}

#[tokio::test]
async fn app_falls_back_on_a_protocol_1_server() {
    let mut s = TestServer::start_with(|c| c.protocol_max = 1).await;
    let (g, mut a, mut b) = pair(&s, None).await;
    chat_both_ways(g, &mut a, &mut b).await;
    assert_eq!(a.protocol_for(g), Some(1));
    assert_eq!(b.protocol_for(g), Some(1));

    // A dropped connection comes back at 1 again.
    s.restart().await;
    a.send_text(g, "after the restart").await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    assert!(texts(&b, g).contains(&"Ada: after the restart".to_string()));
    assert_eq!(a.protocol_for(g), Some(1));
    assert_eq!(b.protocol_for(g), Some(1));
}

#[tokio::test]
async fn protocol_2_request_on_protocol_1_is_not_sent() {
    let s = TestServer::start_with(|c| c.protocol_max = 1).await;
    let c = Conn::connect("127.0.0.1", s.addr().port(), s.fpr())
        .await
        .unwrap();
    assert_eq!(c.protocol(), 1);
    match c
        .request(Request::ListInvites {
            server_tokens: vec![],
        })
        .await
    {
        Err(NetError::Unsupported {
            needs: 2,
            server: 1,
        }) => {}
        other => panic!("wrong answer: {other:?}"),
    }
    assert!(c.is_alive());
    assert!(matches!(
        c.request(Request::Challenge).await.unwrap(),
        Response::Challenge(_)
    ));
}

#[tokio::test]
async fn unsupported_reads_in_plain_words() {
    assert_eq!(
        NetError::Unsupported {
            needs: 2,
            server: 1
        }
        .to_string(),
        "this server runs an older version of Socketchat that can't do that yet; ask the person who runs it to update it"
    );
}

#[tokio::test]
async fn protocol_1_app_works_on_a_0_5_server() {
    let s = TestServer::start().await;
    let (g, mut a, mut b) = pair(&s, Some(1)).await;
    chat_both_ways(g, &mut a, &mut b).await;

    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("note.txt");
    std::fs::write(&file, b"a small note from Bo").unwrap();
    b.send_file(g, &file, false).await.unwrap();
    settle(&mut [&mut a, &mut b]).await;
    let offer = a.files(g).pop().expect("Ada sees the file");
    let out = tempfile::tempdir().unwrap();
    let saved = a.save_file(g, offer.id, out.path()).await.unwrap();
    assert_eq!(std::fs::read(saved).unwrap(), b"a small note from Bo");

    assert_eq!(b.protocol_for(g), Some(1));
    assert_eq!(a.protocol_for(g), Some(2));
}
