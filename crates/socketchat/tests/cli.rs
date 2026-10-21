use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_socketchat");

/// The passphrase for every temporary profile in these tests: 16 random bytes
/// in hex, made once per run so every command opens the same profiles.
fn pass() -> &'static str {
    static PASS: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PASS.get_or_init(|| {
        let mut bytes = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    })
}

fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env("SOCKETCHAT_HOME", home)
        .env("SOCKETCHAT_PASSPHRASE", pass())
        .env("SOCKETCHAT_NAME", home.file_name().unwrap())
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn out(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Server {
    child: Child,
    dir: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn server() -> Server {
    server_with_config(|c| c)
}

/// A server whose config file `edit` rewrites between init and run.
fn server_with_config(edit: impl FnOnce(String) -> String) -> Server {
    let listen = format!("127.0.0.1:{}", free_port());
    server_at(&listen, edit).expect("server did not start")
}

/// A server set up fresh, with a new certificate, listening on `listen`.
/// None when it could not start there.
fn server_at(listen: &str, edit: impl FnOnce(String) -> String) -> Option<Server> {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap();
    let o = Command::new(BIN)
        .args([
            "server",
            "init",
            "--data-dir",
            d,
            "--host",
            "127.0.0.1",
            "--listen",
            listen,
        ])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", out(&o));
    let cfg = dir.path().join("socketchat-server.toml");
    std::fs::write(&cfg, edit(std::fs::read_to_string(&cfg).unwrap())).unwrap();
    let mut child = Command::new(BIN)
        .args(["server", "run", "--data-dir", d])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut first = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut first)
        .unwrap();
    let s = Server { child, dir };
    first.contains("listening").then_some(s)
}

fn server_invite(s: &Server) -> String {
    let o = Command::new(BIN)
        .args([
            "server",
            "invite",
            "--data-dir",
            s.dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", out(&o));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

#[test]
fn help_lists_subcommands() {
    let o = Command::new(BIN).arg("--help").output().unwrap();
    let s = out(&o);
    for word in ["server", "join", "invite", "send", "log"] {
        assert!(s.contains(word), "{word} missing from:\n{s}");
    }
}

#[test]
fn server_init_prints_aup_and_fingerprint() {
    let d = tempfile::tempdir().unwrap();
    let o = Command::new(BIN)
        .args([
            "server",
            "init",
            "--data-dir",
            d.path().to_str().unwrap(),
            "--host",
            "chat.example.com",
        ])
        .output()
        .unwrap();
    let s = out(&o);
    assert!(o.status.success(), "{s}");
    assert!(s.contains("Acceptable use"), "{s}");
    assert!(
        s.lines().all(|l| !l.starts_with('#')),
        "no Markdown heading marks: {s}"
    );
    assert!(!s.contains('`'), "no Markdown backticks: {s}");
    assert!(s.contains("fingerprint"), "{s}");
    assert!(
        s.contains("socketchat server run"),
        "says what to do next: {s}"
    );
    let again = Command::new(BIN)
        .args([
            "server",
            "init",
            "--data-dir",
            d.path().to_str().unwrap(),
            "--host",
            "x",
        ])
        .output()
        .unwrap();
    assert!(!again.status.success());
}

#[test]
fn server_invite_prints_link() {
    let s = server();
    let link = server_invite(&s);
    assert!(link.starts_with("socketchat://127.0.0.1:"), "{link}");
    assert_eq!(link.lines().count(), 1);
}

#[test]
fn invites_state_the_configured_expiry() {
    let s = server_with_config(|c| {
        assert!(c.contains("invite_ttl_hours = 24"), "{c}");
        c.replace("invite_ttl_hours = 24", "invite_ttl_hours = 2")
    });
    let o = Command::new(BIN)
        .args([
            "server",
            "invite",
            "--data-dir",
            s.dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", out(&o));
    let said = String::from_utf8_lossy(&o.stderr);
    assert!(said.contains("expires in 2 hours."), "{said}");
    let link = String::from_utf8_lossy(&o.stdout).trim().to_string();
    let home = tempfile::tempdir().unwrap();
    let ada = home.path().join("Ada");
    assert!(run(&ada, &["join", &link]).status.success());
    assert!(run(&ada, &["new", "Crew"]).status.success());
    for args in [
        ["invite", "--group", "Crew"].as_slice(),
        ["invite", "--dm"].as_slice(),
    ] {
        let o = run(&ada, args);
        assert!(o.status.success(), "{}", out(&o));
        let said = String::from_utf8_lossy(&o.stderr);
        assert!(
            said.contains("It works once and expires in 2 hours."),
            "{args:?}: {said}"
        );
    }
}

#[test]
fn join_with_bad_link_explains() {
    let home = tempfile::tempdir().unwrap();
    let o = run(home.path(), &["join", "https://example.com/nope"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(out(&o).contains("socketchat://"), "{}", out(&o));
}

#[test]
fn no_profile_explains_how_to_start() {
    let home = tempfile::tempdir().unwrap();
    let o = run(home.path(), &["log", "--group", "x"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(out(&o).contains("socketchat join"), "{}", out(&o));
}

#[test]
fn wrong_passphrase_exits_2_with_plain_message() {
    let s = server();
    let home = tempfile::tempdir().unwrap();
    let ada = home.path().join("Ada");
    let o = run(&ada, &["join", &server_invite(&s)]);
    assert!(o.status.success(), "{}", out(&o));
    let o = Command::new(BIN)
        .args(["log", "--group", "x"])
        .env("SOCKETCHAT_HOME", &ada)
        .env("SOCKETCHAT_PASSPHRASE", format!("{}0", pass()))
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2), "{}", out(&o));
    assert!(out(&o).contains("passphrase"), "{}", out(&o));
}

/// A link that names a known server with another certificate changes
/// nothing until the person accepts it, and accepting a certificate the
/// server does not have changes nothing either.
#[test]
fn join_with_a_different_certificate_asks_first() {
    let s = server();
    let home = tempfile::tempdir().unwrap();
    let ada = home.path().join("Ada");
    assert!(run(&ada, &["join", &server_invite(&s)]).status.success());
    let mut bogus: socketchat_proto::InviteLink = server_invite(&s).parse().unwrap();
    bogus.cert_fpr = [7; 32];
    let bogus = bogus.to_string();
    let o = run(&ada, &["join", &bogus]);
    let said = out(&o);
    assert_eq!(o.status.code(), Some(1), "{said}");
    assert!(said.contains("0707 0707 0707"), "{said}");
    assert!(said.contains("socketchat join --new-certificate"), "{said}");
    let o = run(&ada, &["join", "--new-certificate", &bogus]);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(out(&o).contains("does not match"), "{}", out(&o));
    let o = run(&ada, &["new", "Still here"]);
    assert!(o.status.success(), "{}", out(&o));
}

/// Accepting a new certificate names the server and shows the certificate
/// socketchat trusted before and the one it trusts now.
#[test]
fn accepting_a_new_certificate_shows_both_fingerprints() {
    use socketchat_core::keys::fingerprint_text;
    use socketchat_proto::InviteLink;
    let s = server();
    let home = tempfile::tempdir().unwrap();
    let ada = home.path().join("Ada");
    let first: InviteLink = server_invite(&s).parse().unwrap();
    assert!(run(&ada, &["join", &first.to_string()]).status.success());
    // The operator sets the server up again on the same address.
    drop(s);
    let listen = format!("127.0.0.1:{}", first.port);
    let s = (0..50)
        .find_map(|_| {
            server_at(&listen, |c| c).or_else(|| {
                std::thread::sleep(std::time::Duration::from_millis(100));
                None
            })
        })
        .expect("no new server on the old port");
    let link = server_invite(&s);
    let new: InviteLink = link.parse().unwrap();
    assert_ne!(new.cert_fpr, first.cert_fpr);
    let o = run(&ada, &["join", "--new-certificate", &link]);
    let said = out(&o);
    assert!(o.status.success(), "{said}");
    assert!(
        said.contains(&format!(
            "socketchat now trusts the new certificate for 127.0.0.1:{}.",
            first.port
        )),
        "{said}"
    );
    assert!(
        said.contains(&format!(
            "Old certificate: {}",
            fingerprint_text(&first.cert_fpr)
        )),
        "{said}"
    );
    assert!(
        said.contains(&format!(
            "New certificate: {}",
            fingerprint_text(&new.cert_fpr)
        )),
        "{said}"
    );
    let o = run(&ada, &["new", "After"]);
    assert!(o.status.success(), "{}", out(&o));
}

#[test]
fn two_people_chat_through_binary() {
    let s = server();
    let home = tempfile::tempdir().unwrap();
    let (ada, bo) = (home.path().join("Ada"), home.path().join("Bo"));
    assert!(run(&ada, &["join", &server_invite(&s)]).status.success());
    let o = run(&ada, &["new", "Crew"]);
    assert!(o.status.success(), "{}", out(&o));
    let o = run(&ada, &["invite", "--group", "Crew"]);
    assert!(o.status.success(), "{}", out(&o));
    let link = String::from_utf8_lossy(&o.stdout).trim().to_string();
    let o = run(&bo, &["join", &link]);
    assert!(o.status.success(), "{}", out(&o));
    assert!(out(&o).contains("Waiting"), "{}", out(&o));
    assert!(run(&ada, &["sync"]).status.success());
    let o = run(&bo, &["sync"]);
    assert!(out(&o).contains("joined Crew"), "{}", out(&o));
    let o = run(
        &ada,
        &["send", "--group", "Crew", "hello from the command line"],
    );
    assert!(o.status.success(), "{}", out(&o));
    let o = run(&bo, &["log", "--group", "Crew"]);
    let s2 = out(&o);
    assert!(o.status.success(), "{s2}");
    assert!(s2.contains("Ada: hello from the command line"), "{s2}");
}

/// A server that answers every request with a refusal full of terminal
/// escape codes, as a hostile operator could.
fn hostile_server() -> (tempfile::TempDir, String) {
    use socketchat_proto::msg::{from_body, to_frame, ClientFrame, Request, Response, ServerFrame};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = tempfile::tempdir().unwrap();
    socketchat_server::init(dir.path(), "127.0.0.1").unwrap();
    let mut link = socketchat_server::make_server_invite(dir.path()).unwrap();
    let acceptor = socketchat_server::tls::acceptor(dir.path()).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    link.port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut dec = socketchat_proto::FrameDecoder::default();
                    let mut buf = vec![0u8; 4096];
                    loop {
                        while let Ok(Some(b)) = dec.next_frame() {
                            let reply = match from_body::<ClientFrame>(&b) {
                                Ok(ClientFrame::Hello { version }) => {
                                    ServerFrame::HelloOk { version }
                                }
                                Ok(ClientFrame::Req {
                                    id,
                                    body: Request::Challenge,
                                }) => ServerFrame::Resp {
                                    id,
                                    body: Response::Challenge([1; 32]),
                                },
                                Ok(ClientFrame::Req { id, .. }) => ServerFrame::Resp {
                                    id,
                                    body: Response::Refused(
                                        "\x1b]0;pwned\x07\x1b[2Jgo away".into(),
                                    ),
                                },
                                Err(_) => return,
                            };
                            if tls.write_all(&to_frame(&reply).unwrap()).await.is_err() {
                                return;
                            }
                        }
                        match tls.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => dec.push(&buf[..n]),
                        }
                    }
                });
            }
        });
    });
    (dir, link.to_string())
}

#[test]
fn server_refusals_reach_the_terminal_without_escape_codes() {
    let (_dir, link) = hostile_server();
    let home = tempfile::tempdir().unwrap();
    let o = run(home.path(), &["join", &link]);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    let said = out(&o);
    assert!(said.contains("go away"), "{said:?}");
    assert!(!said.contains('\x1b') && !said.contains('\x07'), "{said:?}");
}

#[test]
fn second_process_on_one_profile_is_told_and_exits_1() {
    let s = server();
    let home = tempfile::tempdir().unwrap();
    let ada = home.path().join("Ada");
    assert!(run(&ada, &["join", &server_invite(&s)]).status.success());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let open = rt
        .block_on(socketchat_core::client::Client::open(&ada, pass()))
        .unwrap();
    let o = run(&ada, &["log", "--group", "x"]);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains("socketchat is already open on this profile."),
        "{}",
        out(&o)
    );
    drop(open);
    let o = run(&ada, &["new", "Later"]);
    assert!(o.status.success(), "{}", out(&o));
}

/// What `socketchat invites` prints, with the run's exit success.
fn invites_list(home: &Path) -> (bool, String) {
    let o = run(home, &["invites"]);
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).to_string(),
    )
}

#[test]
fn invites_lists_and_cancels() {
    let s = server();
    let home = tempfile::tempdir().unwrap();
    let ada = home.path().join("Ada");
    assert!(run(&ada, &["join", &server_invite(&s)]).status.success());
    assert!(run(&ada, &["new", "Crew"]).status.success());
    let (ok, text) = invites_list(&ada);
    assert!(ok);
    assert_eq!(text.trim(), "You have no open invite links.");

    let o = run(&ada, &["invite", "--group", "Crew"]);
    assert!(o.status.success(), "{}", out(&o));
    let (ok, text) = invites_list(&ada);
    assert!(ok);
    let rows: Vec<&str> = text.lines().collect();
    assert_eq!(rows.len(), 1, "{text}");
    assert!(rows[0].starts_with("1. "), "{text}");
    assert!(rows[0].contains(": expires in "), "{text}");

    let o = run(&ada, &["invites", "--cancel", "1"]);
    assert!(o.status.success(), "{}", out(&o));
    let said = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(
        said.starts_with("Cancelled Crew (expires in ")
            && said.trim().ends_with("). That link no longer works."),
        "{said}"
    );
    let (_, text) = invites_list(&ada);
    assert_eq!(text.trim(), "You have no open invite links.");
}

#[test]
fn invites_cancel_bad_number_exits_1() {
    let s = server();
    let home = tempfile::tempdir().unwrap();
    let ada = home.path().join("Ada");
    assert!(run(&ada, &["join", &server_invite(&s)]).status.success());
    assert!(run(&ada, &["new", "Crew"]).status.success());
    assert!(run(&ada, &["invite", "--group", "Crew"]).status.success());
    for n in ["0", "2"] {
        let o = run(&ada, &["invites", "--cancel", n]);
        assert_eq!(o.status.code(), Some(1), "{}", out(&o));
        assert!(o.stdout.is_empty(), "{}", out(&o));
        assert!(
            String::from_utf8_lossy(&o.stderr).contains(&format!(
                "There is no link {n}. Run socketchat invites to see the list."
            )),
            "{}",
            out(&o)
        );
    }
    // Nothing was cancelled.
    let (_, text) = invites_list(&ada);
    assert!(text.starts_with("1. "), "{text}");
}

#[test]
fn invites_cancel_with_no_links_exits_1() {
    let s = server();
    let home = tempfile::tempdir().unwrap();
    let ada = home.path().join("Ada");
    assert!(run(&ada, &["join", &server_invite(&s)]).status.success());
    let o = run(&ada, &["invites", "--cancel", "1"]);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(o.stdout.is_empty(), "{}", out(&o));
    assert!(
        String::from_utf8_lossy(&o.stderr)
            .contains("There is no link 1. Run socketchat invites to see the list."),
        "{}",
        out(&o)
    );
}

#[test]
fn invites_keep_their_order_and_cancel_names_the_link() {
    let s = server();
    let home = tempfile::tempdir().unwrap();
    let ada = home.path().join("Ada");
    assert!(run(&ada, &["join", &server_invite(&s)]).status.success());
    for room in ["Crew", "Band"] {
        assert!(run(&ada, &["new", room]).status.success());
        assert!(run(&ada, &["invite", "--group", room]).status.success());
    }
    let (_, first) = invites_list(&ada);
    for _ in 0..3 {
        assert_eq!(invites_list(&ada).1, first, "same order on every run");
    }
    let band = first
        .lines()
        .find(|l| l.contains("Band"))
        .and_then(|l| l.split('.').next())
        .unwrap()
        .to_string();
    let o = run(&ada, &["invites", "--cancel", &band]);
    assert!(o.status.success(), "{}", out(&o));
    let said = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(
        said.starts_with("Cancelled Band (expires in ")
            && said.trim().ends_with("). That link no longer works."),
        "{said}"
    );
    let (_, rest) = invites_list(&ada);
    assert!(rest.contains("Crew") && !rest.contains("Band"), "{rest}");
}

#[test]
fn log_marks_room_seen() {
    let s = server();
    let home = tempfile::tempdir().unwrap();
    let (ada, bo) = (home.path().join("Ada"), home.path().join("Bo"));
    assert!(run(&ada, &["join", &server_invite(&s)]).status.success());
    assert!(run(&ada, &["new", "Crew"]).status.success());
    let o = run(&ada, &["invite", "--group", "Crew"]);
    let link = String::from_utf8_lossy(&o.stdout).trim().to_string();
    assert!(run(&bo, &["join", &link]).status.success());
    assert!(run(&ada, &["sync"]).status.success());
    assert!(run(&bo, &["sync"]).status.success());
    let o = run(&ada, &["send", "--group", "Crew", "are you there"]);
    assert!(o.status.success(), "{}", out(&o));
    assert!(run(&bo, &["sync"]).status.success());
    assert_eq!(unseen_in(&bo, "Crew"), 1, "sync alone leaves it unread");

    let o = run(&bo, &["log", "--group", "Crew"]);
    assert!(out(&o).contains("Ada: are you there"), "{}", out(&o));
    assert_eq!(unseen_in(&bo, "Crew"), 0, "log marks the room read");
}

/// The unread count of a room in a profile no program has open.
fn unseen_in(home: &Path, room: &str) -> u32 {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let c = socketchat_core::client::Client::open(home, pass())
            .await
            .unwrap();
        c.groups()
            .into_iter()
            .find(|g| g.name == room)
            .unwrap()
            .unseen
    })
}

#[test]
fn log_marks_only_the_lines_it_printed() {
    let s = server();
    let home = tempfile::tempdir().unwrap();
    let (ada, bo) = (home.path().join("Ada"), home.path().join("Bo"));
    assert!(run(&ada, &["join", &server_invite(&s)]).status.success());
    assert!(run(&ada, &["new", "Crew"]).status.success());
    let o = run(&ada, &["invite", "--group", "Crew"]);
    let link = String::from_utf8_lossy(&o.stdout).trim().to_string();
    assert!(run(&bo, &["join", &link]).status.success());
    assert!(run(&ada, &["sync"]).status.success());
    assert!(run(&bo, &["sync"]).status.success());
    assert!(run(&bo, &["log", "--group", "Crew"]).status.success());
    for text in ["one", "two", "three"] {
        let o = run(&ada, &["send", "--group", "Crew", text]);
        assert!(o.status.success(), "{}", out(&o));
    }
    assert!(run(&bo, &["sync"]).status.success());
    assert_eq!(unseen_in(&bo, "Crew"), 3);

    let o = run(&bo, &["log", "--group", "Crew", "--limit", "2"]);
    let text = out(&o);
    assert!(
        text.contains("Ada: one") && text.contains("Ada: two"),
        "{text}"
    );
    assert!(!text.contains("Ada: three"), "{text}");
    assert_eq!(unseen_in(&bo, "Crew"), 1, "the unprinted line stays unread");

    let o = run(&bo, &["log", "--group", "Crew", "--limit", "2"]);
    assert!(out(&o).contains("Ada: three"), "{}", out(&o));
    assert_eq!(unseen_in(&bo, "Crew"), 0);
}
