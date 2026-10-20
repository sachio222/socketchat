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
    let dir = tempfile::tempdir().unwrap();
    let listen = format!("127.0.0.1:{}", free_port());
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
            &listen,
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
    assert!(first.contains("listening"), "{first}");
    Server { child, dir }
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
