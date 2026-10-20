use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_socketchat");
const PASS: &str = "correct horse battery staple";

fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env("SOCKETCHAT_HOME", home)
        .env("SOCKETCHAT_PASSPHRASE", PASS)
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
        .env("SOCKETCHAT_PASSPHRASE", "not it")
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
