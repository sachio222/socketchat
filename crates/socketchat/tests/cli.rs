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
    let o = run(home.path(), &["join", "chat.example.com/nope"]);
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(
        out(&o).trim(),
        "That is not a Socketchat invite link: an invite link starts with socketchat://."
    );
}

#[test]
fn join_refuses_any_other_web_address() {
    let home = tempfile::tempdir().unwrap();
    for web in [
        "https://example.com/nope",
        "https://example.com/join#socketchat://chat.example.com:7444/j/x#y",
        "http://socketchat.org/join#socketchat://chat.example.com:7444/j/x#y",
    ] {
        let o = run(home.path(), &["join", web]);
        assert_eq!(o.status.code(), Some(1), "{web}");
        assert_eq!(
            out(&o).trim(),
            "That is not a Socketchat invite link: the only web address that carries an invite is https://socketchat.org/join.",
            "{web}"
        );
    }
    assert!(
        !home.path().join(socketchat_core::store::DB_FILE).exists(),
        "a profile was made for a refused link"
    );
}

#[test]
fn join_accepts_the_web_form_of_a_link() {
    let s = server();
    let home = tempfile::tempdir().unwrap();
    let ada = home.path().join("Ada");
    let web = format!("https://socketchat.org/join#{}", server_invite(&s));
    let o = run(&ada, &["join", &web]);
    assert!(o.status.success(), "{}", out(&o));
    assert!(out(&o).contains("You are on 127.0.0.1"), "{}", out(&o));
    // The address a browser shows after the join page's redirect works too.
    let bo = home.path().join("Bo");
    let web = format!("https://socketchat.org/join/#{}", server_invite(&s));
    let o = run(&bo, &["join", &web]);
    assert!(o.status.success(), "{}", out(&o));
}

#[test]
fn join_with_a_bad_web_link_explains() {
    let home = tempfile::tempdir().unwrap();
    let o = run(home.path(), &["join", "https://socketchat.org/join#nope"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(out(&o).contains("ask for a fresh link"), "{}", out(&o));
}

#[test]
fn no_profile_explains_how_to_start() {
    let home = tempfile::tempdir().unwrap();
    let o = run(home.path(), &["log", "--group", "x"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(out(&o).contains("socketchat join"), "{}", out(&o));
}

/// `socketchat` on a computer with no profile says how to start and exits
/// cleanly, so a first run right after installing is never an error.
#[test]
fn first_run_with_no_profile_prints_how_to_start() {
    let home = tempfile::tempdir().unwrap();
    let o = run(home.path(), &[]);
    assert_eq!(o.status.code(), Some(0), "{}", out(&o));
    let said = String::from_utf8_lossy(&o.stdout);
    for step in [
        "socketchat server init                    set up a local server",
        "socketchat server run                     start a local server",
        "add --host <address> to server init",
        "socketchat join '<invite link>'",
        "socketchat ",
    ] {
        assert!(said.contains(step), "{said}");
    }
    assert!(!home.path().join(socketchat_core::store::DB_FILE).exists());
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

/// Runs `args` with `SOCKETCHAT_PASSPHRASE` set to `value`.
fn run_with_passphrase(home: &Path, value: &std::ffi::OsStr, args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env("SOCKETCHAT_HOME", home)
        .env("SOCKETCHAT_PASSPHRASE", value)
        .env("SOCKETCHAT_NAME", "Ada")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// A passphrase variable that is set but empty comes from a script
/// mistake. It never makes a profile without a passphrase, and never opens
/// one either.
#[test]
fn an_empty_passphrase_variable_is_refused_before_anything_is_made() {
    let s = server();
    let home = tempfile::tempdir().unwrap();
    let ada = home.path().join("Ada");
    let empty = std::ffi::OsStr::new("");
    let o = run_with_passphrase(&ada, empty, &["join", &server_invite(&s)]);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains("SOCKETCHAT_PASSPHRASE is set but empty"),
        "{}",
        out(&o)
    );
    assert!(!ada.join("socketchat.db").exists(), "a profile was made");
    assert!(!ada.join("salt").exists(), "a salt file was made");

    // A profile with a passphrase: the empty value does not open it, and
    // the message names the empty variable, not a wrong passphrase.
    assert!(run(&ada, &["join", &server_invite(&s)]).status.success());
    let o = run_with_passphrase(&ada, empty, &["log", "--group", "x"]);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains("SOCKETCHAT_PASSPHRASE is set but empty"),
        "{}",
        out(&o)
    );
    assert!(!out(&o).contains("has no passphrase"), "{}", out(&o));
}

/// A profile an earlier release made with an empty passphrase still opens
/// with an empty value, and says each time that it has no passphrase.
#[test]
fn a_profile_with_no_passphrase_opens_with_a_warning() {
    let home = tempfile::tempdir().unwrap();
    let ada = home.path().join("Ada");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(
        socketchat_core::client::Client::create_profile_with_any_passphrase(&ada, "", "Ada"),
    )
    .unwrap();
    let o = run_with_passphrase(&ada, std::ffi::OsStr::new(""), &["sync"]);
    assert_eq!(o.status.code(), Some(0), "{}", out(&o));
    let said = out(&o);
    assert!(said.contains("This profile has no passphrase"), "{said}");
    assert!(!said.contains("set but empty"), "{said}");
    // A real passphrase does not open it.
    let o = run(&ada, &["sync"]);
    assert_eq!(o.status.code(), Some(2), "{}", out(&o));
}

/// A profile whose making stopped part way, leaving a salt file and an
/// empty database, is moved aside and made again by the next join.
#[test]
fn join_makes_a_profile_again_after_an_unfinished_one() {
    let s = server();
    let home = tempfile::tempdir().unwrap();
    let ada = home.path().join("Ada");
    std::fs::create_dir_all(&ada).unwrap();
    std::fs::write(ada.join("salt"), [9u8; 16]).unwrap();
    std::fs::write(ada.join("socketchat.db"), b"").unwrap();
    let o = run(&ada, &["join", &server_invite(&s)]);
    assert!(o.status.success(), "{}", out(&o));
    assert!(out(&o).contains("unfinished"), "{}", out(&o));
    assert!(run(&ada, &["sync"]).status.success());
    let aside = std::fs::read_dir(&ada)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("salt.unfinished-")
        })
        .count();
    assert_eq!(aside, 1);
}

/// Setup stopped while the key was being made, or while an unfinished
/// profile was being moved aside after its salt file went: the next join
/// finishes it.
#[test]
fn join_finishes_a_setup_stopped_at_any_point() {
    let s = server();
    let home = tempfile::tempdir().unwrap();
    // While the key was being made: an empty database and its salt file.
    let ada = home.path().join("Ada");
    std::fs::create_dir_all(&ada).unwrap();
    let mut salt = b"sckdf\x01".to_vec();
    for v in [8 * 1024u32, 1, 1] {
        salt.extend_from_slice(&v.to_be_bytes());
    }
    salt.extend_from_slice(&[3; 16]);
    std::fs::write(ada.join("salt"), &salt).unwrap();
    std::fs::write(ada.join("socketchat.db"), b"").unwrap();
    let o = run(&ada, &["join", &server_invite(&s)]);
    assert!(o.status.success(), "{}", out(&o));
    assert!(run(&ada, &["sync"]).status.success());
    // While moving aside: the salt file already moved, the database not.
    let bo = home.path().join("Bo");
    std::fs::create_dir_all(&bo).unwrap();
    std::fs::write(bo.join("salt.unfinished-1700000000"), &salt).unwrap();
    std::fs::write(bo.join("socketchat.db"), b"").unwrap();
    let o = run(&bo, &["join", &server_invite(&s)]);
    assert!(o.status.success(), "{}", out(&o));
    assert!(run(&bo, &["sync"]).status.success());
}

/// Setup stopped while the salt file was being written leaves part of it
/// under a temporary name, which the next join moves aside.
#[test]
fn join_finishes_a_setup_stopped_while_writing_the_salt_file() {
    let s = server();
    let home = tempfile::tempdir().unwrap();
    let ada = home.path().join("Ada");
    std::fs::create_dir_all(&ada).unwrap();
    std::fs::write(ada.join("socketchat.db"), b"").unwrap();
    std::fs::write(ada.join("salt.new"), b"sckdf").unwrap();
    let o = run(&ada, &["join", &server_invite(&s)]);
    assert!(o.status.success(), "{}", out(&o));
    assert!(run(&ada, &["sync"]).status.success());
    let aside = std::fs::read_dir(&ada)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("salt.new.unfinished-")
        })
        .count();
    assert_eq!(aside, 1);
}

/// A salt file waiting for its database is never replaced by a join.
#[test]
fn join_keeps_a_salt_file_without_its_database() {
    let s = server();
    let home = tempfile::tempdir().unwrap();
    let ada = home.path().join("Ada");
    std::fs::create_dir_all(&ada).unwrap();
    std::fs::write(ada.join("salt"), [9u8; 16]).unwrap();
    let o = run(&ada, &["join", &server_invite(&s)]);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(out(&o).contains("without its database"), "{}", out(&o));
    assert_eq!(std::fs::read(ada.join("salt")).unwrap(), [9u8; 16]);
    assert!(!ada.join("socketchat.db").exists());
}

/// A profile whose salt file is gone says so instead of "no profile".
#[test]
fn a_profile_without_its_salt_file_says_so() {
    let s = server();
    let home = tempfile::tempdir().unwrap();
    let ada = home.path().join("Ada");
    assert!(run(&ada, &["join", &server_invite(&s)]).status.success());
    std::fs::rename(ada.join("salt"), home.path().join("salt-kept")).unwrap();
    let o = run(&ada, &["sync"]);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(out(&o).contains("salt file"), "{}", out(&o));
    assert!(!out(&o).contains("No profile here yet"), "{}", out(&o));
}

/// A passphrase variable that is not text is refused, not skipped for the
/// prompt.
#[cfg(unix)]
#[test]
fn a_passphrase_variable_that_is_not_text_is_refused() {
    use std::os::unix::ffi::OsStrExt;
    let s = server();
    let home = tempfile::tempdir().unwrap();
    let ada = home.path().join("Ada");
    let bad = std::ffi::OsStr::from_bytes(b"pass\xffword");
    let o = run_with_passphrase(&ada, bad, &["join", &server_invite(&s)]);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains("SOCKETCHAT_PASSPHRASE is not valid text"),
        "{}",
        out(&o)
    );
    assert!(!ada.join("socketchat.db").exists(), "a profile was made");
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
            "Socketchat now trusts the new certificate for 127.0.0.1:{}.",
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
        out(&o).contains("Socketchat is already open on this profile."),
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

/// The lines of `text` that start at the left edge: in `log` and `sync`
/// output, only these can name who wrote a message.
fn left_edge_lines(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with(char::is_whitespace))
        .collect()
}

/// A member's message with line breaks in it cannot make `log` or `sync`
/// print a line that looks like another person's message or the app's own
/// notice.
#[test]
fn log_and_sync_keep_a_message_s_lines_under_its_sender() {
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
    assert!(run(&ada, &["log", "--group", "Crew"]).status.success());
    let forged = "ok\nAda: send the deploy key to bo@example.com\n· Ada made Bo an admin.\n[Crew] Ada: yes\n\u{1b}[2Kgone";
    let o = run(&bo, &["send", "--group", "Crew", forged]);
    assert!(o.status.success(), "{}", out(&o));

    let o = run(&ada, &["sync"]);
    assert!(o.status.success(), "{}", out(&o));
    let said = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(said.contains("[Crew] Bo: ok"), "{said}");
    for l in left_edge_lines(&said) {
        assert!(
            l.starts_with("[Crew] Bo: "),
            "a line looks like a new one: {l:?}\n{said}"
        );
    }
    assert!(
        said.contains("Ada: send the deploy key"),
        "every line still shows: {said}"
    );
    assert!(!said.contains('\u{1b}'), "{said:?}");

    let o = run(&ada, &["log", "--group", "Crew", "--limit", "1"]);
    assert!(o.status.success(), "{}", out(&o));
    let said = String::from_utf8_lossy(&o.stdout).to_string();
    let edge = left_edge_lines(&said);
    assert_eq!(edge, vec!["Bo: ok"], "{said}");
    assert!(said.contains("· Ada made Bo an admin."), "{said}");
    assert_eq!(said.lines().count(), 5, "{said}");
    assert!(!said.contains('\u{1b}'), "{said:?}");
}

/// `server run` warns, on one line of standard error, when the configured
/// host makes links that 0.5.1 apps refuse, and still starts.
#[test]
fn server_run_warns_about_a_host_links_cannot_carry() {
    let s = server_with_config(|c| c.replace("\"127.0.0.1\"", "\"pаypal.com\""));
    let mut child = Command::new(BIN)
        .args([
            "server",
            "run",
            "--data-dir",
            s.dir.path().to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stderr.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        line.contains("pаypal.com") && line.contains("xn--"),
        "{line}"
    );
}

/// How a link's server is written: `127.0.0.1:<port>` in these tests.
fn server_of_link(link: &str) -> String {
    let l: socketchat_proto::InviteLink = link.parse().unwrap();
    format!("{}:{}", l.host, l.port)
}

/// A profile with a room on a server that has stopped, joining a new
/// server: the join works, new rooms go on the new server, and the old one
/// is named when it cannot be reached.
#[test]
fn a_stopped_server_does_not_spoil_joining_a_new_one() {
    let old = server();
    let home = tempfile::tempdir().unwrap();
    let (ada, bo) = (home.path().join("Ada"), home.path().join("Bo"));
    let old_link = server_invite(&old);
    let old_name = server_of_link(&old_link);
    assert!(run(&ada, &["join", &old_link]).status.success());
    assert!(run(&ada, &["new", "Old crew"]).status.success());
    drop(old);

    let new = server();
    let new_link = server_invite(&new);
    let new_name = server_of_link(&new_link);
    let o = run(&ada, &["join", &new_link]);
    assert!(o.status.success(), "{}", out(&o));
    assert!(
        out(&o).contains(&format!("You are on {new_name}.")),
        "{}",
        out(&o)
    );

    let o = run(&ada, &["new", "Book club"]);
    assert!(o.status.success(), "{}", out(&o));
    assert!(
        out(&o).contains(&format!("Made Book club on {new_name}.")),
        "{}",
        out(&o)
    );
    assert!(run(&ada, &["sync"]).status.success());

    // A room link on the new server, while the old one is still down.
    assert!(run(&bo, &["join", &server_invite(&new)]).status.success());
    assert!(run(&bo, &["new", "Crew"]).status.success());
    let o = run(&bo, &["invite", "--group", "Crew"]);
    let link = String::from_utf8_lossy(&o.stdout).trim().to_string();
    let o = run(&ada, &["join", &link]);
    assert!(o.status.success(), "{}", out(&o));
    assert!(out(&o).contains("Waiting"), "{}", out(&o));

    // The old server's room names its server.
    let o = run(&ada, &["invite", "--group", "Old crew"]);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains(&format!(
            "Could not reach {old_name}: connection refused. Run socketchat servers to see your servers."
        )),
        "{}",
        out(&o)
    );
}

#[test]
fn servers_lists_and_forgets() {
    let (one, two) = (server(), server());
    let home = tempfile::tempdir().unwrap();
    let ada = home.path().join("Ada");
    let (l1, l2) = (server_invite(&one), server_invite(&two));
    let (n1, n2) = (server_of_link(&l1), server_of_link(&l2));
    assert!(run(&ada, &["join", &l1]).status.success());
    assert!(run(&ada, &["new", "First"]).status.success());
    assert!(run(&ada, &["join", &l2]).status.success());
    assert!(run(&ada, &["new", "Second"]).status.success());
    let o = run(&ada, &["new", "Third", "--server", "1"]);
    assert!(o.status.success(), "{}", out(&o));
    assert!(
        out(&o).contains(&format!("Made Third on {n1}.")),
        "{}",
        out(&o)
    );
    let o = run(&ada, &["new", "Fourth", "--server", "9"]);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains("There is no server 9. Run socketchat servers to see the list."),
        "{}",
        out(&o)
    );

    let o = run(&ada, &["servers"]);
    assert!(o.status.success(), "{}", out(&o));
    assert_eq!(
        String::from_utf8_lossy(&o.stdout).trim(),
        format!("1. {n1}: 2 rooms, connected\n2. {n2}: 1 room, connected (new rooms go here)")
    );

    drop(one);
    let o = run(&ada, &["servers"]);
    assert!(
        String::from_utf8_lossy(&o.stdout).contains(&format!(
            "1. {n1}: 2 rooms, could not reach: connection refused"
        )),
        "{}",
        out(&o)
    );

    // Not on a terminal, it needs --yes.
    let o = run(&ada, &["servers", "--forget", "1"]);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(out(&o).contains("--yes"), "{}", out(&o));
    let o = run(&ada, &["servers", "--forget", "7", "--yes"]);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains("There is no server 7. Run socketchat servers to see the list."),
        "{}",
        out(&o)
    );
    let o = run(&ada, &["servers", "--forget", "1", "--yes"]);
    assert!(o.status.success(), "{}", out(&o));
    assert!(
        out(&o).contains(&format!(
            "Forgot {n1}. Its 2 rooms are deleted from this computer."
        )),
        "{}",
        out(&o)
    );
    let o = run(&ada, &["servers"]);
    assert_eq!(
        String::from_utf8_lossy(&o.stdout).trim(),
        format!("1. {n2}: 1 room, connected (new rooms go here)")
    );
    assert!(run(&ada, &["send", "--group", "Second", "still here"])
        .status
        .success());
}

#[test]
fn the_topic_through_binary() {
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
    let o = run(&bo, &["topic", "--group", "Crew"]);
    assert!(o.status.success(), "{}", out(&o));
    assert_eq!(out(&o).trim(), "Crew has no topic.");
    let o = run(
        &ada,
        &[
            "topic",
            "--group",
            "Crew",
            "Piranesi",
            "\x1b[2Jtonight\u{202E}",
        ],
    );
    assert!(o.status.success(), "{}", out(&o));
    assert_eq!(out(&o).trim(), "Set the topic of Crew.");
    let o = run(&bo, &["topic", "--group", "Crew"]);
    let said = out(&o);
    assert!(o.status.success(), "{said}");
    assert!(
        said.starts_with("Topic: Piranesi [2Jtonight (set by Ada, "),
        "{said}"
    );
    assert!(
        !said.contains('\x1b') && !said.contains('\u{202E}'),
        "{said:?}"
    );
    let o = run(&bo, &["log", "--group", "Crew"]);
    assert!(
        out(&o).contains("· Topic: Piranesi [2Jtonight (set by Ada, "),
        "{}",
        out(&o)
    );
    let o = run(&bo, &["topic", "--group", "Crew", "--clear"]);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains("Only admins can set this room's topic."),
        "{}",
        out(&o)
    );
    let o = run(&ada, &["topic", "--group", "Crew", "--clear"]);
    assert!(o.status.success(), "{}", out(&o));
    assert_eq!(out(&o).trim(), "Cleared the topic of Crew.");
    let o = run(&bo, &["topic", "--group", "Crew"]);
    assert_eq!(out(&o).trim(), "Crew has no topic.");
    let o = run(&ada, &["topic", "--group", "Crew", "--clear", "both"]);
    assert!(!o.status.success());
}

#[test]
fn status_prints_the_same_facts_as_plain_lines() {
    use socketchat_core::keys::fingerprint_text;
    let s = server();
    let home = tempfile::tempdir().unwrap();
    let ada = home.path().join("Ada");
    let raw = server_invite(&s);
    let link: socketchat_proto::InviteLink = raw.parse().unwrap();
    assert!(run(&ada, &["join", &raw]).status.success());
    assert!(run(&ada, &["new", "Crew"]).status.success());

    let o = run(&ada, &["status"]);
    let said = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(o.status.success(), "{}", out(&o));
    let lines: Vec<&str> = said.lines().collect();
    for want in [
        "Connection".to_string(),
        "Server: 127.0.0.1".into(),
        format!("Port: {}", link.port),
        format!("Protocol: {}", socketchat_proto::PROTOCOL_VERSION),
        format!(
            "Certificate fingerprint: {}",
            fingerprint_text(&link.cert_fpr)
        ),
        "Inviting into rooms: each room's setting decides".into(),
        "You".into(),
        "Name: Ada".into(),
        "Rooms on this server: 1".into(),
        "App".into(),
        format!("Version: {}", env!("CARGO_PKG_VERSION")),
        "Theme: phosphor".into(),
        "Mouse: on".into(),
        "/details lists what the server can and cannot see in each room.".into(),
    ] {
        assert!(lines.contains(&want.as_str()), "{want}:\n{said}");
    }
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("State: connected since ")),
        "{said}"
    );
    assert!(
        lines.iter().any(|l| l.starts_with("Update check: ")),
        "{said}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("Your half of each safety number: ") && l.len() == 68),
        "{said}"
    );
    assert!(
        !lines.contains(&"This room"),
        "no room without --group:\n{said}"
    );
    // Plain lines, no box.
    assert!(!said.contains('│') && !said.contains('┌'), "{said}");

    let o = run(&ada, &["status", "--group", "Crew"]);
    let said = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(o.status.success(), "{}", out(&o));
    let lines: Vec<&str> = said.lines().collect();
    for want in [
        "This room",
        "Name: Crew",
        "Kind: group chat",
        "Members: 1, 1 verified",
        "Admins: 1",
        "Your role: admin",
        "Who can invite: anyone in the room",
        "Slow mode: off",
        "Has a topic: no",
        "Encryption: end-to-end, MLS (RFC 9420)",
        "Suite: MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519 (0x004F)",
    ] {
        assert!(lines.contains(&want), "{want}:\n{said}");
    }

    let o = run(&ada, &["status", "--group", "Nope"]);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains("You are not in a group called Nope."),
        "{}",
        out(&o)
    );

    // A server that is down still gets a status, saying why.
    drop(s);
    let o = run(&ada, &["status", "--group", "Crew"]);
    let said = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(o.status.success(), "{}", out(&o));
    assert!(
        said.lines()
            .any(|l| l == "State: could not reach: connection refused"),
        "{said}"
    );
    assert!(!said.lines().any(|l| l.starts_with("Protocol")), "{said}");
    assert!(said.lines().any(|l| l == "Name: Crew"), "{said}");
}

#[test]
fn invite_by_name_through_binary() {
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
    assert!(run(&ada, &["new", "Climb"]).status.success());
    let o = run(&ada, &["invite", "Bo"]);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains("Name the room to invite them to with --group <name>."),
        "{}",
        out(&o)
    );
    let o = run(&ada, &["invite", "--group", "Climb", "Zed"]);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(
        out(&o).contains("Nobody called Zed shares a room with you."),
        "{}",
        out(&o)
    );
    let o = run(&ada, &["invite", "--group", "Climb", "Bo"]);
    assert!(o.status.success(), "{}", out(&o));
    assert_eq!(
        out(&o).trim(),
        "Invited Bo to Climb through Crew. Once Bo types /join Climb, socketchat sync or the chat screen adds them."
    );
    // Climb keeps a line that the invite went, for the chat screen later.
    let o = run(&ada, &["log", "--group", "Climb"]);
    assert!(out(&o).contains("Invite sent to Bo."), "{}", out(&o));
    // Bo's app gives its key; Ada's sends the rest; Bo hears the invite.
    assert!(run(&bo, &["sync"]).status.success());
    assert!(run(&ada, &["sync"]).status.success());
    let o = run(&bo, &["sync"]);
    assert!(
        out(&o).contains("[Crew] · Ada invites you to Climb. Type /join Climb to join."),
        "{}",
        out(&o)
    );
}
