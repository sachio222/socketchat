//! The update notice and `socketchat update`, through the program.
//!
//! Programs built for tests never reach GitHub: they ask the local
//! stand-in named by `SOCKETCHAT_TEST_UPDATE_URL`, or nobody.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};

const BIN: &str = env!("CARGO_BIN_EXE_socketchat");
const PASS: &str = "update test passphrase";
const NOTICE: &str = "Socketchat 99.0.0 is out. Run socketchat update.";

/// A stand-in for GitHub's API on a free local port. Every connection gets
/// `reply`, or is closed at once when `reply` is empty. It keeps each
/// request it read.
struct StandIn {
    url: String,
    seen: Arc<Mutex<Vec<String>>>,
}

impl StandIn {
    fn start(reply: Vec<u8>) -> StandIn {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let keep = seen.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { break };
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                keep.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&req).into_owned());
                if !reply.is_empty() {
                    let _ = s.write_all(&reply);
                }
            }
        });
        StandIn { url, seen }
    }

    /// A stand-in that names `tag` as the newest release.
    fn naming(tag: &str) -> StandIn {
        let body = format!(
            r#"{{"tag_name":"{tag}","name":"{tag}","draft":false,"prerelease":false,"body":"Notes","assets":[]}}"#
        );
        StandIn::start(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .into_bytes(),
        )
    }

    fn requests(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

/// A new profile in a fresh folder; the folder's name is the display name.
fn profile() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("Ada");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(socketchat_core::client::Client::create_profile(
        &home, PASS, "Ada",
    ))
    .unwrap();
    (d, home)
}

fn cmd(bin: &Path, home: &Path, url: &str) -> Command {
    let mut c = Command::new(bin);
    c.env("SOCKETCHAT_HOME", home)
        .env("SOCKETCHAT_PASSPHRASE", PASS)
        .env("SOCKETCHAT_TEST_UPDATE_URL", url)
        .env_remove("SOCKETCHAT_NO_UPDATE_CHECK")
        .stdin(Stdio::null());
    c
}

fn sync(home: &Path, url: &str) -> Output {
    cmd(Path::new(BIN), home, url).arg("sync").output().unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn a_newer_release_shows_the_notice_and_the_app_asks_once_a_day() {
    let gh = StandIn::naming("v99.0.0");
    let (_d, home) = profile();
    let o = sync(&home, &gh.url);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(String::from_utf8_lossy(&o.stderr).trim(), NOTICE);
    let reqs = gh.requests();
    assert_eq!(reqs.len(), 1, "{reqs:?}");
    assert!(
        reqs[0].starts_with("GET /repos/sachio222/socketchat/releases/latest HTTP/1.1\r\n"),
        "{}",
        reqs[0]
    );
    // Nothing about the person rides along.
    for private in ["Ada", PASS, home.to_str().unwrap()] {
        assert!(!reqs[0].contains(private), "{private} in {}", reqs[0]);
    }
    // The next run the same day asks nobody and still says it.
    let o = sync(&home, &gh.url);
    assert_eq!(String::from_utf8_lossy(&o.stderr).trim(), NOTICE);
    assert_eq!(gh.requests().len(), 1);
}

#[test]
fn the_same_or_an_older_release_shows_nothing() {
    for tag in [
        format!("v{}", env!("CARGO_PKG_VERSION")),
        "v0.0.1".to_string(),
        "v0.1.0".to_string(),
    ] {
        let gh = StandIn::naming(&tag);
        let (_d, home) = profile();
        let o = sync(&home, &gh.url);
        assert!(o.status.success(), "{}", text(&o));
        assert_eq!(gh.requests().len(), 1, "{tag}");
        assert_eq!(String::from_utf8_lossy(&o.stderr), "", "{tag}");
    }
}

#[test]
fn a_pre_release_of_a_newer_version_counts_as_newer() {
    let gh = StandIn::naming("v99.0.0-rc.1");
    let (_d, home) = profile();
    let o = sync(&home, &gh.url);
    assert_eq!(
        String::from_utf8_lossy(&o.stderr).trim(),
        "Socketchat 99.0.0-rc.1 is out. Run socketchat update."
    );
}

#[test]
fn the_variable_stops_the_request() {
    let gh = StandIn::naming("v99.0.0");
    let (_d, home) = profile();
    for value in ["1", "yes"] {
        let o = cmd(Path::new(BIN), &home, &gh.url)
            .env("SOCKETCHAT_NO_UPDATE_CHECK", value)
            .arg("sync")
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", text(&o));
        assert_eq!(String::from_utf8_lossy(&o.stderr), "");
    }
    assert!(gh.requests().is_empty(), "{:?}", gh.requests());
}

#[test]
fn the_setting_stops_the_request() {
    let gh = StandIn::naming("v99.0.0");
    let (_d, home) = profile();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let c = socketchat_core::client::Client::open(&home, PASS)
            .await
            .unwrap();
        c.set_update_check(false).unwrap();
    });
    let o = sync(&home, &gh.url);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(String::from_utf8_lossy(&o.stderr), "");
    assert!(gh.requests().is_empty(), "{:?}", gh.requests());
}

#[test]
fn a_failed_check_is_silent() {
    let free = TcpListener::bind("127.0.0.1:0").unwrap();
    let nobody = format!("http://{}", free.local_addr().unwrap());
    drop(free);
    let refused = StandIn::start(Vec::new());
    let broken = StandIn::start(b"HTTP/1.1 500 Oops\r\nContent-Length: 0\r\n\r\n".to_vec());
    let nonsense = StandIn::start(b"hello\r\n\r\n".to_vec());
    for url in [&nobody, &refused.url, &broken.url, &nonsense.url] {
        let (_d, home) = profile();
        let o = sync(&home, url);
        assert!(o.status.success(), "{url}: {}", text(&o));
        assert_eq!(text(&o), "", "{url}");
    }
}

/// A copy of the program at `dir/rel`, so it runs from a path of the
/// test's choosing.
fn copy_program(dir: &Path, rel: &str) -> PathBuf {
    let to = dir.join(rel);
    std::fs::create_dir_all(to.parent().unwrap()).unwrap();
    std::fs::copy(BIN, &to).unwrap();
    to
}

#[test]
fn a_homebrew_install_is_told_to_use_brew() {
    let gh = StandIn::naming("v99.0.0");
    let (d, home) = profile();
    let brewed = copy_program(d.path(), "Cellar/socketchat/0.5.1/bin/socketchat");
    let o = cmd(&brewed, &home, &gh.url).arg("sync").output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&o.stderr).trim(),
        "Socketchat 99.0.0 is out. Run brew upgrade socketchat."
    );
}

const CURL: &str = "curl --proto '=https' --tlsv1.2 -LsSf https://github.com/sachio222/socketchat/releases/latest/download/socketchat-installer.sh | sh";
const POWERSHELL: &str = "powershell -ExecutionPolicy Bypass -c \"irm https://github.com/sachio222/socketchat/releases/latest/download/socketchat-installer.ps1 | iex\"";

/// Runs `socketchat update` from `program`, with `home` as the home folder
/// and no XDG folders set, so only `home` decides where the installer puts
/// programs.
fn update_from(program: &Path, home: &Path) -> Output {
    Command::new(program)
        .arg("update")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("XDG_BIN_HOME")
        .env_remove("XDG_DATA_HOME")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// `socketchat update` installs nothing: it only prints a command, and
/// leaves the folder it runs from as it was.
fn assert_installs_nothing(program: &Path) {
    let dir = program.parent().unwrap();
    let names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        names,
        vec![std::ffi::OsString::from(program.file_name().unwrap())]
    );
}

#[test]
fn update_on_a_homebrew_install_prints_the_brew_command() {
    let d = tempfile::tempdir().unwrap();
    let brewed = copy_program(d.path(), "Cellar/socketchat/0.5.1/bin/socketchat");
    let o = update_from(&brewed, &d.path().join("home"));
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert_eq!(
        String::from_utf8_lossy(&o.stdout),
        "Homebrew installed this copy of Socketchat. To update it, run:\n  brew upgrade socketchat\n"
    );
    assert_installs_nothing(&brewed);
}

#[test]
fn update_on_an_installer_copy_prints_the_install_command() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("home");
    let program = copy_program(&home, ".local/bin/socketchat");
    let o = update_from(&program, &home);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let want = if cfg!(windows) {
        format!("The Socketchat installer put this copy here. To update it, run the install command again in PowerShell:\n  {POWERSHELL}\n")
    } else {
        format!("The Socketchat installer put this copy here. To update it, run the install command again:\n  {CURL}\n")
    };
    assert_eq!(String::from_utf8_lossy(&o.stdout), want);
    assert_installs_nothing(&program);
}

#[test]
fn the_installer_folder_follows_xdg_bin_home() {
    let d = tempfile::tempdir().unwrap();
    let program = copy_program(d.path(), "mybin/socketchat");
    let o = Command::new(&program)
        .arg("update")
        .env("HOME", d.path().join("home"))
        .env("USERPROFILE", d.path().join("home"))
        .env("XDG_BIN_HOME", d.path().join("mybin"))
        .env_remove("XDG_DATA_HOME")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&o.stdout)
            .starts_with("The Socketchat installer put this copy here."),
        "{}",
        text(&o)
    );
}

#[test]
fn update_on_an_unknown_copy_prints_every_command() {
    let d = tempfile::tempdir().unwrap();
    let program = copy_program(d.path(), "elsewhere/socketchat");
    let o = update_from(&program, &d.path().join("home"));
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert_eq!(
        String::from_utf8_lossy(&o.stdout),
        format!(
            "To update Socketchat, run the command for the way you installed it.\n  Homebrew: brew upgrade socketchat\n  Installer on macOS or Linux: {CURL}\n  Installer on Windows, in PowerShell: {POWERSHELL}\n"
        )
    );
    assert_installs_nothing(&program);
}

#[test]
fn update_is_in_the_help() {
    let o = Command::new(BIN).arg("--help").output().unwrap();
    let help = text(&o);
    assert!(
        help.lines().any(|l| l.trim_start().starts_with("update ")
            && l.contains("Print the command that updates Socketchat")),
        "{help}"
    );
}
