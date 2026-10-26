//! The update notice: at most once a day, the app asks GitHub which
//! Socketchat release is the newest, and says so when it is newer than the
//! app itself.
//!
//! The question is one HTTPS request to api.github.com for the latest
//! release of sachio222/socketchat. It carries no cookie, no token and
//! nothing about the person, their profile or their chats: only the fixed
//! request below with "socketchat" as the user agent. GitHub sees the
//! computer's IP address and the time, as with any web request. A setting
//! in the profile and the `SOCKETCHAT_NO_UPDATE_CHECK` environment variable
//! turn the check off, and then the app makes no request at all. A check
//! that fails says nothing.
//!
//! Nothing here installs anything. `socketchat update` only prints the
//! command that installs the new version.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// The GitHub repository whose releases the check looks at.
pub const REPO: &str = "sachio222/socketchat";

/// Set to anything but empty or `0`, this turns the check off.
pub const OFF_VAR: &str = "SOCKETCHAT_NO_UPDATE_CHECK";

/// How long the app waits between two checks.
pub const EVERY_SECS: u64 = 24 * 60 * 60;

/// The one request the check makes, after the host.
pub const LATEST_PATH: &str = "/repos/sachio222/socketchat/releases/latest";

const GITHUB_API: &str = "api.github.com";

/// How long a whole check may take, connecting included.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// The largest answer the check reads. GitHub's answer for one release is
/// tens of kilobytes.
const MAX_RESPONSE: usize = 1024 * 1024;

/// The longest version text the check accepts.
const MAX_VERSION: usize = 64;

/// A release version: major.minor.patch, an optional pre-release part such
/// as `rc.1`, and build metadata after `+`, which ordering ignores.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Vec<Ident>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Ident {
    Num(u64),
    Text(String),
}

impl Version {
    /// Reads `0.5.2`, `v0.5.2`, `0.6.0-rc.1` or `0.5.2+build`. Anything
    /// else is `None`.
    pub fn parse(s: &str) -> Option<Version> {
        if s.len() > MAX_VERSION {
            return None;
        }
        let s = s.strip_prefix('v').unwrap_or(s);
        // Build metadata: dot-separated words, which ordering ignores.
        let s = match s.split_once('+') {
            Some((s, build)) => build.split('.').all(ident_ok).then_some(s)?,
            None => s,
        };
        let (core, pre) = match s.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (s, None),
        };
        let num = |p: &str| -> Option<u64> {
            (!p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
                .then(|| p.parse().ok())
                .flatten()
        };
        let mut parts = core.split('.');
        let (major, minor, patch) = (
            num(parts.next()?)?,
            num(parts.next()?)?,
            num(parts.next()?)?,
        );
        if parts.next().is_some() {
            return None;
        }
        let pre = match pre {
            None => vec![],
            Some(p) => p
                .split('.')
                .map(|id| {
                    if !ident_ok(id) {
                        None
                    } else if id.bytes().all(|b| b.is_ascii_digit()) {
                        id.parse().ok().map(Ident::Num)
                    } else {
                        Some(Ident::Text(id.to_string()))
                    }
                })
                .collect::<Option<Vec<_>>>()?,
        };
        Some(Version {
            major,
            minor,
            patch,
            pre,
        })
    }
}

/// A pre-release or build word: ASCII letters, digits and hyphens.
fn ident_ok(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        for (i, id) in self.pre.iter().enumerate() {
            f.write_str(if i == 0 { "-" } else { "." })?;
            match id {
                Ident::Num(n) => write!(f, "{n}")?,
                Ident::Text(t) => f.write_str(t)?,
            }
        }
        Ok(())
    }
}

impl Ord for Version {
    /// Semantic Versioning's order: a pre-release comes before its
    /// release, and pre-release words compare one by one, numbers by value
    /// and before any word.
    fn cmp(&self, other: &Version) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => {
                    for (a, b) in self.pre.iter().zip(&other.pre) {
                        let o = match (a, b) {
                            (Ident::Num(a), Ident::Num(b)) => a.cmp(b),
                            (Ident::Num(_), Ident::Text(_)) => Ordering::Less,
                            (Ident::Text(_), Ident::Num(_)) => Ordering::Greater,
                            (Ident::Text(a), Ident::Text(b)) => a.cmp(b),
                        };
                        if o != Ordering::Equal {
                            return o;
                        }
                    }
                    self.pre.len().cmp(&other.pre.len())
                }
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Version) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Whether a value of [`OFF_VAR`] turns the check off: anything but unset,
/// empty or `0`.
pub fn off_by_env_value(v: Option<&std::ffi::OsStr>) -> bool {
    v.is_some_and(|v| !v.is_empty() && v != "0")
}

/// Whether [`OFF_VAR`] turns the check off for this run.
pub fn off_by_env() -> bool {
    off_by_env_value(std::env::var_os(OFF_VAR).as_deref())
}

/// How this copy of Socketchat was installed, as far as updating goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Install {
    /// Homebrew installed it, so `brew upgrade socketchat` updates it.
    Homebrew,
    /// The Socketchat installer put it in one of its folders, so running
    /// the install command again updates it.
    Installer,
    /// Anything else, such as a program built by hand.
    Unknown,
}

/// Whether the program at `exe` sits in Homebrew's Cellar. Homebrew keeps
/// every formula at `<prefix>/Cellar/<name>/<version>`, whatever the
/// prefix, and links it into `<prefix>/bin`, so the path is followed to
/// the program itself first.
pub fn installed_by_homebrew(exe: &Path) -> bool {
    let real = std::fs::canonicalize(exe).unwrap_or_else(|_| exe.to_path_buf());
    let parts: Vec<&std::ffi::OsStr> = real.components().map(|c| c.as_os_str()).collect();
    parts
        .windows(2)
        .any(|w| w[0] == "Cellar" && w[1] == "socketchat")
}

/// The folders the Socketchat installer puts the program in, in the order
/// it tries them (dist-workspace.toml's install-path): `$XDG_BIN_HOME`,
/// `$XDG_DATA_HOME/../bin`, then `.local/bin` in each of `homes`. An XDG
/// folder that is empty or relative does not count.
pub fn installer_dirs(
    xdg_bin: Option<&Path>,
    xdg_data: Option<&Path>,
    homes: &[PathBuf],
) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(d) = xdg_bin.filter(|d| d.is_absolute()) {
        dirs.push(d.to_path_buf());
    }
    if let Some(d) = xdg_data.filter(|d| d.is_absolute()) {
        dirs.push(d.join("../bin"));
    }
    for h in homes.iter().filter(|h| h.is_absolute()) {
        let d = h.join(".local/bin");
        if !dirs.contains(&d) {
            dirs.push(d);
        }
    }
    dirs
}

/// Whether the program at `exe` sits in one of `dirs`, links followed on
/// both sides.
pub fn installed_by_installer(exe: &Path, dirs: &[PathBuf]) -> bool {
    let real = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let Some(at) = real(exe).parent().map(Path::to_path_buf) else {
        return false;
    };
    dirs.iter().any(|d| real(d) == at)
}

/// How the program at `exe` was installed, with the installer's folders
/// taken from this run's environment.
pub fn install_kind_of(exe: &Path) -> Install {
    if installed_by_homebrew(exe) {
        return Install::Homebrew;
    }
    let var = |name: &str| std::env::var_os(name).map(PathBuf::from);
    let homes: Vec<PathBuf> = [var("HOME"), var("USERPROFILE")]
        .into_iter()
        .flatten()
        .collect();
    let dirs = installer_dirs(
        var("XDG_BIN_HOME").as_deref(),
        var("XDG_DATA_HOME").as_deref(),
        &homes,
    );
    if installed_by_installer(exe, &dirs) {
        Install::Installer
    } else {
        Install::Unknown
    }
}

/// How the running program was installed.
pub fn install_kind() -> Install {
    match std::env::current_exe() {
        Ok(exe) => install_kind_of(&exe),
        Err(_) => Install::Unknown,
    }
}

/// What the profile remembers about the check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateState {
    /// Whether the person leaves the check on. It is on until they turn it
    /// off.
    pub on: bool,
    /// When the app last asked GitHub, answered or not.
    pub asked_unix: Option<u64>,
    /// When GitHub last answered.
    pub answered_unix: Option<u64>,
    /// The newest release GitHub named then.
    pub latest: Option<String>,
}

impl Default for UpdateState {
    fn default() -> UpdateState {
        UpdateState {
            on: true,
            asked_unix: None,
            answered_unix: None,
            latest: None,
        }
    }
}

/// Whether the app should ask GitHub now: the check is on, the environment
/// does not turn it off, and a day has passed since it last asked. A clock
/// that went back counts as a day passed.
pub fn due(s: &UpdateState, env_off: bool, now: u64) -> bool {
    s.on && !env_off
        && match s.asked_unix {
            None => true,
            Some(t) => now < t || now - t >= EVERY_SECS,
        }
}

/// What the app says about a newer release, if GitHub named one newer than
/// `current` and the check is still on.
pub fn notice(s: &UpdateState, env_off: bool, current: &str, install: Install) -> Option<String> {
    if !s.on || env_off {
        return None;
    }
    let latest = Version::parse(s.latest.as_deref()?)?;
    if latest <= Version::parse(current)? {
        return None;
    }
    Some(match install {
        Install::Homebrew => format!("Socketchat {latest} is out. Run brew upgrade socketchat."),
        Install::Installer | Install::Unknown => {
            format!("Socketchat {latest} is out. Run socketchat update.")
        }
    })
}

/// Where an HTTP answer stands after the bytes read so far.
#[derive(Debug, PartialEq, Eq)]
enum Response {
    /// Not all there yet.
    More,
    /// A 200 answer and its body.
    Body(Vec<u8>),
    /// Anything else: another status, or an answer that makes no sense.
    Bad,
}

/// Reads an HTTP/1.1 answer from `buf`; `eof` says the connection ended.
fn parse_response(buf: &[u8], eof: bool) -> Response {
    let more = if eof { Response::Bad } else { Response::More };
    let Some(end) = find(buf, b"\r\n\r\n") else {
        return more;
    };
    let Ok(head) = std::str::from_utf8(&buf[..end]) else {
        return Response::Bad;
    };
    let mut lines = head.split("\r\n");
    let mut status = lines.next().unwrap_or("").splitn(3, ' ');
    if !status.next().unwrap_or("").starts_with("HTTP/1.") || status.next() != Some("200") {
        return Response::Bad;
    }
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Response::Bad;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            match value.parse::<usize>() {
                Ok(n) if n <= MAX_RESPONSE => length = Some(n),
                _ => return Response::Bad,
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if !value.eq_ignore_ascii_case("chunked") {
                return Response::Bad;
            }
            chunked = true;
        }
    }
    let body = &buf[end + 4..];
    if chunked {
        return dechunk(body, eof);
    }
    match length {
        Some(n) if body.len() >= n => Response::Body(body[..n].to_vec()),
        Some(_) => more,
        // No length: the body runs until the connection closes.
        None if eof => Response::Body(body.to_vec()),
        None => Response::More,
    }
}

/// The body of a chunked answer.
fn dechunk(mut b: &[u8], eof: bool) -> Response {
    let more = if eof { Response::Bad } else { Response::More };
    let mut out = Vec::new();
    loop {
        let Some(i) = find(b, b"\r\n") else {
            return more;
        };
        let size = std::str::from_utf8(&b[..i])
            .ok()
            .map(|t| t.split(';').next().unwrap_or("").trim())
            .and_then(|t| usize::from_str_radix(t, 16).ok());
        let Some(size) = size.filter(|n| out.len() + n <= MAX_RESPONSE) else {
            return Response::Bad;
        };
        b = &b[i + 2..];
        if size == 0 {
            return Response::Body(out);
        }
        if b.len() < size + 2 {
            return more;
        }
        if &b[size..size + 2] != b"\r\n" {
            return Response::Bad;
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..];
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// The release GitHub's answer names, unless it is a draft or a pre-release.
fn parse_release(body: &[u8]) -> Option<Version> {
    #[derive(serde::Deserialize)]
    struct Release {
        tag_name: String,
        #[serde(default)]
        draft: bool,
        #[serde(default)]
        prerelease: bool,
    }
    let r: Release = serde_json::from_slice(body).ok()?;
    if r.draft || r.prerelease {
        return None;
    }
    Version::parse(&r.tag_name)
}

/// Sends the one GET request over `stream` and reads the answer, within
/// [`MAX_RESPONSE`] bytes.
async fn get<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    host: &str,
    path: &str,
) -> Option<Vec<u8>> {
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: socketchat\r\nAccept: application/vnd.github+json\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.ok()?;
    stream.flush().await.ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        // A connection that ends with an error ends all the same; a
        // cut-off answer then fails to read.
        let n = stream.read(&mut chunk).await.unwrap_or(0);
        buf.extend_from_slice(&chunk[..n]);
        match parse_response(&buf, n == 0) {
            Response::Body(body) => return Some(body),
            Response::Bad => return None,
            Response::More if buf.len() > MAX_RESPONSE + 64 * 1024 => return None,
            Response::More => {}
        }
    }
}

/// Asks api.github.com for the latest release, over TLS checked against
/// the computer's trusted certificate authorities.
#[cfg_attr(feature = "test-hooks", allow(dead_code))]
async fn ask_github() -> Option<Version> {
    let ask = async {
        // Reading the system's certificate store touches files and, on
        // macOS, the keychain, so it runs off the async threads.
        let roots = tokio::task::spawn_blocking(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
            roots
        })
        .await
        .ok()?;
        if roots.is_empty() {
            return None;
        }
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .ok()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let tcp = TcpStream::connect((GITHUB_API, 443)).await.ok()?;
        let name = ServerName::try_from(GITHUB_API).ok()?;
        let tls = TlsConnector::from(Arc::new(cfg))
            .connect(name, tcp)
            .await
            .ok()?;
        parse_release(&get(tls, GITHUB_API, LATEST_PATH).await?)
    };
    tokio::time::timeout(TIMEOUT, ask).await.ok().flatten()
}

/// Asks a plain-HTTP stand-in for GitHub at `addr` (host:port). Tests use
/// it; release builds leave it out.
#[cfg(any(test, feature = "test-hooks"))]
async fn ask_plain(addr: &str, timeout: Duration) -> Option<Version> {
    let ask = async {
        let tcp = TcpStream::connect(addr).await.ok()?;
        parse_release(&get(tcp, addr, LATEST_PATH).await?)
    };
    tokio::time::timeout(timeout, ask).await.ok().flatten()
}

/// Asks GitHub for the newest release. `None` when the check failed in any
/// way; the caller says nothing then.
///
/// Programs built with the `test-hooks` feature never reach GitHub: they
/// ask the stand-in at `SOCKETCHAT_TEST_UPDATE_URL` (`http://host:port`),
/// or nobody.
pub async fn fetch_latest() -> Option<Version> {
    #[cfg(feature = "test-hooks")]
    {
        let url = std::env::var("SOCKETCHAT_TEST_UPDATE_URL").ok()?;
        let addr = url.strip_prefix("http://")?.trim_end_matches('/');
        ask_plain(addr, TIMEOUT).await
    }
    #[cfg(not(feature = "test-hooks"))]
    {
        ask_github().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap_or_else(|| panic!("{s} should parse"))
    }

    #[test]
    fn versions_parse_with_or_without_a_v() {
        assert_eq!(v("v0.5.2"), v("0.5.2"));
        assert_eq!(v("0.5.2").to_string(), "0.5.2");
        assert_eq!(v("v0.6.0-rc.1").to_string(), "0.6.0-rc.1");
        assert_eq!(v("0.5.2+build.7").to_string(), "0.5.2");
        for bad in [
            "",
            "v",
            "0.5",
            "0.5.2.1",
            "x.y.z",
            "0.5.-1",
            "0.5.2-",
            "0.5.2-rc..1",
            "0.5.2 ",
            " 0.5.2",
            "vv0.5.2",
            "0.5.2-rc.1\u{1b}[2K",
        ] {
            assert_eq!(Version::parse(bad), None, "{bad:?} should not parse");
        }
        assert_eq!(Version::parse(&format!("0.5.2-{}", "a".repeat(80))), None);
    }

    #[test]
    fn versions_order_with_pre_releases_first() {
        let order = [
            "0.5.1",
            "0.5.2-alpha",
            "0.5.2-alpha.1",
            "0.5.2-alpha.beta",
            "0.5.2-beta",
            "0.5.2-beta.2",
            "0.5.2-beta.11",
            "0.5.2-rc.1",
            "0.5.2",
            "0.5.10",
            "0.6.0-rc.1",
            "0.6.0",
            "1.0.0",
        ];
        for pair in order.windows(2) {
            assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1]);
        }
        // Numbers come before words among pre-release parts.
        assert!(v("1.0.0-1") < v("1.0.0-alpha"));
        assert_eq!(v("0.5.2+a").cmp(&v("0.5.2+b")), Ordering::Equal);
    }

    #[test]
    fn the_variable_turns_the_check_off_unless_empty_or_zero() {
        use std::ffi::OsStr;
        assert!(!off_by_env_value(None));
        assert!(!off_by_env_value(Some(OsStr::new(""))));
        assert!(!off_by_env_value(Some(OsStr::new("0"))));
        assert!(off_by_env_value(Some(OsStr::new("1"))));
        assert!(off_by_env_value(Some(OsStr::new("yes"))));
    }

    fn knows(latest: &str) -> UpdateState {
        UpdateState {
            on: true,
            asked_unix: Some(100),
            answered_unix: Some(100),
            latest: Some(latest.into()),
        }
    }

    #[test]
    fn a_newer_release_gives_the_notice() {
        assert_eq!(
            notice(&knows("0.5.2"), false, "0.5.1", Install::Unknown).as_deref(),
            Some("Socketchat 0.5.2 is out. Run socketchat update.")
        );
        assert_eq!(
            notice(&knows("0.5.2"), false, "0.5.1", Install::Homebrew).as_deref(),
            Some("Socketchat 0.5.2 is out. Run brew upgrade socketchat.")
        );
        // A pre-release of the same version is older than the release.
        assert_eq!(
            notice(&knows("0.5.2"), false, "0.5.2-rc.1", Install::Unknown).as_deref(),
            Some("Socketchat 0.5.2 is out. Run socketchat update.")
        );
    }

    #[test]
    fn the_same_or_an_older_release_gives_nothing() {
        for latest in ["0.5.1", "0.5.0", "0.5.1-rc.2", "0.4.9"] {
            assert_eq!(
                notice(&knows(latest), false, "0.5.1", Install::Unknown),
                None
            );
        }
        assert_eq!(
            notice(&knows("0.5.2"), false, "0.6.0-rc.1", Install::Unknown),
            None
        );
        // Nothing known yet, or nothing that reads as a version.
        assert_eq!(
            notice(&UpdateState::default(), false, "0.5.1", Install::Unknown),
            None
        );
        assert_eq!(
            notice(&knows("soon"), false, "0.5.1", Install::Unknown),
            None
        );
    }

    #[test]
    fn a_check_that_is_off_gives_no_notice() {
        let mut s = knows("9.0.0");
        assert_eq!(notice(&s, true, "0.5.1", Install::Unknown), None);
        s.on = false;
        assert_eq!(notice(&s, false, "0.5.1", Install::Unknown), None);
    }

    #[test]
    fn a_check_is_due_once_a_day_and_only_when_on() {
        let day = EVERY_SECS;
        let mut s = UpdateState::default();
        assert!(due(&s, false, 1_000_000));
        s.asked_unix = Some(1_000_000);
        assert!(!due(&s, false, 1_000_000 + 3600));
        assert!(!due(&s, false, 1_000_000 + day - 1));
        assert!(due(&s, false, 1_000_000 + day));
        // The clock went back: ask again.
        assert!(due(&s, false, 999_000));
        assert!(!due(&UpdateState::default(), true, 1_000_000));
        s.on = false;
        assert!(!due(&s, false, 1_000_000 + 2 * day));
    }

    #[test]
    fn homebrew_installs_are_found_by_their_cellar_path() {
        for p in [
            "/opt/homebrew/Cellar/socketchat/0.5.2/bin/socketchat",
            "/usr/local/Cellar/socketchat/0.5.2/bin/socketchat",
            "/home/linuxbrew/.linuxbrew/Cellar/socketchat/0.5.2/bin/socketchat",
        ] {
            assert!(installed_by_homebrew(Path::new(p)), "{p}");
        }
        for p in [
            "/Users/ada/.local/bin/socketchat",
            "/opt/homebrew/Cellar/other/1.0/bin/socketchat",
            "/usr/local/bin/socketchat",
            "/home/ada/Cellar.socketchat/bin/socketchat",
        ] {
            assert!(!installed_by_homebrew(Path::new(p)), "{p}");
        }
    }

    #[test]
    fn installer_copies_are_found_by_the_installers_folders() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path().join("home");
        let dirs = installer_dirs(None, None, std::slice::from_ref(&home));
        assert_eq!(dirs, vec![home.join(".local/bin")]);
        let exe = home.join(".local/bin/socketchat");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, b"").unwrap();
        assert!(installed_by_installer(&exe, &dirs));
        assert!(!installed_by_installer(&d.path().join("socketchat"), &dirs));
        // XDG_BIN_HOME first, then XDG_DATA_HOME/../bin, as the installer
        // looks for them.
        // Built under the temp folder, so they are absolute on Windows too.
        let x = d.path().join("x");
        let dirs = installer_dirs(
            Some(&x.join("bin")),
            Some(&x.join("share")),
            std::slice::from_ref(&home),
        );
        assert_eq!(
            dirs,
            vec![
                x.join("bin"),
                x.join("share").join("../bin"),
                home.join(".local/bin")
            ]
        );
        // A relative or empty XDG folder is not one the installer uses.
        let dirs = installer_dirs(Some(Path::new("")), Some(Path::new("rel")), &[]);
        assert!(dirs.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_homebrew_link_is_followed_to_the_cellar() {
        let d = tempfile::tempdir().unwrap();
        let keg = d.path().join("Cellar/socketchat/0.5.2/bin");
        std::fs::create_dir_all(&keg).unwrap();
        std::fs::write(keg.join("socketchat"), b"").unwrap();
        std::fs::create_dir_all(d.path().join("bin")).unwrap();
        let link = d.path().join("bin/socketchat");
        std::os::unix::fs::symlink(keg.join("socketchat"), &link).unwrap();
        assert!(installed_by_homebrew(&link));
    }

    const RELEASE: &str =
        r#"{"tag_name":"v0.5.2","name":"0.5.2","draft":false,"prerelease":false,"assets":[]}"#;

    fn answer(status: &str, headers: &str, body: &str) -> Vec<u8> {
        format!("HTTP/1.1 {status}\r\n{headers}\r\n{body}").into_bytes()
    }

    #[test]
    fn answers_are_read_by_length_chunks_or_until_closed() {
        let body = RELEASE;
        let sized = answer(
            "200 OK",
            &format!("Content-Length: {}\r\n", body.len()),
            body,
        );
        assert_eq!(
            parse_response(&sized, false),
            Response::Body(body.as_bytes().to_vec())
        );
        assert_eq!(
            parse_response(&sized[..sized.len() - 3], false),
            Response::More
        );
        assert_eq!(
            parse_response(&sized[..sized.len() - 3], true),
            Response::Bad
        );
        let (a, b) = body.split_at(10);
        let chunked = answer(
            "200 OK",
            "transfer-encoding: chunked\r\n",
            &format!("{:x}\r\n{a}\r\n{:X}\r\n{b}\r\n0\r\n\r\n", a.len(), b.len()),
        );
        assert_eq!(
            parse_response(&chunked, false),
            Response::Body(body.as_bytes().to_vec())
        );
        assert_eq!(
            parse_response(&chunked[..chunked.len() - 5], false),
            Response::More
        );
        let closed = answer("200 OK", "", body);
        assert_eq!(parse_response(&closed, false), Response::More);
        assert_eq!(
            parse_response(&closed, true),
            Response::Body(body.as_bytes().to_vec())
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-", false),
            Response::More
        );
    }

    #[test]
    fn other_statuses_and_nonsense_are_failures() {
        for bad in [
            answer("404 Not Found", "Content-Length: 2\r\n", "{}"),
            answer("403 Forbidden", "Content-Length: 2\r\n", "{}"),
            answer("301 Moved", "Content-Length: 0\r\n", ""),
            b"SSH-2.0-OpenSSH\r\n\r\n".to_vec(),
            answer("200 OK", "Content-Length: lots\r\n", "{}"),
            answer(
                "200 OK",
                "transfer-encoding: chunked\r\n",
                "zz\r\n{}\r\n0\r\n\r\n",
            ),
        ] {
            assert_eq!(
                parse_response(&bad, true),
                Response::Bad,
                "{}",
                String::from_utf8_lossy(&bad)
            );
        }
    }

    #[test]
    fn the_release_name_comes_from_its_tag() {
        assert_eq!(parse_release(RELEASE.as_bytes()), Some(v("0.5.2")));
        for skip in [
            r#"{"tag_name":"v0.6.0-rc.1","draft":false,"prerelease":true}"#,
            r#"{"tag_name":"v0.6.0","draft":true,"prerelease":false}"#,
            r#"{"tag_name":"next","draft":false,"prerelease":false}"#,
            r#"{"message":"Not Found"}"#,
            "not json",
        ] {
            assert_eq!(parse_release(skip.as_bytes()), None, "{skip}");
        }
    }

    /// A stand-in for GitHub on a free local port that gives each
    /// connection `reply` (or closes it at once when `reply` is empty), and
    /// hands back every request it read.
    async fn stand_in(reply: Vec<u8>) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut req = vec![0u8; 4096];
            let n = s.read(&mut req).await.unwrap_or(0);
            if !reply.is_empty() {
                let _ = s.write_all(&reply).await;
            }
            vec![String::from_utf8_lossy(&req[..n]).into_owned()]
        });
        (addr, task)
    }

    #[tokio::test]
    async fn the_check_reads_the_newest_release_from_the_stand_in() {
        let body = RELEASE;
        let (addr, seen) = stand_in(answer(
            "200 OK",
            &format!("Content-Length: {}\r\n", body.len()),
            body,
        ))
        .await;
        assert_eq!(ask_plain(&addr, TIMEOUT).await, Some(v("0.5.2")));
        let req = &seen.await.unwrap()[0];
        assert!(
            req.starts_with(&format!("GET {LATEST_PATH} HTTP/1.1\r\n")),
            "{req}"
        );
        assert!(req.contains("\r\nUser-Agent: socketchat\r\n"), "{req}");
        // Nothing else rides along: no cookie, no token.
        let lower = req.to_ascii_lowercase();
        assert!(
            !lower.contains("cookie") && !lower.contains("authorization"),
            "{req}"
        );
    }

    #[tokio::test]
    async fn a_failed_check_gives_none() {
        let (addr, _) = stand_in(Vec::new()).await;
        assert_eq!(ask_plain(&addr, TIMEOUT).await, None);
        let (addr, _) = stand_in(answer("500 Oops", "Content-Length: 0\r\n", "")).await;
        assert_eq!(ask_plain(&addr, TIMEOUT).await, None);
        // Nobody listening.
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = free.local_addr().unwrap().to_string();
        drop(free);
        assert_eq!(ask_plain(&addr, TIMEOUT).await, None);
        // A stand-in that never answers runs out of time.
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let started = std::time::Instant::now();
        assert_eq!(ask_plain(&addr, Duration::from_millis(300)).await, None);
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(l);
    }

    async fn profile() -> (tempfile::TempDir, crate::client::Client) {
        let d = tempfile::tempdir().unwrap();
        let c = crate::client::Client::create_profile(d.path(), "test passphrase", "Ada")
            .await
            .unwrap();
        (d, c)
    }

    /// A request that counts how often it was made and names `found`.
    fn counted(
        n: &Arc<std::sync::atomic::AtomicUsize>,
        found: Option<&str>,
    ) -> impl FnOnce() -> std::future::Ready<Option<Version>> {
        let n = n.clone();
        let found = found.map(v);
        move || {
            n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::future::ready(found)
        }
    }

    #[tokio::test]
    async fn a_check_that_is_off_makes_no_request() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let (_d, c) = profile().await;
        let n = Arc::new(AtomicUsize::new(0));
        c.set_update_check(false).unwrap();
        assert!(c
            .start_update_check_with(false, 1_000_000, counted(&n, Some("9.0.0")))
            .is_none());
        c.set_update_check(true).unwrap();
        // The environment variable turns it off as well.
        assert!(c
            .start_update_check_with(true, 1_000_000, counted(&n, Some("9.0.0")))
            .is_none());
        assert_eq!(n.load(SeqCst), 0);
        assert_eq!(c.update_state().unwrap().asked_unix, None);
    }

    #[tokio::test]
    async fn a_due_check_asks_once_a_day_and_keeps_the_answer() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let (d, c) = profile().await;
        let n = Arc::new(AtomicUsize::new(0));
        let t = 1_000_000;
        let check = c
            .start_update_check_with(false, t, counted(&n, Some("9.0.0")))
            .expect("a first check is due");
        assert_eq!(c.update_state().unwrap().asked_unix, Some(t));
        c.finish_update_check(check.await.unwrap());
        let s = c.update_state().unwrap();
        assert_eq!(s.latest.as_deref(), Some("9.0.0"));
        assert!(s.answered_unix.is_some());
        assert_eq!(n.load(SeqCst), 1);
        // Not again the same day.
        assert!(c
            .start_update_check_with(false, t + 3600, counted(&n, Some("9.1.0")))
            .is_none());
        assert_eq!(n.load(SeqCst), 1);
        // The profile keeps it all.
        drop(c);
        let c = crate::client::Client::open(d.path(), "test passphrase")
            .await
            .unwrap();
        assert_eq!(c.update_state().unwrap(), s);
        c.set_update_check(false).unwrap();
        drop(c);
        let c = crate::client::Client::open(d.path(), "test passphrase")
            .await
            .unwrap();
        assert!(!c.update_state().unwrap().on);
    }

    #[tokio::test]
    async fn a_failed_check_keeps_the_last_answer() {
        use std::sync::atomic::AtomicUsize;
        let (_d, c) = profile().await;
        let n = Arc::new(AtomicUsize::new(0));
        let t = 1_000_000;
        let check = c.start_update_check_with(false, t, counted(&n, Some("0.9.0")));
        c.finish_update_check(check.unwrap().await.unwrap());
        let before = c.update_state().unwrap();
        let check = c.start_update_check_with(false, t + EVERY_SECS, counted(&n, None));
        c.finish_update_check(check.unwrap().await.unwrap());
        let after = c.update_state().unwrap();
        assert_eq!(after.latest, before.latest);
        assert_eq!(after.answered_unix, before.answered_unix);
        assert_eq!(after.asked_unix, Some(t + EVERY_SECS));
    }

    #[tokio::test]
    async fn an_answer_too_big_is_a_failure() {
        let big = "x".repeat(MAX_RESPONSE + 10);
        let (addr, _) = stand_in(answer(
            "200 OK",
            &format!("Content-Length: {}\r\n", big.len()),
            &big,
        ))
        .await;
        assert_eq!(ask_plain(&addr, TIMEOUT).await, None);
    }
}
