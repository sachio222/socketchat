//! `socketchat`: the chat screen, the server, and a few commands for scripts.

use std::io::{BufRead, IsTerminal, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use socketchat_core::client::{
    server_text, Client, Event, JoinStatus, SendOutcome, ServerView, UpdateCheck, Verification,
};
use socketchat_core::invite::hours_text;
use socketchat_core::keys::fingerprint_text;
use socketchat_core::sanitize::{clean_name, clean_text, same_name};
use socketchat_core::update;
use socketchat_core::CoreError;
use socketchat_proto::msg::GroupId;
use socketchat_proto::InviteLink;
use socketchat_server::{
    acceptable_use_text, init, make_server_invite, public_host_warning, Config, Server,
};
use socketchat_tui::app::{
    forget_warning, forgot_text, local_date, local_date_time, server_row, status_lines,
    update_status, AppStatus,
};

#[derive(Parser)]
#[command(
    name = "socketchat",
    version,
    about = "Encrypted group chat for people who run their own server.",
    long_about = "Encrypted group chat for people who run their own server.\n\nRun with no command to open the chat screen."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Set up, run and invite people to a Socketchat server.
    Server {
        #[command(subcommand)]
        cmd: ServerCmd,
    },
    /// Use an invite link. The first time, this also sets up your profile.
    Join {
        link: String,
        /// Trust the server certificate in this link in place of the one
        /// Socketchat already trusts for that server, after its operator set
        /// it up again.
        #[arg(long)]
        new_certificate: bool,
    },
    /// Start a new group chat.
    New {
        name: String,
        /// The server to make it on, by its number in `socketchat
        /// servers`. Without it, the newest server you joined.
        #[arg(long, value_name = "NUMBER")]
        server: Option<usize>,
    },
    /// Print an invite link on one line, or invite someone you share a
    /// room with by name.
    Invite {
        /// The group to invite into. Leave out with --dm for a new two-person chat.
        #[arg(long)]
        group: Option<String>,
        /// Make a link that opens a new two-person chat.
        #[arg(long, conflicts_with = "name")]
        dm: bool,
        /// Someone you share another room with, to invite by name instead of
        /// with a link: their name, or their name and the start of their
        /// key, as Bo#1a2b. They join with /join in the chat screen.
        name: Vec<String>,
    },
    /// See your open invite links, or cancel one.
    Invites {
        /// Stop the link at this number in the list from working.
        #[arg(long, value_name = "NUMBER")]
        cancel: Option<usize>,
    },
    /// See your servers and whether each can be reached, or forget one.
    Servers {
        /// Delete the server at this number in the list, and its rooms,
        /// from this computer. The server is not told.
        #[arg(long, value_name = "NUMBER")]
        forget: Option<usize>,
        /// Forget without asking first.
        #[arg(long, requires = "forget")]
        yes: bool,
    },
    /// Send a message to a group (for scripts).
    Send {
        #[arg(long)]
        group: String,
        #[arg(required = true)]
        text: Vec<String>,
    },
    /// Print a group's topic, or set it for everyone (admins, or anyone the
    /// room allows).
    Topic {
        #[arg(long)]
        group: String,
        /// The new topic. Leave out to print the current one.
        text: Vec<String>,
        /// Remove the topic for everyone.
        #[arg(long, conflicts_with = "text")]
        clear: bool,
    },
    /// Print a group's recent messages, or its oldest unread ones when more
    /// are unread than --limit, and mark them read (for scripts).
    Log {
        #[arg(long)]
        group: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Fetch everything new and print what happened (for scripts).
    Sync,
    /// Print the server and the connection to it, your name, a room and
    /// the app's settings, one fact a line.
    Status {
        /// A room to include, by name.
        #[arg(long)]
        group: Option<String>,
    },
    /// Print the command that updates Socketchat. It installs nothing.
    Update,
}

#[derive(Subcommand)]
enum ServerCmd {
    /// Write a config file and a certificate, and print the acceptable-use statement.
    Init {
        /// Where the server keeps its data.
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// The name or address people use to reach this server.
        #[arg(long, default_value = "localhost")]
        host: String,
        /// Address and port to listen on.
        #[arg(long)]
        listen: Option<SocketAddr>,
    },
    /// Run the server until Ctrl-C.
    Run {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// A config file to use instead of the one in the data directory.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Print a one-time link that registers a new person on this server.
    Invite {
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
}

/// What `socketchat` prints on a computer with no profile yet.
const GETTING_STARTED: &str = "\
Socketchat has no profile on this computer yet. To start:
  socketchat server init                    set up a local server
  socketchat server run                     start a local server
  socketchat join '<invite link>'           join a server you were invited to
Then run socketchat to open the chat screen.
For a server friends on other computers can reach, add --host <address> to server init.";

/// A failure with the exit code it maps to.
struct Fail(u8, String);

impl From<CoreError> for Fail {
    fn from(e: CoreError) -> Fail {
        match e {
            CoreError::WrongPassphrase => Fail(2, "That passphrase does not open this profile. Nothing was changed.".into()),
            CoreError::NoProfile => Fail(
                1,
                "No profile here yet. Ask someone for an invite link, then run: socketchat join <link>".into(),
            ),
            e @ CoreError::Unreachable { .. } => Fail(
                1,
                format!("{e} Run socketchat servers to see your servers."),
            ),
            e => Fail(1, e.to_string()),
        }
    }
}

impl From<socketchat_server::ServerError> for Fail {
    fn from(e: socketchat_server::ServerError) -> Fail {
        Fail(1, e.to_string())
    }
}

impl From<std::io::Error> for Fail {
    fn from(e: std::io::Error) -> Fail {
        Fail(1, e.to_string())
    }
}

fn profile_dir() -> PathBuf {
    if let Some(h) = std::env::var_os("SOCKETCHAT_HOME") {
        return PathBuf::from(h);
    }
    directories::ProjectDirs::from("", "", "socketchat")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".socketchat"))
}

fn server_dir(given: Option<PathBuf>) -> PathBuf {
    given.unwrap_or_else(|| {
        directories::ProjectDirs::from("", "", "socketchat-server")
            .map(|d| d.data_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("socketchat-server"))
    })
}

const EMPTY_VAR: &str = "SOCKETCHAT_PASSPHRASE is set but empty. Set it to your passphrase, or unset it to type the passphrase instead. Nothing was changed.";
const EMPTY_TYPED: &str = "A passphrase cannot be empty.";

/// The passphrase from `SOCKETCHAT_PASSPHRASE`, or typed at a prompt, and
/// whether it came from the variable. It may be empty; the caller decides.
/// A variable that is not text is refused, never skipped for the prompt.
fn read_passphrase() -> Result<(String, bool), Fail> {
    match std::env::var("SOCKETCHAT_PASSPHRASE") {
        Ok(p) => Ok((p, true)),
        Err(std::env::VarError::NotUnicode(_)) => Err(Fail(
            1,
            "SOCKETCHAT_PASSPHRASE is not valid text. Set it to your passphrase, or unset it to type the passphrase instead. Nothing was changed.".into(),
        )),
        Err(std::env::VarError::NotPresent) => {
            Ok((rpassword::prompt_password("Passphrase: ")?, false))
        }
    }
}

/// The passphrase for a new profile, which is never empty.
fn new_passphrase() -> Result<String, Fail> {
    let (p, from_var) = read_passphrase()?;
    if p.is_empty() {
        let says = if from_var { EMPTY_VAR } else { EMPTY_TYPED };
        return Err(Fail(1, says.into()));
    }
    if !from_var && rpassword::prompt_password("Same passphrase again: ")? != p {
        return Err(Fail(
            1,
            "The two passphrases did not match. Nothing was set up.".into(),
        ));
    }
    Ok(p)
}

/// Opens the profile in `dir`. An empty passphrase opens only a profile an
/// earlier release made with one, and Socketchat says so each time.
async fn open_profile(dir: &std::path::Path) -> Result<Client, Fail> {
    let (p, from_var) = read_passphrase()?;
    let c = match Client::open(dir, &p).await {
        Ok(c) => c,
        Err(CoreError::WrongPassphrase) if p.is_empty() => {
            let says = if from_var { EMPTY_VAR } else { EMPTY_TYPED };
            return Err(Fail(1, says.into()));
        }
        Err(e) => return Err(e.into()),
    };
    if p.is_empty() {
        eprintln!(
            "This profile has no passphrase, so anyone who can copy its folder can read what Socketchat keeps there."
        );
    }
    for line in c.open_notes() {
        eprintln!("{line}");
    }
    Ok(c)
}

fn display_name() -> Result<String, Fail> {
    if let Ok(n) = std::env::var("SOCKETCHAT_NAME") {
        return Ok(n);
    }
    eprint!("Pick a display name (others see it, you can change it later): ");
    std::io::stderr().flush()?;
    let mut s = String::new();
    std::io::stdin().lock().read_line(&mut s)?;
    let s = s.trim().to_string();
    if s.is_empty() {
        return Err(Fail(
            1,
            "A display name needs at least one character.".into(),
        ));
    }
    Ok(s)
}

async fn open() -> Result<Client, Fail> {
    let dir = profile_dir();
    if !socketchat_core::store::has_profile(&dir) {
        return Err(CoreError::NoProfile.into());
    }
    open_profile(&dir).await
}

async fn open_or_create() -> Result<Client, Fail> {
    let dir = profile_dir();
    if socketchat_core::store::has_profile(&dir) {
        return open_profile(&dir).await;
    }
    eprintln!("Setting up Socketchat on this computer.");
    let name = display_name()?;
    eprintln!(
        "Your passphrase encrypts everything Socketchat keeps here. Nobody can recover it for you."
    );
    let pass = new_passphrase()?;
    let c = Client::create_profile(&dir, &pass, &name).await?;
    for line in c.open_notes() {
        eprintln!("{line}");
    }
    Ok(c)
}

fn group_by_name(c: &Client, name: &str) -> Result<GroupId, Fail> {
    let hits: Vec<GroupId> = c
        .groups()
        .into_iter()
        .filter(|g| !g.left && same_name(name, &g.name))
        .map(|g| g.id)
        .collect();
    match hits.as_slice() {
        [g] => Ok(*g),
        [] => Err(Fail(1, format!("You are not in a group called {name}."))),
        _ => Err(Fail(
            1,
            format!("You are in more than one group called {name}."),
        )),
    }
}

fn group_name(c: &Client, g: GroupId) -> String {
    c.groups()
        .into_iter()
        .find(|x| x.id == g)
        .map(|x| clean_name(&x.name))
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "a new chat".into())
}

/// How far `log` and `sync` indent a message's second and later lines.
const MORE: &str = "    ";

/// One message as `log` and `sync` print it: `head`, such as "Bo: ", then
/// the text, with each further line of the text indented. A line that
/// starts at the left edge therefore always begins a message, so nobody
/// can write a line that passes for someone else's message.
fn message_lines(head: &str, text: &str) -> String {
    let text = clean_text(text);
    let mut lines = text.split('\n');
    let mut out = format!("{head}{}", lines.next().unwrap_or(""));
    for l in lines {
        out.push('\n');
        out.push_str(MORE);
        out.push_str(l);
    }
    out
}

/// The server at number `n` in `socketchat servers`.
fn server_number(c: &Client, n: usize) -> Result<ServerView, Fail> {
    n.checked_sub(1)
        .and_then(|i| c.servers(None).into_iter().nth(i))
        .ok_or_else(|| {
            Fail(
                1,
                format!("There is no server {n}. Run socketchat servers to see the list."),
            )
        })
}

/// Asks on the terminal before forgetting server `s`, number `n`. Away
/// from a terminal nobody can answer, so it says to add --yes.
fn ask_to_forget(s: &ServerView, n: usize) -> Result<bool, Fail> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err(Fail(
            1,
            format!(
                "To forget {} without being asked, run: socketchat servers --forget {n} --yes",
                s.text
            ),
        ));
    }
    eprintln!(
        "{}",
        forget_warning(&s.text, s.rooms, "open socketchat and /leave")
    );
    eprint!("Type y and press Enter to forget it: ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes"))
}

/// Syncs a few times and prints what happened.
async fn sync_and_report(c: &mut Client) -> Result<(), Fail> {
    for _ in 0..3 {
        c.sync().await?;
    }
    // Rooms that ended and are read go before this program exits.
    c.purge_read(None);
    for e in c.take_events() {
        match e {
            Event::Joined { group, verification } => match verification {
                Verification::Verified => println!("You joined {}. The person who invited you is verified.", group_name(c, group)),
                Verification::Unverified { reason } => println!(
                    "You joined {}, but the invite could not be checked: {}. Compare safety numbers before you trust anyone there.",
                    group_name(c, group),
                    clean_text(&reason).replace('\n', " ")
                ),
                Verification::Waiting { inviter } => println!(
                    "You joined {}. Waiting for {} to confirm this invite.",
                    group_name(c, group),
                    clean_name(&inviter)
                ),
            },
            Event::InviteConfirmed { group, inviter } => println!(
                "{} confirmed your invite to {} and is now verified.",
                clean_name(&inviter),
                group_name(c, group)
            ),
            Event::JoinRequestHandled { group } => println!("Someone you invited joined {}.", group_name(c, group)),
            // A line from the app itself names no sender.
            Event::Message { group, line } if line.notice && line.sender_key.is_none() => println!(
                "{}",
                message_lines(&format!("[{}] · ", group_name(c, group)), &line.text)
            ),
            Event::Message { group, line } => println!(
                "{}",
                message_lines(
                    &format!("[{}] {}: ", group_name(c, group), clean_name(&line.sender)),
                    &line.text
                )
            ),
            Event::Left { name, .. } => {
                let name = clean_name(&name);
                println!(
                    "You are no longer in {}.",
                    if name.is_empty() { "a chat" } else { &name }
                )
            }
            Event::Warning(w) => eprintln!("{}", clean_text(&w)),
            _ => {}
        }
    }
    Ok(())
}

/// Prints the warnings a step left behind, such as a server's new
/// certificate.
fn report_warnings(c: &mut Client) {
    for e in c.take_events() {
        if let Event::Warning(w) = e {
            eprintln!("{}", clean_text(&w));
        }
    }
}

async fn server(cmd: ServerCmd) -> Result<(), Fail> {
    match cmd {
        ServerCmd::Init {
            data_dir,
            host,
            listen,
        } => {
            let dir = server_dir(data_dir);
            let report = init(&dir, &host)?;
            if let Some(l) = listen {
                let mut cfg = Config::load(&dir)?;
                cfg.listen = l;
                cfg.save()?;
            }
            let cfg = Config::load(&dir)?;
            println!("{}", acceptable_use_text());
            println!("---\n");
            println!("Server set up in {}.", cfg.data_dir.display());
            println!(
                "Certificate fingerprint: {}",
                fingerprint_text(&report.cert_fpr)
            );
            println!("Invite links carry this fingerprint, so nobody copies certificates by hand.");
            if host == "localhost" {
                println!("\nInvite links will point at localhost. To invite people on other machines, edit public_host in {}.", report.config_path.display());
            }
            println!("\nNext:\n  socketchat server run --data-dir {d}\n  socketchat server invite --data-dir {d}", d = cfg.data_dir.display());
            Ok(())
        }
        ServerCmd::Run { data_dir, config } => {
            let cfg = match config {
                Some(f) => Config::load_file(&f)?,
                None => Config::load(&server_dir(data_dir))?,
            };
            if let Some(w) = public_host_warning(&cfg) {
                eprintln!("{w}");
            }
            let h = Server::start(cfg).await?;
            // Status lines never stop the server: if whoever started it
            // stopped reading, the writes just fail quietly.
            let say = |s: String| {
                let mut out = std::io::stdout();
                let _ = writeln!(out, "{s}");
                let _ = out.flush();
            };
            say(format!(
                "Socketchat server listening on {}\nCertificate fingerprint: {}",
                h.addr,
                fingerprint_text(&h.cert_fpr)
            ));
            tokio::signal::ctrl_c().await?;
            h.shutdown();
            say("Stopped.".into());
            Ok(())
        }
        ServerCmd::Invite { data_dir } => {
            let dir = server_dir(data_dir);
            let link = make_server_invite(&dir)?;
            let hours = hours_text(Config::load(&dir)?.invite_ttl_hours.into());
            println!("{link}");
            eprintln!("This link registers one person and expires in {hours}.");
            Ok(())
        }
    }
}

/// A command that works on the profile, already open in `c`.
async fn profile_command(c: &mut Client, cmd: Cmd) -> Result<(), Fail> {
    match cmd {
        Cmd::New { name, server } => {
            let server = match server {
                Some(n) => Some(server_number(c, n)?.id),
                None => c.new_room_server(None),
            };
            let g = match server {
                Some(s) => c.create_group_at(s, &name).await?,
                None => c.create_group(&name).await?,
            };
            let on = c.room_server(g).unwrap_or_default();
            println!(
                "Made {name} on {on}. Invite people with: socketchat invite --group \"{name}\""
            );
            Ok(())
        }
        Cmd::Servers { forget, yes } => {
            c.sync().await?;
            let list = c.servers(None);
            match forget {
                None if list.is_empty() => {
                    println!("You have no servers yet. Join one with: socketchat join <link>")
                }
                None => {
                    for (i, s) in list.iter().enumerate() {
                        println!("{}", server_row(i + 1, s));
                    }
                }
                Some(n) => {
                    let s = server_number(c, n)?;
                    if yes || ask_to_forget(&s, n)? {
                        let rooms = c.forget_server(s.id)?;
                        println!("{}", forgot_text(&s.text, rooms));
                    } else {
                        println!("Kept {}.", s.text);
                    }
                }
            }
            c.purge_read(None);
            report_warnings(c);
            Ok(())
        }
        Cmd::Invite { group, name, .. } if !name.is_empty() => {
            c.sync().await?;
            let Some(group) = group else {
                return Err(Fail(
                    1,
                    "Name the room to invite them to with --group <name>.".into(),
                ));
            };
            let gid = group_by_name(c, &group)?;
            let room = group_name(c, gid);
            let sent = c.invite_member(gid, &name.join(" ")).await;
            c.purge_read(None);
            report_warnings(c);
            let sent = sent?;
            let who = clean_name(&sent.name);
            let via = clean_name(&sent.via);
            let when = match sent.wait_secs {
                None => String::new(),
                Some(n) => format!(" {via} limits fast posting, so socketchat sync or the chat screen sends it in {n} seconds or later."),
            };
            println!("Invited {who} to {room} through {via}.{when} Once {who} types /join {room}, socketchat sync or the chat screen adds them.");
            Ok(())
        }
        Cmd::Invite { group, dm, .. } => {
            c.sync().await?;
            let (link, expires_unix) = match (group, dm) {
                (None, true) => c.invite(None, true).await?,
                (Some(g), false) => {
                    let gid = group_by_name(c, &g)?;
                    c.invite(Some(gid), false).await?
                }
                _ => return Err(Fail(1, "Use --group <name>, or --dm on its own.".into())),
            };
            let hours = hours_text(c.hours_until(expires_unix));
            c.purge_read(None);
            report_warnings(c);
            println!("{link}");
            eprintln!("Send this to one person. It works once and expires in {hours}.");
            Ok(())
        }
        Cmd::Invites { cancel } => {
            c.sync().await?;
            let list = c.invites().await?;
            match cancel {
                None if list.is_empty() => println!("You have no open invite links."),
                None => {
                    for (i, v) in list.iter().enumerate() {
                        println!(
                            "{}. {}: expires in {}",
                            i + 1,
                            clean_name(&v.label),
                            hours_text(c.hours_until(v.expires_unix))
                        );
                    }
                }
                Some(n) => {
                    let Some(v) = n.checked_sub(1).and_then(|i| list.get(i)) else {
                        c.purge_read(None);
                        report_warnings(c);
                        return Err(Fail(
                            1,
                            format!(
                                "There is no link {n}. Run socketchat invites to see the list."
                            ),
                        ));
                    };
                    let done = c.cancel_invite(v.token).await;
                    if done.is_ok() {
                        println!(
                            "Cancelled {} (expires in {}). That link no longer works.",
                            clean_name(&v.label),
                            hours_text(c.hours_until(v.expires_unix))
                        );
                    }
                    c.purge_read(None);
                    report_warnings(c);
                    return Ok(done?);
                }
            }
            c.purge_read(None);
            report_warnings(c);
            Ok(())
        }
        Cmd::Send { group, text } => {
            c.sync().await?;
            let gid = group_by_name(c, &group)?;
            // A room that limits fast posting holds the message; it goes
            // once the server allows it, and this waits for that.
            if let SendOutcome::Held { wait_secs } = c.send_text(gid, &text.join(" ")).await? {
                let when = if wait_secs == 1 {
                    "1 second".to_string()
                } else {
                    format!("{wait_secs} seconds")
                };
                eprintln!("This room limits fast posting; sending in {when}.");
                while c.held(gid) > 0 {
                    c.wait(std::time::Duration::from_secs(60)).await;
                    c.sync().await?;
                    let events = c.take_events();
                    for e in &events {
                        if let Event::Warning(w) = e {
                            eprintln!("{}", clean_text(w));
                        }
                    }
                    let not_sent = events
                        .iter()
                        .any(|e| matches!(e, Event::NotSent { group, .. } if *group == gid));
                    if not_sent {
                        return Err(Fail(
                            1,
                            "Not sent, because the people in this room changed while it waited. Send it again if you still want to.".into(),
                        ));
                    }
                    if !c.connected() {
                        report_warnings(c);
                        return Err(Fail(
                            1,
                            "The connection to the server dropped before the message went. It was not sent.".into(),
                        ));
                    }
                }
            }
            c.purge_read(None);
            report_warnings(c);
            Ok(())
        }
        Cmd::Topic { group, text, clear } => {
            c.sync().await?;
            let gid = group_by_name(c, &group)?;
            let room = group_name(c, gid);
            let done = if clear {
                c.clear_topic(gid)
                    .await
                    .map(|()| format!("Cleared the topic of {room}."))
            } else if text.is_empty() {
                Ok(match c.topic(gid) {
                    Some(t) => t.words(&local_date(t.set_unix)),
                    None => format!("{room} has no topic."),
                })
            } else {
                c.set_topic(gid, &text.join(" "))
                    .await
                    .map(|()| format!("Set the topic of {room}."))
            };
            c.purge_read(None);
            report_warnings(c);
            println!("{}", done?);
            Ok(())
        }
        Cmd::Log { group, limit } => {
            c.sync().await?;
            let gid = group_by_name(c, &group)?;
            let lines = c.lines_to_read(gid, limit);
            let members = c.members(gid);
            for l in &lines {
                let head = if l.notice {
                    "· ".to_string()
                } else {
                    format!("{}: ", clean_name(&l.sender))
                };
                // A topic line says who set it, whether they are verified,
                // and the day.
                let text = if l.topic {
                    let verified = members
                        .iter()
                        .any(|m| Some(m.key) == l.sender_key && m.verified);
                    let mine = l.sender_key.is_some() && l.sender_key == c.my_group_key(gid);
                    socketchat_core::topic::words(
                        &l.text,
                        &l.sender,
                        verified,
                        mine,
                        &local_date(l.sent_unix),
                    )
                } else {
                    l.text.clone()
                };
                println!("{}", message_lines(&head, &text));
            }
            if let Some(newest) = lines.last() {
                c.mark_seen_upto(gid, newest.seq)?;
            }
            c.purge_read(None);
            report_warnings(c);
            Ok(())
        }
        Cmd::Sync => sync_and_report(c).await,
        Cmd::Status { group } => {
            // A server that cannot be reached is part of the answer.
            c.sync().await?;
            let gid = group.as_deref().map(|g| group_by_name(c, g)).transpose()?;
            let s = c.status(gid).await;
            let room = gid.map(|g| group_name(c, g));
            let saved = c.theme()?;
            let app = AppStatus {
                theme: socketchat_tui::theme::pick_theme(
                    saved.as_deref(),
                    std::env::var("SOCKETCHAT_THEME").ok().as_deref(),
                    None,
                )
                .name
                .as_str()
                .into(),
                mouse: c.mouse()?.unwrap_or(true),
                updates: update_status(&c.update_state()?, update::off_by_env(), &local_date_time),
            };
            c.purge_read(None);
            report_warnings(c);
            for line in status_lines(&s, room.as_deref(), &app, &local_date_time) {
                println!("{line}");
            }
            Ok(())
        }
        // main_inner and main run these.
        Cmd::Server { .. } | Cmd::Join { .. } | Cmd::Update => Ok(()),
    }
}

/// How long a command waits, once its own work is done, for an update
/// check still under way. A check that takes longer is dropped, and the
/// next one is a day later.
const CHECK_WAIT: Duration = Duration::from_secs(3);

/// Keeps what an update check found, and with `say` prints the update
/// notice when there is one.
async fn finish_update_check(c: &Client, check: Option<UpdateCheck>, say: bool) {
    if let Some(check) = check {
        let found = tokio::time::timeout(CHECK_WAIT, check)
            .await
            .ok()
            .and_then(Result::ok)
            .flatten();
        c.finish_update_check(found);
    }
    if say {
        if let Some(notice) = c.update_notice(update::install_kind()) {
            eprintln!("{notice}");
        }
    }
}

/// The install command on macOS and Linux, as the README gives it.
const CURL_INSTALL: &str = "curl --proto '=https' --tlsv1.2 -LsSf https://github.com/sachio222/socketchat/releases/latest/download/socketchat-installer.sh | sh";
/// The install command on Windows, for PowerShell.
const POWERSHELL_INSTALL: &str = "powershell -ExecutionPolicy Bypass -c \"irm https://github.com/sachio222/socketchat/releases/latest/download/socketchat-installer.ps1 | iex\"";

/// What `socketchat update` prints for a copy installed as `install`, on
/// Windows or not. Socketchat never replaces itself: the person runs the
/// command for the way they installed it.
fn update_advice(install: update::Install, windows: bool) -> String {
    match install {
        update::Install::Homebrew => {
            "Homebrew installed this copy of Socketchat. To update it, run:\n  brew upgrade socketchat".into()
        }
        update::Install::Installer if windows => format!(
            "The Socketchat installer put this copy here. To update it, run the install command again in PowerShell:\n  {POWERSHELL_INSTALL}"
        ),
        update::Install::Installer => format!(
            "The Socketchat installer put this copy here. To update it, run the install command again:\n  {CURL_INSTALL}"
        ),
        update::Install::Unknown => format!(
            "To update Socketchat, run the command for the way you installed it.\n  Homebrew: brew upgrade socketchat\n  Installer on macOS or Linux: {CURL_INSTALL}\n  Installer on Windows, in PowerShell: {POWERSHELL_INSTALL}"
        ),
    }
}

async fn main_inner(cli: Cli) -> Result<(), Fail> {
    match cli.cmd {
        Some(Cmd::Server { cmd }) => server(cmd).await,
        Some(Cmd::Join {
            link,
            new_certificate,
        }) => {
            let link: InviteLink = link
                .trim()
                .parse()
                .map_err(|e| Fail(1, format!("That is not a Socketchat invite link: {e}.")))?;
            let mut c = open_or_create().await?;
            let joined = if new_certificate {
                let old = c.trusted_certificate(&link.host, link.port)?;
                let joined = c.join_new_certificate(&link).await?;
                if let Some(old) = old.filter(|o| *o != link.cert_fpr) {
                    // The app's own line names the server; both
                    // fingerprints follow it.
                    report_warnings(&mut c);
                    eprintln!(
                        "Old certificate: {}\nNew certificate: {}",
                        fingerprint_text(&old),
                        fingerprint_text(&link.cert_fpr)
                    );
                }
                joined
            } else {
                c.join(&link).await?
            };
            match joined {
                JoinStatus::Registered => {
                    report_warnings(&mut c);
                    println!(
                        "You are on {}. Start a group with: socketchat new <name>",
                        server_text(&link.host, link.port)
                    );
                }
                JoinStatus::Waiting { for_name } => {
                    println!("Waiting for {} to let you in.", clean_name(&for_name));
                    sync_and_report(&mut c).await?;
                }
            }
            if std::io::stdout().is_terminal() && std::io::stdin().is_terminal() {
                socketchat_tui::run(c).await?;
            }
            Ok(())
        }
        Some(
            cmd @ (Cmd::New { .. }
            | Cmd::Servers { .. }
            | Cmd::Invite { .. }
            | Cmd::Invites { .. }
            | Cmd::Send { .. }
            | Cmd::Topic { .. }
            | Cmd::Log { .. }
            | Cmd::Sync
            | Cmd::Status { .. }),
        ) => {
            let mut c = open().await?;
            let check = c.start_update_check();
            let done = profile_command(&mut c, cmd).await;
            finish_update_check(&c, check, done.is_ok()).await;
            done
        }
        // main runs it before anything else.
        Some(Cmd::Update) => Ok(()),
        None => {
            // A first run right after installing: say how to start.
            if !profile_dir().join(socketchat_core::store::DB_FILE).exists() {
                println!("{GETTING_STARTED}");
                return Ok(());
            }
            let c = open().await?;
            socketchat_tui::run(c).await?;
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if matches!(cli.cmd, Some(Cmd::Update)) {
        println!("{}", update_advice(update::install_kind(), cfg!(windows)));
        return ExitCode::SUCCESS;
    }
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    match rt.block_on(main_inner(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fail(code, msg)) => {
            // Errors can carry a server's own words: no escape codes.
            eprintln!("{}", clean_text(&msg));
            ExitCode::from(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::message_lines;

    #[test]
    fn later_lines_of_a_message_are_indented() {
        assert_eq!(message_lines("Bo: ", "hi"), "Bo: hi");
        assert_eq!(
            message_lines("Bo: ", "ok\nAda: send it\n· Ada left.\n"),
            "Bo: ok\n    Ada: send it\n    · Ada left.\n    "
        );
        assert_eq!(
            message_lines("[Crew] Bo: ", "a\r\n\u{1b}[2Kb\u{202e}c"),
            "[Crew] Bo: a\n    [2Kbc"
        );
    }
}
