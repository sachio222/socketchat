//! `socketchat`: the chat screen, the server, and a few commands for scripts.

use std::io::{BufRead, IsTerminal, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use socketchat_core::client::{Client, Event, JoinStatus, Verification};
use socketchat_core::invite::hours_text;
use socketchat_core::CoreError;
use socketchat_proto::msg::GroupId;
use socketchat_proto::InviteLink;
use socketchat_server::{init, make_server_invite, Config, Server, ACCEPTABLE_USE};

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
    /// Set up, run and invite people to a socketchat server.
    Server {
        #[command(subcommand)]
        cmd: ServerCmd,
    },
    /// Use an invite link. The first time, this also sets up your profile.
    Join { link: String },
    /// Start a new group chat.
    New { name: String },
    /// Print an invite link on one line.
    Invite {
        /// The group to invite into. Leave out with --dm for a new two-person chat.
        #[arg(long)]
        group: Option<String>,
        /// Make a link that opens a new two-person chat.
        #[arg(long)]
        dm: bool,
    },
    /// Send a message to a group (for scripts).
    Send {
        #[arg(long)]
        group: String,
        #[arg(required = true)]
        text: Vec<String>,
    },
    /// Print a group's recent messages (for scripts).
    Log {
        #[arg(long)]
        group: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Fetch everything new and print what happened (for scripts).
    Sync,
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

fn passphrase(confirm: bool) -> Result<String, Fail> {
    if let Ok(p) = std::env::var("SOCKETCHAT_PASSPHRASE") {
        return Ok(p);
    }
    let p = rpassword::prompt_password("Passphrase: ")?;
    if p.is_empty() {
        return Err(Fail(1, "A passphrase cannot be empty.".into()));
    }
    if confirm && rpassword::prompt_password("Same passphrase again: ")? != p {
        return Err(Fail(
            1,
            "The two passphrases did not match. Nothing was set up.".into(),
        ));
    }
    Ok(p)
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
    if !dir.join(socketchat_core::store::DB_FILE).exists() {
        return Err(CoreError::NoProfile.into());
    }
    Ok(Client::open(&dir, &passphrase(false)?).await?)
}

async fn open_or_create() -> Result<Client, Fail> {
    let dir = profile_dir();
    if dir.join(socketchat_core::store::DB_FILE).exists() {
        return Ok(Client::open(&dir, &passphrase(false)?).await?);
    }
    eprintln!("Setting up socketchat on this computer.");
    let name = display_name()?;
    eprintln!(
        "Your passphrase encrypts everything socketchat keeps here. Nobody can recover it for you."
    );
    let pass = passphrase(true)?;
    Ok(Client::create_profile(&dir, &pass, &name).await?)
}

fn group_by_name(c: &Client, name: &str) -> Result<GroupId, Fail> {
    let hits: Vec<GroupId> = c
        .groups()
        .into_iter()
        .filter(|g| !g.left && g.name.eq_ignore_ascii_case(name))
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
        .map(|x| x.name)
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "a new chat".into())
}

/// Syncs a few times and prints what happened.
async fn sync_and_report(c: &mut Client) -> Result<(), Fail> {
    for _ in 0..3 {
        c.sync().await?;
    }
    for e in c.take_events() {
        match e {
            Event::Joined { group, verification } => match verification {
                Verification::Verified => println!("You joined {}. The person who invited you is verified.", group_name(c, group)),
                Verification::Unverified { reason } => println!(
                    "You joined {}, but the invite could not be checked: {reason}. Compare safety numbers before you trust anyone there.",
                    group_name(c, group)
                ),
            },
            Event::JoinRequestHandled { group } => println!("Someone you invited joined {}.", group_name(c, group)),
            Event::Message { group, line } => println!("[{}] {}: {}", group_name(c, group), line.sender, line.text),
            Event::Left { group } => println!("You are no longer in {}.", group_name(c, group)),
            Event::Warning(w) => eprintln!("{w}"),
            _ => {}
        }
    }
    Ok(())
}

fn fingerprint_text(f: &[u8; 32]) -> String {
    f.chunks(2)
        .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
        .collect::<Vec<_>>()
        .join(" ")
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
            println!("{ACCEPTABLE_USE}");
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
            let h = Server::start(cfg).await?;
            // Status lines never stop the server: if whoever started it
            // stopped reading, the writes just fail quietly.
            let say = |s: String| {
                let mut out = std::io::stdout();
                let _ = writeln!(out, "{s}");
                let _ = out.flush();
            };
            say(format!(
                "socketchat server listening on {}\nCertificate fingerprint: {}",
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

async fn main_inner(cli: Cli) -> Result<(), Fail> {
    match cli.cmd {
        Some(Cmd::Server { cmd }) => server(cmd).await,
        Some(Cmd::Join { link }) => {
            let link: InviteLink = link.trim().parse().map_err(|e| {
                Fail(1, format!("That is not a socketchat invite link ({e}). Links start with socketchat://"))
            })?;
            let mut c = open_or_create().await?;
            match c.join(&link).await? {
                JoinStatus::Registered => {
                    println!(
                        "You are on {}. Start a group with: socketchat new <name>",
                        link.host
                    );
                }
                JoinStatus::Waiting { for_name } => {
                    println!("Waiting for {for_name} to let you in.");
                    sync_and_report(&mut c).await?;
                }
            }
            if std::io::stdout().is_terminal() && std::io::stdin().is_terminal() {
                socketchat_tui::run(c).await?;
            }
            Ok(())
        }
        Some(Cmd::New { name }) => {
            let mut c = open().await?;
            c.create_group(&name).await?;
            println!("Made {name}. Invite people with: socketchat invite --group \"{name}\"");
            Ok(())
        }
        Some(Cmd::Invite { group, dm }) => {
            let mut c = open().await?;
            c.sync().await?;
            let (link, expires_unix) = match (group, dm) {
                (None, true) => c.invite(None, true).await?,
                (Some(g), false) => {
                    let gid = group_by_name(&c, &g)?;
                    c.invite(Some(gid), false).await?
                }
                _ => return Err(Fail(1, "Use --group <name>, or --dm on its own.".into())),
            };
            let hours = hours_text(c.hours_until(expires_unix));
            println!("{link}");
            eprintln!("Send this to one person. It works once and expires in {hours}.");
            Ok(())
        }
        Some(Cmd::Send { group, text }) => {
            let mut c = open().await?;
            c.sync().await?;
            let gid = group_by_name(&c, &group)?;
            c.send_text(gid, &text.join(" ")).await?;
            Ok(())
        }
        Some(Cmd::Log { group, limit }) => {
            let mut c = open().await?;
            c.sync().await?;
            let gid = group_by_name(&c, &group)?;
            for l in c.messages(gid, limit) {
                if l.notice {
                    println!("· {}", l.text);
                } else {
                    println!("{}: {}", l.sender, l.text);
                }
            }
            Ok(())
        }
        Some(Cmd::Sync) => {
            let mut c = open().await?;
            sync_and_report(&mut c).await
        }
        None => {
            let c = open().await?;
            socketchat_tui::run(c).await?;
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
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
            eprintln!("{msg}");
            ExitCode::from(code)
        }
    }
}
