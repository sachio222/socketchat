//! Slash commands typed in the input line.

use socketchat_core::sanitize;
use socketchat_core::settings::{WhoCanInvite, WhoCanSetTopic};

/// A room setting `/settings` changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Setting {
    /// Who can bring people into the room.
    Invite(WhoCanInvite),
    /// Seconds each member who is not an admin waits between messages; 0
    /// turns slow mode off.
    Slow(u32),
    /// Who can set the room's topic.
    Topic(WhoCanSetTopic),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Invite {
        dm: bool,
    },
    /// Invite someone from another room to the open room, or to `room`.
    /// `quoted` says the person used quotes, which settles where the name
    /// ends.
    InviteMember {
        name: String,
        room: Option<String>,
        quoted: bool,
    },
    /// Use a link, or join a room this person was invited to by its name
    /// or its number; with no words, the one invite that waits.
    Join(Option<String>),
    New(String),
    Dm(String),
    Send(String),
    Save {
        file: String,
        dir: Option<String>,
    },
    Verify(String),
    Rename {
        name: String,
        new: String,
    },
    Name(String),
    Kick(String),
    Admin(String),
    Leave,
    /// Open another room: by name, or the switcher with no name.
    Switch(Option<String>),
    /// Rename this room for everyone.
    Title(String),
    /// Show the room's topic, or set it for everyone.
    Topic(Option<String>),
    /// Remove the room's topic for everyone.
    ClearTopic,
    Close,
    /// Vote to keep this room open.
    Keep,
    Invites,
    /// Cancel the link at this number in the last `/invites` list.
    Cancel(usize),
    Servers,
    /// Forget the server at this number in the last `/servers` list.
    Forget(usize),
    Mute,
    Unmute,
    Details,
    /// The server, the connection, this profile, the open room and the
    /// app, in one box.
    Status,
    /// Show this room's settings, or change one.
    Settings(Option<Setting>),
    Clear,
    /// The version, what socketchat is and where to find it.
    About,
    /// Show the colors in use, or switch to the named ones.
    Theme(Option<String>),
    /// Say whether clicks and the scroll wheel work, or turn them on or
    /// off.
    Mouse(Option<bool>),
    /// Say whether the daily check for a new version is on, or turn it on
    /// or off.
    Updates(Option<bool>),
    Help,
    Quit,
}

/// Every command with a one-line description, for `/help`.
pub const HELP: &[(&str, &str)] = &[
    (
        "/invite",
        "make a one-time link that brings someone into this chat",
    ),
    (
        "/invite <name>",
        "invite someone you share a room with to this room",
    ),
    (
        "/invite --dm",
        "make a link that opens a new two-person chat",
    ),
    (
        "/join <link or room>",
        "use a link, or join a room you were invited to",
    ),
    (
        "/join <number>",
        "pick one of several rooms you were invited to",
    ),
    ("/new <name>", "start a new group chat"),
    (
        "/dm <name>",
        "start a two-person chat with someone in this chat",
    ),
    (
        "/send <path>",
        "send a file, photo or video, or drag one onto the window",
    ),
    ("/save <file> [folder]", "save a file someone sent"),
    ("/verify <name>", "compare safety numbers with someone"),
    ("/rename <name> <new>", "rename someone on your screen only"),
    ("/name <new>", "change the name others see for you"),
    ("/kick <name>", "remove someone (admins)"),
    ("/admin <name>", "make someone an admin (admins)"),
    ("/leave", "leave this chat and delete its history here"),
    (
        "/switch [room]",
        "open a room; Tab or Up/Down completes the name",
    ),
    ("/title <name>", "rename this room for everyone (admins)"),
    (
        "/topic [text]",
        "see or set the topic; /topic --clear removes it",
    ),
    ("/close", "close this room for everyone (admins agree)"),
    ("/keep", "say no to closing this room (admins)"),
    ("/invites", "see your open invite links"),
    ("/cancel <number>", "stop an invite link from /invites"),
    ("/servers", "see your servers and whether each is connected"),
    (
        "/forget <number>",
        "delete a server and its rooms from this computer",
    ),
    ("/mute", "hide this room's new-message count"),
    ("/unmute", "show this room's new-message count again"),
    ("/details", "see this room's admins, size and age"),
    ("/settings", "see this room's settings"),
    (
        "/settings invite",
        "admins or anyone: who can bring people in (admins)",
    ),
    (
        "/settings slow",
        "seconds or off: how long members wait between messages (admins)",
    ),
    (
        "/settings topic",
        "admins or anyone: who can set the topic (admins)",
    ),
    ("/clear", "delete this room's messages from this computer"),
    (
        "/theme [name]",
        "see or change the colors: phosphor or classic",
    ),
    (
        "/mouse [on|off]",
        "turn clicking, scrolling and drag to copy on or off",
    ),
    (
        "/updates [on|off]",
        "turn the daily check for a new version on or off",
    ),
    (
        "/status",
        "see the server, connection, this room and the app",
    ),
    ("/about", "see the version and what Socketchat is"),
    ("/help", "see every command and what it does"),
    ("/quit", "close Socketchat"),
];

/// The command word a `HELP` row starts with, such as `/invite` for
/// `/invite --dm`.
fn word_of(usage: &str) -> &str {
    usage.split_whitespace().next().unwrap_or(usage)
}

/// The rows of `HELP` in alphabetical order of their command words, rows
/// for one command in `HELP` order: what the help box lists.
pub fn help_entries() -> Vec<(&'static str, &'static str)> {
    let mut rows = HELP.to_vec();
    rows.sort_by_key(|(c, _)| word_of(c));
    rows
}

/// What picking a help row puts in the message box: the row without its
/// placeholders, so `/save <file> [folder]` gives `/save` and
/// `/settings slow` stays whole.
pub fn command_of(usage: &str) -> String {
    usage
        .split_whitespace()
        .take_while(|w| !w.starts_with('<') && !w.starts_with('['))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether the command word `word`, typed alone, waits for more words in
/// the message box instead of running: it does not run alone, or every
/// `HELP` row for it names something to type, as `/join <link or room>`
/// does, though `/join` alone joins the one invite that waits.
pub fn needs_more(word: &str) -> bool {
    parse_command(word).is_err()
        || !HELP
            .iter()
            .any(|(u, _)| command_of(u) == word && !u.contains('<'))
}

/// Each command word in `HELP`, once, in alphabetical order: what Tab and
/// Up and Down after a slash go through. Every word the parser runs is in
/// `HELP`, and every word in `HELP` runs; tests on both sides keep it that
/// way.
pub fn command_words() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = HELP.iter().map(|(c, _)| word_of(c)).collect();
    out.sort();
    out.dedup();
    out
}

/// Splits on spaces, keeping "quoted parts" together.
fn words(s: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut quoted = false;
    for c in s.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

pub fn parse_command(line: &str) -> Result<Command, String> {
    let line = line.trim();
    let (cmd, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
    let rest = rest.trim();
    let need = |usage: &str| -> Result<String, String> {
        if rest.is_empty() {
            Err(format!("Usage: {usage}"))
        } else {
            Ok(rest.to_string())
        }
    };
    Ok(match cmd {
        "/invite" => match rest {
            "" => Command::Invite { dm: false },
            "--dm" => Command::Invite { dm: true },
            _ => {
                let w = words(rest);
                let Some(name) = w.first().filter(|n| !n.trim().is_empty()) else {
                    return Err("Usage: /invite, /invite <name> or /invite --dm".into());
                };
                Command::InviteMember {
                    name: name.clone(),
                    room: (w.len() > 1).then(|| w[1..].join(" ")),
                    quoted: rest.contains('"'),
                }
            }
        },
        "/join" => Command::Join((!rest.is_empty()).then(|| rest.to_string())),
        "/new" => Command::New(need("/new <name>")?),
        "/dm" => Command::Dm(need("/dm <name>")?),
        "/send" => Command::Send(need("/send <path>")?),
        "/save" => {
            let w = words(&need("/save <file> [folder]")?);
            if w.first().is_none_or(|f| f.trim().is_empty()) {
                return Err("Usage: /save <file> [folder]".into());
            }
            Command::Save {
                file: w[0].clone(),
                dir: (w.len() > 1).then(|| w[1..].join(" ")),
            }
        }
        "/verify" => Command::Verify(need("/verify <name>")?),
        "/rename" => {
            let w = words(&need("/rename <name> <new name>")?);
            if w.len() < 2 {
                return Err("Usage: /rename <name> <new name>".into());
            }
            Command::Rename {
                name: w[0].clone(),
                new: w[1..].join(" "),
            }
        }
        "/name" => Command::Name(need("/name <new name>")?),
        "/kick" => Command::Kick(need("/kick <name>")?),
        "/admin" => Command::Admin(need("/admin <name>")?),
        "/leave" => Command::Leave,
        "/switch" => Command::Switch((!rest.is_empty()).then(|| rest.to_string())),
        "/title" => Command::Title(need("/title <name>")?),
        "/topic" => match rest {
            "" => Command::Topic(None),
            "--clear" => Command::ClearTopic,
            text => Command::Topic(Some(text.to_string())),
        },
        "/close" => Command::Close,
        "/keep" => Command::Keep,
        "/invites" => Command::Invites,
        "/cancel" => Command::Cancel(
            rest.parse()
                .map_err(|_| "Usage: /cancel <number>".to_string())?,
        ),
        "/servers" => Command::Servers,
        "/forget" => Command::Forget(
            rest.parse()
                .map_err(|_| "Usage: /forget <number>".to_string())?,
        ),
        "/mute" => Command::Mute,
        "/unmute" => Command::Unmute,
        "/details" => Command::Details,
        "/status" => Command::Status,
        "/settings" => Command::Settings(parse_setting(rest)?),
        "/clear" => Command::Clear,
        "/about" => Command::About,
        "/theme" => Command::Theme((!rest.is_empty()).then(|| rest.to_string())),
        "/mouse" => Command::Mouse(match rest {
            "" => None,
            "on" => Some(true),
            "off" => Some(false),
            _ => return Err("Usage: /mouse on, or /mouse off".into()),
        }),
        "/updates" => Command::Updates(match rest {
            "" => None,
            "on" => Some(true),
            "off" => Some(false),
            _ => return Err("Usage: /updates on, or /updates off".into()),
        }),
        "/help" => Command::Help,
        "/quit" => Command::Quit,
        other => {
            return Err(format!(
                "There is no {other} command. Type /help to see them all."
            ))
        }
    })
}

/// What follows `/settings`.
fn parse_setting(rest: &str) -> Result<Option<Setting>, String> {
    const USAGE: &str = "Usage: /settings, /settings invite admins, /settings invite anyone, /settings slow <seconds>, /settings slow off, /settings topic admins, or /settings topic anyone";
    let w: Vec<&str> = rest.split_whitespace().collect();
    Ok(Some(match w.as_slice() {
        [] => return Ok(None),
        ["invite", "admins"] => Setting::Invite(WhoCanInvite::Admins),
        ["invite", "anyone"] => Setting::Invite(WhoCanInvite::Anyone),
        ["slow", "off"] => Setting::Slow(0),
        ["slow", n] => Setting::Slow(n.parse().map_err(|_| USAGE.to_string())?),
        ["topic", "admins"] => Setting::Topic(WhoCanSetTopic::Admins),
        ["topic", "anyone"] => Setting::Topic(WhoCanSetTopic::Anyone),
        _ => return Err(USAGE.into()),
    }))
}

/// How many files a refused `/save` lists by name; older ones are counted.
const PICKS_SHOWN: usize = 3;

/// Which file `/save <want>` means among a room's files, oldest first.
/// `want` is a file's name, or its name and its number among the files
/// with that name, as `a.txt:2`. Names never hold `:`, so the number
/// cannot be part of a name. A name more than one file has is refused,
/// with the newest files' numbers, senders and times (from `time`), and
/// the numbers of the older ones.
pub fn pick_file<'a>(
    files: &'a [socketchat_core::client::SharedFile],
    want: &str,
    time: impl Fn(u64) -> String,
) -> Result<&'a socketchat_core::client::SharedFile, String> {
    let named = |n: &str| -> Vec<&'a socketchat_core::client::SharedFile> {
        files
            .iter()
            .filter(|f| sanitize::single_spaced(&f.offer.name) == sanitize::single_spaced(n))
            .collect()
    };
    let mut hits = named(want);
    if let Some((base, k)) = want.rsplit_once(':') {
        let picked = k.parse::<usize>().ok().and_then(|k| {
            let same = named(base);
            k.checked_sub(1).and_then(|i| same.get(i).copied())
        });
        if let Some(f) = picked.filter(|f| !hits.iter().any(|h| h.offer.id == f.offer.id)) {
            hits.push(f);
        }
    }
    match hits.as_slice() {
        [] => Err(format!("No file called {want} in this chat.")),
        [one] => Ok(one),
        many => {
            // Newest first; the oldest past the first few are only counted.
            let mut many = many.to_vec();
            let order = |f: &&socketchat_core::client::SharedFile| {
                files.iter().position(|x| x.offer.id == f.offer.id)
            };
            many.sort_by_key(|f| std::cmp::Reverse(order(f)));
            let label = |f: &socketchat_core::client::SharedFile| {
                let n = named(&f.offer.name)
                    .iter()
                    .position(|x| x.offer.id == f.offer.id)
                    .map_or(0, |i| i + 1);
                match f.offer.name.contains(char::is_whitespace) {
                    true => format!("\"{}\":{n}", f.offer.name),
                    false => format!("{}:{n}", f.offer.name),
                }
            };
            let shown = many.len().min(PICKS_SHOWN);
            let choices: Vec<String> = many[..shown]
                .iter()
                .map(|f| {
                    let who = if f.mine { "you" } else { f.from.as_str() };
                    let when = match f.sent_unix {
                        0 => String::new(),
                        t => format!(" at {}", time(t)),
                    };
                    format!("/save {} for the one {who} sent{when}", label(f))
                })
                .collect();
            let (last, first) = choices.split_last().expect("two or more");
            let older = match &many[shown..] {
                [] => String::new(),
                [one] => format!(" The older one is {}.", label(one)),
                rest => format!(
                    " The {} older ones are {} to {}.",
                    rest.len(),
                    label(rest[rest.len() - 1]),
                    label(rest[0])
                ),
            };
            Err(format!(
                "More than one file is called {want}. Type {}, or {last}.{older}",
                first.join(", ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reverse of the screen test that reads the parser's words: every
    /// command word Tab offers is one the parser runs.
    #[test]
    fn every_command_word_in_help_runs() {
        for w in command_words() {
            if let Err(e) = parse_command(w) {
                assert!(!e.starts_with("There is no"), "{w}: {e}");
            }
        }
    }

    #[test]
    fn save_with_an_empty_name_is_a_usage_error() {
        assert!(parse_command("/save \"\"").is_err());
        assert!(parse_command("/save \"   \"").is_err());
        assert_eq!(
            parse_command("/save \"my file.txt\":2 ~/Desktop"),
            Ok(Command::Save {
                file: "my file.txt:2".into(),
                dir: Some("~/Desktop".into()),
            })
        );
    }

    fn shared(id: u8, name: &str, from: &str, mine: bool, at: u64) -> SharedFile {
        SharedFile {
            offer: socketchat_core::files::FileOffer {
                id: socketchat_proto::msg::FileId([id; 16]),
                name: name.into(),
                size: 1,
                mime: "application/octet-stream".into(),
                sha256: [0; 32],
                key: [0; 32],
                nonce_prefix: [0; 19],
            },
            from: from.into(),
            mine,
            sent_unix: at,
        }
    }

    use socketchat_core::client::SharedFile;

    #[test]
    fn a_long_list_shows_the_newest_few() {
        let files: Vec<SharedFile> = (1..=6)
            .map(|i| shared(i, "a.txt", "Ada", false, 100 + i as u64))
            .collect();
        let time = |t: u64| format!("t{t}");
        let err = pick_file(&files, "a.txt", time).unwrap_err();
        assert_eq!(
            err,
            "More than one file is called a.txt. Type /save a.txt:6 for the one Ada sent at t106, /save a.txt:5 for the one Ada sent at t105, or /save a.txt:4 for the one Ada sent at t104. The 3 older ones are a.txt:1 to a.txt:3."
        );
        let err = pick_file(&files[..4], "a.txt", time).unwrap_err();
        assert!(err.ends_with(" The older one is a.txt:1."), "{err}");
    }

    #[test]
    fn a_shared_name_lists_each_file_to_pick_from() {
        let files = [
            shared(1, "my plan.txt", "Ada", false, 10),
            shared(2, "notes.txt", "Ada", false, 11),
            shared(3, "my plan.txt", "Bo", true, 12),
            shared(4, "my plan.txt", "someone", false, 0),
        ];
        let time = |t: u64| format!("t{t}");
        let err = pick_file(&files, "my plan.txt", time).unwrap_err();
        assert_eq!(
            err,
            "More than one file is called my plan.txt. Type /save \"my plan.txt\":3 for the one someone sent, /save \"my plan.txt\":2 for the one you sent at t12, or /save \"my plan.txt\":1 for the one Ada sent at t10."
        );
        let id = |r: Result<&SharedFile, String>| r.unwrap().offer.id.0[0];
        assert_eq!(id(pick_file(&files, "my plan.txt:2", time)), 3);
        assert_eq!(id(pick_file(&files, "notes.txt", time)), 2);
        assert_eq!(id(pick_file(&files, "notes.txt:1", time)), 2);
        assert!(pick_file(&files, "notes.txt:2", time).is_err());
        assert!(pick_file(&files, "notes.txt:0", time).is_err());
        assert!(pick_file(&files, "my plan.txt:x", time).is_err());
    }
}
