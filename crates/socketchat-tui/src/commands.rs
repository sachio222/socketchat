//! Slash commands typed in the input line.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Invite {
        dm: bool,
    },
    Join(String),
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
    Close,
    /// Vote to keep this room open.
    Keep,
    Invites,
    /// Cancel the link at this number in the last `/invites` list.
    Cancel(usize),
    Mute,
    Unmute,
    Details,
    Clear,
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
        "/invite --dm",
        "make a link that opens a new two-person chat",
    ),
    ("/join <link>", "use an invite link someone sent you"),
    ("/new <name>", "start a new group chat"),
    (
        "/dm <name>",
        "start a two-person chat with someone in this chat",
    ),
    ("/send <path>", "send a file, photo or video"),
    ("/save <file> [folder]", "save a file someone sent"),
    ("/verify <name>", "compare safety numbers with someone"),
    ("/rename <name> <new>", "rename someone on your screen only"),
    ("/name <new>", "change the name others see for you"),
    ("/kick <name>", "remove someone (admins)"),
    ("/admin <name>", "make someone an admin (admins)"),
    ("/leave", "leave this chat and delete its history here"),
    (
        "/switch [room]",
        "open another room; Tab completes the name",
    ),
    ("/title <name>", "rename this room for everyone (admins)"),
    ("/close", "close this room for everyone (admins agree)"),
    ("/keep", "say no to closing this room (admins)"),
    ("/invites", "see your open invite links"),
    ("/cancel <number>", "stop an invite link from /invites"),
    ("/mute", "hide this room's new-message count"),
    ("/unmute", "show this room's new-message count again"),
    ("/details", "see this room's admins, size and age"),
    ("/clear", "delete this room's messages from this computer"),
    ("/quit", "close socketchat"),
];

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
            _ => return Err("Usage: /invite, or /invite --dm".into()),
        },
        "/join" => Command::Join(need("/join <link>")?),
        "/new" => Command::New(need("/new <name>")?),
        "/dm" => Command::Dm(need("/dm <name>")?),
        "/send" => Command::Send(need("/send <path>")?),
        "/save" => {
            let w = words(&need("/save <file> [folder]")?);
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
        "/close" => Command::Close,
        "/keep" => Command::Keep,
        "/invites" => Command::Invites,
        "/cancel" => Command::Cancel(
            rest.parse()
                .map_err(|_| "Usage: /cancel <number>".to_string())?,
        ),
        "/mute" => Command::Mute,
        "/unmute" => Command::Unmute,
        "/details" => Command::Details,
        "/clear" => Command::Clear,
        "/help" => Command::Help,
        "/quit" => Command::Quit,
        other => {
            return Err(format!(
                "There is no {other} command. Type /help to see them all."
            ))
        }
    })
}
