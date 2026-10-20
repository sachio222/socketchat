//! Slash commands typed in the input line.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Invite { dm: bool },
    Join(String),
    New(String),
    Dm(String),
    Send(String),
    Save { file: String, dir: Option<String> },
    Verify(String),
    Rename { name: String, new: String },
    Name(String),
    Kick(String),
    Admin(String),
    Leave,
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
    ("/leave", "leave this chat"),
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
        "/help" => Command::Help,
        "/quit" => Command::Quit,
        other => {
            return Err(format!(
                "There is no {other} command. Type /help to see them all."
            ))
        }
    })
}
