use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("that passphrase does not open this profile")]
    WrongPassphrase,
    #[error("no profile here yet; run `socketchat join <link>` to make one")]
    NoProfile,
    #[error("a profile already exists here")]
    ProfileExists,
    #[error("Socketchat is already open on this profile.")]
    ProfileInUse,
    #[error(transparent)]
    Net(#[from] crate::net::NetError),
    /// A server could not be reached. `server` comes from
    /// [`crate::client::server_text`].
    #[error("Could not reach {server}: {why}.")]
    Unreachable { server: String, why: String },
    #[error("group encryption: {0}")]
    Mls(String),
    #[error("videos keep their location and device data; confirm before sending")]
    VideoNeedsConfirm,
    #[error("this photo keeps its location and device data; confirm before sending")]
    PhotoNeedsConfirm,
    #[error("local storage: {0}")]
    Storage(String),
    /// A link names a server this profile already uses, with a different
    /// certificate. Nothing changes until the person accepts the new one.
    #[error(
        "The link for {} names a different certificate from the one Socketchat trusts for that server.\nTrusted:     {}\nIn the link: {}\nNothing was changed. If the server's operator set it up again and sent you this link, trust the new certificate with: socketchat join --new-certificate <link>",
        crate::client::server_text(.host, *.port),
        crate::keys::fingerprint_text(.pinned),
        crate::keys::fingerprint_text(.offered)
    )]
    NewCertificate {
        host: String,
        port: u16,
        pinned: [u8; 32],
        offered: [u8; 32],
    },
    /// This profile keeps a server address that apps refuse in a link,
    /// such as a name with letters outside ASCII.
    #[error(
        "Socketchat cannot make an invite link for {}, because Socketchat apps refuse a server address with letters outside ASCII. Ask the server's owner to set public_host to the xn-- form of the address and send you a new server invite.",
        crate::client::server_text(.host, *.port)
    )]
    InviteHost { host: String, port: u16 },
    #[error("{0}")]
    Other(String),
}

impl From<rusqlite::Error> for CoreError {
    fn from(e: rusqlite::Error) -> Self {
        CoreError::Storage(e.to_string())
    }
}

impl From<std::io::Error> for CoreError {
    fn from(e: std::io::Error) -> Self {
        CoreError::Storage(e.to_string())
    }
}

impl From<postcard::Error> for CoreError {
    fn from(e: postcard::Error) -> Self {
        CoreError::Storage(e.to_string())
    }
}
