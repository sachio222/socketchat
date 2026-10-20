use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("that passphrase does not open this profile")]
    WrongPassphrase,
    #[error("no profile here yet; run `socketchat join <link>` to make one")]
    NoProfile,
    #[error("a profile already exists here")]
    ProfileExists,
    #[error(transparent)]
    Net(#[from] crate::net::NetError),
    #[error("group encryption: {0}")]
    Mls(String),
    #[error("local storage: {0}")]
    Storage(String),
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
