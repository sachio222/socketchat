//! `socketchat-server.toml`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ServerError;

pub const CONFIG_FILE: &str = "socketchat-server.toml";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Address and port to listen on.
    pub listen: SocketAddr,
    /// Name or address people use to reach this server. Invite links carry it.
    pub public_host: String,
    /// Where the database, certificate and file chunks live.
    pub data_dir: PathBuf,
    /// Days the server keeps messages and files nobody has fetched.
    pub retention_days: u32,
    /// Largest file anyone can send, in megabytes.
    pub max_file_mb: u64,
    /// Hours an invite link stays valid.
    pub invite_ttl_hours: u32,
    /// Whether members, not only admins, can make invite links.
    pub members_can_invite: bool,
    /// Refuse groups that use the post-quantum draft suite.
    pub require_standard_suite: bool,
    /// Most connections served at once.
    pub max_connections: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: SocketAddr::from(([0, 0, 0, 0], socketchat_proto::DEFAULT_PORT)),
            public_host: "localhost".into(),
            data_dir: PathBuf::from("."),
            retention_days: 30,
            max_file_mb: 100,
            invite_ttl_hours: 24,
            members_can_invite: true,
            require_standard_suite: false,
            max_connections: 1000,
        }
    }
}

impl Config {
    /// Reads `socketchat-server.toml` from a data directory.
    pub fn load(data_dir: &Path) -> Result<Config, ServerError> {
        Self::load_file(&data_dir.join(CONFIG_FILE))
    }

    pub fn load_file(path: &Path) -> Result<Config, ServerError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ServerError::Config(format!("{}: {e}", path.display())))?;
        toml::from_str(&text).map_err(|e| ServerError::Config(format!("{}: {e}", path.display())))
    }

    pub fn save(&self) -> Result<(), ServerError> {
        let text = toml::to_string_pretty(self).map_err(|e| ServerError::Config(e.to_string()))?;
        std::fs::write(self.data_dir.join(CONFIG_FILE), text)?;
        Ok(())
    }
}
