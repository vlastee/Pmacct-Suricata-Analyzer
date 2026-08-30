use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Persisted agent configuration (written by `enroll`, read by `run`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// Base URL, e.g. https://10.0.0.210:8091
    pub server: String,
    pub agent_id: i64,
    pub token: String,
    /// PEM of the server's internal CA (pinned: no other root is trusted). None for plain http.
    #[serde(default)]
    pub ca_pem: Option<String>,
    /// Polling interval in seconds (event-driven capture ignores it).
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    /// How often batches are uploaded.
    #[serde(default = "default_send")]
    pub send_every_secs: u64,
    /// Send full command lines (may contain secrets) — off by default.
    #[serde(default)]
    pub send_cmdline: bool,
    /// Capture backend: auto (event-driven when possible, else poll), poll, ebpf (Linux), etw (Windows).
    #[serde(default = "default_capture")]
    pub capture: String,
    /// Local networks (from enrollment); connections to peers outside them are what matters,
    /// but everything non-loopback is reported so LAN-to-LAN scans are attributable too.
    #[serde(default)]
    pub local_networks: Vec<String>,
}

fn default_interval() -> u64 {
    1
}
fn default_send() -> u64 {
    30
}
fn default_capture() -> String {
    "auto".into()
}

impl Config {
    /// Platform default: /etc/pmacct-agent/agent.toml or %ProgramData%\pmacct-agent\agent.toml,
    /// overridable with PMACCT_AGENT_CONFIG.
    pub fn default_path() -> PathBuf {
        if let Ok(p) = std::env::var("PMACCT_AGENT_CONFIG") {
            return PathBuf::from(p);
        }
        Self::data_dir().join("agent.toml")
    }

    /// Directory for config and the spool.
    pub fn data_dir() -> PathBuf {
        if let Ok(p) = std::env::var("PMACCT_AGENT_DIR") {
            return PathBuf::from(p);
        }
        #[cfg(windows)]
        {
            let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
            PathBuf::from(base).join("pmacct-agent")
        }
        #[cfg(not(windows))]
        {
            PathBuf::from("/etc/pmacct-agent")
        }
    }

    pub fn load(path: &std::path::Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        toml::from_str(&raw).with_context(|| format!("parse {}", path.display()))
    }

    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        }
        let raw = toml::to_string_pretty(self)?;
        std::fs::write(path, raw).with_context(|| format!("write {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}
