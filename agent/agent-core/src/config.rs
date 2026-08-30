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
    /// Where batches are spooled while the server is unreachable (bounded). None = platform default:
    /// /var/lib/pmacct-agent/spool or %ProgramData%\pmacct-agent\spool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spool_dir: Option<String>,
    /// Cap on spooled data on disk, in MiB (default 50). Oldest batches are dropped beyond it.
    #[serde(default = "default_spool_max_mb")]
    pub spool_max_mb: u64,
    /// Cap on distinct (minute, program, destination) keys held in memory between uploads
    /// (default 50 000; bounds memory and the size of one batch).
    #[serde(default = "default_max_keys")]
    pub max_keys: usize,
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
fn default_spool_max_mb() -> u64 {
    50
}
fn default_max_keys() -> usize {
    50_000
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

    /// Effective spool directory: config, else PMACCT_AGENT_SPOOL, else the platform default.
    pub fn spool_dir(&self) -> PathBuf {
        if let Some(d) = self.spool_dir.as_deref().map(str::trim).filter(|d| !d.is_empty()) {
            return PathBuf::from(d);
        }
        if let Ok(p) = std::env::var("PMACCT_AGENT_SPOOL") {
            return PathBuf::from(p);
        }
        Self::default_spool_dir()
    }

    /// Platform default spool location (variable data, not configuration).
    pub fn default_spool_dir() -> PathBuf {
        if let Ok(p) = std::env::var("PMACCT_AGENT_DIR") {
            return PathBuf::from(p).join("spool");
        }
        #[cfg(windows)]
        {
            Self::data_dir().join("spool")
        }
        #[cfg(not(windows))]
        {
            PathBuf::from("/var/lib/pmacct-agent/spool")
        }
    }

    /// Directory for the configuration.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spool_dir_precedence() {
        let base = Config { server: "https://x".into(), agent_id: 1, token: "t".into(), ca_pem: None, interval_secs: 1, send_every_secs: 30, send_cmdline: false, capture: "auto".into(), spool_dir: None, spool_max_mb: 50, max_keys: 50_000, local_networks: vec![] };
        // Explicit config wins over everything.
        let mut c = base.clone();
        c.spool_dir = Some("/mnt/fast/spool".into());
        assert_eq!(c.spool_dir(), PathBuf::from("/mnt/fast/spool"));
        // Blank config value falls through to the default.
        c.spool_dir = Some("  ".into());
        assert_eq!(c.spool_dir(), Config::default_spool_dir());
        // Round-trips through TOML, and is omitted when unset.
        let toml_text = toml::to_string(&base).unwrap();
        assert!(!toml_text.contains("spool_dir"));
        let back: Config = toml::from_str(&toml_text).unwrap();
        assert_eq!(back.spool_dir, None);
        let with: Config = toml::from_str(&format!("{toml_text}spool_dir = \"/data/spool\"\n")).unwrap();
        assert_eq!(with.spool_dir(), PathBuf::from("/data/spool"));
        // Older config files without the caps get the defaults.
        let old: Config = toml::from_str("server = \"https://x\"\nagent_id = 1\ntoken = \"t\"\n").unwrap();
        assert_eq!((old.spool_max_mb, old.max_keys), (50, 50_000));
    }
}
