use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl std::fmt::Display for Proto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        })
    }
}

/// Identity of a program as reported to the server.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcInfo {
    pub pid: u32,
    pub exe: String,
    pub name: String,
    pub user: String,
    pub sha256: String,
    #[serde(default)]
    pub cmdline: String,
    /// Container the connection belongs to (own cgroup, or — for pasta/slirp4netns proxies —
    /// the container whose inner socket table holds the same destination). Empty on the host.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub container: String,
}

/// Aggregation key: everything about a connection except the ephemeral source port.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConnKey {
    pub src: IpAddr,
    pub proto: Proto,
    pub dst: IpAddr,
    pub dst_port: u16,
    pub exe: String,
    pub user: String,
    pub container: String,
}

/// One per-minute aggregate — the unit stored in `endpoint_conns` on the server.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ConnRecord {
    pub minute: DateTime<Utc>,
    pub src: IpAddr,
    pub proto: Proto,
    pub dst: IpAddr,
    pub dst_port: u16,
    pub exe: String,
    pub name: String,
    pub user: String,
    pub sha256: String,
    pub pid: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cmdline: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub container: String,
    pub count: u32,
    pub bytes: u64,
}

/// Body of `POST /api/v1/agent/events`. An empty `conns` is a heartbeat.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventsBatch {
    pub hostname: String,
    pub version: String,
    pub ips: Vec<IpAddr>,
    pub capture: String,
    pub dropped: u64,
    pub conns: Vec<ConnRecord>,
    /// Identity facts for executables seen for the first time since the agent started
    /// (one entry per exe + hash); empty in most batches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub programs: Vec<ProgramIdentity>,
}

/// Facts about an executable gathered on the machine itself: where it came from (package
/// manager, snap, flatpak, AppImage, a stray file), whether it still matches what the package
/// installed, and on Windows the Authenticode signature and the version resource. Reported once
/// per (exe, sha256) per agent run; the server keeps the latest per agent.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct ProgramIdentity {
    pub exe: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sha1: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub md5: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<DateTime<Utc>>,
    /// Install channel: dpkg | apk | pacman | snap | flatpak | appimage | nix | container |
    /// venv | user-install | home | tmp | opt | local | unpackaged | "" (not determined).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub origin: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub package: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub package_version: String,
    /// Some(true) when the file's digest matches the package manifest, Some(false) when it differs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    /// Windows Authenticode: valid | unsigned | untrusted | invalid | "" (not checked).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signer: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub company: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub product: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub file_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// Free-text detail: catalog file, why a check was skipped, etc.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

/// The server's current agent build for this platform (in the events ack, for self-update).
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct BuildInfo {
    pub target: String,
    pub version: String,
    pub sha256: String,
    #[serde(default)]
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct EventsAck {
    pub accepted: u32,
    pub rejected: u32,
    /// Newest build the server can hand out for this agent's target, when it has one.
    #[serde(default)]
    pub build: Option<BuildInfo>,
    /// Server policy (global toggle AND this agent's opt-in).
    #[serde(default)]
    pub auto_update: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct EnrollRequest {
    pub enroll_token: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub version: String,
    pub ips: Vec<IpAddr>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct EnrollResponse {
    pub agent_id: i64,
    pub agent_token: String,
    pub name: String,
    #[serde(default)]
    pub local_networks: Vec<String>,
}
