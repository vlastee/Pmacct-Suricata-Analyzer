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
}

#[derive(Clone, Debug, Deserialize)]
pub struct EventsAck {
    pub accepted: u32,
    pub rejected: u32,
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
