//! Container attribution (Linux). Two mechanisms, both file reads under /proc and the container
//! storage directories — no `podman`/`docker` invocations:
//!  1. a process's own container from `/proc/<pid>/cgroup` (`libpod-<id>` / `docker-<id>`);
//!  2. for user-mode network proxies — pasta/passt (rootless Podman ≥ 5) and slirp4netns — which
//!     open host sockets on behalf of containers, the container whose *inner* socket table
//!     (`/proc/<container pid>/net/tcp*`) holds a connection to the same destination.
//! Ids map to names through Podman's `containers.json` / Docker's `config.v2.json`.
use agent_core::model::Proto;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const PROXIES: &[&str] = &["pasta", "pasta.avx2", "passt", "passt.avx2", "slirp4netns", "rootlessport"];

pub fn is_proxy(name: &str) -> bool {
    PROXIES.contains(&name)
}

/// "libpod-<id>" / "docker-<id>" from a cgroup file.
pub fn container_id_from_cgroup(text: &str) -> Option<String> {
    for marker in ["libpod-", "docker-"] {
        if let Some(i) = text.find(marker) {
            let rest = &text[i + marker.len()..];
            let id: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            if id.len() >= 12 {
                return Some(id);
            }
        }
    }
    None
}

/// Podman storage `containers.json`: [{"id": "...", "names": ["..."]}, …].
pub fn parse_containers_json(text: &str) -> Vec<(String, Vec<String>)> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else { return vec![] };
    v.as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    let id = c.get("id")?.as_str()?.to_string();
                    let names = c.get("names").and_then(|n| n.as_array()).map(|n| n.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
                    Some((id, names))
                })
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Default)]
pub struct Containers {
    names: HashMap<String, String>, // full id -> name
    names_at: Option<Instant>,
    pid_cache: HashMap<u32, (Option<String>, Instant)>,
    inner: HashMap<(SocketAddr, Proto), String>, // destination -> container name (or id)
    inner_at: Option<Instant>,
}

impl Containers {
    pub fn new() -> Self {
        Self::default()
    }

    /// The container a process belongs to, from its cgroup.
    pub fn for_pid(&mut self, pid: u32) -> Option<String> {
        if let Some((c, at)) = self.pid_cache.get(&pid) {
            if at.elapsed() < Duration::from_secs(300) {
                return c.clone();
            }
        }
        let id = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok().and_then(|t| container_id_from_cgroup(&t));
        let name = id.map(|id| self.name_of(&id));
        if self.pid_cache.len() > 5000 {
            self.pid_cache.clear();
        }
        self.pid_cache.insert(pid, (name.clone(), Instant::now()));
        name
    }

    /// For a proxy's host-side socket: the container with the same destination in its inner table.
    pub fn for_destination(&mut self, remote: SocketAddr, proto: Proto) -> Option<String> {
        if self.inner_at.map(|t| t.elapsed() > Duration::from_secs(2)).unwrap_or(true) {
            self.refresh_inner();
        }
        self.inner.get(&(remote, proto)).cloned()
    }

    fn name_of(&mut self, id: &str) -> String {
        if self.names_at.map(|t| t.elapsed() > Duration::from_secs(60)).unwrap_or(true) {
            self.refresh_names();
        }
        self.names.iter().find(|(full, _)| full.starts_with(id)).map(|(_, n)| n.clone()).unwrap_or_else(|| id.chars().take(12).collect())
    }

    fn refresh_names(&mut self) {
        self.names_at = Some(Instant::now());
        self.names.clear();
        let mut files = vec!["/var/lib/containers/storage/overlay-containers/containers.json".to_string(), "/root/.local/share/containers/storage/overlay-containers/containers.json".to_string()];
        if let Ok(rd) = std::fs::read_dir("/home") {
            for e in rd.flatten() {
                files.push(format!("{}/.local/share/containers/storage/overlay-containers/containers.json", e.path().display()));
            }
        }
        for f in files {
            if let Ok(text) = std::fs::read_to_string(&f) {
                for (id, names) in parse_containers_json(&text) {
                    if let Some(n) = names.first() {
                        self.names.insert(id, n.clone());
                    }
                }
            }
        }
        if let Ok(rd) = std::fs::read_dir("/var/lib/docker/containers") {
            for e in rd.flatten() {
                let id = e.file_name().to_string_lossy().to_string();
                if let Ok(text) = std::fs::read_to_string(e.path().join("config.v2.json")) {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                        if let Some(n) = v.get("Name").and_then(|n| n.as_str()) {
                            self.names.insert(id, n.trim_start_matches('/').to_string());
                        }
                    }
                }
            }
        }
    }

    /// Scan every container process's inner socket table (one scan per network namespace).
    fn refresh_inner(&mut self) {
        self.inner_at = Some(Instant::now());
        self.inner.clear();
        let Ok(rd) = std::fs::read_dir("/proc") else { return };
        let mut seen_ns: HashMap<String, ()> = HashMap::new();
        for e in rd.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
            let Some(id) = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok().and_then(|t| container_id_from_cgroup(&t)) else { continue };
            let ns = std::fs::read_link(format!("/proc/{pid}/ns/net")).map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
            if ns.is_empty() || seen_ns.contains_key(&ns) {
                continue;
            }
            seen_ns.insert(ns, ());
            let name = self.name_of(&id);
            for (file, proto) in [("tcp", Proto::Tcp), ("tcp6", Proto::Tcp), ("udp", Proto::Udp), ("udp6", Proto::Udp)] {
                if let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/net/{file}")) {
                    for row in crate::capture::linux::parse_table(&text, proto) {
                        if crate::capture::interesting(&row.remote) {
                            self.inner.entry((row.remote, proto)).or_insert_with(|| name.clone());
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_ids() {
        assert_eq!(container_id_from_cgroup("0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-00c2a1bd0ba4f3e5.scope\n").as_deref(), Some("00c2a1bd0ba4f3e5"));
        assert_eq!(container_id_from_cgroup("0::/system.slice/docker-abcdef0123456789abcdef.scope").as_deref(), Some("abcdef0123456789abcdef"));
        assert_eq!(container_id_from_cgroup("0::/user.slice/user-1000.slice/user@1000.service/user.slice/rootless-netns-473c97f6.scope"), None, "the shared pasta netns is not a container");
        assert_eq!(container_id_from_cgroup("0::/init.scope"), None);
    }

    #[test]
    fn containers_json() {
        let v = parse_containers_json(r#"[{"id":"69adf95db338aaaa","names":["pmacct-it-pg"],"layer":"x"},{"id":"f079","names":[]}]"#);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].1[0], "pmacct-it-pg");
        assert!(parse_containers_json("not json").is_empty());
    }
}
