//! Linux: parse /proc/net/{tcp,tcp6,udp,udp6} and map socket inodes to PIDs via /proc/*/fd.
use super::{interesting, Capture, Socket};
use agent_core::model::Proto;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Default)]
pub struct ProcNet {
    inode_pid: HashMap<u64, u32>,
    seen: HashSet<Socket>,
}

const TCP_ESTABLISHED: &str = "01";
const TCP_SYN_SENT: &str = "02";
const TCP_LISTEN: &str = "0A";

impl Capture for ProcNet {
    fn name(&self) -> &'static str {
        "poll"
    }

    fn poll(&mut self) -> Result<Vec<Socket>> {
        let current: HashSet<Socket> = self.snapshot()?.into_iter().collect();
        let new: Vec<Socket> = current.difference(&self.seen).cloned().collect();
        self.seen = current;
        Ok(new)
    }
}

impl ProcNet {
    /// Every currently connected socket (what `pmacct-agent snapshot` prints).
    pub fn snapshot(&mut self) -> Result<Vec<Socket>> {
        let mut rows = Vec::new();
        for (path, proto) in [("/proc/net/tcp", Proto::Tcp), ("/proc/net/tcp6", Proto::Tcp), ("/proc/net/udp", Proto::Udp), ("/proc/net/udp6", Proto::Udp)] {
            if let Ok(text) = std::fs::read_to_string(path) {
                rows.extend(parse_table(&text, proto));
            }
        }
        // Resolve inodes; rescan /proc once if anything is unknown (new sockets appeared).
        let missing = rows.iter().any(|r| r.inode != 0 && !self.inode_pid.contains_key(&r.inode));
        if missing || self.inode_pid.is_empty() {
            self.inode_pid = scan_inodes();
        }
        Ok(rows
            .into_iter()
            .filter(|r| interesting(&r.remote))
            .map(|r| Socket { proto: r.proto, local: r.local, remote: r.remote, pid: self.inode_pid.get(&r.inode).copied().unwrap_or(0), comm: String::new() })
            .collect())
    }
}

#[derive(Debug, PartialEq)]
pub struct Row {
    pub proto: Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub inode: u64,
}

/// Parse a /proc/net table. Keeps established / connecting TCP and connected UDP (remote set).
pub fn parse_table(text: &str, proto: Proto) -> Vec<Row> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let state = f[3];
        match proto {
            Proto::Tcp if state != TCP_ESTABLISHED && state != TCP_SYN_SENT => continue,
            Proto::Tcp | Proto::Udp if state == TCP_LISTEN => continue,
            _ => {}
        }
        let (Some(local), Some(remote)) = (parse_addr(f[1]), parse_addr(f[2])) else { continue };
        let inode = f[9].parse().unwrap_or(0);
        out.push(Row { proto, local, remote, inode });
    }
    out
}

/// "0100007F:0035" (v4, little-endian words) or 32 hex chars for v6.
fn parse_addr(s: &str) -> Option<SocketAddr> {
    let (h, p) = s.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    let ip: IpAddr = match h.len() {
        8 => {
            let n = u32::from_str_radix(h, 16).ok()?;
            Ipv4Addr::from(n.swap_bytes()).into()
        }
        32 => {
            let mut b = [0u8; 16];
            for (i, chunk) in h.as_bytes().chunks(8).enumerate() {
                let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
                b[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            let v6 = Ipv6Addr::from(b);
            match v6.to_ipv4_mapped() {
                Some(v4) => v4.into(),
                None => v6.into(),
            }
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Map socket inodes to PIDs by reading every /proc/<pid>/fd symlink (needs root for other users).
pub fn scan_inodes() -> HashMap<u64, u32> {
    let mut out = HashMap::new();
    let Ok(rd) = std::fs::read_dir("/proc") else { return out };
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let Ok(fds) = std::fs::read_dir(e.path().join("fd")) else { continue };
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                if let Some(t) = target.to_str() {
                    if let Some(rest) = t.strip_prefix("socket:[") {
                        if let Ok(inode) = rest.trim_end_matches(']').parse::<u64>() {
                            out.insert(inode, pid);
                        }
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_net_tcp() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n\
   1: 7300000A:C1B2 0A0E10AC:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 20 4 30 10 -1\n\
   2: 7300000A:C1B3 0A0E10AC:01BB 06 00000000:00000000 00:00000000 00000000  1000        0 67891 1 0000000000000000 20 4 30 10 -1\n";
        let rows = parse_table(text, Proto::Tcp);
        assert_eq!(rows.len(), 1, "listener and TIME_WAIT excluded");
        assert_eq!(rows[0].local, "10.0.0.115:49586".parse().unwrap());
        assert_eq!(rows[0].remote, "172.16.14.10:443".parse().unwrap());
        assert_eq!(rows[0].inode, 67890);
    }

    #[test]
    fn parses_v6_and_mapped() {
        let text = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0000000000000000FFFF00007300000A:D3E2 0000000000000000FFFF00000A0E10AC:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 111 1 0000000000000000 20 4 30 10 -1\n\
   1: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000  0        0 222 2 0000000000000000 0\n";
        let rows = parse_table(text, Proto::Tcp);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].local, "10.0.0.115:54242".parse().unwrap(), "v4-mapped collapses to v4");
        assert_eq!(rows[0].remote, "172.16.14.10:443".parse().unwrap());
        let udp = parse_table(text, Proto::Udp);
        assert_eq!(udp.len(), 2);
        assert!(!interesting(&udp[1].remote), "unconnected UDP has no peer");
    }
}
