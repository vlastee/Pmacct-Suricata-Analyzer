//! Connection capture backends. Each returns the connections observed *since the previous call*.
//! `poll` reads the OS socket table (misses connections shorter than one interval); `ebpf`
//! (Linux, root) is told about every connect()/sendmsg() by the kernel; `etw` (Windows) is next.
use agent_core::model::Proto;
use anyhow::Result;
use std::net::SocketAddr;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Socket {
    pub proto: Proto,
    /// Local address; port 0 when the backend cannot know it (eBPF connect hooks).
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub pid: u32,
    /// Command name from the kernel when available (eBPF); the resolver fills the rest.
    pub comm: String,
}

pub trait Capture: Send {
    fn name(&self) -> &'static str;
    /// Connections that appeared since the last call (listeners excluded).
    fn poll(&mut self) -> Result<Vec<Socket>>;
}

#[cfg(target_os = "linux")]
pub mod ebpf;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(windows)]
pub mod windows;

/// Pick a backend: `auto` prefers the event-driven one and falls back to polling.
pub fn new(mode: &str) -> Result<Box<dyn Capture>> {
    let mode = mode.trim().to_ascii_lowercase();
    #[cfg(target_os = "linux")]
    {
        match mode.as_str() {
            "poll" => return Ok(Box::new(linux::ProcNet::default())),
            "ebpf" => return Ok(Box::new(ebpf::Ebpf::new()?)),
            _ => match ebpf::Ebpf::new() {
                Ok(b) => return Ok(Box::new(b)),
                Err(e) => {
                    log::warn!("eBPF capture unavailable ({e:#}); falling back to polling");
                    return Ok(Box::new(linux::ProcNet::default()));
                }
            },
        }
    }
    #[cfg(windows)]
    {
        let _ = mode;
        Ok(Box::new(windows::IpHelper::default()))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        compile_error!("pmacct-agent supports Linux and Windows")
    }
}

/// Peers that never matter: loopback, unspecified, link-local, multicast.
pub fn interesting(remote: &SocketAddr) -> bool {
    let ip = remote.ip();
    if remote.port() == 0 || ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    match ip {
        std::net::IpAddr::V4(v4) => !v4.is_link_local() && !v4.is_broadcast(),
        std::net::IpAddr::V6(v6) => !v6.is_unicast_link_local(),
    }
}
