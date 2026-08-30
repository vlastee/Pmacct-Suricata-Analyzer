//! The agent loop: poll sockets, attribute new connections to programs, aggregate per minute,
//! upload every `send_every_secs` (heartbeat when idle), spool on failure.
use crate::capture::{self, Socket};
use crate::procinfo::Resolver;
use agent_core::aggregator::Aggregator;
use agent_core::client::Client;
use agent_core::config::Config;
use agent_core::model::{ConnKey, EventsBatch};
use agent_core::spool::Spool;
use anyhow::Result;
use log::{info, warn};
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::watch;

pub fn local_ips() -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = if_addrs::get_if_addrs()
        .map(|v| v.into_iter().map(|i| i.ip()).filter(|ip| !ip.is_loopback() && !ip.is_unspecified()).collect())
        .unwrap_or_default();
    out.retain(|ip| match ip {
        IpAddr::V4(v4) => !v4.is_link_local(),
        IpAddr::V6(v6) => !v6.is_unicast_link_local(),
    });
    out.sort();
    out.dedup();
    out
}

pub fn host_name() -> String {
    hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or_default()
}

/// Per-platform container attribution state (a no-op outside Linux).
#[cfg(target_os = "linux")]
pub type ContainerMap = crate::containers::Containers;
#[cfg(not(target_os = "linux"))]
#[derive(Default)]
pub struct ContainerMap;
#[cfg(not(target_os = "linux"))]
impl ContainerMap {
    pub fn new() -> Self {
        Self
    }
}

/// Resolve the program behind a socket; a process that already exited (short-lived, eBPF) keeps
/// at least the kernel's command name. On Linux the container is attached: the process's own,
/// or — for pasta/slirp4netns proxies — the one whose inner socket table has this destination.
pub fn identify(resolver: &mut Resolver, containers: &mut ContainerMap, s: &Socket, send_cmdline: bool) -> agent_core::model::ProcInfo {
    let mut info = resolver.resolve(s.pid, send_cmdline);
    if info.exe.is_empty() && info.name.is_empty() && !s.comm.is_empty() {
        info.name = s.comm.clone();
        info.exe = s.comm.clone();
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(c) = containers.for_pid(s.pid) {
            info.container = c;
        } else if crate::containers::is_proxy(&info.name) {
            if let Some(c) = containers.for_destination(s.remote, s.proto) {
                info.container = c;
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = containers;
    }
    info
}

/// Runs until `stop` flips to true.
pub async fn run(cfg: Config, mut stop: watch::Receiver<bool>) -> Result<()> {
    let client = Client::new(&cfg.server, &cfg.token, cfg.ca_pem.as_deref())?;
    let spool = Spool::new(cfg.spool_dir(), 500, cfg.spool_max_mb.max(1) * 1024 * 1024);
    let mut capture = capture::new(&cfg.capture)?;
    let mut resolver = Resolver::default();
    let mut containers = ContainerMap::new();
    let mut agg = Aggregator::new(cfg.max_keys.max(1000));
    let mut poll = tokio::time::interval(Duration::from_secs(cfg.interval_secs.max(1)));
    let mut send = tokio::time::interval(Duration::from_secs(cfg.send_every_secs.clamp(5, 600)));
    let mut last_upload = std::time::Instant::now();
    let capture_name = capture.name().to_string();
    info!("capture={} interval={}s upload every {}s spool={} ({} queued, cap {} MiB)", capture_name, cfg.interval_secs, cfg.send_every_secs, spool.dir().display(), spool.len(), cfg.spool_max_mb);

    loop {
        tokio::select! {
            _ = poll.tick() => {
                match capture.poll() {
                    Ok(sockets) => {
                        let now = chrono::Utc::now();
                        for s in sockets {
                            let info = identify(&mut resolver, &mut containers, &s, cfg.send_cmdline);
                            let key = ConnKey { src: s.local.ip(), proto: s.proto, dst: s.remote.ip(), dst_port: s.remote.port(), exe: info.exe.clone(), user: info.user.clone(), container: info.container.clone() };
                            agg.observe(now, key, &info, 0, cfg.send_cmdline);
                        }
                    }
                    Err(e) => warn!("capture: {e}"),
                }
            }
            _ = send.tick() => {
                let now = chrono::Utc::now();
                let conns = agg.drain(now, false);
                let heartbeat_due = last_upload.elapsed() >= Duration::from_secs(60);
                if !conns.is_empty() || heartbeat_due {
                    let batch = EventsBatch { hostname: host_name(), version: agent_core::VERSION.into(), ips: local_ips(), capture: capture_name.clone(), dropped: agg.dropped, conns };
                    match client.send(&batch).await {
                        Ok(ack) => {
                            last_upload = std::time::Instant::now();
                            if ack.accepted > 0 || ack.rejected > 0 { info!("uploaded {} accepted, {} rejected", ack.accepted, ack.rejected); }
                            // Drain the spool while the server answers.
                            let mut flushed = 0;
                            while let Ok(Some((path, old))) = spool.peek() {
                                if client.send(&old).await.is_err() { break; }
                                spool.remove(&path);
                                flushed += 1;
                                if flushed >= 20 { break; }
                            }
                            if flushed > 0 { info!("flushed {flushed} spooled batches"); }
                        }
                        Err(e) => {
                            warn!("upload failed: {e:#}");
                            if !batch.conns.is_empty() {
                                if let Err(e) = spool.push(&batch) { warn!("spool: {e}"); }
                            }
                        }
                    }
                }
            }
            _ = stop.changed() => {
                if *stop.borrow() {
                    let conns = agg.drain(chrono::Utc::now(), true);
                    if !conns.is_empty() {
                        let batch = EventsBatch { hostname: host_name(), version: agent_core::VERSION.into(), ips: local_ips(), capture: capture_name.clone(), dropped: agg.dropped, conns };
                        if client.send(&batch).await.is_err() { let _ = spool.push(&batch); }
                    }
                    info!("stopped");
                    return Ok(());
                }
            }
        }
    }
}
