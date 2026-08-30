//! Linux eBPF backend: cgroup sock_addr hooks (connect4/6, sendmsg4/6) on the root cgroup report
//! every outgoing connection / unconnected UDP send with PID, UID, comm and destination, through
//! a ring buffer. Needs root (CAP_BPF + CAP_NET_ADMIN) and cgroup v2; the compiled program is
//! embedded (see ../../bpf/conn.bpf.c).
use super::{interesting, Capture, Socket};
use agent_core::model::Proto;
use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::programs::{CgroupAttachMode, CgroupSockAddr};
use aya::Ebpf as Bpf;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

const PROGRAM: &[u8] = include_bytes!("../../../bpf/conn.bpf.o");
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

#[repr(C)]
#[derive(Clone, Copy)]
struct Event {
    pid: u32,
    uid: u32,
    family: u16,
    proto: u16,
    dport: u16,
    _pad: u16,
    daddr: [u8; 16],
    comm: [u8; 16],
}

pub struct Ebpf {
    _bpf: Bpf,
    ring: RingBuf<aya::maps::MapData>,
    src: SourceCache,
}

impl Ebpf {
    pub fn new() -> Result<Self> {
        let mut bpf = Bpf::load(PROGRAM).context("load eBPF program")?;
        let cgroup = std::fs::File::open(CGROUP_ROOT).with_context(|| format!("open {CGROUP_ROOT} (cgroup v2 required)"))?;
        for name in ["connect4", "connect6", "sendmsg4", "sendmsg6"] {
            let prog: &mut CgroupSockAddr = bpf.program_mut(name).with_context(|| format!("program {name} missing"))?.try_into()?;
            prog.load().with_context(|| format!("load {name}"))?;
            prog.attach(&cgroup, CgroupAttachMode::AllowMultiple).with_context(|| format!("attach {name} to {CGROUP_ROOT}"))?;
        }
        let ring = RingBuf::try_from(bpf.take_map("EVENTS").context("EVENTS map missing")?)?;
        Ok(Self { _bpf: bpf, ring, src: SourceCache::default() })
    }
}

impl Capture for Ebpf {
    fn name(&self) -> &'static str {
        "ebpf"
    }

    fn poll(&mut self) -> Result<Vec<Socket>> {
        let mut out = Vec::new();
        while let Some(item) = self.ring.next() {
            if item.len() < std::mem::size_of::<Event>() {
                continue;
            }
            // Safety: the kernel program writes a plain `struct event` of exactly this layout.
            let ev: Event = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const Event) };
            let dst: IpAddr = match ev.family {
                2 => Ipv4Addr::from(<[u8; 4]>::try_from(&ev.daddr[..4]).unwrap()).into(),
                _ => {
                    let v6 = Ipv6Addr::from(ev.daddr);
                    v6.to_ipv4_mapped().map(IpAddr::from).unwrap_or(IpAddr::from(v6))
                }
            };
            let remote = SocketAddr::new(dst, ev.dport);
            if !interesting(&remote) {
                continue;
            }
            let proto = if ev.proto == 17 { Proto::Udp } else { Proto::Tcp };
            let comm = std::str::from_utf8(&ev.comm).unwrap_or("").trim_end_matches('\0').to_string();
            out.push(Socket { proto, local: SocketAddr::new(self.src.for_dst(&dst), 0), remote, pid: ev.pid, comm });
        }
        Ok(out)
    }
}

/// The connect hooks fire before a source address is chosen, so pick the address of the
/// interface that owns the default route (refreshed every minute).
#[derive(Default)]
struct SourceCache {
    v4: Option<IpAddr>,
    v6: Option<IpAddr>,
    at: Option<Instant>,
}

impl SourceCache {
    fn for_dst(&mut self, dst: &IpAddr) -> IpAddr {
        if self.at.map(|t| t.elapsed() > Duration::from_secs(60)).unwrap_or(true) {
            self.refresh();
        }
        match dst {
            IpAddr::V4(_) => self.v4.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            IpAddr::V6(_) => self.v6.unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        }
    }

    fn refresh(&mut self) {
        self.at = Some(Instant::now());
        let iface = default_iface();
        let addrs = if_addrs::get_if_addrs().unwrap_or_default();
        let pick = |want_v4: bool| {
            let ok = |a: &if_addrs::Interface| {
                let ip = a.ip();
                !ip.is_loopback() && ip.is_ipv4() == want_v4 && match ip {
                    IpAddr::V4(v) => !v.is_link_local(),
                    IpAddr::V6(v) => !v.is_unicast_link_local() && !v.is_unique_local(),
                }
            };
            iface
                .as_ref()
                .and_then(|name| addrs.iter().find(|a| &a.name == name && ok(a)))
                .or_else(|| addrs.iter().find(|a| ok(a)))
                .map(|a| a.ip())
        };
        self.v4 = pick(true);
        self.v6 = pick(false);
    }
}

/// Interface of the IPv4 default route from /proc/net/route.
fn default_iface() -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    text.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.len() > 2 && f[1] == "00000000").then(|| f[0].to_string())
    })
}
