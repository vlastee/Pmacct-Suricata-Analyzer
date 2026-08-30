//! Windows: GetExtendedTcpTable (v4 + v6) with owning PIDs. UDP tables carry no remote address,
//! so UDP attribution waits for the ETW backend.
use super::{interesting, Capture, Socket};
use agent_core::model::Proto;
use anyhow::{bail, Result};
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

#[derive(Default)]
pub struct IpHelper {
    seen: HashSet<Socket>,
}

const MIB_TCP_STATE_ESTAB: u32 = 5;
const MIB_TCP_STATE_SYN_SENT: u32 = 3;

fn port(raw: u32) -> u16 {
    u16::from_be((raw & 0xffff) as u16)
}

fn table(af: u32) -> Result<Vec<u8>> {
    let mut size: u32 = 0;
    unsafe {
        let _ = GetExtendedTcpTable(None, &mut size, false, af, TCP_TABLE_OWNER_PID_ALL, 0);
        let mut buf = vec![0u8; size as usize + 64];
        let rc = GetExtendedTcpTable(Some(buf.as_mut_ptr() as *mut _), &mut size, false, af, TCP_TABLE_OWNER_PID_ALL, 0);
        if rc != 0 {
            bail!("GetExtendedTcpTable(af={af}) failed: {rc}");
        }
        Ok(buf)
    }
}

impl Capture for IpHelper {
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

impl IpHelper {
    pub fn snapshot(&mut self) -> Result<Vec<Socket>> {
        let mut out = Vec::new();
        let v4 = table(AF_INET.0 as u32)?;
        unsafe {
            let t = &*(v4.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(t.table.as_ptr() as *const MIB_TCPROW_OWNER_PID, t.dwNumEntries as usize);
            for r in rows {
                if r.dwState != MIB_TCP_STATE_ESTAB && r.dwState != MIB_TCP_STATE_SYN_SENT {
                    continue;
                }
                let local = SocketAddr::new(Ipv4Addr::from(u32::from_be(r.dwLocalAddr)).into(), port(r.dwLocalPort));
                let remote = SocketAddr::new(Ipv4Addr::from(u32::from_be(r.dwRemoteAddr)).into(), port(r.dwRemotePort));
                if interesting(&remote) {
                    out.push(Socket { proto: Proto::Tcp, local, remote, pid: r.dwOwningPid, comm: String::new() });
                }
            }
        }
        let v6 = table(AF_INET6.0 as u32)?;
        unsafe {
            let t = &*(v6.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(t.table.as_ptr() as *const MIB_TCP6ROW_OWNER_PID, t.dwNumEntries as usize);
            for r in rows {
                if r.dwState != MIB_TCP_STATE_ESTAB && r.dwState != MIB_TCP_STATE_SYN_SENT {
                    continue;
                }
                let lip = Ipv6Addr::from(r.ucLocalAddr);
                let rip = Ipv6Addr::from(r.ucRemoteAddr);
                let local = SocketAddr::new(lip.to_ipv4_mapped().map(Into::into).unwrap_or(lip.into()), port(r.dwLocalPort));
                let remote = SocketAddr::new(rip.to_ipv4_mapped().map(Into::into).unwrap_or(rip.into()), port(r.dwRemotePort));
                if interesting(&remote) {
                    out.push(Socket { proto: Proto::Tcp, local, remote, pid: r.dwOwningPid, comm: String::new() });
                }
            }
        }
        Ok(out)
    }
}
