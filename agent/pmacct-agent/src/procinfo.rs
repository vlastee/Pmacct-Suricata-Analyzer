//! Resolve a PID to a program identity, cached (PIDs are reused, so entries expire).
use agent_core::model::ProcInfo;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

pub struct Resolver {
    cache: HashMap<u32, (ProcInfo, Instant)>,
    hashes: HashMap<(String, u64, u64), String>, // (path, size, mtime) -> sha256
    ttl: Duration,
}

impl Default for Resolver {
    fn default() -> Self {
        Self { cache: HashMap::new(), hashes: HashMap::new(), ttl: Duration::from_secs(300) }
    }
}

impl Resolver {
    pub fn resolve(&mut self, pid: u32, want_cmdline: bool) -> ProcInfo {
        if let Some((info, at)) = self.cache.get(&pid) {
            if at.elapsed() < self.ttl {
                return info.clone();
            }
        }
        let mut info = platform::lookup(pid, want_cmdline);
        info.pid = pid;
        // The executable's file name is the stable identity; the kernel's comm is truncated to 15
        // characters and can be inherited or renamed (VS Code helpers show up as "code"), so it
        // only stands in when the path could not be read.
        if let Some(base) = Path::new(&info.exe).file_name().and_then(|s| s.to_str()).filter(|b| !b.is_empty()) {
            info.name = base.to_string();
        }
        if !info.exe.is_empty() {
            info.sha256 = self.hash(&info.exe);
        }
        self.cache.insert(pid, (info.clone(), Instant::now()));
        if self.cache.len() > 5000 {
            self.cache.retain(|_, (_, at)| at.elapsed() < self.ttl);
        }
        info
    }

    fn hash(&mut self, exe: &str) -> String {
        let Ok(meta) = std::fs::metadata(exe) else { return String::new() };
        if meta.len() > 256 << 20 {
            return String::new();
        }
        let mtime = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
        let key = (exe.to_string(), meta.len(), mtime);
        if let Some(h) = self.hashes.get(&key) {
            return h.clone();
        }
        let h = std::fs::read(exe).map(|b| hex::encode(Sha256::digest(&b))).unwrap_or_default();
        if self.hashes.len() > 2000 {
            self.hashes.clear();
        }
        self.hashes.insert(key, h.clone());
        h
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use agent_core::model::ProcInfo;

    pub fn lookup(pid: u32, want_cmdline: bool) -> ProcInfo {
        let base = format!("/proc/{pid}");
        let exe = std::fs::read_link(format!("{base}/exe")).map(|p| p.to_string_lossy().trim_end_matches(" (deleted)").to_string()).unwrap_or_default();
        let name = std::fs::read_to_string(format!("{base}/comm")).map(|s| s.trim().to_string()).unwrap_or_default();
        let uid = std::fs::read_to_string(format!("{base}/status"))
            .ok()
            .and_then(|s| s.lines().find(|l| l.starts_with("Uid:")).and_then(|l| l.split_whitespace().nth(1).and_then(|u| u.parse::<u32>().ok())));
        let user = uid.map(username).unwrap_or_default();
        let cmdline = if want_cmdline {
            std::fs::read(format!("{base}/cmdline")).map(|b| String::from_utf8_lossy(&b).replace('\0', " ").trim().to_string()).unwrap_or_default()
        } else {
            String::new()
        };
        ProcInfo { pid, exe, name, user, sha256: String::new(), cmdline, container: String::new() }
    }

    fn username(uid: u32) -> String {
        if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
            for line in passwd.lines() {
                let f: Vec<&str> = line.split(':').collect();
                if f.len() > 2 && f[2].parse::<u32>().ok() == Some(uid) {
                    return f[0].to_string();
                }
            }
        }
        uid.to_string()
    }
}

#[cfg(windows)]
mod platform {
    use agent_core::model::ProcInfo;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{GetTokenInformation, LookupAccountSidW, TokenUser, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};

    pub fn lookup(pid: u32, _want_cmdline: bool) -> ProcInfo {
        let mut info = ProcInfo { pid, ..Default::default() };
        if pid == 0 || pid == 4 {
            info.name = if pid == 4 { "System".into() } else { "Idle".into() };
            return info;
        }
        unsafe {
            let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else { return info };
            info.exe = image_name(h);
            info.user = token_user(h);
            let _ = CloseHandle(h);
        }
        info
    }

    unsafe fn image_name(h: HANDLE) -> String {
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        if QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len).is_ok() {
            String::from_utf16_lossy(&buf[..len as usize])
        } else {
            String::new()
        }
    }

    unsafe fn token_user(h: HANDLE) -> String {
        let mut tok = HANDLE::default();
        if OpenProcessToken(h, TOKEN_QUERY, &mut tok).is_err() {
            return String::new();
        }
        let mut needed = 0u32;
        let _ = GetTokenInformation(tok, TokenUser, None, 0, &mut needed);
        let mut buf = vec![0u8; needed as usize + 16];
        let out = if GetTokenInformation(tok, TokenUser, Some(buf.as_mut_ptr() as *mut _), buf.len() as u32, &mut needed).is_ok() {
            let tu = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut name = vec![0u16; 256];
            let mut domain = vec![0u16; 256];
            let (mut nlen, mut dlen) = (name.len() as u32, domain.len() as u32);
            let mut use_ = SID_NAME_USE::default();
            if LookupAccountSidW(None, tu.User.Sid, Some(PWSTR(name.as_mut_ptr())), &mut nlen, Some(PWSTR(domain.as_mut_ptr())), &mut dlen, &mut use_).is_ok() {
                let n = String::from_utf16_lossy(&name[..nlen as usize]);
                let d = String::from_utf16_lossy(&domain[..dlen as usize]);
                if d.is_empty() { n } else { format!("{d}\\{n}") }
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        let _ = CloseHandle(tok);
        out
    }
}
