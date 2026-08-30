//! Program identity facts gathered on the machine itself — plain file reads, nothing is
//! executed and nothing leaves the host until the batch is uploaded.
//!
//! * SHA-256 / SHA-1 / MD5 of the executable in one streaming pass (SHA-1 and MD5 are what the
//!   Team Cymru Malware Hash Registry and package manifests use).
//! * Linux: the owning package from the dpkg / apk / pacman databases, whether the file still
//!   matches the package manifest (dpkg `.md5sums`, apk sha1, pacman mtree sha256), and the
//!   install channel for everything else (snap, flatpak, AppImage, nix, venv, home, tmp, ...).
//! * Windows: Authenticode (embedded or catalog-signed) via WinVerifyTrust, the signer's
//!   certificate subject and the version resource (CompanyName / ProductName / FileVersion).
use agent_core::model::ProgramIdentity;
use chrono::{DateTime, Utc};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

/// Digests of one file, computed in a single read.
#[derive(Clone, Debug, Default)]
pub struct FileHashes {
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub size: u64,
    pub modified: Option<DateTime<Utc>>,
}

/// Files above this are not hashed (they are not what we are looking for and would tie up the agent).
pub const MAX_HASH_BYTES: u64 = 256 << 20;

/// Hashes a file streaming in 1 MiB chunks; `None` when it cannot be read or is too large.
pub fn hash_file(path: &Path) -> Option<FileHashes> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_HASH_BYTES {
        return None;
    }
    let mut f = std::fs::File::open(path).ok()?;
    let (mut a, mut b, mut c) = (Sha256::new(), Sha1::new(), Md5::new());
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        a.update(&buf[..n]);
        b.update(&buf[..n]);
        c.update(&buf[..n]);
    }
    Some(FileHashes {
        sha256: hex::encode(a.finalize()),
        sha1: hex::encode(b.finalize()),
        md5: hex::encode(c.finalize()),
        size: meta.len(),
        modified: meta.modified().ok().map(DateTime::<Utc>::from),
    })
}

/// A program waiting to be described: what the resolver knows before the package lookups.
#[derive(Clone, Debug)]
pub struct Pending {
    pub exe: String,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub pid: u32,
    pub container: String,
    pub hashes: FileHashes,
}

/// Remembers which (exe, hash) pairs were already described this run and queues new ones.
/// Descriptions are resolved in bulk by [`Identities::take`], so the package databases are
/// scanned once per batch rather than once per program.
#[derive(Default)]
pub struct Identities {
    seen: HashSet<(String, String)>,
    pending: Vec<Pending>,
}

impl Identities {
    pub fn note(&mut self, exe: &str, pid: u32, container: &str, hashes: &FileHashes) {
        if exe.is_empty() || hashes.sha256.is_empty() {
            return;
        }
        let key = (exe.to_string(), hashes.sha256.clone());
        if self.seen.contains(&key) {
            return;
        }
        if self.seen.len() > 20_000 {
            self.seen.clear();
        }
        self.seen.insert(key);
        self.pending.push(Pending { exe: exe.into(), pid, container: container.into(), hashes: hashes.clone() });
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Resolves and returns everything queued since the last call.
    pub fn take(&mut self) -> Vec<ProgramIdentity> {
        let raw = std::mem::take(&mut self.pending);
        if raw.is_empty() {
            return vec![];
        }
        describe_many(raw)
    }
}

/// Describes a set of programs; package databases are read once for the whole set.
pub fn describe_many(raw: Vec<Pending>) -> Vec<ProgramIdentity> {
    let mut ids: Vec<ProgramIdentity> = raw
        .iter()
        .map(|p| ProgramIdentity {
            exe: p.exe.clone(),
            sha256: p.hashes.sha256.clone(),
            sha1: p.hashes.sha1.clone(),
            md5: p.hashes.md5.clone(),
            size: p.hashes.size,
            modified: p.hashes.modified,
            ..Default::default()
        })
        .collect();
    for (id, p) in ids.iter_mut().zip(raw.iter()) {
        if !p.container.is_empty() {
            id.origin = "container".into();
            id.package = p.container.clone();
            id.note = "runs inside a container image; the host's package database does not apply".into();
        }
    }
    platform::describe_many(&mut ids, &raw);
    ids
}

fn base_name(p: &str) -> &str {
    p.rsplit(['/', '\\']).next().unwrap_or(p)
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{base_name, Pending};
    use agent_core::model::ProgramIdentity;
    use std::collections::{HashMap, HashSet};
    use std::io::Read;
    use std::path::Path;

    pub fn describe_many(ids: &mut [ProgramIdentity], raw: &[Pending]) {
        let mut need: Vec<usize> = Vec::new();
        for (i, id) in ids.iter_mut().enumerate() {
            if !id.origin.is_empty() || classify_channel(id, raw[i].pid) {
                continue;
            }
            need.push(i);
        }
        if need.is_empty() {
            return;
        }
        let db = PackageDb::detect();
        let wanted: HashMap<String, &ProgramIdentity> = need.iter().map(|&i| (ids[i].exe.clone(), &ids[i])).collect();
        let owners = db.owners(&wanted);
        for i in need {
            let id = &mut ids[i];
            match owners.get(&id.exe) {
                Some(hit) => {
                    id.origin = hit.origin.clone();
                    id.package = hit.package.clone();
                    id.package_version = hit.version.clone();
                    id.verified = hit.verified;
                    if hit.verified == Some(false) {
                        id.note = format!("digest differs from the {} manifest", hit.origin);
                    }
                }
                None => classify_unpackaged(id, &db),
            }
        }
    }

    /// Channels recognisable from the path alone (plus a look at the process for flatpak /
    /// AppImage names). Returns true when the origin was decided.
    fn classify_channel(id: &mut ProgramIdentity, pid: u32) -> bool {
        let exe = id.exe.as_str();
        let comps: Vec<&str> = exe.split('/').filter(|c| !c.is_empty()).collect();
        // Flatpak apps run in their own mount namespace: the path is /app/... or the runtime's /usr/...
        if pid > 0 {
            if let Ok(info) = std::fs::read_to_string(format!("/proc/{pid}/root/.flatpak-info")) {
                id.origin = "flatpak".into();
                for line in info.lines() {
                    if let Some(v) = line.strip_prefix("name=") {
                        id.package = v.trim().into();
                    } else if let Some(v) = line.strip_prefix("runtime=") {
                        if exe.starts_with("/usr/") {
                            id.note = format!("part of the runtime {}", v.trim());
                        }
                    }
                }
                return true;
            }
        }
        if exe.starts_with("/app/") {
            id.origin = "flatpak".into();
            return true;
        }
        let snap_root = comps.first().map(|c| *c == "snap").unwrap_or(false) || exe.starts_with("/var/lib/snapd/snap/");
        if snap_root {
            let off = if exe.starts_with("/var/lib/snapd/snap/") { 4 } else { 1 };
            if comps.len() > off + 1 {
                id.origin = "snap".into();
                id.package = comps[off].into();
                id.package_version = format!("rev {}", comps[off + 1]);
                return true;
            }
        }
        for prefix in ["/var/lib/flatpak/app/", "/var/lib/flatpak/runtime/"] {
            if let Some(rest) = exe.strip_prefix(prefix) {
                let mut it = rest.split('/');
                id.origin = "flatpak".into();
                id.package = it.next().unwrap_or("").into();
                let (arch, branch) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
                if !branch.is_empty() {
                    id.package_version = format!("{branch}/{arch}");
                }
                return true;
            }
        }
        if let Some(i) = exe.find("/.local/share/flatpak/") {
            let rest = &exe[i + "/.local/share/flatpak/".len()..];
            let mut it = rest.split('/');
            let _kind = it.next();
            id.origin = "flatpak".into();
            id.package = it.next().unwrap_or("").into();
            return true;
        }
        if let Some(rest) = exe.strip_prefix("/nix/store/") {
            let dir = rest.split('/').next().unwrap_or("");
            id.origin = "nix".into();
            id.package = dir.splitn(2, '-').nth(1).unwrap_or(dir).into();
            return true;
        }
        if exe.starts_with("/tmp/.mount_") {
            id.origin = "appimage".into();
            if pid > 0 {
                if let Ok(env) = std::fs::read(format!("/proc/{pid}/environ")) {
                    for kv in env.split(|b| *b == 0) {
                        if let Some(v) = kv.strip_prefix(b"APPIMAGE=") {
                            id.package = base_name(&String::from_utf8_lossy(v)).to_string();
                        }
                    }
                }
            }
            return true;
        }
        if exe.starts_with("/tmp/") || exe.starts_with("/var/tmp/") || exe.starts_with("/dev/shm/") || exe.starts_with("/run/user/") {
            id.origin = "tmp".into();
            return true;
        }
        if exe.starts_with("/home/") || exe.starts_with("/root/") {
            let low = exe.to_ascii_lowercase();
            id.origin = if ["/.venv/", "/venv/", "/site-packages/", "/node_modules/", "/.npm/", "/.nvm/", "/.pyenv/", "/.rustup/"].iter().any(|m| low.contains(m)) {
                "venv"
            } else if ["/.cargo/bin/", "/go/bin/", "/.local/bin/", "/.local/share/", "/.vscode", "/.config/", "/.cache/", "/applications/", "/apps/", "/.steam/", "/.var/app/"].iter().any(|m| low.contains(m)) {
                "user-install"
            } else if low.contains("/downloads/") {
                "download"
            } else {
                "home"
            }
            .into();
            return true;
        }
        false
    }

    fn classify_unpackaged(id: &mut ProgramIdentity, db: &PackageDb) {
        let exe = id.exe.as_str();
        id.origin = if exe.starts_with("/opt/") {
            "opt"
        } else if exe.starts_with("/usr/local/") {
            "local"
        } else if db.kind.is_empty() {
            ""
        } else {
            "unpackaged"
        }
        .into();
        if db.kind == "rpm" {
            id.note = "rpm-based system: package ownership is not determined yet (rpm database not parsed)".into();
            if id.origin == "unpackaged" {
                id.origin.clear();
            }
        } else if !db.kind.is_empty() && id.origin == "unpackaged" {
            id.note = format!("no {} package owns this file", db.kind);
        }
    }

    #[derive(Debug)]
    pub struct Hit {
        origin: String,
        package: String,
        version: String,
        verified: Option<bool>,
    }

    /// The package database present on this system.
    pub struct PackageDb {
        pub kind: &'static str, // dpkg | apk | pacman | rpm | ""
        root: &'static str,
    }

    impl PackageDb {
        pub fn detect() -> Self {
            Self::detect_in("/")
        }

        fn detect_in(root: &'static str) -> Self {
            let has = |p: &str| Path::new(root).join(p).exists();
            let kind = if has("var/lib/dpkg/status") {
                "dpkg"
            } else if has("lib/apk/db/installed") {
                "apk"
            } else if has("var/lib/pacman/local") {
                "pacman"
            } else if has("var/lib/rpm") || has("usr/lib/sysimage/rpm") {
                "rpm"
            } else {
                ""
            };
            Self { kind, root }
        }

        fn path(&self, p: &str) -> std::path::PathBuf {
            Path::new(self.root).join(p)
        }

        /// Maps each wanted executable to its owning package, when one exists.
        pub fn owners(&self, wanted: &HashMap<String, &ProgramIdentity>) -> HashMap<String, Hit> {
            match self.kind {
                "dpkg" => self.dpkg(wanted),
                "apk" => self.apk(wanted),
                "pacman" => self.pacman(wanted),
                _ => HashMap::new(),
            }
        }

        // ---- dpkg (Debian, Ubuntu, Mint, ...) ----

        fn dpkg(&self, wanted: &HashMap<String, &ProgramIdentity>) -> HashMap<String, Hit> {
            // Both spellings of a merged-/usr path: packages built before the merge list /bin/ls,
            // the kernel reports /usr/bin/ls.
            let mut alias: HashMap<String, String> = HashMap::new();
            for exe in wanted.keys() {
                for a in usr_aliases(exe) {
                    alias.insert(a, exe.clone());
                }
            }
            let mut owner: HashMap<String, String> = HashMap::new(); // exe -> list stem (pkg[:arch])
            let Ok(dir) = std::fs::read_dir(self.path("var/lib/dpkg/info")) else { return HashMap::new() };
            for ent in dir.flatten() {
                let name = ent.file_name().to_string_lossy().to_string();
                let Some(stem) = name.strip_suffix(".list") else { continue };
                let Ok(text) = std::fs::read_to_string(ent.path()) else { continue };
                for line in text.lines() {
                    if let Some(exe) = alias.get(line) {
                        owner.entry(exe.clone()).or_insert_with(|| stem.to_string());
                    }
                }
                if owner.len() == wanted.len() {
                    break;
                }
            }
            if owner.is_empty() {
                return HashMap::new();
            }
            let versions = self.dpkg_versions(owner.values().map(|s| s.split(':').next().unwrap_or(s).to_string()).collect());
            let mut out = HashMap::new();
            for (exe, stem) in owner {
                let pkg = stem.split(':').next().unwrap_or(&stem).to_string();
                let verified = self.dpkg_verify(&stem, &exe, &wanted[&exe].md5);
                out.insert(exe, Hit { origin: "dpkg".into(), package: pkg.clone(), version: versions.get(&pkg).cloned().unwrap_or_default(), verified });
            }
            out
        }

        fn dpkg_versions(&self, pkgs: HashSet<String>) -> HashMap<String, String> {
            let mut out = HashMap::new();
            let Ok(text) = std::fs::read_to_string(self.path("var/lib/dpkg/status")) else { return out };
            for para in text.split("\n\n") {
                let (mut name, mut ver, mut installed) = ("", "", false);
                for line in para.lines() {
                    if let Some(v) = line.strip_prefix("Package: ") {
                        name = v.trim();
                    } else if let Some(v) = line.strip_prefix("Version: ") {
                        ver = v.trim();
                    } else if let Some(v) = line.strip_prefix("Status: ") {
                        installed = v.contains(" installed");
                    }
                }
                if installed && pkgs.contains(name) {
                    out.insert(name.to_string(), ver.to_string());
                }
            }
            out
        }

        /// Compares the file's MD5 with the package manifest (`<pkg>.md5sums`); None when the
        /// package ships no manifest entry for it (conffiles, symlinks, files generated at install).
        fn dpkg_verify(&self, stem: &str, exe: &str, md5: &str) -> Option<bool> {
            if md5.is_empty() {
                return None;
            }
            let text = std::fs::read_to_string(self.path(&format!("var/lib/dpkg/info/{stem}.md5sums"))).ok()?;
            let rel: Vec<String> = usr_aliases(exe).into_iter().map(|a| a.trim_start_matches('/').to_string()).collect();
            for line in text.lines() {
                let mut it = line.splitn(2, "  ");
                let (sum, path) = (it.next().unwrap_or(""), it.next().unwrap_or("").trim());
                if rel.iter().any(|r| r == path) {
                    return Some(sum.eq_ignore_ascii_case(md5));
                }
            }
            None
        }

        // ---- apk (Alpine) ----

        fn apk(&self, wanted: &HashMap<String, &ProgramIdentity>) -> HashMap<String, Hit> {
            let mut out = HashMap::new();
            let Ok(text) = std::fs::read_to_string(self.path("lib/apk/db/installed")) else { return out };
            for para in text.split("\n\n") {
                let (mut pkg, mut ver, mut dir) = (String::new(), String::new(), String::new());
                let mut last_file: Option<(String, String)> = None; // (exe, sha1 from Z:)
                let mut lines = para.lines().peekable();
                while let Some(line) = lines.next() {
                    match line.split_at(line.len().min(2)) {
                        ("P:", v) => pkg = v.into(),
                        ("V:", v) => ver = v.into(),
                        ("F:", v) => dir = v.into(),
                        ("R:", v) => {
                            let full = format!("/{dir}/{v}");
                            if wanted.contains_key(&full) {
                                let z = lines.peek().and_then(|l| l.strip_prefix("Z:Q1")).map(|b| decode_b64_hex(b)).unwrap_or_default();
                                last_file = Some((full, z));
                            }
                        }
                        _ => {}
                    }
                    if let Some((exe, z)) = last_file.take() {
                        let verified = if z.is_empty() || wanted[&exe].sha1.is_empty() { None } else { Some(z.eq_ignore_ascii_case(&wanted[&exe].sha1)) };
                        out.insert(exe, Hit { origin: "apk".into(), package: pkg.clone(), version: ver.clone(), verified });
                    }
                }
            }
            out
        }

        // ---- pacman (Arch, Manjaro, ...) ----

        fn pacman(&self, wanted: &HashMap<String, &ProgramIdentity>) -> HashMap<String, Hit> {
            let mut out = HashMap::new();
            let rel: HashMap<String, String> = wanted.keys().map(|e| (e.trim_start_matches('/').to_string(), e.clone())).collect();
            let Ok(dir) = std::fs::read_dir(self.path("var/lib/pacman/local")) else { return out };
            for ent in dir.flatten() {
                let Ok(files) = std::fs::read_to_string(ent.path().join("files")) else { continue };
                let hits: Vec<&String> = files.lines().filter_map(|l| rel.get(l)).collect();
                if hits.is_empty() {
                    continue;
                }
                let desc = std::fs::read_to_string(ent.path().join("desc")).unwrap_or_default();
                let field = |k: &str| desc.split(&format!("%{k}%\n")).nth(1).and_then(|s| s.lines().next()).unwrap_or("").to_string();
                let (pkg, ver) = (field("NAME"), field("VERSION"));
                let sums = mtree_sha256(&ent.path().join("mtree"));
                for exe in hits {
                    let verified = sums.get(exe.trim_start_matches('/')).map(|s| s.eq_ignore_ascii_case(&wanted[exe].sha256));
                    out.insert(exe.clone(), Hit { origin: "pacman".into(), package: pkg.clone(), version: ver.clone(), verified });
                }
            }
            out
        }
    }

    /// `/usr/bin/x` and `/bin/x` (and lib, sbin, lib64, ...) name the same file on a merged-/usr system.
    fn usr_aliases(exe: &str) -> Vec<String> {
        let mut v = vec![exe.to_string()];
        for d in ["bin", "sbin", "lib", "lib32", "lib64", "libx32"] {
            let usr = format!("/usr/{d}/");
            let short = format!("/{d}/");
            if let Some(rest) = exe.strip_prefix(&usr) {
                v.push(format!("{short}{rest}"));
            } else if let Some(rest) = exe.strip_prefix(&short) {
                v.push(format!("{usr}{rest}"));
            }
        }
        v
    }

    /// Parses a pacman `mtree` (gzip) file: `./usr/bin/ls ... sha256digest=<hex>` → path → hex.
    pub fn mtree_sha256(path: &Path) -> HashMap<String, String> {
        let mut out = HashMap::new();
        let Ok(f) = std::fs::File::open(path) else { return out };
        let mut text = String::new();
        if flate2::read::GzDecoder::new(f).read_to_string(&mut text).is_err() {
            return out;
        }
        for line in text.lines() {
            let mut it = line.split_whitespace();
            let Some(name) = it.next() else { continue };
            let Some(name) = name.strip_prefix("./") else { continue };
            if let Some(sum) = it.find_map(|kv| kv.strip_prefix("sha256digest=")) {
                out.insert(unescape_mtree(name), sum.to_string());
            }
        }
        out
    }

    fn unescape_mtree(s: &str) -> String {
        // mtree encodes unusual bytes as \ooo; paths of executables rarely use them.
        if !s.contains('\\') {
            return s.to_string();
        }
        let mut out = Vec::new();
        let b = s.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
                out.push(u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 4]).unwrap(), 8).unwrap_or(b'?'));
                i += 4;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        String::from_utf8_lossy(&out).to_string()
    }

    /// apk stores checksums as base64 of the raw digest (after the "Q1" tag); returns lower-case hex.
    pub fn decode_b64_hex(b64: &str) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut bits: u32 = 0;
        let mut nbits = 0;
        let mut out = Vec::new();
        for c in b64.bytes() {
            if c == b'=' {
                break;
            }
            let Some(v) = T.iter().position(|t| *t == c) else { return String::new() };
            bits = (bits << 6) | v as u32;
            nbits += 6;
            if nbits >= 8 {
                nbits -= 8;
                out.push(((bits >> nbits) & 0xff) as u8);
            }
        }
        hex::encode(out)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::collections::HashMap;

        fn write(dir: &Path, rel: &str, body: &str) {
            let p = dir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }

        fn leak(p: std::path::PathBuf) -> &'static str {
            Box::leak(p.to_string_lossy().to_string().into_boxed_str())
        }

        #[test]
        fn dpkg_owner_version_and_manifest() {
            let tmp = tempdir("dpkg");
            write(&tmp, "var/lib/dpkg/status", "Package: coreutils\nStatus: install ok installed\nVersion: 9.4-3ubuntu6\n\nPackage: gone\nStatus: deinstall ok config-files\nVersion: 1\n\nPackage: brave-browser\nStatus: install ok installed\nVersion: 1.70.1\n");
            write(&tmp, "var/lib/dpkg/info/coreutils.list", "/.\n/bin\n/bin/ls\n/usr/bin/cat\n");
            write(&tmp, "var/lib/dpkg/info/coreutils.md5sums", "d41d8cd98f00b204e9800998ecf8427e  bin/ls\nffffffffffffffffffffffffffffffff  usr/bin/cat\n");
            write(&tmp, "var/lib/dpkg/info/brave-browser.list", "/opt/brave.com/brave/brave\n");
            let db = PackageDb::detect_in(leak(tmp.clone()));
            assert_eq!(db.kind, "dpkg");
            let ls = ProgramIdentity { exe: "/usr/bin/ls".into(), md5: "d41d8cd98f00b204e9800998ecf8427e".into(), ..Default::default() };
            let cat = ProgramIdentity { exe: "/usr/bin/cat".into(), md5: "00000000000000000000000000000000".into(), ..Default::default() };
            let brave = ProgramIdentity { exe: "/opt/brave.com/brave/brave".into(), ..Default::default() };
            let other = ProgramIdentity { exe: "/usr/bin/other".into(), ..Default::default() };
            let wanted: HashMap<String, &ProgramIdentity> = [&ls, &cat, &brave, &other].iter().map(|p| (p.exe.clone(), *p)).collect();
            let got = db.owners(&wanted);
            let h = &got["/usr/bin/ls"];
            assert_eq!((h.origin.as_str(), h.package.as_str(), h.version.as_str(), h.verified), ("dpkg", "coreutils", "9.4-3ubuntu6", Some(true)));
            assert_eq!(got["/usr/bin/cat"].verified, Some(false));
            let b = &got["/opt/brave.com/brave/brave"];
            assert_eq!((b.package.as_str(), b.version.as_str(), b.verified), ("brave-browser", "1.70.1", None));
            assert!(!got.contains_key("/usr/bin/other"));
            let _ = std::fs::remove_dir_all(&tmp);
        }

        #[test]
        fn apk_owner_and_checksum() {
            let tmp = tempdir("apk");
            // Z: is base64 of the raw sha1 (here: sha1 of the empty string).
            write(&tmp, "lib/apk/db/installed", "P:busybox\nV:1.36.1-r29\nF:bin\nR:busybox\nZ:Q12jmj7l5rSw0yVb/vlWAYkK/YBwk=\nR:sh\n\nP:curl\nV:8.5.0-r0\nF:usr/bin\nR:curl\nZ:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n");
            let db = PackageDb::detect_in(leak(tmp.clone()));
            assert_eq!(db.kind, "apk");
            let bb = ProgramIdentity { exe: "/bin/busybox".into(), sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709".into(), ..Default::default() };
            let curl = ProgramIdentity { exe: "/usr/bin/curl".into(), sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709".into(), ..Default::default() };
            let wanted: HashMap<String, &ProgramIdentity> = [&bb, &curl].iter().map(|p| (p.exe.clone(), *p)).collect();
            let got = db.owners(&wanted);
            assert_eq!((got["/bin/busybox"].package.as_str(), got["/bin/busybox"].version.as_str(), got["/bin/busybox"].verified), ("busybox", "1.36.1-r29", Some(true)));
            assert_eq!(got["/usr/bin/curl"].verified, Some(false));
            let _ = std::fs::remove_dir_all(&tmp);
        }

        #[test]
        fn pacman_owner_and_mtree() {
            let tmp = tempdir("pacman");
            write(&tmp, "var/lib/pacman/local/coreutils-9.4-2/desc", "%NAME%\ncoreutils\n\n%VERSION%\n9.4-2\n\n%DESC%\nx\n");
            write(&tmp, "var/lib/pacman/local/coreutils-9.4-2/files", "%FILES%\nusr/\nusr/bin/\nusr/bin/ls\n");
            let mtree = "#mtree\n/set type=file\n./usr/bin/ls time=1.0 mode=755 size=10 sha256digest=abc\n";
            let f = std::fs::File::create(tmp.join("var/lib/pacman/local/coreutils-9.4-2/mtree")).unwrap();
            let mut gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
            std::io::Write::write_all(&mut gz, mtree.as_bytes()).unwrap();
            gz.finish().unwrap();
            let db = PackageDb::detect_in(leak(tmp.clone()));
            assert_eq!(db.kind, "pacman");
            let ls = ProgramIdentity { exe: "/usr/bin/ls".into(), sha256: "ABC".into(), ..Default::default() };
            let wanted: HashMap<String, &ProgramIdentity> = [&ls].iter().map(|p| (p.exe.clone(), *p)).collect();
            let got = db.owners(&wanted);
            assert_eq!((got["/usr/bin/ls"].package.as_str(), got["/usr/bin/ls"].version.as_str(), got["/usr/bin/ls"].verified), ("coreutils", "9.4-2", Some(true)));
            let _ = std::fs::remove_dir_all(&tmp);
        }

        #[test]
        fn channels_from_path() {
            let cases = [
                ("/snap/firefox/4173/usr/lib/firefox/firefox", "snap", "firefox", "rev 4173"),
                ("/var/lib/flatpak/app/org.mozilla.firefox/x86_64/stable/abc123/files/bin/firefox", "flatpak", "org.mozilla.firefox", "stable/x86_64"),
                ("/home/petro/.local/share/flatpak/app/com.spotify.Client/x86_64/stable/x/files/spotify", "flatpak", "com.spotify.Client", ""),
                ("/nix/store/abc123-curl-8.5.0/bin/curl", "nix", "curl-8.5.0", ""),
                ("/tmp/.mount_ObsidiXYZ/obsidian", "appimage", "", ""),
                ("/tmp/x/payload", "tmp", "", ""),
                ("/home/petro/Downloads/setup", "download", "", ""),
                ("/home/petro/.cargo/bin/cargo", "user-install", "", ""),
                ("/home/petro/proj/.venv/bin/python", "venv", "", ""),
                ("/home/petro/bin/tool", "home", "", ""),
                ("/app/bin/foo", "flatpak", "", ""),
            ];
            for (exe, origin, pkg, ver) in cases {
                let mut id = ProgramIdentity { exe: exe.into(), ..Default::default() };
                assert!(classify_channel(&mut id, 0), "{exe}");
                assert_eq!((id.origin.as_str(), id.package.as_str(), id.package_version.as_str()), (origin, pkg, ver), "{exe}");
            }
            let mut id = ProgramIdentity { exe: "/usr/bin/ls".into(), ..Default::default() };
            assert!(!classify_channel(&mut id, 0));
        }

        #[test]
        fn unpackaged_classification() {
            let db = PackageDb { kind: "dpkg", root: "/nonexistent" };
            for (exe, origin) in [("/opt/x/x", "opt"), ("/usr/local/bin/x", "local"), ("/usr/bin/x", "unpackaged"), ("/srv/x", "unpackaged")] {
                let mut id = ProgramIdentity { exe: exe.into(), ..Default::default() };
                classify_unpackaged(&mut id, &db);
                assert_eq!(id.origin, origin, "{exe}");
            }
            let rpm = PackageDb { kind: "rpm", root: "/nonexistent" };
            let mut id = ProgramIdentity { exe: "/usr/bin/x".into(), ..Default::default() };
            classify_unpackaged(&mut id, &rpm);
            assert_eq!(id.origin, "");
            assert!(id.note.contains("rpm"));
        }

        #[test]
        fn aliases_and_b64() {
            assert_eq!(usr_aliases("/usr/bin/ls"), vec!["/usr/bin/ls", "/bin/ls"]);
            assert_eq!(usr_aliases("/lib/systemd/systemd"), vec!["/lib/systemd/systemd", "/usr/lib/systemd/systemd"]);
            assert_eq!(usr_aliases("/opt/x"), vec!["/opt/x"]);
            assert_eq!(decode_b64_hex("2jmj7l5rSw0yVb/vlWAYkK/YBwk="), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        }

        fn tempdir(tag: &str) -> std::path::PathBuf {
            let d = std::env::temp_dir().join(format!("pmacct-identity-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            d
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::{base_name, Pending};
    use agent_core::model::ProgramIdentity;
    use std::ffi::c_void;
    use std::ptr::null_mut;
    use windows::core::{PCWSTR, GUID};
    use windows::Win32::Foundation::{
        CloseHandle, CERT_E_CHAINING, CERT_E_EXPIRED, CERT_E_REVOKED, CERT_E_UNTRUSTEDROOT, CRYPT_E_SECURITY_SETTINGS, GENERIC_READ, HANDLE, HWND, TRUST_E_BAD_DIGEST,
        TRUST_E_EXPLICIT_DISTRUST, TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_NOT_TRUSTED,
    };
    use windows::Win32::Security::Cryptography::Catalog::{
        CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext, CryptCATAdminReleaseContext,
        CryptCATCatalogInfoFromContext, CATALOG_INFO,
    };
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext, CertGetNameStringW, CryptMsgClose, CryptMsgGetParam, CryptQueryObject, CERT_FIND_SUBJECT_CERT, CERT_INFO,
        CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_ALL, CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, HCERTSTORE,
        PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG,
        WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };
    use windows::Win32::Storage::FileSystem::{CreateFileW, GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING};

    pub fn describe_many(ids: &mut [ProgramIdentity], _raw: &[Pending]) {
        for id in ids.iter_mut() {
            if !id.origin.is_empty() {
                continue;
            }
            classify(id);
            let (signature, signer, note) = authenticode(&id.exe);
            id.signature = signature;
            id.signer = signer;
            if !note.is_empty() {
                id.note = note;
            }
            let (company, product, file_version, description) = version_info(&id.exe);
            id.company = company;
            id.product = product;
            id.file_version = file_version;
            id.description = description;
        }
    }

    fn classify(id: &mut ProgramIdentity) {
        let low = id.exe.to_ascii_lowercase().replace('/', "\\");
        let after_drive = low.splitn(2, ":\\").nth(1).unwrap_or(&low).to_string();
        id.origin = if after_drive.starts_with("windows\\") {
            "windows"
        } else if after_drive.starts_with("program files\\windowsapps\\") {
            // MSIX packages: Publisher.App_1.2.3.0_x64__hash
            if let Some(dir) = after_drive.split('\\').nth(2) {
                let mut parts = dir.split('_');
                id.package = parts.next().unwrap_or("").to_string();
                id.package_version = parts.next().unwrap_or("").to_string();
            }
            "store"
        } else if after_drive.starts_with("program files") {
            "program-files"
        } else if after_drive.starts_with("programdata\\") {
            "programdata"
        } else if after_drive.contains("\\temp\\") || after_drive.contains("\\tmp\\") {
            "tmp"
        } else if after_drive.starts_with("users\\") {
            if after_drive.contains("\\downloads\\") {
                "download"
            } else if after_drive.contains("\\appdata\\") {
                "user-install"
            } else {
                "home"
            }
        } else {
            ""
        }
        .into();
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Runs WinVerifyTrust (verify, then close the state handle) and returns the raw result code.
    unsafe fn verify_trust(data: &mut WINTRUST_DATA) -> i32 {
        let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        let rc = WinVerifyTrust(HWND::default(), &mut action, data as *mut WINTRUST_DATA as *mut c_void);
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(HWND::default(), &mut action, data as *mut WINTRUST_DATA as *mut c_void);
        rc
    }

    fn wintrust_data() -> WINTRUST_DATA {
        WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE,
            ..Default::default()
        }
    }

    fn status(rc: i32) -> (String, String) {
        let s = match rc {
            0 => "valid",
            x if x == TRUST_E_NOSIGNATURE.0 => "unsigned",
            x if x == TRUST_E_BAD_DIGEST.0 || x == TRUST_E_EXPLICIT_DISTRUST.0 || x == CERT_E_REVOKED.0 => "invalid",
            x if x == CERT_E_UNTRUSTEDROOT.0 || x == TRUST_E_SUBJECT_NOT_TRUSTED.0 || x == CERT_E_EXPIRED.0 || x == CRYPT_E_SECURITY_SETTINGS.0 || x == CERT_E_CHAINING.0 => "untrusted",
            _ => "untrusted",
        };
        let note = match s {
            "valid" | "unsigned" => String::new(),
            _ => format!("WinVerifyTrust 0x{:08x}", rc as u32),
        };
        (s.into(), note)
    }

    /// (signature, signer, note) for an executable: embedded signature first, then the
    /// Windows security catalogs (how files shipped with Windows are signed).
    pub fn authenticode(path: &str) -> (String, String, String) {
        let wpath = wide(path);
        unsafe {
            let mut fi = WINTRUST_FILE_INFO { cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32, pcwszFilePath: PCWSTR(wpath.as_ptr()), hFile: HANDLE::default(), pgKnownSubject: null_mut() };
            let mut wd = wintrust_data();
            wd.dwUnionChoice = WTD_CHOICE_FILE;
            wd.Anonymous = WINTRUST_DATA_0 { pFile: &mut fi };
            let rc = verify_trust(&mut wd);
            if rc != TRUST_E_NOSIGNATURE.0 {
                let (s, note) = status(rc);
                return (s, signer_of(&wpath), note);
            }
            match catalog_verify(&wpath) {
                Some((rc, cat)) => {
                    let (s, note) = status(rc);
                    let note = if note.is_empty() { format!("catalog {}", base_name(&cat)) } else { format!("{note}; catalog {}", base_name(&cat)) };
                    (s, signer_of(&wide(&cat)), note)
                }
                None => ("unsigned".into(), String::new(), String::new()),
            }
        }
    }

    unsafe fn catalog_verify(wpath: &[u16]) -> Option<(i32, String)> {
        let h = CreateFileW(PCWSTR(wpath.as_ptr()), GENERIC_READ.0, FILE_SHARE_READ, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None).ok()?;
        let mut admin: isize = 0;
        let alg = wide("SHA256");
        if CryptCATAdminAcquireContext2(&mut admin, None, PCWSTR(alg.as_ptr()), None, Some(0)).is_err() {
            let _ = CloseHandle(h);
            return None;
        }
        let mut cb = 0u32;
        let _ = CryptCATAdminCalcHashFromFileHandle2(admin, h, &mut cb, None, Some(0));
        let mut hash = vec![0u8; cb as usize];
        let mut result = None;
        if cb > 0 && CryptCATAdminCalcHashFromFileHandle2(admin, h, &mut cb, Some(hash.as_mut_ptr()), Some(0)).is_ok() {
            let cat = CryptCATAdminEnumCatalogFromHash(admin, &hash, Some(0), None);
            if cat != 0 {
                let mut info = CATALOG_INFO { cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32, ..Default::default() };
                if CryptCATCatalogInfoFromContext(cat, &mut info, 0).is_ok() {
                    let cat_path = String::from_utf16_lossy(&info.wszCatalogFile).trim_end_matches('\0').to_string();
                    let tag = wide(&hash.iter().map(|b| format!("{b:02X}")).collect::<String>());
                    let mut ci = WINTRUST_CATALOG_INFO {
                        cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                        pcwszCatalogFilePath: PCWSTR(info.wszCatalogFile.as_ptr()),
                        pcwszMemberTag: PCWSTR(tag.as_ptr()),
                        pcwszMemberFilePath: PCWSTR(wpath.as_ptr()),
                        hMemberFile: h,
                        pbCalculatedFileHash: hash.as_mut_ptr(),
                        cbCalculatedFileHash: cb,
                        hCatAdmin: admin,
                        ..Default::default()
                    };
                    let mut wd = wintrust_data();
                    wd.dwUnionChoice = WTD_CHOICE_CATALOG;
                    wd.Anonymous = WINTRUST_DATA_0 { pCatalog: &mut ci };
                    let rc = verify_trust(&mut wd);
                    result = Some((rc, cat_path));
                }
                let _ = CryptCATAdminReleaseCatalogContext(admin, cat, 0);
            }
        }
        let _ = CryptCATAdminReleaseContext(admin, 0);
        let _ = CloseHandle(h);
        result
    }

    /// Subject (simple display name) of the signing certificate of a PKCS#7-signed file
    /// (an executable with an embedded signature, or a security catalog).
    unsafe fn signer_of(wpath: &[u16]) -> String {
        let mut store = HCERTSTORE::default();
        let mut msg: *mut c_void = null_mut();
        if CryptQueryObject(CERT_QUERY_OBJECT_FILE, wpath.as_ptr() as *const c_void, CERT_QUERY_CONTENT_FLAG_ALL, CERT_QUERY_FORMAT_FLAG_BINARY, 0, None, None, None, Some(&mut store), Some(&mut msg), None).is_err() {
            return String::new();
        }
        let mut out = String::new();
        let mut cb = 0u32;
        if !msg.is_null() && CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, None, &mut cb).is_ok() && cb > 0 {
            let mut buf = vec![0u8; cb as usize];
            if CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, Some(buf.as_mut_ptr() as *mut c_void), &mut cb).is_ok() {
                let si = &*(buf.as_ptr() as *const CMSG_SIGNER_INFO);
                let ci = CERT_INFO { Issuer: si.Issuer, SerialNumber: si.SerialNumber, ..Default::default() };
                let cert = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, Some(&ci as *const CERT_INFO as *const c_void), None);
                if !cert.is_null() {
                    let mut name = vec![0u16; 512];
                    let n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut name));
                    if n > 1 {
                        out = String::from_utf16_lossy(&name[..(n - 1) as usize]);
                    }
                    let _ = CertFreeCertificateContext(Some(cert));
                }
            }
        }
        if !msg.is_null() {
            let _ = CryptMsgClose(Some(msg));
        }
        if !store.is_invalid() {
            let _ = CertCloseStore(Some(store), 0);
        }
        out
    }

    /// (CompanyName, ProductName, FileVersion, FileDescription) from the version resource.
    pub fn version_info(path: &str) -> (String, String, String, String) {
        let empty = (String::new(), String::new(), String::new(), String::new());
        let w = wide(path);
        unsafe {
            let size = GetFileVersionInfoSizeW(PCWSTR(w.as_ptr()), None);
            if size == 0 {
                return empty;
            }
            let mut buf = vec![0u8; size as usize];
            if GetFileVersionInfoW(PCWSTR(w.as_ptr()), None, size, buf.as_mut_ptr() as *mut c_void).is_err() {
                return empty;
            }
            let mut langs: Vec<String> = Vec::new();
            let tr = wide("\\VarFileInfo\\Translation");
            let mut p: *mut c_void = null_mut();
            let mut len = 0u32;
            if VerQueryValueW(buf.as_ptr() as *const c_void, PCWSTR(tr.as_ptr()), &mut p, &mut len).as_bool() && len >= 4 && !p.is_null() {
                let n = (len / 4) as usize;
                let arr = std::slice::from_raw_parts(p as *const u16, n * 2);
                for i in 0..n {
                    langs.push(format!("{:04X}{:04X}", arr[2 * i], arr[2 * i + 1]));
                }
            }
            for l in ["040904B0", "040904E4", "04090000", "000004B0"] {
                if !langs.iter().any(|x| x == l) {
                    langs.push(l.into());
                }
            }
            let get = |key: &str| -> String {
                for l in &langs {
                    let sub = wide(&format!("\\StringFileInfo\\{l}\\{key}"));
                    let mut p: *mut c_void = null_mut();
                    let mut len = 0u32;
                    if VerQueryValueW(buf.as_ptr() as *const c_void, PCWSTR(sub.as_ptr()), &mut p, &mut len).as_bool() && len > 0 && !p.is_null() {
                        let s = std::slice::from_raw_parts(p as *const u16, len as usize);
                        let v = String::from_utf16_lossy(s).trim_end_matches('\0').trim().to_string();
                        if !v.is_empty() {
                            return v;
                        }
                    }
                }
                String::new()
            };
            (get("CompanyName"), get("ProductName"), get("FileVersion"), get("FileDescription"))
        }
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use super::Pending;
    use agent_core::model::ProgramIdentity;
    pub fn describe_many(_ids: &mut [ProgramIdentity], _raw: &[Pending]) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_and_dedup() {
        let dir = std::env::temp_dir().join(format!("pmacct-identity-hash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f");
        std::fs::write(&p, b"abc").unwrap();
        let h = hash_file(&p).unwrap();
        assert_eq!(h.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(h.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(h.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(h.size, 3);
        assert!(h.modified.is_some());
        let mut ids = Identities::default();
        let exe = p.to_string_lossy().to_string();
        ids.note(&exe, 0, "", &h);
        ids.note(&exe, 0, "", &h);
        ids.note("", 0, "", &h);
        assert_eq!(ids.pending(), 1);
        let got = ids.take();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].sha256, h.sha256);
        assert!(ids.take().is_empty());
        // A container process is attributed to its image, never to the host's package database.
        ids.note("/app/server", 1, "web-app", &h);
        let got = ids.take();
        assert_eq!((got[0].origin.as_str(), got[0].package.as_str()), ("container", "web-app"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
