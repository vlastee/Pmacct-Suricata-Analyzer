//! Self-update: fetch the server's build for this platform over the pinned connection, verify
//! its checksum, sanity-run it, swap it into place (keeping the previous binary as .old) and
//! restart the service. Used by `pmacct-agent update` and by the run loop when the server
//! advertises a newer version and auto-update is on.
use agent_core::client::{Client, TARGET};
use agent_core::model::BuildInfo;
use agent_core::version;
use anyhow::{bail, Context, Result};
use log::{info, warn};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Decide whether `build` should replace the running binary.
pub fn wanted(build: &BuildInfo, current_version: &str) -> bool {
    build.target == TARGET && version::newer(&build.version, current_version)
}

fn current_exe() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    // Linux resolves to "/path (deleted)" after a swap; strip that so a second update works.
    let s = exe.to_string_lossy().trim_end_matches(" (deleted)").to_string();
    Ok(PathBuf::from(s))
}

/// Download, verify, install. Returns the version installed. Does not restart when `restart` is false.
pub async fn apply(client: &Client, build: &BuildInfo, restart: bool) -> Result<String> {
    let data = client.download(&build.target).await?;
    let sum = hex::encode(Sha256::digest(&data));
    if !sum.eq_ignore_ascii_case(&build.sha256) {
        bail!("checksum mismatch: downloaded {sum}, server announced {}", build.sha256);
    }
    let exe = current_exe()?;
    let new = exe.with_extension("new");
    let old = exe.with_extension("old");
    std::fs::write(&new, &data).with_context(|| format!("write {}", new.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755))?;
    }
    // Sanity: the new binary must run and report its version.
    let out = std::process::Command::new(&new).arg("--version").output().context("run new binary")?;
    let text = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() || !text.contains(&build.version) {
        let _ = std::fs::remove_file(&new);
        bail!("new binary failed its self-test (exit {:?}, output {:?})", out.status.code(), text.trim());
    }
    swap(&exe, &new, &old)?;
    info!("installed pmacct-agent {} (previous kept as {})", build.version, old.display());
    if restart {
        restart_service();
    }
    Ok(build.version.clone())
}

/// Put the new binary in place atomically where the OS allows; the running file is renamed to
/// .old first (allowed on both Linux and Windows even while executing).
fn swap(exe: &Path, new: &Path, old: &Path) -> Result<()> {
    let _ = std::fs::remove_file(old);
    std::fs::rename(exe, old).with_context(|| format!("rename {} -> {}", exe.display(), old.display()))?;
    if let Err(e) = std::fs::rename(new, exe) {
        // Roll back so the service can still start.
        let _ = std::fs::rename(old, exe);
        return Err(anyhow::Error::new(e).context(format!("rename {} -> {}", new.display(), exe.display())));
    }
    Ok(())
}

/// Ask the service manager to restart us (detached — this process is about to die).
fn restart_service() {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl").args(["restart", crate::service::SERVICE_NAME]).spawn();
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", &format!("sc stop {0} & timeout /t 3 /nobreak >nul & sc start {0}", crate::service::SERVICE_NAME)])
            .spawn();
    }
}

/// `pmacct-agent update`: manual, immediate, ignores the auto-update switches.
pub async fn manual(cfg: &agent_core::config::Config, force: bool) -> Result<()> {
    let client = Client::new(&cfg.server, &cfg.token, cfg.ca_pem.as_deref())?;
    let builds = client.builds().await?;
    let Some(b) = builds.into_iter().find(|b| b.target == TARGET) else { bail!("the server has no build for {TARGET}") };
    println!("running {} · server offers {} ({})", agent_core::VERSION, b.version, &b.sha256[..12]);
    if !force && !version::newer(&b.version, agent_core::VERSION) {
        println!("already up to date (use --force to reinstall)");
        return Ok(());
    }
    let v = apply(&client, &b, true).await?;
    println!("updated to {v}; the service is restarting");
    Ok(())
}

/// Called from the run loop with the server's ack: update when policy and version say so.
pub async fn maybe_auto(client: &Client, build: &BuildInfo, server_allows: bool, local_allows: bool) -> bool {
    if !server_allows || !local_allows || !wanted(build, agent_core::VERSION) {
        return false;
    }
    // Stagger so a whole fleet does not restart in the same second.
    let jitter = (std::process::id() % 120) as u64;
    info!("server offers pmacct-agent {} (running {}); updating in {jitter}s", build.version, agent_core::VERSION);
    tokio::time::sleep(std::time::Duration::from_secs(jitter)).await;
    match apply(client, build, true).await {
        Ok(_) => true,
        Err(e) => {
            warn!("auto-update failed: {e:#}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swap_keeps_previous_and_rolls_back() {
        let dir = std::env::temp_dir().join(format!("pmacct-agent-swap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("pmacct-agent");
        let new = exe.with_extension("new");
        let old = exe.with_extension("old");
        std::fs::write(&exe, b"v1").unwrap();
        std::fs::write(&new, b"v2").unwrap();
        swap(&exe, &new, &old).unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"v2");
        assert_eq!(std::fs::read(&old).unwrap(), b"v1", "previous binary kept for rollback");
        assert!(!new.exists());
        // A missing .new must not leave us without a binary.
        assert!(swap(&exe, &new, &old).is_err());
        assert_eq!(std::fs::read(&exe).unwrap(), b"v2", "rolled back");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wanted_only_for_newer_same_target() {
        let b = |t: &str, v: &str| BuildInfo { target: t.into(), version: v.into(), sha256: String::new(), size: 0 };
        assert!(wanted(&b(TARGET, "99.0.0"), "0.2.0"));
        assert!(!wanted(&b(TARGET, "0.2.0"), "0.2.0"));
        assert!(!wanted(&b(TARGET, "0.1.0"), "0.2.0"));
        assert!(!wanted(&b("other-arch", "99.0.0"), "0.2.0"));
    }
}
