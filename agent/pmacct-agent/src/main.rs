mod capture;
mod procinfo;
mod runner;
mod service;

use agent_core::config::Config;
use agent_core::model::EnrollRequest;
use agent_core::{client, pin};
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "pmacct-agent", version, about = "pmacct-analyzer endpoint agent — reports which program opened which connection")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Enroll this machine with an enrollment token from the Agents page
    Enroll {
        /// Server URL, e.g. https://10.0.0.210:8091
        #[arg(long)]
        server: String,
        /// Single-use enrollment token
        #[arg(long)]
        token: String,
        /// Expected CA pin (ca_spki_sha256 shown on the Agents page). Without it the fetched CA
        /// is trusted on first use and its fingerprint printed for you to verify.
        #[arg(long)]
        ca_pin: Option<String>,
        /// Send full command lines (may contain secrets)
        #[arg(long)]
        send_cmdline: bool,
        /// Capture backend: auto (default), poll, ebpf
        #[arg(long, default_value = "auto")]
        capture: String,
    },
    /// Run the agent (foreground; the installed service uses this too)
    Run {
        #[arg(long, hide = true)]
        service: bool,
    },
    /// Register and start the system service (systemd / Windows service)
    Install,
    /// Stop and remove the system service (keeps the configuration)
    Uninstall,
    /// Show the configuration and try one heartbeat
    Status,
    /// Print the current connections with their programs; with --capture ebpf, stream new
    /// connections for --seconds (troubleshooting; run as root/admin)
    Snapshot {
        /// auto | poll | ebpf
        #[arg(long, default_value = "poll")]
        capture: String,
        /// How long to collect events (event-driven backends)
        #[arg(long, default_value_t = 5)]
        seconds: u64,
    },
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).format_timestamp_secs().init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Enroll { server, token, ca_pin, send_cmdline, capture } => rt().block_on(enroll(server, token, ca_pin, send_cmdline, capture)),
        Cmd::Run { service } => {
            #[cfg(windows)]
            if service {
                return service::run_as_service();
            }
            let _ = service;
            let cfg = Config::load(&Config::default_path())?;
            let (tx, rx) = tokio::sync::watch::channel(false);
            rt().block_on(async move {
                tokio::spawn(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    let _ = tx.send(true);
                });
                runner::run(cfg, rx).await
            })
        }
        Cmd::Install => service::install(),
        Cmd::Uninstall => service::uninstall(),
        Cmd::Status => rt().block_on(status()),
        Cmd::Snapshot { capture, seconds } => snapshot(&capture, seconds),
    }
}

fn snapshot(mode: &str, seconds: u64) -> Result<()> {
    use std::io::Write;
    let mut res = procinfo::Resolver::default();
    let out = std::io::stdout();
    let mut out = out.lock();
    let line = |out: &mut std::io::StdoutLock, s: &capture::Socket, info: &agent_core::model::ProcInfo| {
        writeln!(out, "{:<4} {:<42} -> {:<42} pid={:<7} {} [{}] {}", s.proto, s.local, s.remote, s.pid, if info.name.is_empty() { "?" } else { &info.name }, info.user, info.exe).is_ok()
    };
    if mode == "poll" {
        #[cfg(target_os = "linux")]
        let mut cap = capture::linux::ProcNet::default();
        #[cfg(windows)]
        let mut cap = capture::windows::IpHelper::default();
        let sockets = cap.snapshot()?;
        let _ = writeln!(out, "capture=poll sockets={}", sockets.len());
        for s in sockets {
            let info = res.resolve(s.pid, false);
            if !line(&mut out, &s, &info) {
                break;
            }
        }
        return Ok(());
    }
    let mut cap = capture::new(mode)?;
    let _ = writeln!(out, "capture={} collecting for {seconds}s…", cap.name());
    let end = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    let mut n = 0;
    while std::time::Instant::now() < end {
        for s in cap.poll()? {
            n += 1;
            let info = runner::identify(&mut res, &s, false);
            if !line(&mut out, &s, &info) {
                return Ok(());
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    let _ = writeln!(out, "{n} connections in {seconds}s");
    Ok(())
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime")
}

async fn enroll(server: String, token: String, ca_pin: Option<String>, send_cmdline: bool, capture: String) -> Result<()> {
    let server = server.trim().trim_end_matches('/').to_string();
    let mut ca_pem = None;
    if server.starts_with("https://") {
        let pem = client::fetch_ca_insecure(&server).await.context("fetching the server CA")?;
        let spki = pin::spki_sha256_base64(&pem)?;
        let fp = pin::fingerprint_sha256(&pem)?;
        match &ca_pin {
            Some(want) if want.trim() != spki => bail!("CA pin mismatch: server presented {spki}, expected {want} — not enrolling"),
            Some(_) => println!("CA pin verified ({})", pin::subject(&pem).unwrap_or_default()),
            None => println!("WARNING: no --ca-pin given; trusting the server CA on first use.\n  subject     {}\n  fingerprint {fp}\n  spki pin    {spki}\nCompare with the Agents page.", pin::subject(&pem).unwrap_or_default()),
        }
        ca_pem = Some(pem);
    } else {
        println!("WARNING: plain http — the token will cross the network unencrypted; the server may refuse.");
    }
    let req = EnrollRequest {
        enroll_token: token.trim().to_string(),
        hostname: runner::host_name(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        version: agent_core::VERSION.into(),
        ips: runner::local_ips(),
    };
    let resp = client::enroll(&server, ca_pem.as_deref(), &req).await.context("enrollment")?;
    let cfg = Config { server: server.clone(), agent_id: resp.agent_id, token: resp.agent_token, ca_pem, interval_secs: 1, send_every_secs: 30, send_cmdline, capture, local_networks: resp.local_networks };
    let path = Config::default_path();
    cfg.save(&path)?;
    println!("enrolled as \"{}\" (agent #{}); configuration written to {}", resp.name, resp.agent_id, path.display());
    println!("next: pmacct-agent install   (or: pmacct-agent run)");
    Ok(())
}

async fn status() -> Result<()> {
    let path = Config::default_path();
    let cfg = Config::load(&path)?;
    println!("config      {}", path.display());
    println!("server      {}", cfg.server);
    println!("agent id    {}", cfg.agent_id);
    println!("capture     {}", cfg.capture);
    println!("pinned CA   {}", cfg.ca_pem.as_deref().map(|p| pin::fingerprint_sha256(p).unwrap_or_default()).unwrap_or_else(|| "none (http)".into()));
    println!("local ips   {:?}", runner::local_ips());
    let c = client::Client::new(&cfg.server, &cfg.token, cfg.ca_pem.as_deref())?;
    let batch = agent_core::model::EventsBatch { hostname: runner::host_name(), version: agent_core::VERSION.into(), ips: runner::local_ips(), capture: String::new(), dropped: 0, conns: vec![] };
    match c.send(&batch).await {
        Ok(_) => println!("heartbeat   ok"),
        Err(e) => println!("heartbeat   FAILED: {e:#}"),
    }
    Ok(())
}
