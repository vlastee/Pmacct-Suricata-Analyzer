//! Service installation: a systemd unit on Linux, a Windows service via the SCM on Windows.
use anyhow::{Context, Result};

pub const SERVICE_NAME: &str = "pmacct-agent";

#[cfg(target_os = "linux")]
pub fn install() -> Result<()> {
    use agent_core::config::Config;
    let cfg = Config::load(&Config::default_path()).context("load configuration (run `pmacct-agent enroll` first)")?;
    let spool = cfg.spool_dir();
    std::fs::create_dir_all(&spool).with_context(|| format!("create {}", spool.display()))?;
    let exe = std::env::current_exe()?;
    let target = std::path::Path::new("/usr/local/bin/pmacct-agent");
    if exe != target {
        std::fs::copy(&exe, target).with_context(|| format!("copy {} to {}", exe.display(), target.display()))?;
    }
    let unit = format!(
        "[Unit]\nDescription=pmacct-analyzer endpoint agent\nAfter=network-online.target\nWants=network-online.target\n\n\
[Service]\nExecStart={}\nRestart=always\nRestartSec=5\nUser=root\nProtectSystem=strict\nReadWritePaths=/etc/pmacct-agent {}\nNoNewPrivileges=yes\nPrivateTmp=yes\n\n\
[Install]\nWantedBy=multi-user.target\n",
        format!("{} run", target.display()),
        spool.display()
    );
    std::fs::write("/etc/systemd/system/pmacct-agent.service", unit).context("write unit")?;
    for args in [vec!["daemon-reload"], vec!["enable", "--now", SERVICE_NAME]] {
        let st = std::process::Command::new("systemctl").args(&args).status().context("systemctl")?;
        anyhow::ensure!(st.success(), "systemctl {:?} failed", args);
    }
    println!("installed and started: systemctl status {SERVICE_NAME}");
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn uninstall() -> Result<()> {
    let _ = std::process::Command::new("systemctl").args(["disable", "--now", SERVICE_NAME]).status();
    let _ = std::fs::remove_file("/etc/systemd/system/pmacct-agent.service");
    let _ = std::process::Command::new("systemctl").arg("daemon-reload").status();
    println!("removed the service (configuration in /etc/pmacct-agent kept)");
    Ok(())
}

#[cfg(windows)]
pub fn install() -> Result<()> {
    use std::ffi::OsString;
    use windows_service::service::{ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE | ServiceManagerAccess::CONNECT)?;
    let exe = std::env::current_exe()?;
    let dir = agent_core::config::Config::data_dir();
    std::fs::create_dir_all(&dir)?;
    let target = dir.join("pmacct-agent.exe");
    if exe != target {
        std::fs::copy(&exe, &target).with_context(|| format!("copy to {}", target.display()))?;
    }
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("pmacct-analyzer endpoint agent"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: target,
        launch_arguments: vec![OsString::from("run"), OsString::from("--service")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager.create_service(&info, ServiceAccess::START | ServiceAccess::CHANGE_CONFIG)?;
    service.set_description("Reports which program opened which network connection to pmacct-analyzer.")?;
    service.start::<OsString>(&[])?;
    println!("installed and started the {SERVICE_NAME} service");
    Ok(())
}

#[cfg(windows)]
pub fn uninstall() -> Result<()> {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS)?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
    }
    service.delete()?;
    println!("removed the {SERVICE_NAME} service (configuration kept)");
    Ok(())
}

/// Windows service entry: the SCM calls this; it runs the agent loop until a Stop control.
#[cfg(windows)]
pub fn run_as_service() -> Result<()> {
    use windows_service::service_dispatcher;
    windows_service::define_windows_service!(ffi_service_main, service_main);
    fn service_main(_args: Vec<std::ffi::OsString>) {
        use std::time::Duration;
        use windows_service::service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType};
        use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handler = move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let Ok(status) = service_control_handler::register(SERVICE_NAME, handler) else { return };
        let set = |state: ServiceState| {
            let _ = status.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::from_secs(10),
                process_id: None,
            });
        };
        set(ServiceState::Running);
        let cfg = agent_core::config::Config::load(&agent_core::config::Config::default_path());
        if let Ok(cfg) = cfg {
            let rt = tokio::runtime::Runtime::new().expect("runtime");
            let _ = rt.block_on(crate::runner::run(cfg, rx));
        }
        set(ServiceState::Stopped);
    }
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}
