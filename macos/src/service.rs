use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    sync::OnceLock,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use tokio::sync::oneshot;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
        ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

use crate::{bridge::Bridge, config::Config, redirector::RedirectorGuard};

pub const SERVICE_NAME: &str = "ProcSocks";
const SERVICE_DISPLAY_NAME: &str = "ProcSocks per-process SOCKS router";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
static SERVICE_CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

pub fn dispatch(config_path: PathBuf) -> Result<()> {
    SERVICE_CONFIG_PATH
        .set(config_path)
        .map_err(|_| anyhow::anyhow!("service configuration path was already initialized"))?;
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("failed to connect ProcSocks to the Windows Service Control Manager")?;
    Ok(())
}

fn service_main(_arguments: Vec<OsString>) {
    let config_path = SERVICE_CONFIG_PATH
        .get()
        .cloned()
        .unwrap_or_else(|| PathBuf::from("procsocks.json"));
    let log_directory = config_path.parent().unwrap_or_else(|| Path::new("."));
    let file_appender = tracing_appender::rolling::never(log_directory, "procsocks.log");
    let (log_writer, log_guard) = tracing_appender::non_blocking(file_appender);
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("procsocks=info"))
        .with_ansi(false)
        .with_target(false)
        .with_writer(log_writer)
        .try_init();

    if let Err(error) = run_service(&config_path) {
        error!(%error, "service stopped with an error");
    }
    drop(log_guard);
}

fn run_service(config_path: &Path) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let mut shutdown_tx = Some(shutdown_tx);
    let event_handler = move |event| match event {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(sender) = shutdown_tx.take() {
                let _ = sender.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("failed to register the service control handler")?;
    set_status(
        &status_handle,
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::NO_ERROR,
        Duration::from_secs(30),
    )?;

    let result = run_service_worker(config_path, &status_handle, shutdown_rx);
    let exit_code = if result.is_ok() {
        ServiceExitCode::NO_ERROR
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };
    set_status(
        &status_handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
        Duration::ZERO,
    )?;
    result
}

fn run_service_worker(
    config_path: &Path,
    status_handle: &ServiceStatusHandle,
    shutdown_rx: oneshot::Receiver<()>,
) -> Result<()> {
    let config = std::sync::Arc::new(Config::load(config_path)?);
    config.validate_redirector()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create the async runtime")?;

    runtime.block_on(async move {
        // Bind before enabling interception so a port error cannot strand process rules.
        let bridge = Bridge::bind(std::sync::Arc::clone(&config)).await?;
        let redirector = RedirectorGuard::start(&config)?;
        set_status(
            status_handle,
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            ServiceExitCode::NO_ERROR,
            Duration::ZERO,
        )?;
        info!(
            process_patterns = ?config.process_patterns,
            "service enabled per-process TCP redirection"
        );

        let bridge_result = tokio::select! {
            result = bridge.run() => Some(result),
            _ = shutdown_rx => None,
        };

        set_status(
            status_handle,
            ServiceState::StopPending,
            ServiceControlAccept::empty(),
            ServiceExitCode::NO_ERROR,
            Duration::from_secs(15),
        )?;
        drop(redirector);
        info!("service shutdown complete");

        match bridge_result {
            Some(result) => result,
            None => Ok(()),
        }
    })
}

fn set_status(
    handle: &ServiceStatusHandle,
    state: ServiceState,
    controls: ServiceControlAccept,
    exit_code: ServiceExitCode,
    wait_hint: Duration,
) -> Result<()> {
    handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: state,
            controls_accepted: controls,
            exit_code,
            checkpoint: 0,
            wait_hint,
            process_id: None,
        })
        .context("failed to report service status")?;
    Ok(())
}

pub fn install(config_path: &Path) -> Result<()> {
    let config_path = config_path
        .canonicalize()
        .with_context(|| format!("failed to resolve config {}", config_path.display()))?;
    let config = Config::load(&config_path)?;
    RedirectorGuard::probe(&config)?;
    crate::redirector::install_driver(&config)?;

    let executable_path = std::env::current_exe()
        .context("failed to locate procsocks.exe")?
        .canonicalize()
        .context("failed to resolve procsocks.exe")?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("failed to open the Windows Service Control Manager; run as Administrator")?;

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path,
        launch_arguments: vec![
            OsString::from("--config"),
            config_path.into_os_string(),
            OsString::from("service-run"),
        ],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::DELETE;
    let service = manager
        .create_service(&service_info, access)
        .context("failed to create ProcSocks service (is it already installed?)")?;
    service
        .set_description(
            "Routes selected TCP processes through a local SOCKS5 proxy without a global TUN.",
        )
        .context("failed to set service description")?;
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(5),
                },
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(15),
                },
                ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(60),
                },
            ]),
        })
        .context("failed to set service recovery actions")?;
    service
        .set_failure_actions_on_non_crash_failures(true)
        .context("failed to enable service recovery actions")?;
    Ok(())
}

pub fn start() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::START,
    )?;
    if service.query_status()?.current_state == ServiceState::Running {
        return Ok(());
    }
    service.start::<&OsStr>(&[])?;
    wait_for_state(&service, ServiceState::Running, Duration::from_secs(30))
}

pub fn stop() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
    )?;
    if service.query_status()?.current_state == ServiceState::Stopped {
        return Ok(());
    }
    service.stop()?;
    wait_for_state(&service, ServiceState::Stopped, Duration::from_secs(30))
}

pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        service.stop()?;
        wait_for_state(&service, ServiceState::Stopped, Duration::from_secs(30))?;
    }
    service
        .delete()
        .context("failed to delete ProcSocks service")?;
    Ok(())
}

pub fn status() -> Result<String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)?;
    let status = service.query_status()?;
    Ok(format!(
        "name={SERVICE_NAME}\nstate={:?}\nprocess_id={}",
        status.current_state,
        status
            .process_id
            .map_or_else(|| "none".to_string(), |id| id.to_string())
    ))
}

fn wait_for_state(
    service: &windows_service::service::Service,
    desired: ServiceState,
    timeout: Duration,
) -> Result<()> {
    let started = Instant::now();
    loop {
        let status = service.query_status()?;
        if status.current_state == desired {
            return Ok(());
        }
        if desired == ServiceState::Running && status.current_state == ServiceState::Stopped {
            bail!("ProcSocks stopped during startup: {:?}", status.exit_code);
        }
        if started.elapsed() >= timeout {
            bail!(
                "timed out waiting for ProcSocks to become {desired:?}; current state is {:?}",
                status.current_state
            );
        }
        thread::sleep(Duration::from_millis(250));
    }
}
