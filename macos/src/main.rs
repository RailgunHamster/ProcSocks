//! ProcSocks 命令行入口。
//!
//! 两个平台共用同一套配置、规则语义、SNI/Host 嗅探和 SOCKS5 客户端；只有
//! **重定向后端**是各自实现的：
//!
//! | | Windows | macOS |
//! |---|---|---|
//! | 重定向 | NetFilter SDK 驱动（`redirector`） | pf `rdr` + `route-to`（`pf`） |
//! | 连接前导 | 驱动以 SOCKS5 客户端身份接入 | 裸 TCP，目标靠 libproc 反查 |
//! | 目标识别 | 驱动在 SOCKS5 请求里给出 | `libproc` 扫 socket 表 |
//! | 常驻方式 | Windows 服务 | LaunchDaemon |

mod bridge;
mod config;
mod sniff;
mod traffic;

/// 进程规则匹配只在 macOS 后端用得到：Windows 那边规则是交给 NetFilter 驱动
/// 内部求值的，Rust 侧不再重复实现一遍。放这里条件编译，免得 Windows 构建里
/// 凭空多出一整块死代码。
#[cfg(target_os = "macos")]
mod rules;

#[cfg(windows)]
mod native;
#[cfg(windows)]
mod redirector;
#[cfg(windows)]
mod service;

#[cfg(target_os = "macos")]
mod gui;
#[cfg(target_os = "macos")]
mod launchd;
#[cfg(target_os = "macos")]
mod libproc;
#[cfg(target_os = "macos")]
mod pf;
#[cfg(target_os = "macos")]
mod pf_bridge;

use std::{future::Future, io::IsTerminal, path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use config::Config;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// JSON configuration file.
    #[arg(long, global = true, default_value = "procsocks.json")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate the configuration and the redirector backend.
    Check,
    /// Print an example configuration to standard output.
    Example,
    /// Run only the SOCKS hostname-recovery bridge.
    Bridge,
    /// Run the bridge and enable per-process TCP redirection.
    Run,
    /// Inspect or install the packet redirector backend.
    Driver {
        #[command(subcommand)]
        command: DriverCommand,
    },
    /// Install, start, stop, or inspect the unattended service.
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },

    /// List this user's running processes for the macOS menu bar app.
    #[cfg(target_os = "macos")]
    Processes,

    /// Manage the isolated backend used by the macOS menu bar app.
    #[cfg(target_os = "macos")]
    Gui {
        #[command(subcommand)]
        command: GuiCommand,
    },

    /// Internal entry point used by the Windows Service Control Manager.
    #[cfg(windows)]
    #[command(hide = true)]
    ServiceRun,

    /// Internal entry point for the macOS dead-man switch.
    ///
    /// 它由 `pf::spawn_watchdog` 拉起，阻塞在标准输入上；父进程一旦消失
    /// （包括被 SIGKILL），标准输入关闭，本进程立刻把 pf 规则撤干净。
    #[cfg(target_os = "macos")]
    #[command(name = "pf-watchdog", hide = true)]
    PfWatchdog {
        /// 序列化后的待还原状态。
        #[arg(long)]
        state: Option<String>,
        /// Exercise the pipe protocol without modifying pf (integration tests).
        #[arg(long)]
        dry_run: bool,
    },

    /// Internal: time one connection-attribution lookup.
    ///
    /// `redirectPorts: "all"` 时整机每条非 root 的 TCP 连接都要走一次归属查询，
    /// 所以这个数字直接决定全机网络手感。加个能直接量的入口，别靠猜。
    #[cfg(target_os = "macos")]
    #[command(name = "bench-libproc", hide = true)]
    BenchLibproc {
        #[arg(long, default_value_t = 200)]
        iterations: u32,
    },
}

#[derive(Debug, Subcommand)]
enum DriverCommand {
    /// Verify and import a user-supplied native bundle into redirectorDir.
    #[cfg(windows)]
    Import {
        /// Existing directory containing Redirector.bin, nfapi.dll, and nfdriver.sys.
        #[arg(long)]
        from: PathBuf,
    },
    /// Install the native driver. Requires an Administrator console.
    #[cfg(windows)]
    Install,
    /// Print redirector backend status.
    Status,
    /// Print the pf ruleset that `run` would load, without touching the kernel.
    ///
    /// 排错用：可以拿它和 `sudo pfctl -sn`、`sudo pfctl -sr` 的实际内容对照。
    #[cfg(target_os = "macos")]
    Ruleset,
}

#[derive(Debug, Subcommand)]
enum ServiceCommand {
    /// Install an automatic-start service and the packet driver.
    Install,
    /// Start the installed service.
    Start,
    /// Stop the installed service gracefully.
    Stop,
    /// Print the installed service state.
    Status,
    /// Stop and unregister the service; files and driver are retained.
    Uninstall,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Subcommand)]
enum GuiCommand {
    /// Install a root-owned backend, apply the config, and start it.
    Apply {
        /// Ordinary user who may read the connection log.
        #[arg(long)]
        owner: u32,
        /// Enable the proxy automatically on subsequent boots.
        #[arg(long)]
        autostart: bool,
        /// Save the managed configuration without starting interception.
        #[arg(long)]
        stopped: bool,
    },
    Validate,
    Stop,
    Status,
    Uninstall,
    /// Test a real SOCKS5 CONNECT without changing pf.
    Probe,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // 这两个入口要在日志系统就绪之前就分派掉：死人开关必须保持安静，
    // Windows 服务入口则有自己的日志落盘方式。
    #[cfg(windows)]
    if matches!(&cli.command, Command::ServiceRun) {
        return service::dispatch(cli.config);
    }
    #[cfg(target_os = "macos")]
    if let Command::PfWatchdog { state, dry_run } = &cli.command {
        return pf::run_watchdog(state.as_deref(), *dry_run);
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("procsocks=info")),
        )
        .with_target(false)
        .with_ansi(std::io::stdout().is_terminal())
        .init();

    match cli.command {
        #[cfg(target_os = "macos")]
        Command::Processes => {
            println!("{}", serde_json::to_string(&libproc::running_processes()?)?);
        }
        #[cfg(target_os = "macos")]
        Command::Gui { command } => match command {
            GuiCommand::Apply {
                owner,
                autostart,
                stopped,
            } => {
                gui::apply(&cli.config, owner, autostart, !stopped)?;
            }
            GuiCommand::Validate => {
                let config = Config::load(&cli.config)?;
                config.validate_redirector_settings()?;
                pf::validate_ruleset(&config)?;
                println!("configuration and rules: ok");
            }
            GuiCommand::Stop => gui::stop()?,
            GuiCommand::Status => println!("{}", serde_json::to_string(&gui::status()?)?),
            GuiCommand::Uninstall => gui::uninstall()?,
            GuiCommand::Probe => {
                let config = Config::load(&cli.config)?;
                let elapsed = bridge::probe_upstream(&config).await?;
                println!("SOCKS5 CONNECT example.com:443 succeeded in {elapsed} ms");
            }
        },
        Command::Example => {
            println!("{}", serde_json::to_string_pretty(&example_value()?)?);
        }

        Command::Check => {
            let config = Config::load(&cli.config)?;
            println!("configuration: ok");
            println!("listen: {}", config.listen);
            println!(
                "upstream: {}:{}",
                config.upstream.host, config.upstream.port
            );
            println!("process rules: {}", config.process_patterns.len());
            println!("bypass rules: {}", config.bypass_patterns.len());
            println!("redirect ports: {}", config.redirect_ports);
            #[cfg(target_os = "macos")]
            println!("redirect IPv6: {}", config.redirect_ipv6);
            config.validate_redirector()?;

            #[cfg(windows)]
            {
                let bundle = redirector::RedirectorGuard::probe(&config)?;
                println!("native bundle: {} (verified)", bundle.id);
                println!("redirector exports: ok");
            }
            #[cfg(target_os = "macos")]
            {
                pf::PfGuard::probe(&config)?;
                println!("redirector: pf (macOS built-in)");
                println!("pfctl: {}", pf::PFCTL_PATH);
                println!("pf ruleset: syntax ok");
                if pf::is_root() {
                    println!("{}", pf::PfGuard::status(&config)?);
                } else {
                    println!("pf status: 需要 root 才能读取（sudo 后可看到完整状态）");
                }
                for warning in config_warnings(&config) {
                    println!("warning: {warning}");
                }
            }
        }

        Command::Bridge => {
            let config = Arc::new(Config::load(&cli.config)?);
            let bridge = bridge::Bridge::bind(config).await?;
            run_until_shutdown(bridge.run()).await?;
        }

        Command::Run => {
            let config = Arc::new(Config::load(&cli.config)?);
            config.validate_redirector()?;

            for warning in config_warnings(&config) {
                warn!("{warning}");
            }

            #[cfg(windows)]
            {
                // Bind first. If the port is unavailable, no interception rule is enabled.
                let bridge = bridge::Bridge::bind(Arc::clone(&config)).await?;
                let _redirector = redirector::RedirectorGuard::start(&config)?;
                info!(
                    process_patterns = ?config.process_patterns,
                    "per-process TCP redirection enabled"
                );
                run_until_shutdown(bridge.run()).await?;
            }

            #[cfg(target_os = "macos")]
            {
                // 顺序至关重要：先 bind 成功，再载入 pf 规则。
                // 反过来的话，规则生效而没人接客，整机 TCP 会全部失败。
                let traffic = gui::traffic_publisher(&cli.config)?;
                let bridge = pf_bridge::PfBridge::bind(
                    Arc::clone(&config),
                    traffic
                        .as_ref()
                        .map(|publisher| Arc::clone(&publisher.ledger)),
                )
                .await?;
                let _guard = pf::PfGuard::start(&config)?;
                info!(
                    process_patterns = ?config.process_patterns,
                    "per-process TCP redirection enabled"
                );
                run_until_shutdown(bridge.run()).await?;
            }
        }

        Command::Driver { command } => {
            let config = Config::load(&cli.config)?;
            match command {
                #[cfg(windows)]
                DriverCommand::Import { from } => {
                    let (bundle_id, imported) =
                        redirector::import_components(&from, &config.redirector_dir)?;
                    for path in imported {
                        println!("imported: {}", path.display());
                    }
                    println!("native bundle: {bundle_id} (verified)");
                }
                #[cfg(windows)]
                DriverCommand::Install => {
                    let path = redirector::install_driver(&config)?;
                    println!("driver installed: {}", path.display());
                }
                DriverCommand::Status => {
                    #[cfg(windows)]
                    println!("{}", redirector::driver_status(&config)?);
                    #[cfg(target_os = "macos")]
                    println!("{}", pf::PfGuard::status(&config)?);
                }
                #[cfg(target_os = "macos")]
                DriverCommand::Ruleset => {
                    config.validate_redirector()?;
                    print!("{}", pf::generate_ruleset(&config));
                }
            }
        }

        Command::Service { command } => match command {
            ServiceCommand::Install => {
                #[cfg(windows)]
                {
                    service::install(&cli.config)?;
                    println!("service installed: {}", service::SERVICE_NAME);
                }
                #[cfg(target_os = "macos")]
                {
                    launchd::install(&cli.config)?;
                    println!("LaunchDaemon installed: {}", launchd::LABEL);
                }
            }
            ServiceCommand::Start => {
                #[cfg(windows)]
                {
                    service::start()?;
                    println!("service started: {}", service::SERVICE_NAME);
                }
                #[cfg(target_os = "macos")]
                {
                    launchd::start()?;
                    println!("LaunchDaemon started: {}", launchd::LABEL);
                }
            }
            ServiceCommand::Stop => {
                #[cfg(windows)]
                {
                    service::stop()?;
                    println!("service stopped: {}", service::SERVICE_NAME);
                }
                #[cfg(target_os = "macos")]
                {
                    launchd::stop()?;
                    println!("LaunchDaemon stopped: {}", launchd::LABEL);
                }
            }
            ServiceCommand::Status => {
                #[cfg(windows)]
                println!("{}", service::status()?);
                #[cfg(target_os = "macos")]
                println!("{}", launchd::status()?);
            }
            ServiceCommand::Uninstall => {
                #[cfg(windows)]
                {
                    service::uninstall()?;
                    println!("service uninstalled: {}", service::SERVICE_NAME);
                }
                #[cfg(target_os = "macos")]
                {
                    launchd::uninstall()?;
                    println!("LaunchDaemon uninstalled: {}", launchd::LABEL);
                }
            }
        },

        #[cfg(windows)]
        Command::ServiceRun => unreachable!("service mode was dispatched before logging setup"),
        #[cfg(target_os = "macos")]
        Command::PfWatchdog { .. } => unreachable!("watchdog was dispatched before logging setup"),
        #[cfg(target_os = "macos")]
        Command::BenchLibproc { iterations } => {
            println!("{}", libproc::benchmark(iterations)?);
        }
    }

    Ok(())
}

/// 生成 `example` 子命令要打印的配置。
///
/// macOS 上把 Windows 专属字段去掉，免得使用者以为自己得去准备内核驱动。
#[cfg(target_os = "macos")]
fn example_value() -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(Config::example())?;
    if let Some(map) = value.as_object_mut() {
        map.remove("redirectorDir");
        map.remove("driverName");
    }
    Ok(value)
}

#[cfg(not(target_os = "macos"))]
fn example_value() -> Result<serde_json::Value> {
    Ok(serde_json::to_value(Config::example())?)
}

/// 配置层面「能跑但危险」的提醒。`check` 会打印，`run` 会记成 warning。
///
/// 这些风险全部来自 macOS 后端「pf 无法按进程匹配」这个前提，Windows 那边
/// 由驱动做进程过滤，不存在同样的问题，所以整块只在 macOS 上编译。
#[cfg(target_os = "macos")]
fn config_warnings(config: &Config) -> Vec<String> {
    use config::RedirectPorts;

    let mut warnings = Vec::new();

    if config.redirect_ports.covers(22) {
        warnings.push(
            "redirectPorts 覆盖了 22 端口：如果本进程异常退出而 pf 规则残留，\
             SSH 会一起断掉。无人值守的机器上建议把 22 排除在重定向之外。"
                .to_string(),
        );
    }
    if matches!(config.redirect_ports, RedirectPorts::All) {
        warnings.push(
            "redirectPorts=all：因为 pf 无法按进程匹配，整机所有非 root 的 TCP \
             连接都会先经过本进程，再由规则决定代理还是直连。"
                .to_string(),
        );
    }
    if !config.redirect_ipv6 {
        warnings.push(
            "redirectIpv6=false：IPv6 的 TCP 连接不会被重定向，会绕过代理由系统直连。".to_string(),
        );
    }

    warnings
}

#[cfg(not(target_os = "macos"))]
fn config_warnings(_config: &Config) -> Vec<String> {
    Vec::new()
}

async fn run_until_shutdown<F>(run: F) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        // Register both handlers before polling the listener. launchd sends
        // SIGTERM on bootout; returning normally lets PfGuard restore the rules.
        let mut terminate =
            signal(SignalKind::terminate()).context("failed to install the SIGTERM handler")?;
        let mut interrupt =
            signal(SignalKind::interrupt()).context("failed to install the SIGINT handler")?;
        // Privileged launchers can pass down a blocked signal mask. Install
        // handlers first, then allow pending and future shutdown signals on
        // this thread; Tokio's other threads may retain the inherited mask.
        unblock_shutdown_signals()?;
        tokio::select! {
            result = run => result,
            _ = terminate.recv() => {
                info!(signal = "SIGTERM", "shutdown requested");
                Ok(())
            }
            _ = interrupt.recv() => {
                info!(signal = "SIGINT", "shutdown requested");
                Ok(())
            }
        }
    }
    #[cfg(not(unix))]
    tokio::select! {
        result = run => result,
        result = tokio::signal::ctrl_c() => {
            result.context("failed to install the Ctrl+C handler")?;
            info!("shutdown requested");
            Ok(())
        }
    }
}

#[cfg(unix)]
fn unblock_shutdown_signals() -> Result<()> {
    // SAFETY: the initialized set and its pointer remain valid for each call.
    // pthread_sigmask changes only this thread's mask, after our handlers exist.
    let result = unsafe {
        let mut signals = std::mem::zeroed::<libc::sigset_t>();
        if libc::sigemptyset(&mut signals) != 0
            || libc::sigaddset(&mut signals, libc::SIGTERM) != 0
            || libc::sigaddset(&mut signals, libc::SIGINT) != 0
        {
            return Err(std::io::Error::last_os_error())
                .context("failed to prepare shutdown signals");
        }
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &signals, std::ptr::null_mut())
    };
    if result != 0 {
        return Err(std::io::Error::from_raw_os_error(result))
            .context("failed to unblock shutdown signals");
    }
    Ok(())
}
