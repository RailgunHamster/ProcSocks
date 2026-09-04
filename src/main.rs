#![cfg_attr(not(windows), allow(dead_code))]

#[cfg(not(windows))]
compile_error!("procsocks currently supports Windows only");

mod bridge;
mod config;
mod native;
mod redirector;
mod service;
mod sniff;

use std::{path::PathBuf, sync::Arc};

use anyhow::Result;
use bridge::Bridge;
use clap::{Parser, Subcommand};
use config::Config;
use redirector::RedirectorGuard;
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
    /// Validate the configuration and native redirector components.
    Check,
    /// Print an example configuration to standard output.
    Example,
    /// Run only the SOCKS hostname-recovery bridge.
    Bridge,
    /// Run the bridge and enable per-process TCP redirection.
    Run,
    /// Inspect or install the packet redirector driver.
    Driver {
        #[command(subcommand)]
        command: DriverCommand,
    },
    /// Install, start, stop, or inspect the unattended Windows service.
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
    /// Internal entry point used by the Windows Service Control Manager.
    #[command(hide = true)]
    ServiceRun,
}

#[derive(Debug, Subcommand)]
enum DriverCommand {
    /// Verify and import a user-supplied native bundle into redirectorDir.
    Import {
        /// Existing directory containing Redirector.bin, nfapi.dll, and nfdriver.sys.
        #[arg(long)]
        from: PathBuf,
    },
    /// Install the native driver. Requires an Administrator console.
    Install,
    /// Print driver file and Windows service status.
    Status,
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if matches!(&cli.command, Command::ServiceRun) {
        return service::dispatch(cli.config);
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("procsocks=info")),
        )
        .with_target(false)
        .init();

    match cli.command {
        Command::Example => {
            println!("{}", serde_json::to_string_pretty(&Config::example())?);
        }
        Command::Check => {
            let config = Config::load(&cli.config)?;
            let bundle = RedirectorGuard::probe(&config)?;
            println!("configuration: ok");
            println!("listen: {}", config.listen);
            println!(
                "upstream: {}:{}",
                config.upstream.host, config.upstream.port
            );
            println!("process rules: {}", config.process_patterns.len());
            println!("native bundle: {} (verified)", bundle.id);
            println!("redirector exports: ok");
        }
        Command::Bridge => {
            let config = Arc::new(Config::load(&cli.config)?);
            let bridge = Bridge::bind(config).await?;
            run_until_shutdown(bridge).await?;
        }
        Command::Run => {
            let config = Arc::new(Config::load(&cli.config)?);
            config.validate_redirector()?;

            // Bind first. If the port is unavailable, no interception rule is enabled.
            let bridge = Bridge::bind(Arc::clone(&config)).await?;
            let _redirector = RedirectorGuard::start(&config)?;
            info!(
                process_patterns = ?config.process_patterns,
                "per-process TCP redirection enabled"
            );
            run_until_shutdown(bridge).await?;
        }
        Command::Driver { command } => {
            let config = Config::load(&cli.config)?;
            match command {
                DriverCommand::Import { from } => {
                    let (bundle_id, imported) =
                        redirector::import_components(&from, &config.redirector_dir)?;
                    for path in imported {
                        println!("imported: {}", path.display());
                    }
                    println!("native bundle: {bundle_id} (verified)");
                }
                DriverCommand::Install => {
                    let path = redirector::install_driver(&config)?;
                    println!("driver installed: {}", path.display());
                }
                DriverCommand::Status => println!("{}", redirector::driver_status(&config)?),
            }
        }
        Command::Service { command } => match command {
            ServiceCommand::Install => {
                service::install(&cli.config)?;
                println!("service installed: {}", service::SERVICE_NAME);
            }
            ServiceCommand::Start => {
                service::start()?;
                println!("service started: {}", service::SERVICE_NAME);
            }
            ServiceCommand::Stop => {
                service::stop()?;
                println!("service stopped: {}", service::SERVICE_NAME);
            }
            ServiceCommand::Status => println!("{}", service::status()?),
            ServiceCommand::Uninstall => {
                service::uninstall()?;
                println!("service uninstalled: {}", service::SERVICE_NAME);
            }
        },
        Command::ServiceRun => unreachable!("service mode was dispatched before logging setup"),
    }

    Ok(())
}

async fn run_until_shutdown(bridge: Bridge) -> Result<()> {
    tokio::select! {
        result = bridge.run() => result,
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                warn!(%error, "failed to install Ctrl+C handler");
            }
            info!("shutdown requested");
            Ok(())
        }
    }
}
