//! A root-owned launchd backend for the unprivileged macOS menu bar app.
//! Uses its own label and files; the existing CLI service is not overwritten.
#![cfg(target_os = "macos")]

use std::{
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::{config::Config, launchd, pf};

pub const LABEL: &str = "com.procsocks.menubar.core";
const DIRECTORY: &str = "/Library/Application Support/ProcSocks";
const EXECUTABLE: &str = "/Library/Application Support/ProcSocks/procsocks";
const CONFIG: &str = "/Library/Application Support/ProcSocks/config.json";
const RUNTIME_PLIST: &str = "/Library/Application Support/ProcSocks/agent.plist";
const BOOT_PLIST: &str = "/Library/LaunchDaemons/com.procsocks.menubar.core.plist";
const LOG: &str = "/Library/Application Support/ProcSocks/core.log";
const TRAFFIC: &str = "/Library/Application Support/ProcSocks/traffic.json";
const LAUNCHCTL: &str = "/bin/launchctl";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    installed: bool,
    loaded: bool,
    running: bool,
    autostart: bool,
    state: String,
    pid: Option<u32>,
    last_exit_code: Option<i32>,
}

pub fn status() -> Result<Status> {
    let output = Command::new(LAUNCHCTL)
        .args(["print", &format!("system/{LABEL}")])
        .output()
        .context("failed to inspect the menu bar backend")?;
    if output.status.code() == Some(113) {
        return Ok(parse_status("", false));
    }
    if !output.status.success() {
        bail!(
            "launchctl status failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(parse_status(&String::from_utf8_lossy(&output.stdout), true))
}

pub(crate) fn traffic_publisher(config: &Path) -> Result<Option<crate::traffic::Publisher>> {
    // Only the managed GUI service publishes to its private support directory.
    // The log's existing owner identifies the same user authorized at install.
    if config.canonicalize().ok().as_deref() != Some(Path::new(CONFIG)) {
        return Ok(None);
    }
    require_root()?;
    ensure_directory()?;
    let owner = fs::symlink_metadata(LOG)?.uid();
    if owner == 0 {
        bail!("the menu bar traffic reader must be an ordinary user");
    }
    crate::traffic::Publisher::start(TRAFFIC.into(), owner).map(Some)
}

fn parse_status(text: &str, loaded: bool) -> Status {
    let value = |key: &str| {
        text.lines().find_map(|line| {
            line.trim()
                .strip_prefix(key)
                .map(|value| value.trim().to_owned())
        })
    };
    let pid = value("pid = ").and_then(|pid| pid.parse::<u32>().ok());
    let state = value("state = ").unwrap_or_else(|| "stopped".into());
    Status {
        installed: Path::new(EXECUTABLE).is_file(),
        loaded,
        running: loaded && pid.is_some() && state == "running",
        autostart: Path::new(BOOT_PLIST).is_file(),
        state,
        pid,
        last_exit_code: value("last exit code = ").and_then(|code| code.parse().ok()),
    }
}

pub fn apply(source_config: &Path, owner: u32, autostart: bool, start: bool) -> Result<()> {
    require_root()?;
    if owner == 0 {
        bail!("the menu bar app must run as an ordinary user");
    }
    let config = Config::load(source_config)?;
    if start || autostart {
        config.validate_redirector()?;
        pf::PfGuard::probe(&config)?;
    } else {
        config.validate_redirector_settings()?;
        pf::validate_ruleset(&config)?;
    }
    let source = std::env::current_exe().context("failed to locate the bundled core")?;
    let binary = fs::read(source).context("failed to read the bundled core")?;
    // Serialize the validated snapshot, not a second read of the user's file.
    let config_bytes = serde_json::to_vec_pretty(&config)?;
    ensure_directory()?;
    stop()?;
    atomic_write(Path::new(EXECUTABLE), &binary, 0o755)?;
    atomic_write(Path::new(CONFIG), &config_bytes, 0o600)?;
    let plist = launchd::render_plist_for(Path::new(EXECUTABLE), Path::new(CONFIG), LABEL, LOG);
    atomic_write(Path::new(RUNTIME_PLIST), plist.as_bytes(), 0o644)?;
    let log = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(LOG)
        .context("failed to prepare the private backend log")?;
    log.set_permissions(fs::Permissions::from_mode(0o600))?;
    let log_path = std::ffi::CString::new(LOG)?;
    // SAFETY: the string is NUL-terminated; the parent directory is root-owned.
    if unsafe { libc::chown(log_path.as_ptr(), owner, u32::MAX) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to assign the backend log");
    }
    let offset = log.metadata()?.len();
    if autostart {
        atomic_write(Path::new(BOOT_PLIST), plist.as_bytes(), 0o644)?;
    } else {
        remove_if_exists(Path::new(BOOT_PLIST))?;
    }
    execute(&["enable", &format!("system/{LABEL}")])?;
    if !start {
        println!("menu bar backend configured and stopped");
        return Ok(());
    }
    execute(&["bootstrap", "system", RUNTIME_PLIST])?;

    // A launchd PID alone is not readiness: bind/pf failures can restart forever.
    // Require this new PID's pf-ready line written after the previous log offset.
    let deadline = Instant::now() + Duration::from_secs(12);
    while Instant::now() < deadline {
        let state = status()?;
        if let Some(pid) = state.pid
            && state.running
        {
            let new_log = read_log_since(offset)?;
            if new_log.lines().any(|line| {
                line.contains("pf 透明重定向已启用")
                    && line
                        .split_whitespace()
                        .any(|word| word == format!("pid={pid}"))
            }) {
                println!("menu bar backend ready; pid={pid}");
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let recent = read_log_since(offset)?;
    let _ = stop();
    let _ = remove_if_exists(Path::new(BOOT_PLIST));
    let lines = recent.lines().rev().take(12).collect::<Vec<_>>();
    bail!(
        "menu bar backend failed to become ready:\n{}",
        lines.into_iter().rev().collect::<Vec<_>>().join("\n")
    )
}

fn read_log_since(offset: u64) -> Result<String> {
    let mut file = fs::File::open(LOG)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::new();
    file.take(128 * 1024).read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub fn stop() -> Result<()> {
    require_root()?;
    if status()?.loaded {
        let result = execute(&["bootout", &format!("system/{LABEL}")]);
        // launchctl print can briefly report a job which bootout has already
        // removed. Stopping an already unloaded job is successful and safe.
        if result.is_err() && status()?.loaded {
            result?;
        }
    }
    println!("menu bar backend stopped");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    require_root()?;
    stop()?;
    // Keep the log for diagnosis. Never delete other service labels or folders.
    for path in [BOOT_PLIST, RUNTIME_PLIST, CONFIG, EXECUTABLE, TRAFFIC] {
        remove_if_exists(Path::new(path))?;
    }
    Ok(())
}

fn require_root() -> Result<()> {
    if !pf::is_root() {
        bail!("控制菜单栏代理需要 macOS 管理员认证");
    }
    Ok(())
}

fn ensure_directory() -> Result<()> {
    fs::create_dir_all(DIRECTORY)?;
    let metadata = fs::symlink_metadata(DIRECTORY)?;
    if !metadata.is_dir() || metadata.uid() != 0 {
        bail!("{DIRECTORY} must be a root-owned directory");
    }
    fs::set_permissions(DIRECTORY, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().context("file has no parent directory")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temporary = parent.join(format!(".procsocks-{}-{nonce}", std::process::id()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.with_context(|| format!("failed to install {}", path.display()))
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn execute(args: &[&str]) -> Result<()> {
    let output = Command::new(LAUNCHCTL).args(args).output()?;
    if !output.status.success() {
        bail!(
            "launchctl {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loaded_without_a_live_running_pid_is_not_running() {
        assert!(!parse_status("state = waiting\nlast exit code = 1", true).running);
        assert!(!parse_status("state = running", true).running);
        let status = parse_status("state = running\n pid = 123\n last exit code = 0", true);
        assert!(status.running);
        assert_eq!(status.pid, Some(123));
    }

    #[test]
    fn an_unloaded_job_is_stopped() {
        let status = parse_status("", false);
        assert!(!status.loaded);
        assert!(!status.running);
        assert_eq!(status.state, "stopped");
    }

    #[test]
    fn gui_plist_uses_its_own_label_and_log() {
        let plist = launchd::render_plist_for(Path::new(EXECUTABLE), Path::new(CONFIG), LABEL, LOG);
        assert!(plist.contains(&format!("<string>{LABEL}</string>")));
        assert!(!plist.contains(&format!("<string>{}</string>", launchd::LABEL)));
        assert!(plist.contains(LOG));
        assert!(plist.contains("<string>procsocks=info</string>"));
    }
}
