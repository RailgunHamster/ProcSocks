//! macOS：把 procsocks 装成一个开机自启的 LaunchDaemon。
//!
//! 对应 Windows 那边的 [`crate::service`]。用 launchd 而不是自己守护进程有几个
//! 直接好处：
//!
//! * `KeepAlive` 让进程被 SIGKILL 之后一秒内自动重启；
//! * 标准输出/错误直接落到日志文件，不需要额外引 `tracing-appender`；
//! * 系统重启后自动恢复，符合「无人值守」的原始使用场景。
//!
//! 它和 [`crate::pf`] 里的死人开关是互补的：死人开关负责**立刻撤掉 pf 规则**，
//! launchd 负责**尽快把服务拉起来**。两者缺一不可——只靠 KeepAlive 的话，在
//! 重启之前的那段时间整机 TCP 是断的；只靠死人开关的话，服务不会自己恢复。

#![cfg(target_os = "macos")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use anyhow::{Context, Result, bail};

use crate::pf;

/// launchd 的 job 标签。
pub const LABEL: &str = "com.procsocks.agent";

const PLIST_PATH: &str = "/Library/LaunchDaemons/com.procsocks.agent.plist";
const LOG_PATH: &str = "/var/log/procsocks.log";
const LAUNCHCTL: &str = "/bin/launchctl";

/// 生成 plist 内容。抽出来是为了能在测试里断言关键字段。
pub fn render_plist(executable: &Path, config: &Path) -> String {
    render_plist_for(executable, config, LABEL, LOG_PATH)
}

pub(crate) fn render_plist_for(executable: &Path, config: &Path, label: &str, log: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{executable}</string>
        <string>--config</string>
        <string>{config}</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <!-- 默认节流是 10 秒；这里压到 1 秒，缩短崩溃后整机 TCP 不通的窗口 -->
    <key>ThrottleInterval</key>
    <integer>1</integer>
    <key>EnvironmentVariables</key>
    <dict><key>RUST_LOG</key><string>procsocks=info</string></dict>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
</dict>
</plist>
"#,
        executable = escape_xml(&executable.to_string_lossy()),
        config = escape_xml(&config.to_string_lossy()),
        label = escape_xml(label),
        log = escape_xml(log),
    )
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub fn install(config_path: &Path) -> Result<()> {
    if !pf::is_root() {
        bail!("安装 LaunchDaemon 需要 root 权限；请用 sudo 运行");
    }
    let config_path = config_path
        .canonicalize()
        .with_context(|| format!("failed to resolve config {}", config_path.display()))?;
    let executable = std::env::current_exe()
        .context("failed to locate the current executable")?
        .canonicalize()
        .context("failed to resolve the current executable")?;

    // 先确认配置本身能过校验，免得装上一个开机就崩的服务。
    let config = crate::config::Config::load(&config_path)?;
    pf::PfGuard::probe(&config)?;

    let plist = render_plist(&executable, &config_path);
    fs::write(PLIST_PATH, plist)
        .with_context(|| format!("failed to write {PLIST_PATH}; are you root?"))?;
    // LaunchDaemon 的 plist 必须 root:wheel 且不可被其他用户改写。
    fs::set_permissions(PLIST_PATH, fs::Permissions::from_mode(0o644))
        .with_context(|| format!("failed to set permissions on {PLIST_PATH}"))?;

    println!("wrote {PLIST_PATH}");
    println!("log: {LOG_PATH}");
    Ok(())
}

pub fn start() -> Result<()> {
    require_root()?;
    if !Path::new(PLIST_PATH).is_file() {
        bail!("LaunchDaemon 未安装；请先运行 service install");
    }
    start_with(&mut execute_launchctl)
}

pub fn stop() -> Result<()> {
    require_root()?;
    stop_with(&mut execute_launchctl)
}

fn require_root() -> Result<()> {
    if !pf::is_root() {
        bail!("控制 LaunchDaemon 需要 root 权限；请用 sudo 运行");
    }
    Ok(())
}

fn start_with(execute: &mut impl FnMut(&[&str]) -> Result<Output>) -> Result<()> {
    let target = format!("system/{LABEL}");
    if is_loaded(execute)? {
        // No -k: repeating start must not kill a healthy proxy or race its watchdog.
        check_output(&["kickstart", &target], execute(&["kickstart", &target])?)?;
    } else {
        check_output(&["enable", &target], execute(&["enable", &target])?)?;
        let args = ["bootstrap", "system", PLIST_PATH];
        check_output(&args, execute(&args)?)?;
    }
    Ok(())
}

fn stop_with(execute: &mut impl FnMut(&[&str]) -> Result<Output>) -> Result<()> {
    if is_loaded(execute)? {
        // Sending SIGTERM alone triggers KeepAlive. Remove the job definition
        // for this boot so it stays stopped; retain the plist for the next start.
        let target = format!("system/{LABEL}");
        let args = ["bootout", &target];
        check_output(&args, execute(&args)?)?;
    }
    Ok(())
}

fn is_loaded(execute: &mut impl FnMut(&[&str]) -> Result<Output>) -> Result<bool> {
    let target = format!("system/{LABEL}");
    let args = ["print", &target];
    let output = execute(&args)?;
    if output.status.code() == Some(113) {
        // launchctl error 113: "Could not find specified service".
        return Ok(false);
    }
    check_output(&args, output).map(|_| true)
}

pub fn status() -> Result<String> {
    let target = format!("system/{LABEL}");
    let args = ["print", &target];
    let output = execute_launchctl(&args)?;
    let installed = if Path::new(PLIST_PATH).is_file() {
        "yes"
    } else {
        "no"
    };
    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        // launchctl print 的输出很长，只挑几行有用的。
        let mut summary = String::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("state =")
                || trimmed.starts_with("pid =")
                || trimmed.starts_with("last exit code =")
                || trimmed.starts_with("program =")
            {
                summary.push_str(trimmed);
                summary.push('\n');
            }
        }
        if summary.is_empty() {
            summary.push_str("loaded (no state reported)\n");
        }
        Ok(format!(
            "launchd_label={LABEL}\nplist={PLIST_PATH}\ninstalled={installed}\nloaded=yes\n{summary}"
        ))
    } else if output.status.code() == Some(113) {
        Ok(format!(
            "launchd_label={LABEL}\nplist={PLIST_PATH}\ninstalled={installed}\nloaded=no\nstate = stopped\n"
        ))
    } else {
        check_output(&args, output)
    }
}

pub fn uninstall() -> Result<()> {
    if !pf::is_root() {
        bail!("卸载 LaunchDaemon 需要 root 权限；请用 sudo 运行");
    }
    // Never remove the plist if a loaded service could not be stopped.
    stop()?;
    let plist = PathBuf::from(PLIST_PATH);
    if plist.is_file() {
        fs::remove_file(&plist).with_context(|| format!("failed to remove {PLIST_PATH}"))?;
    }
    Ok(())
}

fn execute_launchctl(args: &[&str]) -> Result<Output> {
    Command::new(LAUNCHCTL)
        .args(args)
        .output()
        .context("failed to execute launchctl")
}

fn check_output(args: &[&str], output: Output) -> Result<String> {
    if !output.status.success() {
        bail!(
            "launchctl {} failed ({}): {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_pins_the_executable_config_and_keepalive() {
        let plist = render_plist(
            Path::new("/usr/local/bin/procsocks"),
            Path::new("/etc/procsocks.json"),
        );
        assert!(plist.contains("<string>/usr/local/bin/procsocks</string>"));
        assert!(plist.contains("<string>/etc/procsocks.json</string>"));
        assert!(plist.contains("<key>KeepAlive</key>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<integer>1</integer>"), "throttle interval");
        assert!(plist.contains(LOG_PATH));
        // 参数顺序必须是 exe --config <path> run
        let exe = plist.find("procsocks</string>").unwrap();
        let flag = plist.find("<string>--config</string>").unwrap();
        let run = plist.find("<string>run</string>").unwrap();
        assert!(exe < flag && flag < run);
    }

    #[test]
    fn label_matches_the_plist_filename() {
        assert!(PLIST_PATH.ends_with(&format!("{LABEL}.plist")));
    }

    #[test]
    fn plist_escapes_paths_as_valid_xml() {
        use std::{io::Write, process::Stdio};

        let plist = render_plist(
            Path::new("/Applications/Tools & <Proxy>/procsocks"),
            Path::new("/etc/config \"home\" & 'work'.json"),
        );
        let mut child = Command::new("/usr/bin/plutil")
            .args(["-lint", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(plist.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}\n{plist}");
        assert!(plist.contains("Tools &amp; &lt;Proxy&gt;"));
        assert!(plist.contains("&quot;home&quot; &amp; &apos;work&apos;"));
    }

    fn fake_output(code: i32) -> Output {
        use std::os::unix::process::ExitStatusExt;

        Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: Vec::new(),
            stderr: b"fake launchctl error".to_vec(),
        }
    }

    #[test]
    fn service_can_start_stop_and_start_again_without_forced_restarts() {
        let mut loaded = false;
        let mut calls = Vec::new();
        let mut execute = |args: &[&str]| -> Result<Output> {
            calls.push(args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>());
            assert!(
                !args.contains(&"-k"),
                "start must not kill a running service"
            );
            let code = match args[0] {
                "print" => {
                    if loaded {
                        0
                    } else {
                        113
                    }
                }
                "bootstrap" => {
                    assert!(!loaded, "cannot bootstrap a loaded service");
                    assert_eq!(&args[1..], &["system", PLIST_PATH]);
                    loaded = true;
                    0
                }
                "kickstart" => {
                    assert!(loaded, "kickstart cannot load an unregistered service");
                    0
                }
                "bootout" => {
                    assert!(loaded);
                    loaded = false;
                    0
                }
                "enable" => 0,
                other => panic!("unexpected launchctl command {other}"),
            };
            Ok(fake_output(code))
        };
        start_with(&mut execute).unwrap();
        start_with(&mut execute).unwrap();
        stop_with(&mut execute).unwrap();
        stop_with(&mut execute).unwrap();
        start_with(&mut execute).unwrap();
        assert!(loaded);
        assert_eq!(
            calls.iter().filter(|args| args[0] == "bootstrap").count(),
            2
        );
        assert_eq!(calls.iter().filter(|args| args[0] == "bootout").count(), 1);
    }

    #[test]
    fn launchctl_errors_are_not_treated_as_an_unloaded_service() {
        for start in [true, false] {
            let mut calls = 0;
            let mut execute = |_: &[&str]| {
                calls += 1;
                Ok(fake_output(1))
            };
            let error = if start {
                start_with(&mut execute)
            } else {
                stop_with(&mut execute)
            }
            .unwrap_err();
            assert!(error.to_string().contains("launchctl print "));
            assert!(error.to_string().contains("fake launchctl error"));
            assert_eq!(calls, 1, "failed status must prevent mutations");
        }
    }
}
