//! macOS：用 pf 做透明的按进程 TCP 重定向（后端的一半）。
//!
//! ## 为什么是 pf
//!
//! macOS 上做「按进程的透明 TCP 代理」只有两条路：
//!
//! 1. Network Extension —— Apple 官方路线，但需要付费开发者账号 + Developer ID
//!    证书 + 携带 `com.apple.developer.networking.networkextension` 的 provisioning
//!    profile，而且只能按 bundle ID 匹配应用（拿不到进程名）。
//! 2. pf —— macOS 自带的内核包过滤器，只要有 root 就能用，不花一分钱，而且能配合
//!    libproc 拿到**可执行文件完整路径**，从而保住 ProcSocks 原有的路径正则规则语义。
//!
//! 本项目走第 2 条。
//!
//! ## 两条规则各自的作用
//!
//! ```text
//! rdr pass on lo0 inet proto tcp from any to ! 127.0.0.0/8 -> 127.0.0.1 port 7891
//! pass out route-to (lo0 127.0.0.1) inet proto tcp from any to ! 127.0.0.0/8 user != 0
//! ```
//!
//! * `rdr` 负责把目的地址改写成我们的监听地址。但它**单独拦不住本机自己发出的
//!   流量**——pf 的 translation 规则在这个场景下不会独立生效。
//! * `pass out route-to` 才是真正把本机进程的包踹到 `lo0` 的那一步。两条合起来，
//!   本机普通用户的出站 TCP 才会被送到监听器。
//! * `user != 0` 是**防死循环的关键**：代理自己以 root 运行，它去连上游 SOCKS5、
//!   或者替不匹配的进程直连原始目的地时，这些出站连接都会被豁免，不会被再抓一次。
//! * `to ! 127.0.0.0/8` 是**第二条安全线**：任何以回环地址为目的地的连接都不改写，
//!   这样代理连本机上游、以及其它应用访问本机服务都不会被卷进来。
//!
//! 这套机制的全部环节都在 `spike/` 下用真实运行验证过，证据存在
//! `docs/spike-result-2026-09-26.txt`。
//!
//! ## 规则段顺序
//!
//! pf 要求规则严格按 `options → normalization → queueing → translation → filtering`
//! 排列。`rdr` 属于 translation，必须排在 filtering 段（Apple 的 anchor 声明和我们的
//! `pass out`）**之前**，否则 pfctl 会直接报
//! `Rules must be in order: options, normalization, queueing, translation, filtering`。
//! 这个坑在 spike 第一轮真实踩到过。
//!
//! ## 死循环与「把自己关在门外」
//!
//! 因为 pf 无法按进程匹配，`redirectPorts: "all"` 意味着**整机所有非 root 的 TCP
//! 连接都会经过本进程**。这带来一个严重后果：如果本进程被 SIGKILL，pf 规则会留在
//! 内核里，而监听器已经没了——所有 TCP 连接会被 RST，**连 SSH 都进不来**。
//!
//! 所以除了 `Drop` 里的正常清理，还会派生一个**死人开关**（见 [`spawn_watchdog`]）：
//! 它是一个独立进程，通过管道读端阻塞等待。父进程无论以何种方式消失（包括
//! SIGKILL），管道都会关闭，子进程立刻醒来把 pf 规则撤干净。

#![cfg(target_os = "macos")]

use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{Context, Result, bail};
use tracing::{debug, info, warn};

use crate::config::{Config, RedirectPorts};

/// 我们临时主规则集的落盘位置。刻意避开 `/tmp`（root 写可预测路径 = 符号链接攻击面）。
pub const RUNTIME_DIR: &str = "/var/run/procsocks";

const PFCTL: &str = "/sbin/pfctl";
/// `pfctl` 的绝对路径，供 `check` 输出用。
pub const PFCTL_PATH: &str = PFCTL;
const SYSCTL: &str = "/usr/sbin/sysctl";
const PF_CONF: &str = "/etc/pf.conf";
const SYSCTL_FORWARDING: &str = "net.inet.ip.forwarding";
const SYSCTL_FORWARDING6: &str = "net.inet6.ip6.forwarding";

/// 代理进程用来在 pf 里豁免自己的用户名。代理必须以 root 运行（既要 pfctl 也要
/// libproc 读别的进程），所以这里就是 `root`。
const PROXY_USER: &str = "root";

// ---------------------------------------------------------------------------
// 规则集生成 —— 全项目唯一的一份
// ---------------------------------------------------------------------------

/// IPv6 那一半的监听地址：同一个端口，绑到 `::1`。
///
/// 配置里只写了 IPv4 的 `listen`，IPv6 侧由端口推出来——两个协议栈必须落在同一个
/// 端口上，否则 pf 的两条 rdr 规则就得配两个目标，徒增出错面。
pub fn ipv6_listen_address(config: &Config) -> Option<std::net::SocketAddr> {
    if !config.redirect_ipv6 || !config.listen.is_ipv4() {
        return None;
    }
    Some(std::net::SocketAddr::new(
        std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        config.listen.port(),
    ))
}

/// 生成完整的主规则集内容。
///
/// macOS 的 `rdr` 规则必须位于被求值的主规则集中，因此复制 Apple 的默认
/// anchor 声明并插入重定向规则，退出时用 `pfctl -f /etc/pf.conf` 还原。
pub fn generate_ruleset(config: &Config) -> String {
    generate_ruleset_with_udp(
        config,
        if config.redirect_udp {
            Some("utun0")
        } else {
            None
        },
    )
}

fn generate_ruleset_with_udp(config: &Config, interface: Option<&str>) -> String {
    let listen = config.listen;
    let port_clause = match config.redirect_ports {
        RedirectPorts::All => String::new(),
        RedirectPorts::List(ref ports) => {
            let list = ports
                .iter()
                .map(|port| port.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            format!(" port {{ {list} }}")
        }
    };

    // IPv6 段是可选的。**默认必须开**——关掉就是静默泄漏：目标域名有 AAAA 记录时
    // 应用会走 IPv6 直连出去，完全绕过代理。
    let ipv6_translation = match ipv6_listen_address(config) {
        Some(address) => format!(
            "# IPv6 同理。少了这一段，应用的 IPv6 连接会绕过代理直连出去。\n\
             rdr pass on lo0 inet6 proto tcp from any to ! ::1{port_clause} -> {ip} port {port}\n",
            ip = address.ip(),
            port = address.port(),
        ),
        None => String::new(),
    };
    let ipv6_filtering = match ipv6_listen_address(config) {
        Some(_) => format!(
            "pass out route-to (lo0 ::1) inet6 proto tcp from any to ! ::1{port_clause} user != {PROXY_USER}\n"
        ),
        None => String::new(),
    };

    let udp_filtering = match interface {
        Some(interface) if config.redirect_udp => {
            let mut rules = format!(
                "# Only this root-owned utun can mark reinjected packets. Preserve direct UDP source ports.\n\
                 pass in quick on {interface} proto udp tag procsocks_udp_reinject no state\n\
                 pass out quick proto udp tagged procsocks_udp_reinject no state\n\
                 pass out quick route-to ({interface} 127.0.0.1) inet proto udp from any to ! <procsocks_udp_excluded4>{port_clause} user != {PROXY_USER} no state\n"
            );
            if config.redirect_ipv6 {
                rules.push_str(&format!("pass out quick route-to ({interface} ::1) inet6 proto udp from any to ! <procsocks_udp_excluded6>{port_clause} user != {PROXY_USER} no state\n"));
            }
            rules
        }
        _ => String::new(),
    };

    format!(
        "\
#
# ProcSocks 临时主规则集 —— 由 procsocks 生成，进程退出时会被还原
# 不要在 /etc/pf.conf 里引用它
#
# IPv4 loopback, multicast and limited broadcast; IPv6 loopback/multicast/link-local.
table <procsocks_udp_excluded4> const {{ 127.0.0.0/8, 224.0.0.0/4, 255.255.255.255 }}
table <procsocks_udp_excluded6> const {{ ::1, ff00::/8, fe80::/10 }}
# ---- normalization ----
scrub-anchor \"com.apple/*\"

# ---- translation ----
nat-anchor \"com.apple/*\"
rdr-anchor \"com.apple/*\"
dummynet-anchor \"com.apple/*\"

# 把目标不是回环地址的 TCP 改写到本地监听器。
# `to ! 127.0.0.0/8` 保证代理连本机上游、以及其它应用访问本机服务不会被卷进来。
# 只改写被 route-to 送入 lo0 的流量。否则 all 会改写真实网卡上
# 返回给 root/上游代理的临时端口，破坏代理自身的连接。
rdr pass on lo0 inet proto tcp from any to ! 127.0.0.0/8{port_clause} -> {listen_ip} port {listen_port}
{ipv6_translation}
# ---- filtering ----
{udp_filtering}anchor \"com.apple/*\"
load anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"

# 本机自己产生的流量要靠 route-to 才会被送到 lo0；user 子句豁免代理自身，防死循环。
pass out route-to (lo0 127.0.0.1) inet proto tcp from any to ! 127.0.0.0/8{port_clause} user != {PROXY_USER}
{ipv6_filtering}",
        listen_ip = listen.ip(),
        listen_port = listen.port(),
    )
}

/// 规则集文件路径。
pub fn ruleset_path() -> PathBuf {
    Path::new(RUNTIME_DIR).join("pf.conf")
}

// ---------------------------------------------------------------------------
// pfctl / sysctl 封装
// ---------------------------------------------------------------------------

fn run(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {program}"))?;
    output_text(program, args, output)
}

fn output_text(program: &str, args: &[&str], output: std::process::Output) -> Result<String> {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        bail!(
            "{program} {} failed ({}): {}",
            args.join(" "),
            output.status,
            stderr.trim()
        );
    }
    // 必须把两者合起来返回：`pfctl -E` 把 "pf enabled" 和 "Token : ..." 写到
    // **stderr**。只返回 stdout 会把 token 丢掉，于是 `-X` 永远不会执行，
    // pf 的 enable 引用就泄漏了。
    let mut combined = stdout;
    if !combined.is_empty() && !combined.ends_with('\n') && !stderr.is_empty() {
        combined.push('\n');
    }
    combined.push_str(&stderr);
    Ok(combined)
}

/// 从 `pfctl -E` 的输出里抠出 enable 引用令牌。
///
/// 注意这段输出走的是 **stderr**：
///
/// ```text
/// No ALTQ support in kernel
/// ALTQ related functions disabled
/// pf enabled
/// Token : 11665184855729364174
/// ```
///
/// 一旦 [`run`] 又变回只返回 stdout，令牌就会静默变成 `None`，`pfctl -X` 再也
/// 不会执行，pf 的 enable 引用就泄漏了。所以单独抽成函数并加了测试。
fn parse_enable_token(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|line| line.split_once("Token").map(|(_, value)| value))
        .map(|value| value.trim().trim_start_matches(':').trim().to_string())
        .filter(|value| !value.is_empty())
}

fn pf_enabled() -> Result<bool> {
    let text = run(PFCTL, &["-s", "info"])?;
    text.lines()
        .find_map(|line| line.strip_prefix("Status:"))
        .map(|value| value.trim().starts_with("Enabled"))
        .context("pfctl did not report the packet filter status")
}

fn forwarding() -> Result<i32> {
    let text = run(SYSCTL, &["-n", SYSCTL_FORWARDING])?;
    text.trim()
        .parse()
        .with_context(|| format!("unexpected {SYSCTL_FORWARDING} value"))
}

pub fn is_root() -> bool {
    // 不引入 libc：读 /dev/console 的属主判断不可靠，直接看有效 uid。
    // SAFETY: geteuid 无参数、无副作用。
    unsafe { geteuid() == 0 }
}

unsafe extern "C" {
    fn geteuid() -> u32;
}

// ---------------------------------------------------------------------------
// 需要还原的状态
// ---------------------------------------------------------------------------

/// 载入规则前记录下来的、退出时必须还原的东西。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PfState {
    /// 我们进来时 pf 是不是已经启用了。若原本是关的，退出时要关回去。
    pub pf_was_enabled: bool,
    /// `net.inet.ip.forwarding` 的原始值。
    pub forwarding_before: i32,
    #[serde(default)]
    pub forwarding6_before: Option<i32>,
    /// `pfctl -E` 返回的引用计数令牌，用 `-X` 释放。
    pub pf_token: Option<String>,
}

/// 尝试还原进入前的状态，报告所有失败；pf enable 令牌只应释放一次。
pub fn restore(state: &PfState) -> Result<()> {
    let mut errors = Vec::new();
    // 1. 把主规则集还原成 Apple 的默认内容。
    if let Err(error) = run(PFCTL, &["-f", PF_CONF]) {
        warn!(%error, "还原 /etc/pf.conf 失败；如需手工兜底请执行 sudo pfctl -d");
        errors.push(error.to_string());
    } else {
        debug!("restored the system ruleset");
    }

    // 2. 释放我们持有的那一份 enable 引用。
    if let Some(token) = &state.pf_token
        && let Err(error) = run(PFCTL, &["-X", token.as_str()])
    {
        errors.push(error.to_string());
    }

    // A manually enabled filter may have had no reference-counted owners.
    // Releasing our last token must not turn that pre-existing filter off.
    if state.pf_was_enabled {
        match pf_enabled() {
            Ok(false) => {
                if let Err(error) = run(PFCTL, &["-e"]) {
                    errors.push(error.to_string());
                }
            }
            Ok(true) => {}
            Err(error) => errors.push(error.to_string()),
        }
    }

    // 3. 如果进来时 pf 是关的，就关回去。
    // A token releases only our reference. Do not disable pf underneath another
    // component that acquired its own reference while ProcSocks was running.
    if !state.pf_was_enabled
        && state.pf_token.is_none()
        && let Err(error) = run(PFCTL, &["-d"])
    {
        errors.push(error.to_string());
    }

    // 4. 还原 ip forwarding。
    let policy = format!("{SYSCTL_FORWARDING}={}", state.forwarding_before);
    if let Err(error) = run(SYSCTL, &["-w", policy.as_str()]) {
        errors.push(error.to_string());
    }

    if let Some(before) = state.forwarding6_before {
        let policy = format!("{SYSCTL_FORWARDING6}={before}");
        if let Err(error) = run(SYSCTL, &["-w", policy.as_str()]) {
            errors.push(error.to_string());
        }
    }

    // 5. 清掉临时规则集文件。
    if errors.is_empty() {
        let _ = fs::remove_file(ruleset_path());
        Ok(())
    } else {
        bail!("pf restoration failed: {}", errors.join("; "))
    }
}

// ---------------------------------------------------------------------------
// 重定向后端
// ---------------------------------------------------------------------------

/// 已启用的 pf 重定向。析构时自动还原。
pub struct PfGuard {
    state: PfState,
    /// 死人开关子进程，持有实例锁、pf enable 令牌并负责统一清理。
    watchdog: Option<std::process::Child>,
    /// 死人开关那条管道的写端。**必须一直持有**：一旦这个句柄被丢弃，管道就关闭，
    /// 子进程会把 EOF 误读成「父进程已死」，然后在我们还在正常服务的时候
    /// 把 pf 规则撤掉。它只能在析构时释放。
    watchdog_pipe: Option<std::process::ChildStdin>,
}

/// 只解析、不加载地验证规则集语法。
///
/// `pfctl -n` 不需要 root，所以 `check` 可以在没有权限的情况下就把语法问题
/// 挡下来——包括最容易踩的那个「translation 段排在 filtering 段之后」。
pub fn validate_ruleset(config: &Config) -> Result<()> {
    // Feed pfctl directly so root never writes a predictable file in /tmp.
    let args = ["-n", "-f", "-"];
    let mut child = Command::new(PFCTL)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to execute pfctl for syntax validation")?;
    let written = child
        .stdin
        .take()
        .context("pfctl stdin is unavailable")?
        // lo0 always exists. The real utun is allocated only during start;
        // dry-run validation must also work on Macs with no other VPN active.
        .write_all(
            generate_ruleset_with_udp(
                config,
                if config.redirect_udp {
                    Some("lo0")
                } else {
                    None
                },
            )
            .as_bytes(),
        );
    let output = child
        .wait_with_output()
        .context("failed to wait for pfctl")?;
    written.context("failed to pass the ruleset to pfctl")?;
    output_text(PFCTL, &args, output)
        .map(|_| ())
        .context("生成的 pf 规则集没有通过语法校验")
}

impl PfGuard {
    /// 载入重定向规则。调用前监听器必须**已经 bind 成功**——否则一旦规则生效
    /// 而没人接客，整机 TCP 会全部失败。
    pub fn start(config: &Config, udp_interface: Option<&str>) -> Result<Self> {
        config.validate_redirector()?;

        if !is_root() {
            bail!("透明重定向需要 root 权限；请用 sudo 运行，或安装为 LaunchDaemon");
        }

        // The watchdog takes the global lock before reading state or enabling
        // pf. Its ready reply includes the token it will release on any exit.
        let (watchdog, watchdog_pipe, state) = spawn_watchdog()
            .context("无法启动死人开关；拒绝在没有崩溃清理保护的情况下启用重定向")?;
        let guard = Self {
            state,
            watchdog: Some(watchdog),
            watchdog_pipe: Some(watchdog_pipe),
        };
        if guard.state.pf_was_enabled {
            // 不是硬错误——我们仍然能还原 /etc/pf.conf。但要提醒使用者，
            // 别的组件（VPN / 安全软件）可能正在用 pf。
            warn!("pf 当前已被启用；本程序会替换主规则集，退出时还原。");
        }
        // 写规则集文件。
        let directory = Path::new(RUNTIME_DIR);
        fs::create_dir_all(directory).with_context(|| format!("failed to create {RUNTIME_DIR}"))?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to lock down {RUNTIME_DIR}"))?;
        let path = ruleset_path();
        fs::write(&path, generate_ruleset_with_udp(config, udp_interface))
            .with_context(|| format!("failed to write {}", path.display()))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to lock down {}", path.display()))?;

        // 打开 ip forwarding：本机自己发出的包要能被 route-to 引到 lo0。
        let forwarding_on = format!("{SYSCTL_FORWARDING}=1");
        run(SYSCTL, &["-w", forwarding_on.as_str()])?;
        if config.redirect_udp && config.redirect_ipv6 {
            run(SYSCTL, &["-w", &format!("{SYSCTL_FORWARDING6}=1")])?;
        }

        // 载入主规则集。
        let ruleset = path.to_string_lossy().into_owned();
        run(PFCTL, &["-f", ruleset.as_str()]).with_context(|| {
            format!(
                "载入 pf 规则失败；规则集内容见 {}（确认 Apple 的 anchor 声明在 filtering 段）",
                path.display()
            )
        })?;

        info!(
            pid = std::process::id(),
            listen = %config.listen,
            ports = %config.redirect_ports,
            "pf 透明重定向已启用"
        );

        Ok(guard)
    }

    /// 只做校验，不载入任何规则。给 `check` 子命令用。
    pub fn probe(config: &Config) -> Result<()> {
        config.validate_redirector()?;
        if !Path::new(PFCTL).is_file() {
            bail!("{PFCTL} 不存在；这台机器上 pf 不可用");
        }
        if !Path::new(PF_CONF).is_file() {
            bail!("{PF_CONF} 不存在；无法在退出时还原系统规则集");
        }
        // 免 root 就能做的：把真正要用的规则集交给 pfctl 做纯语法校验。
        validate_ruleset(config)?;
        // 需要 root 的：读 pf 当前状态。非 root 时跳过而不是报错，
        // 因为 `check` 本来就该能在没有权限的情况下跑。
        if is_root() {
            pf_enabled().context("无法读取 pf 状态；确认在 macOS 上且 pfctl 可用")?;
        }
        Ok(())
    }

    /// 打印当前重定向状态，不做任何修改。
    pub fn status(config: &Config) -> Result<String> {
        let mut out = String::new();
        out.push_str(&format!(
            "platform=macos\npfctl={PFCTL}\nruleset={}\n",
            ruleset_path().display()
        ));

        match pf_enabled() {
            Ok(enabled) => out.push_str(&format!(
                "pf_enabled={}\n",
                if enabled { "yes" } else { "no" }
            )),
            Err(error) => out.push_str(&format!("pf_enabled=unknown ({error})\n")),
        }
        match forwarding() {
            Ok(value) => out.push_str(&format!("ip_forwarding={value}\n")),
            Err(error) => out.push_str(&format!("ip_forwarding=unknown ({error})\n")),
        }

        // 我们自己的规则是否在生效：查 rdr 表里有没有指向我们监听端口的规则。
        let listen_port = config.listen.port().to_string();
        let installed = run(PFCTL, &["-sn"])
            .map(|text| {
                text.lines()
                    .any(|line| line.contains("rdr") && line.contains(&listen_port))
            })
            .unwrap_or(false);
        out.push_str(&format!(
            "redirector_installed={}\n",
            if installed { "yes" } else { "no" }
        ));

        out.push_str(&format!("proxy_user={PROXY_USER}\n"));
        out.push_str(&format!("ports={}\n", config.redirect_ports));
        Ok(out)
    }
}

impl Drop for PfGuard {
    fn drop(&mut self) {
        // EOF requests the same cleanup for graceful shutdown and SIGKILL.
        // The watchdog keeps its global lock until restoration finishes, so a
        // new instance cannot load rules while the old one is removing them.
        self.watchdog_pipe.take();
        if let Some(mut child) = self.watchdog.take() {
            match child.wait() {
                Ok(status) if status.success() => {}
                result => {
                    warn!(
                        ?result,
                        "watchdog cleanup failed; restoring from the parent's snapshot"
                    );
                    if let Err(error) = restore(&self.state) {
                        warn!(%error, "pf cleanup still failed; manual recovery is required");
                        return;
                    }
                }
            }
        }
        info!("pf 重定向已撤销，系统规则集已还原");
    }
}

// ---------------------------------------------------------------------------
// 死人开关
// ---------------------------------------------------------------------------

/// 派生子进程，它阻塞在读管道上；父进程一旦消失（哪怕是 SIGKILL），
/// 管道关闭、读操作立即返回 EOF，子进程就执行还原。
///
/// 返回子进程和管道的写端：**写端必须由调用方一直持有**，见 [`PfGuard`] 的说明。
fn spawn_watchdog() -> Result<(std::process::Child, std::process::ChildStdin, PfState)> {
    let executable = std::env::current_exe().context("failed to locate the current executable")?;
    let mut child = Command::new(executable)
        .arg("pf-watchdog")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        // Keep the watchdog outside the service's process group. Group-directed
        // signals must not remove its chance to restore after the parent exits.
        .process_group(0)
        .spawn()
        .context("failed to spawn the pf watchdog")?;
    let pipe = child
        .stdin
        .take()
        .context("watchdog stdin is unavailable")?;
    let result = (|| -> Result<PfState> {
        let stdout = child
            .stdout
            .take()
            .context("watchdog stdout is unavailable")?;
        let mut ready = String::new();
        BufReader::new(stdout)
            .read_line(&mut ready)
            .context("failed to read watchdog readiness")?;
        serde_json::from_str(&ready).context("watchdog did not report an armed state")
    })();
    match result {
        Ok(state) => {
            debug!(pid = child.id(), "dead-man switch armed");
            Ok((child, pipe, state))
        }
        Err(error) => {
            drop(pipe);
            let _ = child.wait();
            Err(error)
        }
    }
}

/// 死人开关的入口。由 [`spawn_watchdog`] 以隐藏子命令 `pf-watchdog` 拉起。
///
/// 生产模式先锁定实例、记录状态并取得 pf enable 令牌，然后报告就绪。
/// 正常关闭和异常死亡都由管道 EOF 触发同一次清理。
pub fn run_watchdog(state_json: Option<&str>, dry_run: bool) -> Result<()> {
    let (_lock, state) = if let Some(json) = state_json {
        let state =
            serde_json::from_str(json).context("failed to decode the watchdog state payload")?;
        (None, state)
    } else {
        if dry_run {
            bail!("watchdog dry-run requires a state payload");
        }
        if !is_root() {
            bail!("arming the pf watchdog requires root");
        }
        let lock = lock_runtime()?;
        let mut state = PfState {
            pf_was_enabled: pf_enabled()?,
            forwarding_before: forwarding()?,
            forwarding6_before: Some(run(SYSCTL, &["-n", SYSCTL_FORWARDING6])?.trim().parse()?),
            pf_token: None,
        };
        let armed = (|| -> Result<()> {
            let output = run(PFCTL, &["-E"])?;
            state.pf_token =
                Some(parse_enable_token(&output).context("pfctl did not return an enable token")?);
            let mut stdout = std::io::stdout().lock();
            serde_json::to_writer(&mut stdout, &state)?;
            writeln!(stdout)?;
            stdout.flush()?;
            Ok(())
        })();
        if let Err(error) = armed {
            let _ = restore(&state);
            return Err(error);
        }
        (Some(lock), state)
    };
    let mut stdin = std::io::stdin();
    // 父进程活着时这里会一直阻塞；父进程一死就返回 0（EOF）或报错。
    let _ = std::io::copy(&mut stdin, &mut std::io::sink());

    // 只有确实还在 root 下才动手，否则 pfctl 也会失败。
    if is_root() && !dry_run {
        restore(&state)?;
    }
    Ok(())
}

/// flock is released by the kernel even after a crash. The watchdog holds it
/// through restoration, preventing instances on different ports from colliding.
fn lock_runtime() -> Result<File> {
    let directory = Path::new(RUNTIME_DIR);
    fs::create_dir_all(directory).context("failed to create the pf runtime directory")?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(directory.join("instance.lock"))?;
    lock_file(&file).context("another ProcSocks instance is running or still restoring pf")?;
    Ok(file)
}

fn lock_file(file: &File) -> Result<()> {
    unsafe extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }
    // Darwin LOCK_EX | LOCK_NB: take an exclusive lock without blocking.
    if unsafe { flock(file.as_raw_fd(), 2 | 4) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Upstream};

    fn sample(ports: RedirectPorts) -> Config {
        let mut config = Config::example();
        config.redirect_ports = ports;
        config
    }

    #[test]
    fn translation_rules_precede_filtering_rules() {
        let ruleset = generate_ruleset(&sample(RedirectPorts::All));
        let rdr = ruleset.find("rdr pass").expect("rdr rule present");
        // 注意要带上换行：`rdr-anchor "com.apple/*"` 里也含有
        // `anchor "com.apple/*"` 这个子串，直接 find 会命中错误的位置。
        let anchor = ruleset
            .find("\nanchor \"com.apple/*\"")
            .expect("anchor present");
        let pass = ruleset
            .find("pass out route-to")
            .expect("route-to rule present");
        assert!(
            rdr < anchor && anchor < pass,
            "pf 要求 translation 段排在 filtering 段之前，规则集：\n{ruleset}"
        );
    }

    #[test]
    fn all_ports_emit_no_port_clause() {
        let ruleset = generate_ruleset(&sample(RedirectPorts::All));
        assert!(!ruleset.contains("port { 80"));
        assert!(ruleset.contains("-> 127.0.0.1 port 7891"));
    }

    #[test]
    fn explicit_ports_emit_a_brace_list() {
        let ruleset = generate_ruleset(&sample(RedirectPorts::parse("80,443").unwrap()));
        assert!(ruleset.contains("port { 80, 443 } ->"), "{ruleset}");
    }

    #[test]
    fn loopback_is_never_redirected() {
        // 这是防死循环的第二道安全线，必须始终存在。
        // 只统计真正生效的规则行——注释里也会提到这个表达式。
        let ruleset = generate_ruleset(&sample(RedirectPorts::All));
        let rule_lines = ruleset
            .lines()
            .filter(|line| {
                let line = line.trim_start();
                line.starts_with("rdr ") || line.starts_with("pass ")
            })
            .filter(|line| line.contains("to ! 127.0.0.0/8"))
            .count();
        assert_eq!(rule_lines, 2, "{ruleset}");
    }

    #[test]
    fn the_proxy_user_is_exempted() {
        let ruleset = generate_ruleset(&sample(RedirectPorts::All));
        assert!(ruleset.contains("user != root"), "{ruleset}");
    }

    #[test]
    fn all_ports_do_not_rewrite_replies_on_external_interfaces() {
        let ruleset = generate_ruleset(&sample(RedirectPorts::All));
        let translations = ruleset.lines().filter(|line| line.starts_with("rdr pass "));
        for translation in translations {
            assert!(
                translation.contains(" on lo0 "),
                "external-interface replies must retain their destination: {translation}"
            );
        }
    }

    /// IPv6 段默认必须在。少了它，目标域名有 AAAA 记录时应用会走 IPv6 直连，
    /// 完全绕过代理——这是静默泄漏，不是"少支持一个特性"。
    #[test]
    fn ipv6_rules_are_present_by_default() {
        let ruleset = generate_ruleset(&sample(RedirectPorts::All));
        assert!(
            ruleset.contains("rdr pass on lo0 inet6 proto tcp from any to ! ::1 -> ::1 port 7891"),
            "{ruleset}"
        );
        assert!(
            ruleset.contains("pass out route-to (lo0 ::1) inet6 proto tcp"),
            "{ruleset}"
        );
        assert!(ruleset.contains("user != root"), "{ruleset}");
    }

    #[test]
    fn ipv6_rules_can_be_disabled() {
        let mut config = sample(RedirectPorts::All);
        config.redirect_ipv6 = false;
        let ruleset = generate_ruleset(&config);
        assert!(!ruleset.contains("inet6"), "{ruleset}");
        assert!(ipv6_listen_address(&config).is_none());
    }

    #[test]
    fn ipv6_listen_address_reuses_the_configured_port() {
        let config = sample(RedirectPorts::All);
        let address = ipv6_listen_address(&config).expect("ipv6 listener");
        assert_eq!(address.port(), config.listen.port());
        assert_eq!(address.ip().to_string(), "::1");
    }

    /// 加进 inet6 段之后，段顺序约束仍然必须成立。
    #[test]
    fn ipv6_does_not_break_section_ordering() {
        let ruleset = generate_ruleset(&sample(RedirectPorts::All));
        let last_translation = ruleset
            .rfind("rdr pass on lo0 inet6")
            .expect("ipv6 translation rule");
        let first_filtering = ruleset
            .find("\nanchor \"com.apple/*\"")
            .expect("apple anchor");
        assert!(
            last_translation < first_filtering,
            "translation 段必须整体排在 filtering 段之前：\n{ruleset}"
        );
    }

    /// `pfctl -E` 的真实输出格式（取自 spike 里的实测记录）。
    const ENABLE_OUTPUT: &str = "No ALTQ support in kernel\n\
                                 ALTQ related functions disabled\n\
                                 pf enabled\n\
                                 Token : 11665184855729364174\n";

    #[test]
    fn extracts_the_enable_token_from_pfctl_output() {
        assert_eq!(
            parse_enable_token(ENABLE_OUTPUT).as_deref(),
            Some("11665184855729364174")
        );
    }

    /// 这条测试锁住的是一个真实踩过的坑：token 在 stderr 上。
    /// 如果 `run` 哪天又只返回 stdout，这里会立刻失败。
    #[test]
    fn run_captures_stderr_and_stdout_together() {
        let output =
            run("/bin/sh", &["-c", "echo to-stdout; echo to-stderr 1>&2"]).expect("sh should run");
        assert!(output.contains("to-stdout"), "stdout lost: {output:?}");
        assert!(output.contains("to-stderr"), "stderr lost: {output:?}");
    }

    #[test]
    fn missing_token_is_reported_as_none() {
        assert_eq!(parse_enable_token("pf enabled\n"), None);
        assert_eq!(parse_enable_token(""), None);
    }

    #[test]
    fn watchdog_round_trips_state() {
        let state = PfState {
            pf_was_enabled: false,
            forwarding_before: 0,
            forwarding6_before: Some(0),
            pf_token: Some("12345".to_string()),
        };
        let json = serde_json::to_string(&state).unwrap();
        let parsed: PfState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.forwarding_before, 0);
        assert_eq!(parsed.pf_token.as_deref(), Some("12345"));
    }

    #[test]
    fn the_instance_lock_excludes_other_instances_until_its_owner_exits() {
        let path = std::env::temp_dir().join(format!("procsocks-lock-test-{}", std::process::id()));
        let first = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let second = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        lock_file(&first).unwrap();
        assert!(
            lock_file(&second).is_err(),
            "a second instance must not alter pf"
        );
        drop(first);
        // Other tests can fork while this fd is open. Such children temporarily
        // inherit the lock until exec closes the CLOEXEC fd; allow that handoff.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while lock_file(&second).is_err() {
            assert!(
                std::time::Instant::now() < deadline,
                "the released instance lock remained held"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        drop(second);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn validates_the_dual_stack_ruleset_through_pfctl_stdin() {
        validate_ruleset(&Config::example()).unwrap();
    }

    #[test]
    fn example_config_stays_constructible() {
        let config = sample(RedirectPorts::List(vec![80, 443]));
        assert!(config.validate_bridge().is_ok());
        let _ = Upstream {
            host: "127.0.0.1".into(),
            port: 7890,
            username: None,
            password: None,
        };
    }
}
