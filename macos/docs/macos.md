# ProcSocks on macOS

macOS 后端与 Windows 后端解决的是同一个问题——**让指定进程的 TCP / UDP 走 SOCKS5，
不开启系统全局代理、不安装默认路由**——但底层的实现机制完全不同。这份文档说明
为什么、怎么工作、怎么部署，以及有哪些必须知道的限制。

---

## 1. 为什么不用 Network Extension

macOS 上做透明的按进程代理，Apple 官方只认一条路：Network Extension
（`NEAppProxyProvider` / `NETransparentProxyProvider`）。这条路有两个硬门槛：

1. **要钱，而且绕不过去。** Network Extension 的 entitlement 必须由 Apple 签发
   的 provisioning profile 承载，而 provisioning profile 只能由付费的 Apple
   Developer Program 账号生成。免费 Apple ID 连 Certificates / Identifiers
   面板都没有。系统扩展本身的安装权限（`com.apple.developer.system-extension.install`）
   同样是受限 entitlement。
2. **只能按 bundle ID 匹配，拿不到进程名。** 这是 Apple API 的限制，不是实现问题。
   ProxyBridge 的 macOS 文档里专门列了这一条。也就是说 Network Extension 路线
   下，ProcSocks 引以为特色的「对可执行文件完整路径做正则搜索」会被直接砍掉。

而 macOS 上还有一扇没关的门：**pf**（从 OpenBSD 移植过来的内核包过滤器）。
它只要有 root 就能用，不花一分钱，而且配合 `libproc` 能拿到进程的**完整可执行
路径**，从而完整保留 ProcSocks 原有的规则语义。

本项目走第二条路。

---

## 2. 机制

```text
应用 connect(104.20.23.154, 443)      ← 应用完全无感知：不改环境变量、不设系统代理
   │
   ▼  pf（内核）
   ├─ rdr pass on lo0 inet proto tcp from any to ! 127.0.0.0/8 ... -> 127.0.0.1 port 7891
   └─ pass out route-to (lo0 127.0.0.1) ... user != root
   │
   ▼
procsocks（root）accept()  →  对端 = 192.168.72.242:61081
   │                            ↑ 源 IP 和源端口都被 pf 保留了
   ├─ libproc 扫 socket 表 → pid=90133, path=/usr/bin/curl,
   │                          foreign=104.20.23.154:443   ← 原始目的地
   ├─ 用 path 跑 processPatterns / bypassPatterns
   │
   ├─ 命中 → 嗅探 TLS SNI / HTTP Host → SOCKS5 连上游
   └─ 未命中 → root 直连原始目的地，纯字节转发（pf 豁免，不回环）
   │
   ▼
上游 SOCKS5（127.0.0.1:7890）
```

### 2.1 为什么是两条 pf 规则而不是一条

`rdr` 负责改写目的地址，但**单独拦不住本机自己发出的流量**——本机进程产生的包
需要 `pass out route-to` 把它引到 `lo0`，两条规则合起来才成立。这一点在
`spike/` 下反复验证过。

`rdr` 必须限制为 `on lo0`，只处理上述送入回环接口的流量。否则重定向
所有端口时，真实网卡收到的回复也会被改写，破坏 root 和上游代理的连接。

### 2.2 `user != root`：防死循环的关键

代理自己要去连上游 SOCKS5、要替不匹配的进程直连原始目的地。如果这些出站连接
被 pf 再抓一次，就会形成死循环。pf 的 `user` 判据按**socket 属主**匹配，而代理以
root 运行，所以 `user != root` 天然把代理自己排除在外。

### 2.3 `to ! 127.0.0.0/8`：第二道安全线

任何以回环地址为目的地的连接都不改写。这保证了：

* 代理连本机上游（默认 `127.0.0.1:7890`）不会被卷进来；
* 应用访问本机服务（开发服务器、数据库、`127.0.0.1` 上的 API）照常工作。

用户态还有第三道闸：`pf_bridge` 会检查 libproc 还原出的目的地，如果是回环地址
就**拒绝转发并告警**。正常情况下永远不该触发；一旦触发说明 pf 规则被改坏了，
此时继续转发会让代理连上自己并形成连接风暴。

### 2.4 连接归属：libproc

`src/libproc.rs` 直接对 `libproc` 做 FFI，扫描全系统 socket 表，按**本地地址和端口**
找到发起连接的进程，一次性拿到：

| 字段 | 用途 |
|---|---|
| `pid` | 日志、诊断 |
| 可执行文件完整路径 | `processPatterns` / `bypassPatterns` 正则匹配 |
| `foreign` 地址 | **原始目的地**。socket 的 foreign 地址不会被 rdr 改写 |
| TCP 状态 | 诊断 |

`foreign` 这一条让整条路线里最脆的一环——解析 `pfctl -s state` 的文本输出——
被彻底删掉了。一次系统调用扫描同时给出「谁发的」和「发给谁」，原子且一致。

`struct socket_info` 的内存布局是手写的，用 `offsetof` / `sizeof` 从 macOS SDK
实测得到，并在 `src/libproc.rs` 末尾用 **编译期断言**锁定。Apple 哪天改了布局，
构建会直接失败，而不是运行时静默读错内存。

---

## 3. 与 Windows 后端的差异

两个平台共用同一套配置、规则语义、SNI/Host 嗅探和 SOCKS5 客户端。只有重定向
后端是各自实现的：

| | Windows | macOS |
|---|---|---|
| 重定向机制 | NetFilter SDK 内核驱动 | pf `rdr` + `route-to` |
| 连接前导 | 驱动**以 SOCKS5 客户端身份**接入，目标在请求里给出 | 裸 TCP，无前导 |
| 目标识别 | 驱动提供 | `libproc` 扫 socket 表 |
| 进程匹配 | 驱动内部正则 | Rust 侧 `regex` |
| 驱动/组件 | `Redirector.bin` + `nfapi.dll` + `nfdriver.sys`（用户自备，专有许可） | 无，系统自带 pf |
| 常驻方式 | Windows 服务 | LaunchDaemon |
| 权限 | 管理员 | root |

代码里的分界在 `src/main.rs` 的模块声明：`native` / `redirector` / `service` 是
Windows 专属，`pf` / `pf_bridge` / `libproc` / `launchd` / `rules` 是 macOS 专属，
`bridge` / `config` / `sniff` 共用。`cargo check --target x86_64-pc-windows-msvc`
可以在 macOS 上验证 Windows 那半边没被改坏。

---

## 4. 配置

macOS 不需要 `redirectorDir` 和 `driverName`（`procsocks example` 在 macOS 上
会自动去掉这两个字段）。

```json
{
  "listen": "127.0.0.1:7891",
  "upstream": {
    "host": "127.0.0.1",
    "port": 7890,
    "username": null,
    "password": null
  },
  "processPatterns": [
    "/Applications/ChatGPT.app",
    "codex"
  ],
  "bypassPatterns": [
    "procsocks",
    "/usr/bin/ssh",
    "/usr/sbin/sshd"
  ],
  "redirectPorts": "all",
  "redirectIpv6": true,
  "redirectUdp": true,
  "sniffTimeoutMs": 2000,
  "connectTimeoutMs": 15000,
  "maxSniffBytes": 65536,
  "requireHostname": true
}
```

与 Windows 共通的字段含义见主 [README](../README.md)。macOS 特有的字段：

| 字段 | 作用 | 默认 |
|---|---|---|
| `redirectPorts` | 哪些**目标端口**进入透明重定向：`"all"` 或 `"443,80"` 这样的列表 | `"all"` |
| `redirectUdp` | 通过 SOCKS5 UDP ASSOCIATE 代理匹配进程的 UDP；上游须支持 UDP | `true` |
| `redirectIpv6` | 生成 IPv6 重定向规则，并在 `[::1]:同一端口` 监听；关闭后 IPv6 TCP / UDP 会直连，`check` / `run` 会提醒 | `true` |

透明模式的 `listen` 必须是 IPv4 回环地址；IPv6 监听由 `redirectIpv6` 自动补充。
两个监听都绑定成功后才载入 pf，任一端口被占用都会中止启动并释放已绑定的端口。
单独运行 `bridge` 时可以将 `listen` 配置为 `[::1]:7891`。

---

## 5. 部署

### 5.1 先验证，再拦截

```bash
cd procsocks
cargo build --release

# 创建配置，再按需要修改上游与进程规则
./target/release/procsocks example > procsocks.json

# 1) 只跑 SOCKS 桥接，验证「域名还原 + 上游 SOCKS5」（不碰 pf，不需要 root）
./target/release/procsocks --config procsocks.json bridge
#    另开一个终端：
python3 scripts/verify-bridge.py
python3 scripts/verify-bridge.py --tls

# 2) 校验配置和 pf 规则集语法（不需要 root）
./target/release/procsocks --config procsocks.json check

# 2b) 打印将要载入内核的规则集，肉眼过一遍
./target/release/procsocks --config procsocks.json driver ruleset

# 3) 完整端到端验证（需要 root）
sudo bash scripts/verify-macos.sh

# 4) 前台运行，Ctrl+C 停止
sudo ./target/release/procsocks --config procsocks.json run
```

第 3 步是关键：它会用真实流量验证代理路径、root 豁免、回环不拦截、直连回退、
正常退出还原，以及 **SIGKILL 之后死人开关能否撤掉规则并释放 pf enable 引用**。
脚本默认读取 `procsocks.local.json`，使用其中的上游连接参数生成一份临时验收配置，
只匹配 `/usr/bin/curl` 并覆盖探针端口，原配置保持不变。报告与日志保存于权限为
`0700` 的独立临时目录；任何 FAIL 都会使脚本返回非零退出码。
验收会固定 `RUST_LOG=procsocks=info`，避免外部日志设置关闭就绪与归属记录；
决策统计按每个探针的实际 PID 匹配，不会把其他应用的后台连接算作通过。

`redirectIpv6` 开启时，IPv6 探针也必须通过。默认使用 `https://api64.ipify.org`，
可以通过 `IPV6_PROBE_URL` 替换为适合当前网络的 IPv6 目标。如果直连探针在当前
网络不可达，也可替换 `DIRECT_PROBE_URL`。例如：

```bash
sudo env DIRECT_PROBE_URL=http://www.baidu.com/ bash scripts/verify-macos.sh
```

### 5.2 装成开机自启

```bash
sudo ./target/release/procsocks --config /etc/procsocks.json service install
sudo ./target/release/procsocks service start
sudo ./target/release/procsocks service status
sudo ./target/release/procsocks service stop
sudo ./target/release/procsocks service uninstall
```

它会写入 `/Library/LaunchDaemons/com.procsocks.agent.plist`，`KeepAlive` 打开、
`ThrottleInterval` 压到 1 秒，日志落在 `/var/log/procsocks.log`。

`install` 校验配置与 pf 规则语法并写入 plist；`start` 首次加载服务，重复执行不会强制重启
正在运行的进程。`stop` 从当前 launchd domain 卸载服务，避免 KeepAlive 将其立即
拉起，保留 plist 以便再次 `start`，下次开机仍会自动启动。`status` 分别报告
`installed`（plist 是否存在）和 `loaded`（服务是否已加载）；卸载命令只在成功
停止服务后删除 plist。Ctrl+C 和 SIGTERM 都会触发正常的 pf 清理。

服务模式读配置只在启动时，改完配置要 `service stop` → `check` → `service start`。

---

## 6. 安全边界与风险

### 6.1 `redirectPorts: "all"` 的真实含义

因为 pf **无法按进程匹配**，`all` 意味着**整机所有非 root 用户的 TCP 连接**
都会先经过 procsocks，再由它按可执行路径决定代理还是直连。这不是实现偷懒，
是按进程过滤在这个机制下必须由用户态来做的必然结果。

后果有三条，都必须在部署前想清楚：

1. **多一跳延迟。** 每条 TCP 连接都要经过一次 accept + libproc 扫描。
2. **爆炸半径大。** 本进程挂了而 pf 规则还在，整机 TCP 全断。
3. **SSH 风险。** 如果连 22 端口也在重定向范围内，一旦规则残留，**远程 SSH
   也进不来**。无人值守的机器上建议明确把 22 排除。

`procsocks check` 和 `run` 在 `redirectPorts` 覆盖 22 或为 `all` 时会主动打印
警告。

### 6.2 死人开关

针对 6.1 第 2 条，`pf.rs` 里实现了一个**死人开关**：启动 pf 规则之前先派生一个
独立进程组中的子进程。它先取得实例锁、记录原始状态并持有 pf enable 令牌，
向父进程报告就绪后阻塞在读管道上。正常停止或父进程异常消失——包括 `SIGKILL`——
都会关闭管道，子进程执行同一次还原（恢复 `/etc/pf.conf`、还原 `ip.forwarding`、
释放自己的 pf enable 引用）。父进程正常停止时会等它完成。
主进程会处理 SIGTERM 与 SIGINT，并在注册处理器后解除启动器继承的信号屏蔽，
确保管理员认证工具或服务管理器启动的实例也能正常停止。

实例锁一直保持到清理结束，使用不同监听端口的第二个实例也会被拒绝，避免两套
主规则集互相覆盖。死人开关无法启动时会拒绝启用重定向；清理失败会报告错误。
只释放自己的 pf 引用，不会强制关闭其他组件新取得的 pf 引用；原先手动启用的
pf 会保持启用。

它和 launchd 的 `KeepAlive` 是互补的：死人开关负责**立刻撤规则**，KeepAlive 负责
**尽快把服务拉起来**。只有前者，服务不会自愈；只有后者，重启前的那段时间整机
TCP 是断的。

手工兜底永远可用：

```bash
sudo pfctl -d && sudo pfctl -f /etc/pf.conf
sudo sysctl -w net.inet.ip.forwarding=0
```

### 6.3 规则集什么时候被改动

`run` 会往内核载入一份**完整的主规则集**（内容 = Apple 默认的 `/etc/pf.conf`
加上我们的规则）。`/etc/pf.conf` **文件本身不会被修改**，进程退出时用
`pfctl -f /etc/pf.conf` 原样还原。

如果进入时 pf 已经是启用状态（可能有别的 VPN 或安全软件在用），会打印一条
警告——我们会临时替换主规则集，退出时还原。

---

## 7. 已知限制

| 限制 | 说明 | 可能的后续 |
|---|---|---|
| **IPv6 依赖部署网络** | 默认生成 `inet6` 段并增加 `::1` 监听；已通过 macOS 26.6.2 的真实 pf IPv6 拦截、进程归属与上游转发验收。目标机器仍需有可用的 IPv6 路由。 | 部署时用可达的 IPv6 目标运行端到端探针 |
| **UDP / QUIC 依赖上游** | 默认开启 SOCKS5 UDP ASSOCIATE；UDP 保留原始目标 IP，不恢复 QUIC 域名。 | 上游须支持 UDP；IPv6 UDP 另需上游 IPv6 能力 |
| **root 进程不被代理** | `user != root` 是防死循环的机制，代价是 root 跑的应用会被豁免。macOS 上用户级应用极少以 root 运行，影响很小。 | 改用专用代理用户 + 端口段豁免 |
| **每条连接一次 socket 表扫描** | `proc_listpids` + 逐进程 `PROC_PIDLISTFDS` 的完整扫描。 | 命中率缓存、按 uid 预筛 |
| **无法按用户/网络排除** | TCP 排除回环；UDP 另排除多播、广播及 IPv6 链路本地地址。本网段（NAS、打印机）目前仍在重定向范围内。 | 增加 `excludeNets` / `excludePorts` |

---

## 8. 排错

```bash
# 连接级诊断
RUST_LOG=procsocks=debug sudo ./target/release/procsocks --config procsocks.json run
```

日志里每条被接管的连接都会有一行 `attributed connection`，带上 pid、可执行路径、
原始目的地、命中规则和 `decision = proxy|direct`。先看这一行。

| 现象 | 可能原因 |
|---|---|
| 完全没有 `attributed connection` | pf 规则没生效。`sudo pfctl -sn \| grep rdr` 看规则在不在；确认 `/var/run/procsocks/pf.conf` 存在 |
| 有连接但 `could not attribute port ...` | libproc 没查到发起进程。通常是连接已关闭，或非 root 运行 |
| `decision = direct` 但期望走代理 | `processPatterns` 没匹配上。看日志里的 `executable=` 实际路径，注意匹配是**大小写敏感**的（需要忽略就写 `(?i)`） |
| `refusing to relay ... loopback` | pf 规则被改坏了，见 2.3 |
| `could not recover a hostname` | 严格模式下目标不是 TLS/HTTP 且拿不到 SNI/Host。要么关掉 `requireHostname`，要么把该进程加进 `bypassPatterns` |
| 整机网络不通 | 立刻 `sudo pfctl -d && sudo pfctl -f /etc/pf.conf` |

---

## 9. 验证证据

无需 root 或外网的回归验证：

```bash
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings

# 安装了对应 Rust target 时，可检查 Windows 后端的编译兼容性
cargo check --all-targets --locked --target x86_64-pc-windows-msvc
```

这些测试覆盖 HTTP 分段时等待完整 Host / CONNECT 行、TLS 跨记录 SNI、
模拟上游的 SOCKS5 认证与完整双向字节转发、上下游握手超时、双栈监听失败回滚、
IPv6 连接归属、launchd 启停逻辑、真实进程的 SIGTERM/SIGINT 正常退出与继承
信号屏蔽时的退出，以及死人开关的管道触发条件。它们不替代第 5.1 节的 root pf 实测。
死人开关的集成测试显式使用 `--dry-run`，即使以 root 执行测试，也不会改动 pf。

2026-09-30 在 macOS 26.6.2 / arm64 上完成了 66 项自动测试与 7 项真实 pf
端到端验收，全部通过；SIGTERM 和 SIGKILL 后均恢复了原先的 pf 启用状态、
enable 引用与 IPv4 forwarding 值。记录见
[`macos-acceptance-2026-09-30.txt`](macos-acceptance-2026-09-30.txt)。

`spike/` 目录下的三个文件是这条路线可行性的原始证据——在写任何生产代码之前，
先用最小代价证明了机制成立：

| 文件 | 作用 |
|---|---|
| `spike/run-spike.sh` | 载入临时 pf 规则、起最小监听器、跑 6 项测试、出报告、自动还原 |
| `spike/listener.py` | 最小透明监听器（含 libproc 交叉验证） |
| `spike/pidforport.c` | libproc 原语的 C 版本，用来反向验证 Rust 的结构体布局 |

实测结论（macOS 26.6.2 / arm64）：

```text
[PASS] Q1 能否拦本机普通用户流量      拦到了 1 条连接
[PASS] Q2 能否还原原始目的地          还原出原始目的地 -> 104.20.23.154:80
[PASS] Q3 代理自身能否不回环          root 的 0 条连接被正确豁免，且访问成功
[PASS] Q4 端到端透传                  普通用户无感知拿到 200，559 字节
[PASS] Q5 能否定位发起进程            [libproc] pid=90133  /usr/bin/curl
[PASS] Q5b libproc 能否替代 pfctl     foreign 就是原始目的地，pfctl 文本解析可以删掉
```

UDP 通过 PF `route-to` 进入专用 `utun`，没有 `rdr` 地址改写，因此同一 socket 的
多个目标不会串流。`libproc` 匹配 UDP socket 的本地地址、端口、连接目标与 socket
代数；无法确定唯一进程时丢弃，不猜测。回包重新构造原始来源端点与校验和。
本项目不安装默认路由，不修改系统 DNS；UDP 接口随后台退出销毁，PF 规则由同一
watchdog 清理。`redirectPorts` 同时约束 TCP / UDP，`redirectUdp` 默认 `true`。
系统共享 DNS 解析不自动跟随调用应用；应用自有 UDP DNS 受进程规则控制。
详细验收见 [UDP 验证](udp.md)。
