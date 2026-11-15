# 全平台统一架构与 FlClash 集成设计

本文档记录对当前 `ProcSocks` 仓库代码结构的梳理结论，以及后续「全平台统一写法」与「并入 `FlClash` 作为按进程接管模式」的整体架构蓝图。

---

## 1. 现状盘点：为什么当前仓库分成了两套工程

翻查仓库历史与 `macos/docs/macos.md` 第 3 节可以看到，项目在设计 macOS 版之初就已经确立了**单 Crate 条件编译统一架构**：

- `macos/src/main.rs` 与 `macos/Cargo.toml` 实际上同时包含了 `#[cfg(windows)]`（`native`、`redirector`、`service`）与 `#[cfg(target_os = "macos")]`（`pf`、`pf_bridge`、`udp_tun`、`libproc`、`launchd`、`gui`、`rules`）两套后端，并可在 macOS 上直接对 `x86_64-pc-windows-msvc` 做交叉编译检查。
- 但在提交 `4293cf2` 将 macOS 分支合回主仓时，为了保证原 Windows 的 17 个源码文件逐字节不变，采取了保守的目录物理隔离：将旧根工程移入 `windows/`，把原本已经合并好的工程放入 `macos/`。
- 这一临时拆分导致提交 `1c3fabe` 引入 UDP 支持时，只能额外建立 `shared/udp.rs` 并通过 `#[path = "../../shared/udp.rs"]` 同时挂载到两个工程，配置字段（如 `redirectUdp`）与桥接逻辑不得不在 `windows/src/` 和 `macos/src/` 双线同步修改。

因此，推进后续演进的第一步应当是**消除目录分叉，恢复根目录单一跨平台 Cargo 工程**。

---

## 2. 定位边界：为什么不能直接用 `mihomo` 的全局 TUN 规则代替 ProcSocks

`mihomo`（Clash.Meta）自身具备跨平台的 `TUN` 网卡与 `PROCESS-PATH` / `PROCESS-PATH-REGEX` 分流规则，在写法上看似已经全平台统一，但两者的系统影响面完全不同：

| 维度 | 全局 TUN + `PROCESS-PATH`（mihomo 原生） | 按进程透明重定向（ProcSocks） |
| --- | --- | --- |
| 默认路由 | 安装 `0.0.0.0/1` + `128.0.0.0/1` 全局路由 | **不改路由表**，不创建默认路由 |
| 系统 DNS | 通常伴随网卡 DNS 改写与 `any:53` 全局劫持 | **不改系统 DNS**，仅被选进程自发 UDP DNS 走代理 |
| 未选中进程 | 整机所有流量先进入 TUN 用户态协议栈再 `DIRECT` 放行 | Windows / Linux 内核态直接放行；macOS 仅对范围内端口做直连回退 |
| 与其他 VPN 共存 | 极易与 Tailscale（Wintun / MagicDNS `100.100.100.100`）、企业 VPN 争抢路由与 DNS | **天然无感共存**，Tailscale / SSH / 远程桌面完全走原系统路径 |

结论：**ProcSocks 的核心价值在于「零默认路由侵入、零系统 DNS 改动」的按进程接管**。它与 `FlClash` 的定位完全互补：`FlClash` 负责订阅管理、协议出站与规则分流；`ProcSocks` 作为系统代理与全局 TUN 之外的**第三种桌面网络接管后端**。

---

## 3. 全平台统一架构：分三层收敛

操作系统内核不存在跨平台的透明按进程 Socket 拦截标准 API，因此「全平台统一」不应强求内核机制一致，而应按以下三层划分职责：

```text
┌──────────────────────────────────────────────────────────────────────┐
│ 第 2 层：统一控制面与跨平台 GUI（独立 CLI / FlClash Flutter + Helper） │
│  · 应用/进程列表勾选、高级正则、驱动向导、实时按进程上下行流量图表     │
│  · 特权生命周期托管（FlClashHelperService / 系统服务 / LaunchDaemon）  │
├──────────────────────────────────────────────────────────────────────┤
│ 第 1 层：统一 Rust 核心层（procsocks-core，平台无关，约占 75% 代码）   │
│  · Config Schema · 正则规则引擎 (rules) · TLS SNI / HTTP Host 嗅探     │
│  · SOCKS5 CONNECT / UDP ASSOCIATE 客户端与重连 · 进程流量账本 (traffic)│
├──────────────────────┬───────────────────────┬───────────────────────┤
│ 第 3 层：平台拦截后端（实现统一的 RedirectBackend / ProcessInspector） │
│  Windows             │  macOS                │  Linux（规划）        │
│  · 一期: NetFilter   │  · pf (route-to lo0 / │  · cgroup v2 + eBPF   │
│  · 二期: WinDivert   │    utun) + libproc    │    (connect4/6,       │
│                      │  · PfWatchdog 死人开关│     sendmsg4/6)       │
└──────────────────────┴───────────────────────┴───────────────────────┘
```

### 3.1 第 1 层：Rust 代码与外部契约统一

将仓库收敛为根级 Cargo Workspace（或 `lib + bin` 单包）：

1. **统一配置与 CLI 子命令**：Windows、macOS、Linux 共用同一份 `Config` 结构与 CLI（`check`、`example`、`bridge`、`run`、`processes`、`driver`、`service`），平台专属字段通过 `#[serde(default)]` 兼容解析，`example` 按目标平台裁剪无关字段。
2. **统一进程枚举接口（`procsocks processes`）**：
   - macOS：复用现有 `libproc::running_processes()`；
   - Windows：通过 `CreateToolhelp32Snapshot` + `QueryFullProcessImageNameW` 输出相同 JSON 结构（PID、可执行文件完整路径、显示名）；
   - Linux：扫描 `/proc/<pid>/exe`。
3. **统一按进程流量统计（`traffic.rs`）**：
   - 现有 `traffic.rs` 只统计实际成功写入上游 SOCKS5 隧道的有效载荷字节（不含握手与直连回退），此前仅接入了 macOS；
   - Windows 后端在本地桥收到驱动转来的回环连接时，调用 `GetExtendedTcpTable` / `GetExtendedUdpTable` 按回环源端口反查发起进程 PID 与路径，即可直接接入同一套 `traffic.rs` 账本，产出格式完全一致的 `traffic.json`。

### 3.2 第 2 层：GUI 与特权守护统一

- 若独立维护 `ProcSocks` 桌面端，每个系统都要各写一套 GUI 和提权常驻逻辑（如现有 `macos/gui/` 的 SwiftUI 菜单栏，而 Windows 仍只有 CLI）。
- 与 `FlClash` 结合后，**UI 层统一收敛到 Flutter，特权常驻统一收敛到 `FlClashHelperService`**：一套前端同时覆盖 Windows / macOS / Linux 的进程勾选、正则配置与 5 / 15 / 30 分钟进程流量曲线；`ProcSocks` 本体保持纯粹、无 GUI 依赖的 Rust 守护/CLI 形态，兼顾无头服务器场景。

### 3.3 第 3 层：各平台底层拦截后端选型与演进

底层抽象出统一的生命周期守卫（启动前自检 → 先绑定本地监听口 → 再启用内核拦截 → 退出/崩溃自动回滚）：

- **macOS（保持现有方案）**：
  - `pf`（`route-to` 送入 `lo0` / 专用 `utun`）+ `libproc` 查 Socket 表还原原始目标与进程路径 + `PfWatchdog` 独立子进程管道死人开关。
  - 无需付费 Apple Developer Program 的 Network Extension 签名，且保留完整可执行路径正则能力。
- **Linux（后续补齐方向）**：
  - 采用 **`cgroup v2 + eBPF`**（挂载 `BPF_CGROUP_INET4_CONNECT` / `INET6_CONNECT` / `UDP4_SENDMSG` / `UDP6_SENDMSG`）。
  - 在目标进程发起系统调用瞬间即可在内核态获取 PID / 可执行路径并改写目标地址至本地桥接端口，无需改路由表、无需扫描全表，未命中进程零开销。
- **Windows（两阶段演进）**：
  - **阶段一（现状稳定版：NetFilter SDK `netfilter2`）**：复用已通过 TCP / UDP / DNS 完整验收的 `Redirector.bin + nfapi.dll + nfdriver.sys` 与 `native-components.lock.json` SHA-256 强校验机制，最快完成与 `FlClash` 的联调落地。缺点是驱动属专有软件，安装包不能内置，首次使用需手动导入三件套。
  - **阶段二（全开源免外部依赖版：`WinDivert` 后端）**：在同一后端接口下新增 `windivert` 实现——利用 `WINDIVERT_LAYER_SOCKET` 实时跟踪「本地端口 ↔ 进程路径」映射表，再用 `WINDIVERT_LAYER_NETWORK` 仅拦截命中进程的出站包送入本地用户态桥接。`WinDivert` 拥有微软 WHQL 签名且采用开源许可证（LGPLv3 / GPLv2），**可直接随整合版安装包一起打包分发，彻底消除用户手动准备第三方驱动组件的门槛**。

---

## 4. 与 FlClash 深度结合的工程方案

### 4.1 为什么采用「`FlClashHelperService` 托管独立 `procsocks` 子进程」

对比三种集成方式：

1. **塞进 Go 内核 `core/Clash.Meta`（不采用）**：`FlClash` 的 Go 内核保持 `CGO_ENABLED=0` 构建并作为独立子模块跟随上游 `mihomo`；塞入 Windows C ABI 驱动调用与 macOS `pf`/`libproc` FFI 会引入 CGo 并造成持续的上游合并冲突。
2. **由非特权 Flutter 进程直接启停 `procsocks`（不采用）**：Windows 驱动交互与 macOS `pfctl` / `utun` 均需管理员或 `root` 权限，每次切换开关弹 UAC / 密码框体验割裂。
3. **复用 `FlClashHelperService` 以受控子进程方式托管 `procsocks`（采用）**：
   - `FlClash` 的 `services/helper` 已是以 `SYSTEM` / `root` 常驻的本地 Rust 服务（带调用方 SID / UID 校验、可执行文件编译期 SHA-256 校验，以及 Windows `JobObject` `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` 防孤儿进程机制）。
   - **保持 `procsocks` 为独立子进程而非 `LoadLibrary` 进 `helper` 进程内**，原因有四：
     1. Windows 加载 `Redirector.bin` 时需临时切换进程当前目录以解析同目录的 `nfapi.dll`，在多线程 HTTP 服务内 `set_current_dir` 存在竞态；
     2. 隔离第三方驱动适配层的崩溃或 `aio_free()` 阻塞风险，避免拖垮 `FlClashHelperService` 与 `FlClashCore`；
     3. 完整保留 macOS `PfWatchdog` 的父子进程管道死人开关模型；
     4. 许可证与文件边界清晰：随安装包分发的仅有 GPL-3.0 的 `FlClashProcSocks` 二进制，用户自备驱动组件独立存放在应用数据目录 `%APPDATA%\com.follow\clash\procsocks\driver\`。

### 4.2 仓库组织方式

- `ProcSocks` 保持独立 Git 仓库，确保服务器 / 命令行用户仍可单独构建运行 `procsocks`。
- `FlClash` 通过 Git Submodule 将本仓挂载至 `services/procsocks`（与 `core/Clash.Meta`、`plugins/prism_ui` 一致），构建桌面端安装包时一并编译产出二进制并注入 `EXPECTED_PROCSOCKS_SHA256`。

### 4.3 结合时必须落地的 5 个工程细节

1. **第三种网络接管开关（与全局 TUN 自动互斥）**
   - 在 `FlClash` 仪表盘的 `TakeoverSwitch` 中并列提供 `System Proxy`、`TUN`、`ProcSocks（按进程接管）`。
   - 开启 `ProcSocks` 时自动关闭 `TUN`，保证路由表与系统 DNS 干净，不干扰同时运行的 Tailscale 等工具。
2. **上游端口/鉴权自动同步 + 本地 `127.0.0.1:0` 动态监听**
   - `upstream.port` 与 `upstream.username` / `password` 由 `FlClash` 从当前生效的 `mixedPort` 和本地代理鉴权配置实时生成，禁止硬编码 `7890`。
   - 支持将 `listen` 设为 `127.0.0.1:0`，先由操作系统分配空闲回环端口，拿到实际端口后再写入驱动 `AIO_TARGET_PORT` 或 `pf` 重定向规则，彻底避免与订阅配置中常见的 `socks-port: 7891` 撞端口。
3. **底层强制注入防死循环（回环自咬）白名单**
   - 生成运行配置时，无条件在 `bypassPatterns` 中注入代理链路自身进程（`FlClash`、`FlClashCore`、`FlClashHelperService`、`procsocks`），避免 `FlClashCore` 发往远端节点的出站连接被再次拦截造成回环风暴。
   - 默认预置可选的「内网与远程控制保护列表」（`tailscaled`、`tailscale-ipn`、`sshd`、`mstsc`、`RustDesk`、`ToDesk`、向日葵等）。
4. **`requireHostname` 默认策略适配通用桌面场景**
   - `ProcSocks` 独立版面向 AI CLI 默认开启 `requireHostname: true`（嗅探不到 SNI / HTTP `Host` 即拒绝）。
   - 集成进 `FlClash` 后需覆盖游戏、SSH、桌面 IM 等非 HTTP/TLS 流量，默认应设为 `requireHostname: false`：能嗅探到域名则还原域名交给 `mihomo` 匹配 `DOMAIN` / `GEOSITE` 规则；嗅探不到则保留原始目标 IP 交给 `mihomo` 匹配 `GEOIP` / `MATCH` 规则，同时在高级设置保留「严格域名模式」开关。
5. **Windows 原生组件导入向导与跨平台进程选择器**
   - 在 `FlClash` 网络设置页提供图形化的进程勾选列表（支持运行中进程一键勾选、选择可执行文件、手动编写正则）以及按进程实时流量视图。
   - 在阶段一（NetFilter 后端）内置图形化「驱动组件检查与导入」卡片：引导用户选择本地目录，调用 `driver import` / `driver install` 完成哈希锁校验与驱动注册，明确展示当前驱动状态。

---

## 5. 分步实施路线图

1. **Step 1 — 收敛 `ProcSocks` 单一跨平台工程**：以 `macos/` 跨平台源码为基座合入 `shared/udp.rs` 与 `windows/` 脚本/文档，恢复根目录 `Cargo.toml`；支持 `listen: "127.0.0.1:0"` 动态端口输出；在 Windows 上补齐 `processes` 子命令与 `traffic.json` 按进程流量统计。
2. **Step 2 — 扩展 `FlClashHelperService` 控制接口**：在 `FlClash/services/helper` 新增 `/procsocks/start`、`/procsocks/stop`、`/procsocks/status`、`/procsocks/driver` 本地受控端点，绑定 `JobObject` / 信号优雅退出清理。
3. **Step 3 — 接入 `FlClash` 状态管理与仪表盘开关**：新增持久化配置模型 `ProcSocksProps`，实现与 `TUN` 的互斥切换、与 `mixedPort` / 本地鉴权的自动同步，以及强制 `bypassPatterns` 注入。
4. **Step 4 — 完成 Flutter 图形界面**：实现跨平台应用/进程选择器、Windows 驱动导入校验向导卡片，以及读取 `traffic.json` 的按进程实时速率图表。
5. **Step 5 — 评估开源后端扩展（二期）**：在 Windows 验证 `WinDivert` 后端以替代专有 NetFilter SDK 三件套，并在 Linux 补齐 `cgroup v2 + eBPF` 后端，实现三端免外部专有依赖的完全开箱即用。
