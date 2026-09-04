# ProcSocks

[中文](#中文) · [English](#english)

## 中文

ProcSocks 是一个小型 Windows 命令行路由工具，可以只让指定进程的
TCP 连接通过已有的 SOCKS5 代理，而不必开启系统全局代理或 TUN 网卡。
它主要面向不方便使用图形化分流工具的无人值守电脑和服务器。

当前版本针对 WinServer 上的实际使用场景：

```text
指定进程
  -> 原生按进程 TCP 重定向器
  -> ProcSocks（127.0.0.1:7891）
  -> 恢复 TLS SNI / HTTP Host
  -> 上游 SOCKS5（127.0.0.1:7890）
```

当原生重定向器只能提供目标 IP，而上游 SOCKS 服务器需要域名请求时，
中间的主机名恢复步骤十分重要。

### 功能范围

- 仅处理 TCP `CONNECT` 流量。
- 按进程规则会对可执行文件完整路径进行正则搜索；例如 `codex.exe`
  可以匹配路径中包含该名称的程序。
- 支持从 TLS ClientHello SNI、HTTP `Host` 和 `CONNECT` authority 恢复域名。
- 严格模式下不会路由 UDP/QUIC、TLS Encrypted ClientHello，以及无法看到
  主机名的协议。
- 配置校验会强制本地监听地址使用回环地址。

### 原生依赖与许可证边界

Windows 没有为透明的按进程 TCP 重定向提供可靠的纯用户态 API。
当前后端需要三个原生文件：

- `Redirector.bin`：Netch 的适配器。Netch 使用其 GPL-3.0 源码构建该文件，
  并通过 NetFilter SDK API 工作。
- `nfapi.dll` 和 `nfdriver.sys`：NetFilter SDK 组件，属于使用独立许可证的
  专有软件。

本仓库及其 Release 不包含上述二进制文件，也不包含 NetFilter SDK 的
头文件、源码或导入库。ProcSocks 不授予这些文件的使用或再分发权利。
请自行取得适用于预期用途的组件和许可证，并在部署前查看
[NetFilter SDK 许可证][nfsdk-license]、[购买/下载页面][nfsdk-buy]及
[驱动签名文档][nfsdk-signing]。

Netch 的公开 1.9.7 构建不会编译或修改 `nfapi.dll` 和 `nfdriver.sys`；
其构建流程复制这两个文件，并另外将 `Redirector.bin` 与 `nfapi.lib`
链接。这样做不会让 NetFilter SDK 文件变成 Netch GPL 许可证的一部分。

ProcSocks 本身采用 [GPL-3.0-only](LICENSE) 许可证。导入经过验证的原生
组件后，ProcSocks 不依赖 Netch 的程序目录、图形界面或配置文件。
源码、署名和再分发注意事项见
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

ProcSocks 是独立项目，与 Netch 或 NetFilter SDK 没有关联，也未获得其
背书。GitHub 官方 Release 可以包含 ProcSocks 源码和 `procsocks.exe`，
但不得捆绑三个由用户提供的原生组件。导入命令只读取本地目录，不会
自动下载第三方文件。

### 原生组件版本锁

不要混用不同版本来源的 `Redirector.bin`、`nfapi.dll` 和
`nfdriver.sys`。单看文件版本号无法证明 ABI、架构、签名或文件内容一致。

[`native-components.lock.json`](native-components.lock.json) 是版本锁的
唯一依据，其中记录每套已测试组件的架构、文件大小、说明用版本号和
精确 SHA-256。版本锁会在编译时嵌入 `procsocks.exe`。以下命令会在
启用拦截前拒绝未知文件或混合版本：

- `driver import` 会校验来源文件，复制后再次校验。
- `check`、`run` 和服务安装会校验本地原生组件。
- `run` 和服务启动还会校验已经安装的驱动文件。
- `driver status` 会同时报告组件包和已安装驱动的校验状态。

当前通过测试的 x64 组件包如下：

| 组件 | 文件版本 | 大小 | SHA-256 |
| --- | --- | ---: | --- |
| `Redirector.bin` | Netch 1.9.7 适配器 | 373760 | `ef325b06656b68302ed90b7c76877a845df62c44182b59100d32e612cf7f514b` |
| `nfapi.dll` | 1.5.1.7 | 389632 | `f0519b24f076f52f12353d955ef89863963b5988130233673f2f4a4445e842cc` |
| `nfdriver.sys` | 1.6.3.0 | 90672 | `4af6f672119f4f13e33b8914630eedea97d299b5c92c2105a4015dd0ca6e933e` |

Netch 1.9.7 发布的完整 `Netch.7z` 归档 SHA-256 为
`692aa6ddd20ed98cf9dd1c51c0495206c8ea3aeef9e9f50fb1de94eca28be5a8`。
该值用于验证归档本身；ProcSocks 仍会分别验证提取出的三个文件。

不要自动将这些文件替换为最新版 NetFilter SDK。只有当匹配的适配器完成
TCP、关闭、重启、Windows 10/11 和 Windows Server 测试矩阵，并在新的
ProcSocks 版本中记录指纹后，才应支持新的 SDK 版本。

### 构建

```powershell
cargo build --release
```

输出文件为 `target\release\procsocks.exe`。

### 配置

将 `config.example.json` 复制为 `procsocks.json`。示例默认只匹配
`curl.exe`，便于在加入长期运行的程序前先验证完整链路。

#### 准备原生组件

1. 获取已正确授权的 x64 NetFilter SDK 组件。当前锁定的适配器需要匹配
   `nfapi.dll` 1.5.1.7 和驱动 1.6.3.0；不要假定更新版本 ABI 兼容。
2. 从 Netch 官方 1.9.7 源码或 Release 获取或构建 `Redirector.bin`。
   如果再分发该适配器，请保留对应的 GPL 源码和许可证声明。
3. 将且仅将 `Redirector.bin`、`nfapi.dll` 和 `nfdriver.sys` 放入一个
   临时目录，不要重命名。
4. 导入该目录。相对 `redirectorDir` 路径会以 JSON 配置文件所在目录为准：

```powershell
.\procsocks.exe --config .\procsocks.json driver import --from C:\Users\you\Downloads\procsocks-native
.\procsocks.exe --config .\procsocks.json check
```

导入命令不会访问网络，也不会接受未经测试的哈希。如果合法的厂商版本
被拒绝，请将其单独保留并作为新组件包完成兼容性测试；不要绕过校验或
直接覆盖版本锁。

用于 Codex 时，最终的进程规则通常为：

```json
"processPatterns": ["ChatGPT.exe", "codex.exe"]
```

不要把 `procsocks.exe` 加入代理进程集合。程序会自动绕过自身，示例中
也明确将其列为绕过规则。

### 命令

```powershell
# 校验 JSON，并加载原生 API，但不启动拦截
.\procsocks.exe --config .\procsocks.json check

# 导入、检查或安装用户提供的驱动（安装需要管理员权限）
.\procsocks.exe --config .\procsocks.json driver import --from C:\Users\you\Downloads\procsocks-native
.\procsocks.exe --config .\procsocks.json driver status
.\procsocks.exe --config .\procsocks.json driver install

# 只测试主机名恢复 SOCKS 桥接
.\procsocks.exe --config .\procsocks.json bridge

# 启动桥接和透明的按进程重定向（需要管理员权限）
.\procsocks.exe --config .\procsocks.json run

# 安装为自动启动服务，然后通过命令行控制（需要管理员权限）
.\procsocks.exe --config .\procsocks.json service install
.\procsocks.exe service start
.\procsocks.exe service status
.\procsocks.exe service stop
.\procsocks.exe service uninstall
```

设置 `RUST_LOG=procsocks=debug` 可以查看连接级诊断信息。前台运行时使用
Ctrl+C 停止；正常关闭过程中会移除重定向规则。服务模式会在配置文件
旁写入 `procsocks.log`，并为异常失败配置三次延迟重启。

### 安全验证顺序

1. 启动 `bridge`，再使用一个会把 IP 目标发送至 `127.0.0.1:7891` 的
   SOCKS 客户端测试 HTTPS 地址。
2. 停止 `bridge`，以管理员身份启动 `run`，并且只选择 `curl.exe`，
   随后让 curl 在不显式指定代理的情况下测试同一地址。
3. 两项测试都通过后，再把规则替换为最终需要的应用程序。

这样可以避免在桥接功能尚未验证时拦截正在使用的远程控制客户端。

---

## English

ProcSocks is a small Windows command-line router for sending selected TCP
processes through an existing SOCKS5 proxy without enabling a system-wide proxy
or TUN adapter. It is intended for unattended machines where a GUI proxy rule
manager is inconvenient.

The first version targets the concrete setup used on WinServer:

```text
selected process
  -> native per-process TCP redirector
  -> ProcSocks at 127.0.0.1:7891
  -> TLS SNI / HTTP Host recovery
  -> upstream SOCKS5 at 127.0.0.1:7890
```

The hostname recovery step matters when the native redirector supplies only an
IP address but the upstream SOCKS server requires a domain-name request.

### Scope

- TCP `CONNECT` traffic only.
- Per-process rules are regular-expression searches against the full executable
  path. A simple rule such as `codex.exe` matches any path containing that name.
- TLS ClientHello SNI and HTTP `Host`/`CONNECT` authority are supported.
- UDP/QUIC, TLS Encrypted ClientHello, and protocols without a visible hostname
  are deliberately not routed in strict mode.
- The local listener is restricted to a loopback address by validation.

### Native dependency and licensing boundary

Windows does not expose a reliable user-mode-only API for transparent
per-process TCP redirection. The current backend consists of three native
files:

- `Redirector.bin` is the Netch adapter. Netch builds it from its own GPL-3.0
  source and links it to the NetFilter SDK API.
- `nfapi.dll` and `nfdriver.sys` are NetFilter SDK components. NetFilter SDK is
  proprietary software with its own license.

None of these binaries, the NetFilter SDK headers, or the NetFilter SDK source
are included in this repository or its release artifacts. ProcSocks does not
grant a license to them. Obtain the components yourself under terms that cover
your intended use. Consult the [NetFilter SDK license][nfsdk-license],
[purchase/download page][nfsdk-buy], and [driver-signing documentation][nfsdk-signing]
before deployment.

Netch does not compile or patch `nfapi.dll` or `nfdriver.sys` in its public
1.9.7 build. Its build copies those two files and compiles the separate
`Redirector.bin` adapter against `nfapi.lib`. This does not make the NetFilter
SDK files part of Netch's GPL license.

ProcSocks itself is licensed under [GPL-3.0-only](LICENSE). Once a verified
native bundle is imported, ProcSocks does not depend on the Netch application
directory, GUI, or configuration. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
for source links, attribution, and redistribution cautions.

ProcSocks is an independent project. It is not affiliated with or endorsed by
Netch or NetFilter SDK.

Official GitHub source releases may contain ProcSocks source and builds of
`procsocks.exe`, but must not bundle any of the three user-supplied native
components. The import command intentionally reads only from a local directory
and never downloads third-party files.

[nfsdk-license]: https://www.netfiltersdk.com/license.html
[nfsdk-buy]: https://www.netfiltersdk.com/buy_now.html
[nfsdk-signing]: https://www.netfiltersdk.com/help/nfsdk_sockfilter/signing.html

### Native version lock

Never combine `Redirector.bin`, `nfapi.dll`, and `nfdriver.sys` from different
releases. A file-version string is not sufficient because it does not prove the
ABI, architecture, signature, or file contents.

[`native-components.lock.json`](native-components.lock.json) is the source of
truth. It records the architecture, file size, file version for documentation,
and exact SHA-256 of every component in each tested bundle. The lock is embedded
inside `procsocks.exe` at build time. The following commands reject unknown or
mixed files before enabling interception:

- `driver import` verifies the source, copies it, and verifies the copy.
- `check`, `run`, and service installation verify the local native bundle.
- `run` and service startup also verify the installed driver file.
- `driver status` reports both bundle and installed-driver verification.

The currently tested x64 bundle is:

| Component | File version | Size | SHA-256 |
| --- | --- | ---: | --- |
| `Redirector.bin` | Netch 1.9.7 adapter | 373760 | `ef325b06656b68302ed90b7c76877a845df62c44182b59100d32e612cf7f514b` |
| `nfapi.dll` | 1.5.1.7 | 389632 | `f0519b24f076f52f12353d955ef89863963b5988130233673f2f4a4445e842cc` |
| `nfdriver.sys` | 1.6.3.0 | 90672 | `4af6f672119f4f13e33b8914630eedea97d299b5c92c2105a4015dd0ca6e933e` |

The Netch 1.9.7 release publishes SHA-256
`692aa6ddd20ed98cf9dd1c51c0495206c8ea3aeef9e9f50fb1de94eca28be5a8`
for its complete `Netch.7z` archive. That archive checksum verifies the archive;
ProcSocks still independently verifies the three extracted files.

Do not automatically replace these files with the newest NetFilter SDK build.
A new SDK build is supported only after its matching adapter has passed the
TCP, shutdown, restart, Windows 10/11, and Windows Server test matrix and its
fingerprints have been added in a new ProcSocks release.

### Build

```powershell
cargo build --release
```

The output is `target\release\procsocks.exe`.

### Configure

Copy `config.example.json` to `procsocks.json`. The example intentionally
targets only `curl.exe` so the complete route can be verified before adding
long-running applications.

#### Supply the native bundle

1. Obtain a properly licensed x64 NetFilter SDK bundle. For the currently
   locked adapter, request/use the matching `nfapi.dll` 1.5.1.7 and driver
   1.6.3.0. Do not assume a newer SDK is ABI-compatible.
2. Obtain or build `Redirector.bin` from the official Netch 1.9.7 source or
   release. Keep the corresponding GPL source and notice when redistributing
   that adapter.
3. Put exactly `Redirector.bin`, `nfapi.dll`, and `nfdriver.sys` in a temporary
   staging directory. Do not rename the files.
4. Import the directory. Relative `redirectorDir` paths are resolved beside the
   JSON config:

```powershell
.\procsocks.exe --config .\procsocks.json driver import --from C:\Users\you\Downloads\procsocks-native
.\procsocks.exe --config .\procsocks.json check
```

The import command does not access the network and will not accept an untested
hash. If a legitimate vendor-provided build is rejected, keep it separate and
qualify it as a new bundle; do not bypass the check or overwrite the lock entry.

For Codex, the eventual process rules are normally:

```json
"processPatterns": ["ChatGPT.exe", "codex.exe"]
```

Do not add `procsocks.exe` to the routed set. It is bypassed automatically and
is also listed explicitly in the example.

### Commands

```powershell
# Validate JSON and load the native API without starting interception
.\procsocks.exe --config .\procsocks.json check

# Import, inspect, or install the user-supplied driver (install requires Administrator)
.\procsocks.exe --config .\procsocks.json driver import --from C:\Users\you\Downloads\procsocks-native
.\procsocks.exe --config .\procsocks.json driver status
.\procsocks.exe --config .\procsocks.json driver install

# Test only the hostname-recovery SOCKS bridge
.\procsocks.exe --config .\procsocks.json bridge

# Start bridge plus transparent per-process redirection (Administrator)
.\procsocks.exe --config .\procsocks.json run

# Install for automatic startup, then control it from the CLI (Administrator)
.\procsocks.exe --config .\procsocks.json service install
.\procsocks.exe service start
.\procsocks.exe service status
.\procsocks.exe service stop
.\procsocks.exe service uninstall
```

Set `RUST_LOG=procsocks=debug` for connection-level diagnostics. Stop the
foreground process with Ctrl+C; the redirector rules are removed during normal
shutdown. Service mode writes `procsocks.log` beside its configured JSON file
and installs three delayed restart attempts for unexpected failures.

### Safe verification sequence

1. Start `bridge`, then test an HTTPS URL with a SOCKS client that sends an IP
   destination to `127.0.0.1:7891`.
2. Stop `bridge`, start `run` as Administrator with only `curl.exe` selected,
   and test the same URL without specifying a proxy in curl.
3. Only after both tests pass, replace the rule with the intended applications.

This sequence avoids intercepting an active remote-control client while the
bridge itself is still being tested.
