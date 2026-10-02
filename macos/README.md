# ProcSocks for macOS

原生菜单栏应用使用 SwiftUI 和 AppKit，Rust 核心使用系统自带的 pf 与 libproc
按进程路由 TCP / UDP 通信。支持 macOS 13 及以上，无需额外内核驱动。

## 构建与使用

在本目录运行，需要 Rust 与 Xcode 的 Swift 工具链：

```sh
scripts/build-macos-app.sh
open dist/ProcSocks.app
```

从菜单栏的分流箭头图标打开设置，配置已有 SOCKS5 服务器，从应用/进程列表
勾选目标并启用代理。复杂正则仍可在高级规则中配置；绕过规则优先。

实时流量按进程显示实际代理连接的上传/下载速度与累计用量，图表范围为
5、15、30 分钟。代理 UDP / QUIC 的数据字节也会计入；直连回退不会计入。

- [GUI 使用、配置、权限与联网测试](docs/gui.md)
- [pf 后端、CLI、部署与限制](docs/macos.md)
- [Windows 版本](../windows/README.md)

## 源码与验证

`src/` 为 Rust 核心，`gui/` 为原生 Swift 包，`scripts/` 提供打包和验证工具。
两个平台独立构建，输出分别位于各自的 `target/` 与 `dist/`。

```sh
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
swift test --package-path gui
```

个人配置、日志和构建产物不纳入 Git。GUI 保存的配置位于
`~/Library/Application Support/ProcSocks/procsocks.json`；管理员认证由 macOS
完成。具体路径与统计语义见 GUI 使用说明。

## English

ProcSocks for macOS provides a SwiftUI/AppKit menu bar GUI and a Rust TCP/UDP router
using system pf, utun and libproc. macOS 13 or newer is required.

From this directory, run `scripts/build-macos-app.sh` and open
`dist/ProcSocks.app`. Select applications or executables from the GUI; advanced
regular expressions remain available. Charts show only traffic actually relayed
through upstream SOCKS5, grouped by process, over 5, 15 or 30 minutes.

The Swift package is in `gui/`; the Rust core is in `src/`. See the linked guides
for setup, limitations and the independent native network test application.

Licensed under [GPL-3.0-only](LICENSE). See [third-party notices](THIRD_PARTY_NOTICES.md)
for the optional Windows backend components retained in the Rust source.

## UDP

“代理 UDP（含 QUIC）”默认开启，继续使用同一份进程列表、端口范围和高级规则。
上游须支持 SOCKS5 UDP ASSOCIATE；测试上游会验证 TCP 与实际 UDP DNS 往返。
UDP 用原始目标 IP，`requireHostname` 仅约束 TCP。IPv6 UDP 还需上游支持 IPv6。
系统代发的 DNS 属于 mDNSResponder，默认继续直连；应用自己发送的 UDP DNS
会按该应用的规则代理。多播、255.255.255.255 广播、回环和 IPv6 链路本地通信保持原路径。

实现和验收说明见 [UDP 验证](docs/udp.md)。
