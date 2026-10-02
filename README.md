# ProcSocks

[中文](#中文) · [English](#english)

## 中文

ProcSocks 让指定进程的 TCP / UDP 通信通过已有的 SOCKS5 代理。Windows 和 macOS
版本在同一个仓库中，分别保留平台源码、构建目录和部署说明。

| 平台 | 项目目录 | 界面与后端 | 使用说明 |
| --- | --- | --- | --- |
| Windows | [`windows/`](windows/) | 命令行 / Windows 服务，NetFilter SDK 重定向 | [构建、配置与部署](windows/README.md) |
| macOS | [`macos/`](macos/) | SwiftUI / AppKit 菜单栏 GUI，Rust + 系统 pf | [菜单栏应用](macos/docs/gui.md) · [后端与 CLI](macos/docs/macos.md) |

### macOS

需要 macOS 13 及以上、Rust 和 Xcode 的 Swift 工具链。

```sh
cd macos
scripts/build-macos-app.sh
open dist/ProcSocks.app
```

点击菜单栏的分流箭头图标，填写已有 SOCKS5 服务器，从应用/进程列表勾选
目标并启用代理。高级正则规则继续生效。实时流量只统计实际经上游 SOCKS5
转发的 TCP / UDP 数据字节，可按进程查看上传/下载曲线，范围为 5、15、30 分钟。

Swift GUI 位于 `macos/gui/`，Rust 核心位于 `macos/src/`。

### Windows

```powershell
cd windows
cargo build --release --locked
```

输出为 `windows\target\release\procsocks.exe`。原有 Windows 源码、配置示例
和部署说明已移入 `windows/`，UDP 版本需要更新重定向适配层（见 Windows 使用说明）；以前位于仓库根目录的构建命令
现在需要先进入 `windows`。服务名和驱动保持不变。

两平台支持 TCP 和 SOCKS5 UDP ASSOCIATE，UDP 默认启用并遵循相同进程规则。上游必须支持 UDP，IPv6 UDP 还取决于上游的 IPv6 能力。Windows 需要用户自行提供
并取得适用许可的原生组件，详见 [第三方声明](THIRD_PARTY_NOTICES.md)。macOS
使用系统自带 pf，不依赖上述 Windows 驱动。

项目使用 [GPL-3.0-only](LICENSE) 许可证。个人配置、日志、构建产物和第三方
驱动二进制不提交到仓库。

## English

ProcSocks routes selected processes' TCP and UDP traffic through an existing SOCKS5
proxy. Both platforms share this repository and have separate project folders:

- [`windows/`](windows/): the existing CLI and Windows service. Run Cargo from
  this directory; see the [Windows guide](windows/README.md). It uses the same UDP protocol implementation as macOS.
- [`macos/`](macos/): the Rust pf backend and native menu bar app. Build with
  `cd macos && scripts/build-macos-app.sh`, then open `dist/ProcSocks.app`.
  See the [GUI guide](macos/docs/gui.md) and [backend guide](macos/docs/macos.md).

The Mac GUI provides app/process selection, advanced regular expressions and
per-process upload/download charts covering 5, 15 or 30 minutes. Traffic counters
include only bytes actually relayed through upstream SOCKS5 tunnels.

TCP and UDP ASSOCIATE are supported. The upstream must support UDP. Windows native dependencies have separate licensing
requirements; see [third-party notices](THIRD_PARTY_NOTICES.md). ProcSocks itself
is licensed under [GPL-3.0-only](LICENSE).
