# ProcSocks Windows deployment

[中文](#中文) · [English](#english)

## 中文

本目录只保存脱敏的部署模板。不要把真实代理密码、设备名、Tailscale IP、
SSH 用户、私钥或第三方原生二进制提交到 Git。

### 前提

- x64 Windows 10、Windows 11 或 Windows Server。
- 已有可用的 SOCKS5 代理，例如 `127.0.0.1:7890`。地址和端口可在配置中修改。
- 管理员权限，用于安装内核驱动和 Windows 服务。
- 用户自行取得且许可证允许使用的 `Redirector.bin`、`nfapi.dll` 和
  `nfdriver.sys`。三者必须匹配 `native-components.lock.json` 中同一组件包。

### 推荐目录

```text
C:\ProgramData\ProcSocks\
  procsocks.exe
  procsocks.json        # 真实配置，不进入 Git
  procsocks.log
  driver\
    Redirector.bin      # 用户提供，不进入 Git/Release
    nfapi.dll           # 用户提供，不进入 Git/Release
    nfdriver.sys        # 用户提供，不进入 Git/Release
```

从 `windows-codex.example.json` 复制一份真实配置，至少确认以下内容：

- `upstream.host` 和 `upstream.port` 指向实际 SOCKS5 服务。
- 代理需要认证时，同时设置 `upstream.username` 和 `upstream.password`。
- `processPatterns` 只包含确实需要代理的程序。
- `bypassPatterns` 包含 `procsocks.exe` 和远程控制客户端，避免失去远程连接。
- `listen` 保持为回环地址；默认 `127.0.0.1:7891`。

### 安全安装顺序

先使用只匹配 `curl.exe` 的 `config.example.json` 测试，不要直接拦截正在使用的
远程控制或 AI 客户端。

```powershell
$install = 'C:\ProgramData\ProcSocks'
$native = 'C:\Path\To\LicensedNativeBundle'

& "$install\procsocks.exe" --config "$install\procsocks.test.json" driver import --from $native
& "$install\procsocks.exe" --config "$install\procsocks.test.json" check
& "$install\procsocks.exe" --config "$install\procsocks.test.json" service install
& "$install\procsocks.exe" service start
```

清除当前 shell 的代理环境变量，然后让 curl 在不显式指定代理的情况下测试：

```powershell
$env:HTTP_PROXY = $null
$env:HTTPS_PROXY = $null
$env:ALL_PROXY = $null
curl.exe --fail --noproxy '*' https://www.gstatic.com/generate_204 --output NUL
Get-Content "$install\procsocks.log" -Tail 20
```

日志必须出现 `routing connection`。随后停止并卸载测试服务，再使用正式配置安装：

```powershell
& "$install\procsocks.exe" service stop
& "$install\procsocks.exe" service uninstall
& "$install\procsocks.exe" --config "$install\procsocks.json" check
& "$install\procsocks.exe" --config "$install\procsocks.json" service install
& "$install\procsocks.exe" service start
```

`service uninstall` 只移除 ProcSocks 服务，会保留原生组件和 `netfilter2` 驱动。

### 检查状态

```powershell
& "$install\procsocks.exe" service status
& "$install\procsocks.exe" --config "$install\procsocks.json" driver status
Get-NetTCPConnection -State Listen -LocalPort 7890,7891
Get-Content "$install\procsocks.log" -Tail 50
```

### 修改 SOCKS5 地址或其他配置

服务只在启动时读取配置。修改 `procsocks.json` 后必须校验并重启：

```powershell
& "$install\procsocks.exe" service stop
& "$install\procsocks.exe" --config "$install\procsocks.json" check
& "$install\procsocks.exe" service start
```

如果 `check` 失败，不要重新启动服务；修正配置或恢复上一份配置。

### 更新 ProcSocks

```powershell
& "$install\procsocks.exe" service stop
Copy-Item .\procsocks.exe "$install\procsocks.exe"
& "$install\procsocks.exe" --config "$install\procsocks.json" check
& "$install\procsocks.exe" service start
```

若新版本更改了原生组件锁，请先阅读 Release 说明并重新执行 `driver import`；
不要混用不同组件包的文件。

### 远程部署

通过私有 SSH/Tailscale 通道复制 `procsocks.exe` 和脱敏后生成的设备配置。
只有在许可证允许目标机器使用原生组件时，才可以通过同一私有通道传输它们。
不要把第三方原生文件放到公开下载地址、Git 仓库或 GitHub Release。

远程安装仍应遵守上述 `curl.exe` 测试顺序，并在正式规则中绕过远程控制客户端。

---

## English

This directory contains sanitized deployment templates only. Never commit real
proxy passwords, device names, Tailscale IPs, SSH users, private keys, or
third-party native binaries.

### Prerequisites

- x64 Windows 10, Windows 11, or Windows Server.
- A working SOCKS5 proxy, such as `127.0.0.1:7890`. Its address and port are configurable.
- Administrator access to install the kernel driver and Windows service.
- User-supplied and properly licensed `Redirector.bin`, `nfapi.dll`, and
  `nfdriver.sys`. All three must match one bundle in `native-components.lock.json`.

### Recommended layout

```text
C:\ProgramData\ProcSocks\
  procsocks.exe
  procsocks.json        # real configuration; never commit it
  procsocks.log
  driver\
    Redirector.bin      # user-supplied; never put in Git or Releases
    nfapi.dll           # user-supplied; never put in Git or Releases
    nfdriver.sys        # user-supplied; never put in Git or Releases
```

Copy `windows-codex.example.json` to a private configuration and verify at least:

- `upstream.host` and `upstream.port` point to the real SOCKS5 service.
- Set both `upstream.username` and `upstream.password` when authentication is required.
- `processPatterns` contains only applications that should be routed.
- `bypassPatterns` includes `procsocks.exe` and the remote-control client.
- `listen` remains a loopback endpoint; the default is `127.0.0.1:7891`.

### Safe installation sequence

Test with `config.example.json`, which selects only `curl.exe`. Do not begin by
intercepting the remote-control or AI client currently in use.

```powershell
$install = 'C:\ProgramData\ProcSocks'
$native = 'C:\Path\To\LicensedNativeBundle'

& "$install\procsocks.exe" --config "$install\procsocks.test.json" driver import --from $native
& "$install\procsocks.exe" --config "$install\procsocks.test.json" check
& "$install\procsocks.exe" --config "$install\procsocks.test.json" service install
& "$install\procsocks.exe" service start
```

Clear proxy environment variables and run curl without an explicit proxy:

```powershell
$env:HTTP_PROXY = $null
$env:HTTPS_PROXY = $null
$env:ALL_PROXY = $null
curl.exe --fail --noproxy '*' https://www.gstatic.com/generate_204 --output NUL
Get-Content "$install\procsocks.log" -Tail 20
```

The log must contain `routing connection`. Stop and remove the test service,
then install the service with the final configuration:

```powershell
& "$install\procsocks.exe" service stop
& "$install\procsocks.exe" service uninstall
& "$install\procsocks.exe" --config "$install\procsocks.json" check
& "$install\procsocks.exe" --config "$install\procsocks.json" service install
& "$install\procsocks.exe" service start
```

`service uninstall` removes only the ProcSocks service. It retains the native
components and the `netfilter2` driver.

### Status checks

```powershell
& "$install\procsocks.exe" service status
& "$install\procsocks.exe" --config "$install\procsocks.json" driver status
Get-NetTCPConnection -State Listen -LocalPort 7890,7891
Get-Content "$install\procsocks.log" -Tail 50
```

### Changing the SOCKS5 endpoint or other settings

The service reads the configuration only at startup. Validate and restart it
after editing `procsocks.json`:

```powershell
& "$install\procsocks.exe" service stop
& "$install\procsocks.exe" --config "$install\procsocks.json" check
& "$install\procsocks.exe" service start
```

If `check` fails, do not restart the service. Correct the configuration or
restore the previous copy.

### Updating ProcSocks

```powershell
& "$install\procsocks.exe" service stop
Copy-Item .\procsocks.exe "$install\procsocks.exe"
& "$install\procsocks.exe" --config "$install\procsocks.json" check
& "$install\procsocks.exe" service start
```

If a release changes the native component lock, read its release notes and run
`driver import` again first. Never mix files from different bundles.

### Remote deployment

Copy `procsocks.exe` and a device-specific sanitized configuration through a
private SSH/Tailscale path. Transfer the native files through that path only if
their license covers use on the target machine. Never place third-party native
files on a public download, in Git, or in a GitHub Release.

Follow the same `curl.exe` test sequence remotely and keep the remote-control
client in the final bypass list.
