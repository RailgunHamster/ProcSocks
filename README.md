# ProcSocks

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

## Scope

- TCP `CONNECT` traffic only.
- Per-process rules are regular-expression searches against the full executable
  path. A simple rule such as `codex.exe` matches any path containing that name.
- TLS ClientHello SNI and HTTP `Host`/`CONNECT` authority are supported.
- UDP/QUIC, TLS Encrypted ClientHello, and protocols without a visible hostname
  are deliberately not routed in strict mode.
- The local listener is restricted to a loopback address by validation.

## Native dependency and licensing boundary

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

## Native version lock

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

## Build

```powershell
cargo build --release
```

The output is `target\release\procsocks.exe`.

## Configure

Copy `config.example.json` to `procsocks.json`. The example intentionally
targets only `curl.exe` so the complete route can be verified before adding
long-running applications.

### Supply the native bundle

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

## Commands

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

## Safe verification sequence

1. Start `bridge`, then test an HTTPS URL with a SOCKS client that sends an IP
   destination to `127.0.0.1:7891`.
2. Stop `bridge`, start `run` as Administrator with only `curl.exe` selected,
   and test the same URL without specifying a proxy in curl.
3. Only after both tests pass, replace the rule with the intended applications.

This sequence avoids intercepting an active remote-control client while the
bridge itself is still being tested.
