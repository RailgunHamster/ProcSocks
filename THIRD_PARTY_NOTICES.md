# Third-party notices

This repository and its release artifacts intentionally contain no third-party
native binaries, NetFilter SDK headers or import libraries, driver files, or
vendored Netch source tree. The native files named below are optional,
user-supplied runtime components and are not licensed by the ProcSocks project.

The hashes in `native-components.lock.json` are compatibility and integrity
metadata. Publishing a filename, version, size, or hash does not grant a right
to copy or redistribute the corresponding file.

## Netch Redirector

ProcSocks can load `Redirector.bin`, an adapter built by the Netch project.

- Upstream project: <https://github.com/NetchX/Netch>
- Source used for the tested adapter: <https://github.com/NetchX/Netch/tree/1.9.7/Redirector>
- Upstream tag: `1.9.7`
- Upstream license: GNU General Public License v3.0
- License text: <https://github.com/NetchX/Netch/blob/1.9.7/LICENSE>

The Netch build links the adapter to the separately supplied NetFilter SDK API.
If you distribute an adapter binary, you are responsible for satisfying the
Netch license, including the applicable source-code and notice obligations, and
for confirming that the complete distribution is legally permitted. ProcSocks
does not redistribute the adapter.

## NetFilter SDK

ProcSocks can interoperate with these NetFilter SDK runtime components:

- `nfapi.dll`
- `nfdriver.sys` (installed locally as `netfilter2.sys` by the current backend)

NetFilter SDK is proprietary software distributed under its own terms. Obtain
the SDK or runtime files directly from the vendor under a license appropriate
for your use. In particular, access to a trial or evaluation build should not
be assumed to grant redistribution rights.

- Product site and downloads: <https://www.netfiltersdk.com/>
- License: <https://www.netfiltersdk.com/license.html>
- Purchase options: <https://www.netfiltersdk.com/buy_now.html>
- Driver signing documentation: <https://www.netfiltersdk.com/help/nfsdk_sockfilter/signing.html>

ProcSocks does not grant any rights in NetFilter SDK and is not affiliated with
or endorsed by its vendor.

## Distribution rule for this repository

Do not commit or attach `Redirector.bin`, `nfapi.dll`, `nfdriver.sys`, or
`netfilter2.sys` to this repository or its GitHub Releases. Users must supply
the native bundle locally. Maintainers should add support for a new bundle only
after compatibility testing and should record only its metadata in
`native-components.lock.json`.

This notice documents the project's dependency boundary; it is not legal
advice. Distributors remain responsible for reviewing and complying with all
applicable licenses.
