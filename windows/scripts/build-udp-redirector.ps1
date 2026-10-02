param([Parameter(Mandatory=$true)][string]$NetchSource, [string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
# User-supplied Netch 1.9.7 source and its licensed SDK dependencies are required.
$expected = '99480e99c3f5f4b0f6c4a32fdbbb4911be2a3687'
if ((git -C $NetchSource rev-parse HEAD) -ne $expected) { throw 'Expected Netch 1.9.7 source commit 99480e9.' }
& git -C $NetchSource diff --quiet HEAD -- Redirector
if ($LASTEXITCODE -ne 0) { throw 'Netch Redirector source has local modifications.' }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $PSScriptRoot '../driver-udp-build' }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force $OutputDirectory | Out-Null
$source = Join-Path $OutputDirectory 'Redirector'
if (Test-Path $source) { throw "Build directory already exists: $source; choose an empty output directory." }
Copy-Item (Join-Path $NetchSource 'Redirector') $source -Recurse
$event = Join-Path $source 'EventHandler.cpp'
$text = [IO.File]::ReadAllText($event)
$start = $text.IndexOf("`tif (DNSHandler::IsDNS((PSOCKADDR_IN6)target))", $text.IndexOf('void udpSend('))
$end = $text.IndexOf("`tudpContextLock.lock();", $start)
if ($start -lt 0 -or $end -lt 0) { throw 'Unexpected Netch UDP handler source.' }
# The original adapter bypasses all port 53 datagrams before checking process
# ownership. Let ordinary UDP handling proxy port 53 for selected processes;
# preserve the separate global DNS feature only when explicitly enabled.
$replacement = @'
	if (filterDNS && DNSHandler::IsDNS((PSOCKADDR_IN6)target))
	{
		UP += length;
		DNSHandler::CreateHandler(id, (PSOCKADDR_IN6)target, buffer, length, options);
		return;
	}

'@
$text = $text.Substring(0,$start) + $replacement + $text.Substring($end)
$receive = $text.IndexOf('void udpReceiveHandler(')
$prefix = $text.Substring(0,$receive)
$suffix = $text.Substring($receive).Replace('char buffer[1458];','char buffer[65535];').Replace('if (length == 0 || length == SOCKET_ERROR)','if (length == SOCKET_ERROR)')
$text = $prefix + $suffix
[IO.File]::WriteAllText($event,$text)
# Validate relay source and complete headers before decoding; use memmove for
# the overlapping header removal, and retain valid zero-length UDP payloads.
$helper = Join-Path $source 'SocksHelper.cpp'
$text = [IO.File]::ReadAllText($helper)
$read = $text.IndexOf('int SocksHelper::UDP::Read(')
if ($read -lt 0) { throw 'Unexpected Netch UDP reader source.' }
$reader = @'
int SocksHelper::UDP::Read(PSOCKADDR_IN6 target, char* buffer, int length, PTIMEVAL timeout)
{
    if (this->udpSocket == INVALID_SOCKET) return SOCKET_ERROR;
    if (timeout != NULL)
    {
        fd_set fds;
        FD_ZERO(&fds); FD_SET(this->udpSocket, &fds);
        int ready = select(0, &fds, NULL, NULL, timeout);
        if (ready == 0 || ready == SOCKET_ERROR) return ready;
    }
    while (true)
    {
        SOCKADDR_IN6 peer = {};
        int peerLength = sizeof(peer);
        int size = recvfrom(this->udpSocket, buffer, length, 0, (PSOCKADDR)&peer, &peerLength);
        if (size == SOCKET_ERROR)
        {
            if (WSAGetLastError() == WSAEMSGSIZE) continue;
            return SOCKET_ERROR;
        }
        if (peer.sin6_family != this->address.sin6_family) continue;
        if (peer.sin6_family == AF_INET)
        {
            auto a = (PSOCKADDR_IN)&peer;
            auto b = (PSOCKADDR_IN)&this->address;
            if (a->sin_port != b->sin_port || a->sin_addr.s_addr != b->sin_addr.s_addr) continue;
        }
        else if (peer.sin6_family == AF_INET6)
        {
            if (peer.sin6_port != this->address.sin6_port || memcmp(&peer.sin6_addr, &this->address.sin6_addr, 16) != 0) continue;
        }
        else continue;
        if (size < 4 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0) continue;
        SOCKADDR_IN6 addr = {};
        int header = 0;
        if (buffer[3] == 1 && size >= 10)
        {
            auto ipv4 = (PSOCKADDR_IN)&addr;
            ipv4->sin_family = AF_INET;
            memcpy(&ipv4->sin_addr, buffer + 4, 4);
            memcpy(&ipv4->sin_port, buffer + 8, 2);
            if (ipv4->sin_port == 0) continue;
            header = 10;
        }
        else if (buffer[3] == 4 && size >= 22)
        {
            addr.sin6_family = AF_INET6;
            memcpy(&addr.sin6_addr, buffer + 4, 16);
            memcpy(&addr.sin6_port, buffer + 20, 2);
            if (addr.sin6_port == 0) continue;
            header = 22;
        }
        else continue;
        memmove(buffer, buffer + header, size - header);
        if (target != NULL) memcpy(target, &addr, sizeof(addr));
        return size - header;
    }
}
'@
[IO.File]::WriteAllText($helper,$text.Substring(0,$read) + $reader)
$redirector = Join-Path $source 'Redirector.cpp'
[IO.File]::AppendAllText($redirector, "`nextern `"C`" __declspec(dllexport) BOOL __cdecl aio_process_udp_dns() { return TRUE; }`n")
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$msbuild = & $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
if (-not $msbuild) { throw 'Visual Studio C++ Build Tools with MSBuild are required.' }
# Reproducible PE output; avoid absolute PDB paths and link timestamps.
$project = Join-Path $source 'Redirector.vcxproj'
[xml]$xml = [IO.File]::ReadAllText($project)
$ns = $xml.DocumentElement.NamespaceURI
foreach ($group in $xml.Project.ItemDefinitionGroup) {
    foreach ($name in @('ClCompile','Link')) {
        $node = $group.$name
        if (-not $node) { continue }
        $option = $xml.CreateElement('AdditionalOptions',$ns)
        $option.InnerText = '/Brepro %(AdditionalOptions)'
        $node.AppendChild($option) | Out-Null
    }
    if ($group.Link.GenerateDebugInformation) { $group.Link.GenerateDebugInformation = 'false' }
    if ($group.ClCompile.DebugInformationFormat) { $group.ClCompile.DebugInformationFormat = 'None' }
}
$xml.Save($project)
& $msbuild (Join-Path $source 'Redirector.vcxproj') /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143 /p:AdditionalOptions=/Brepro /verbosity:minimal
if ($LASTEXITCODE -ne 0) { throw 'Redirector build failed.' }
$dll = Join-Path $source 'bin/Release/Redirector.dll'
if (-not (Test-Path $dll)) { $dll = Join-Path $source 'bin/Release/Redirector.bin' }
if (-not (Test-Path $dll)) { throw 'Redirector build output missing.' }
$target = Join-Path $OutputDirectory 'Redirector.bin'
Copy-Item $dll $target
Get-Item $target | Select-Object FullName,Length
Get-FileHash $target -Algorithm SHA256
Write-Host 'Keep nfapi.dll and nfdriver.sys from the locked Netch 1.9.7 bundle. Do not bundle SDK binaries in Git.'
