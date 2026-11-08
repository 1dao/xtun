$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$downloadDir = Join-Path $projectRoot 'build/wintun-0.14.1'
$binDir = Join-Path $projectRoot 'bin'
New-Item -ItemType Directory -Force -Path $downloadDir, $binDir | Out-Null
$archive = Join-Path $downloadDir 'wintun.zip'
$expectedHash = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
Invoke-WebRequest 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $archive
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash -ne $expectedHash) { throw 'Wintun archive SHA-256 mismatch' }
Expand-Archive -LiteralPath $archive -DestinationPath $downloadDir -Force
$dll = Join-Path $downloadDir 'wintun/bin/amd64/wintun.dll'
$signature = Get-AuthenticodeSignature -LiteralPath $dll
if ($signature.Status -ne 'Valid') { throw ('Wintun Authenticode signature is not valid: ' + $signature.Status) }
$destination = Join-Path $binDir 'wintun.dll'
if ((Test-Path -LiteralPath $destination) -and
    (Get-FileHash -LiteralPath $destination).Hash -ne (Get-FileHash -LiteralPath $dll).Hash) {
    throw 'A different wintun.dll already exists; inspect it before replacing'
}
Copy-Item -LiteralPath $dll -Destination $destination -Force
Copy-Item -LiteralPath (Join-Path $downloadDir 'wintun/LICENSE.txt') -Destination (Join-Path $binDir 'wintun-LICENSE.txt') -Force
'Verified official signed Wintun x64 DLL and license copied beside xtun.exe. No driver or adapter was installed.'
