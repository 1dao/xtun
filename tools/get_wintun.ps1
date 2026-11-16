$ErrorActionPreference = 'Stop'
# A build launched from PowerShell 7 can leave its modules ahead of Windows
# PowerShell's modules in PSModulePath. Select the matching built-ins explicitly.
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    foreach ($module in 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Security', 'Microsoft.PowerShell.Archive') {
        Import-Module (Join-Path $PSHOME "Modules/$module") -Force
    }
}
$projectRoot = Split-Path -Parent $PSScriptRoot
$downloadDir = Join-Path $projectRoot 'build/wintun-0.14.1'
$binDir = Join-Path $projectRoot 'bin'
$vendorDir = Join-Path $projectRoot '3rd/dll'
$cachedDll = Join-Path $vendorDir 'wintun.dll'
$dllHash = 'E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE'
if (Test-Path -LiteralPath $cachedDll) {
    if ((Get-FileHash -LiteralPath $cachedDll).Hash -ne $dllHash) { throw 'Cached Wintun x64 DLL SHA-256 mismatch' }
    if ((Get-AuthenticodeSignature -LiteralPath $cachedDll).Status -ne 'Valid') { throw 'Cached Wintun signature is not valid' }
    if (Test-Path -LiteralPath (Join-Path $vendorDir 'LICENSE.txt')) {
        New-Item -ItemType Directory -Force -Path $binDir | Out-Null
        Copy-Item -LiteralPath (Join-Path $vendorDir 'LICENSE.txt') -Destination (Join-Path $binDir 'wintun-LICENSE.txt') -Force
        'Verified cached official signed Wintun x64 DLL.'
        exit 0
    }
}
New-Item -ItemType Directory -Force -Path $downloadDir, $binDir, $vendorDir | Out-Null
$archive = Join-Path $downloadDir 'wintun.zip'
$expectedHash = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
Invoke-WebRequest 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $archive
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash -ne $expectedHash) { throw 'Wintun archive SHA-256 mismatch' }
Expand-Archive -LiteralPath $archive -DestinationPath $downloadDir -Force
$dll = Join-Path $downloadDir 'wintun/bin/amd64/wintun.dll'
$signature = Get-AuthenticodeSignature -LiteralPath $dll
if ($signature.Status -ne 'Valid') { throw ('Wintun Authenticode signature is not valid: ' + $signature.Status) }
$destination = $cachedDll
if ((Test-Path -LiteralPath $destination) -and
    (Get-FileHash -LiteralPath $destination).Hash -ne (Get-FileHash -LiteralPath $dll).Hash) {
    throw 'A different wintun.dll already exists; inspect it before replacing'
}
Copy-Item -LiteralPath $dll -Destination $destination -Force
Copy-Item -LiteralPath (Join-Path $downloadDir 'wintun/LICENSE.txt') -Destination (Join-Path $vendorDir 'LICENSE.txt') -Force
Copy-Item -LiteralPath (Join-Path $downloadDir 'wintun/LICENSE.txt') -Destination (Join-Path $binDir 'wintun-LICENSE.txt') -Force
'Verified official signed Wintun x64 DLL and license saved in 3rd/dll. No driver or adapter was installed.'
