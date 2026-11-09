$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$testDir = Join-Path $projectRoot ('build/probe-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDir | Out-Null
$exe = Join-Path $projectRoot 'bin/xtun.exe'
$linuxRoot = (& wsl -d archlinux --exec wslpath -a $projectRoot.Replace('\','/')).Trim()
$linuxDir = (& wsl -d archlinux --exec wslpath -a $testDir.Replace('\','/')).Trim()
$linuxAddresses = (& wsl -d archlinux --exec ip -j -4 address show dev eth0) | ConvertFrom-Json
$linuxIp = $linuxAddresses[0].addr_info[0].local
& $exe keygen (Join-Path $testDir 'peer.key')
if ($LASTEXITCODE -ne 0) { throw 'key generation failed' }
$serverConfig = "bind=0.0.0.0`nport=51216`nidentity=probe`npsk_file=peer.key`naddress=10.77.0.1`npeer_address=10.77.0.2`nrun_seconds=10"
$clientConfig = "endpoint=$linuxIp`nport=51216`nidentity=probe`npsk_file=peer.key`naddress=10.77.0.2`npeer_address=10.77.0.1`nrun_seconds=8"
[IO.File]::WriteAllText((Join-Path $testDir 'server.cfg'), $serverConfig)
[IO.File]::WriteAllText((Join-Path $testDir 'client.cfg'), $clientConfig)
$start = [Diagnostics.ProcessStartInfo]::new('wsl.exe')
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
foreach ($arg in @('-d','archlinux','--',($linuxRoot + '/bin/xtun'),'server',($linuxDir + '/server.cfg'),'--probe')) { $start.ArgumentList.Add($arg) }
$server = [Diagnostics.Process]::Start($start)
$serverOut = $server.StandardOutput.ReadToEndAsync()
$serverErr = $server.StandardError.ReadToEndAsync()
try {
    Start-Sleep -Milliseconds 500
    & $exe client (Join-Path $testDir 'client.cfg') --probe
    if ($LASTEXITCODE -ne 0) { throw 'Windows-to-Linux probe failed' }
    if (-not $server.WaitForExit(15000)) { throw 'Linux probe server did not exit' }
    $serverOut.Result
    $serverErr.Result
    if ($server.ExitCode -ne 0) { throw 'Linux probe server failed' }
    'PASS Windows/Linux authenticated UDP interoperability (no adapters or routes changed)'
} finally {
    if (-not $server.HasExited) { $server.Kill($true); $server.WaitForExit() }
    $server.Dispose()
    # Keep diagnostics; remove only the generated secret.
    [IO.File]::WriteAllBytes((Join-Path $testDir 'peer.key'), [byte[]]::new(0))
}
