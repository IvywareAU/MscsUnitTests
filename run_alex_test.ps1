# Copyright © 2026 Khrustal & Mann
#              MELBOURNE, VICTORIA, AUSTRALIA, 3000
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
#
# run_alex_test.ps1 — Windows twin of run_alex_test.sh: orchestrate the two-process AlexTest
# (LinuxPortPlan Phase-3 exit) over native-IOCP loopback TCP.
#
# Launches the server, then the client, and asserts BOTH processes exit 0. The server's exit 0
# is the authoritative proof that the client's BCast crossed the process boundary over TCP.
#
# Usage: run_alex_test.ps1 <path\to\alex_test.exe> [port]
param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [int]$Port = 7811
)
$ErrorActionPreference = 'Stop'
Write-Host "=== two-process AlexTest: $Exe on 127.0.0.1:$Port ==="

$srvLog = Join-Path $env:TEMP 'alex_server.log'
$cliLog = Join-Path $env:TEMP 'alex_client.log'

# Start the server; it self-terminates on BCast receipt or after its internal timeout.
$srv = Start-Process -FilePath $Exe -ArgumentList @('server', "$Port") `
        -RedirectStandardOutput $srvLog -RedirectStandardError "$srvLog.err" `
        -PassThru -NoNewWindow
# Cache the process handle NOW: without this, Start-Process -PassThru leaves .ExitCode null
# after the process exits (a well-known PowerShell quirk).
[void]$srv.Handle
Write-Host "server launched (pid=$($srv.Id)); waiting for bind/listen..."
Start-Sleep -Milliseconds 1500

# Run the client to completion.
$cli = Start-Process -FilePath $Exe -ArgumentList @('send', '127.0.0.1', "$Port") `
        -RedirectStandardOutput $cliLog -RedirectStandardError "$cliLog.err" `
        -PassThru -NoNewWindow -Wait
$cliRc = $cli.ExitCode
Write-Host "client exit=$cliRc"

# Reap the server (it should exit on its own once it got the BCast).
if (-not $srv.WaitForExit(15000)) { Write-Host "server did not self-exit in 15s -- killing"; $srv.Kill() }
$srvRc = $srv.ExitCode
Write-Host "server exit=$srvRc"

Write-Host "----- server log -----"; if (Test-Path $srvLog) { Get-Content $srvLog }
Write-Host "----- client log -----"; if (Test-Path $cliLog) { Get-Content $cliLog }
Write-Host "----------------------"

if ($srvRc -eq 0 -and $cliRc -eq 0) {
    Write-Host "RESULT: PASS (server received the client's BCast; both processes exit 0)"
    exit 0
} else {
    Write-Host "RESULT: FAIL (server_rc=$srvRc client_rc=$cliRc)"
    exit 1
}
