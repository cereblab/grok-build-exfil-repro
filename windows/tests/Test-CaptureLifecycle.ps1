#Requires -Version 7.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

if (-not $IsWindows) {
    throw 'This lifecycle smoke test supports Windows only.'
}

$windowsRoot = Split-Path $PSScriptRoot -Parent
$repositoryRoot = Split-Path $windowsRoot -Parent
$python = Join-Path $windowsRoot '.venv\Scripts\python.exe'
$captureScript = Join-Path $windowsRoot 'scripts\Start-EgressCapture.ps1'
$pwsh = (Get-Process -Id $PID).Path
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Documented virtual-environment Python is missing: $python"
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'egress-capture-lifecycle-' + [Guid]::NewGuid().ToString('N')
)
$null = [System.IO.Directory]::CreateDirectory($testRoot)
$fakeMitmdump = Join-Path $testRoot 'fake_mitmdump.py'
$fakeSource = @'
import os
import sys
import time

if "--version" in sys.argv:
    print("Mitmproxy: 12.2.3")
    print("Python: 3.12.10")
    raise SystemExit(0)

mode = os.environ.get("EGRESS_TEST_MITMDUMP_MODE", "exit_immediately")
print(f"durable stdout marker: {mode}", flush=True)
print(f"durable stderr marker: {mode}", file=sys.stderr, flush=True)
if mode == "ca_generation_failure":
    raise SystemExit(23)
if mode == "exit_immediately":
    raise SystemExit(31)
if mode == "never_bind":
    time.sleep(120)
    raise SystemExit(0)
raise SystemExit(41)
'@
[System.IO.File]::WriteAllText($fakeMitmdump, $fakeSource, $Utf8NoBom)

function Assert-True {
    param([Parameter(Mandatory)][bool] $Condition, [Parameter(Mandatory)][string] $Message)
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

function Get-FreeLoopbackPort {
    $listener = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Loopback,
        0
    )
    $listener.Start()
    try { return ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

function Test-LoopbackListener {
    param([Parameter(Mandatory)][int] $Port)
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $task = $client.ConnectAsync('127.0.0.1', $Port)
        return $task.Wait(250) -and $client.Connected
    }
    catch { return $false }
    finally { $client.Dispose() }
}

function New-TestCertificate {
    param([Parameter(Mandatory)][string] $ConfigDirectory)
    $null = [System.IO.Directory]::CreateDirectory($ConfigDirectory)
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    try {
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=Egress Capture Lifecycle $([Guid]::NewGuid().ToString('N'))",
            $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $certificate = $request.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddMinutes(-1),
            [DateTimeOffset]::UtcNow.AddHours(1)
        )
        try {
            $cerPath = Join-Path $ConfigDirectory 'mitmproxy-ca-cert.cer'
            $pemPath = Join-Path $ConfigDirectory 'mitmproxy-ca-cert.pem'
            [System.IO.File]::WriteAllBytes(
                $cerPath,
                $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            )
            [System.IO.File]::WriteAllText($pemPath, $certificate.ExportCertificatePem(), $Utf8NoBom)
            return [ordered] @{
                cer_path = $cerPath
                pem_path = $pemPath
                thumbprint = $certificate.Thumbprint
            }
        }
        finally { $certificate.Dispose() }
    }
    finally { $rsa.Dispose() }
}

function Get-RootCertificateMatchCount {
    param([Parameter(Mandatory)][string] $Thumbprint)
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::Root,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        return $store.Certificates.Find(
            [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
            $Thumbprint,
            $false
        ).Count
    }
    finally {
        $store.Close()
        $store.Dispose()
    }
}

function Start-CaptureChild {
    param(
        [Parameter(Mandatory)][string] $RunDirectory,
        [Parameter(Mandatory)][string] $ConfigDirectory,
        [Parameter(Mandatory)][string] $StopFile,
        [Parameter(Mandatory)][int] $Port,
        [string] $Mode,
        [string] $Executable,
        [string[]] $PrefixArguments = @(),
        [switch] $SkipCertificateImport,
        [int] $CertificateGenerationTimeoutSeconds = 3,
        [int] $CertificateOperationTimeoutSeconds = 5,
        [int] $StartupTimeoutSeconds = 3,
        [int] $ShutdownTimeoutSeconds = 3
    )
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $pwsh
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $venvScripts = Split-Path $python -Parent
    $startInfo.Environment['PATH'] = "$venvScripts$([System.IO.Path]::PathSeparator)$($startInfo.Environment['PATH'])"
    if (-not [string]::IsNullOrWhiteSpace($Mode)) {
        $startInfo.Environment['EGRESS_TEST_MITMDUMP_MODE'] = $Mode
    }
    foreach ($argument in @(
        '-NoProfile', '-File', $captureScript,
        '-RunDirectory', $RunDirectory,
        '-ListenPort', $Port.ToString(),
        '-StopFile', $StopFile,
        '-MitmproxyConfigDirectory', $ConfigDirectory,
        '-CertificateGenerationTimeoutSeconds', $CertificateGenerationTimeoutSeconds.ToString(),
        '-CertificateOperationTimeoutSeconds', $CertificateOperationTimeoutSeconds.ToString(),
        '-StartupTimeoutSeconds', $StartupTimeoutSeconds.ToString(),
        '-ShutdownTimeoutSeconds', $ShutdownTimeoutSeconds.ToString()
    )) { $startInfo.ArgumentList.Add($argument) }
    if (-not [string]::IsNullOrWhiteSpace($Executable)) {
        $startInfo.ArgumentList.Add('-MitmdumpExecutable')
        $startInfo.ArgumentList.Add($Executable)
    }
    if (@($PrefixArguments).Count -gt 0) {
        $startInfo.ArgumentList.Add('-MitmdumpPrefixArguments')
        foreach ($prefix in @($PrefixArguments)) { $startInfo.ArgumentList.Add($prefix) }
    }
    if ($SkipCertificateImport) { $startInfo.ArgumentList.Add('-SkipCertificateImport') }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw 'Capture lifecycle child process did not start.' }
    return [pscustomobject] @{
        Process = $process
        StdoutTask = $process.StandardOutput.ReadToEndAsync()
        StderrTask = $process.StandardError.ReadToEndAsync()
    }
}

function Wait-CaptureChild {
    param([Parameter(Mandatory)] $Child, [int] $TimeoutSeconds = 40)
    if (-not $Child.Process.WaitForExit($TimeoutSeconds * 1000)) {
        $Child.Process.Kill($true)
        $Child.Process.WaitForExit()
        throw "Capture lifecycle child exceeded $TimeoutSeconds seconds."
    }
    return [pscustomobject] @{
        ExitCode = $Child.Process.ExitCode
        Stdout = $Child.StdoutTask.GetAwaiter().GetResult()
        Stderr = $Child.StderrTask.GetAwaiter().GetResult()
    }
}

function Assert-ManifestValid {
    param([Parameter(Mandatory)][string] $RunDirectory)
    $previous = [Environment]::GetEnvironmentVariable('PYTHONPATH', 'Process')
    [Environment]::SetEnvironmentVariable('PYTHONPATH', $windowsRoot, 'Process')
    try {
        $output = @(& $python -m analysis.verify_manifest $RunDirectory 2>&1)
        Assert-True ($LASTEXITCODE -eq 0) "Manifest verification failed: $($output -join [Environment]::NewLine)"
    }
    finally { [Environment]::SetEnvironmentVariable('PYTHONPATH', $previous, 'Process') }
}

function Assert-FailureArtifacts {
    param(
        [Parameter(Mandatory)][string] $RunDirectory,
        [Parameter(Mandatory)][string] $ExpectedStage,
        [Parameter(Mandatory)][int] $Port,
        [bool] $ExpectPortReleased = $true
    )
    foreach ($relative in @(
        'run.json',
        'startup-journal.jsonl',
        'mitmdump.stdout.log',
        'mitmdump.stderr.log',
        'startup-failure.json',
        'evidence-manifest.json',
        'requests.jsonl',
        'websockets.jsonl'
    )) {
        Assert-True (Test-Path -LiteralPath (Join-Path $RunDirectory $relative) -PathType Leaf) "Missing failure artifact $relative"
    }
    $run = Get-Content -LiteralPath (Join-Path $RunDirectory 'run.json') -Raw | ConvertFrom-Json
    $failure = Get-Content -LiteralPath (Join-Path $RunDirectory 'startup-failure.json') -Raw | ConvertFrom-Json
    Assert-True ($run.startup_status -eq 'CAPTURE_START_FAILED') 'Failure run did not use CAPTURE_START_FAILED.'
    Assert-True ($run.proxy_started -eq $false) 'Failure run incorrectly recorded proxy_started=true.'
    Assert-True ($failure.failure_stage -eq $ExpectedStage) "Expected failure stage $ExpectedStage, got $($failure.failure_stage)."
    Assert-True ($failure.cleanup.process_stopped -ne $false) 'Failure cleanup did not stop the started process.'
    Assert-True ($failure.cleanup.ca_removal_succeeded -eq $true) 'Failure cleanup did not complete CA removal handling.'
    Assert-True ((Get-Item -LiteralPath (Join-Path $RunDirectory 'requests.jsonl')).Length -eq 0) 'Failed run unexpectedly captured HTTP metadata.'
    Assert-True ((Get-Item -LiteralPath (Join-Path $RunDirectory 'websockets.jsonl')).Length -eq 0) 'Failed run unexpectedly captured WebSocket metadata.'
    Assert-True ((-not (Test-LoopbackListener -Port $Port)) -eq $ExpectPortReleased) 'Unexpected final port state.'
    Assert-ManifestValid -RunDirectory $RunDirectory
}

function Invoke-FailureCase {
    param(
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][string] $ExpectedStage,
        [Parameter(Mandatory)][string] $Mode,
        [ValidateSet('none', 'valid', 'invalid')][string] $Certificate = 'valid',
        [switch] $MissingExecutable,
        [switch] $ImportCertificate,
        [switch] $OccupyPort
    )
    $caseRoot = Join-Path $testRoot $Name
    $runDirectory = Join-Path $caseRoot 'run'
    $configDirectory = Join-Path $caseRoot 'config'
    $stopFile = Join-Path $caseRoot 'stop.signal'
    $null = [System.IO.Directory]::CreateDirectory($caseRoot)
    $certificateInfo = $null
    if ($Certificate -eq 'valid') {
        $certificateInfo = New-TestCertificate -ConfigDirectory $configDirectory
        Assert-True ((Get-RootCertificateMatchCount -Thumbprint $certificateInfo.thumbprint) -eq 0) 'Fixture certificate already existed in CurrentUser Root.'
    }
    elseif ($Certificate -eq 'invalid') {
        $null = [System.IO.Directory]::CreateDirectory($configDirectory)
        [System.IO.File]::WriteAllText((Join-Path $configDirectory 'mitmproxy-ca-cert.cer'), 'not a certificate', $Utf8NoBom)
        [System.IO.File]::WriteAllText((Join-Path $configDirectory 'mitmproxy-ca-cert.pem'), 'not a certificate', $Utf8NoBom)
    }
    $port = Get-FreeLoopbackPort
    $occupier = $null
    if ($OccupyPort) {
        $occupier = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $port)
        $occupier.Start()
    }
    $executable = if ($MissingExecutable) { Join-Path $caseRoot 'missing-mitmdump.exe' } else { $python }
    $prefix = if ($MissingExecutable) { @() } else { @($fakeMitmdump) }
    $child = $null
    try {
        $child = Start-CaptureChild `
            -RunDirectory $runDirectory `
            -ConfigDirectory $configDirectory `
            -StopFile $stopFile `
            -Port $port `
            -Mode $Mode `
            -Executable $executable `
            -PrefixArguments $prefix `
            -SkipCertificateImport:(-not $ImportCertificate)
        $result = Wait-CaptureChild -Child $child
        Assert-True ($result.ExitCode -ne 0) "$Name unexpectedly succeeded."
        Assert-FailureArtifacts -RunDirectory $runDirectory -ExpectedStage $ExpectedStage -Port $port -ExpectPortReleased:(-not $OccupyPort)
        if ($null -ne $certificateInfo) {
            Assert-True ((Get-RootCertificateMatchCount -Thumbprint $certificateInfo.thumbprint) -eq 0) "$Name left a fixture certificate trusted."
            Assert-True (Test-Path -LiteralPath $certificateInfo.cer_path -PathType Leaf) "$Name removed the fixture CER file."
            Assert-True (Test-Path -LiteralPath $certificateInfo.pem_path -PathType Leaf) "$Name removed the fixture PEM file."
        }
        if ($Mode -in @('exit_immediately', 'never_bind')) {
            $stdout = Get-Content -LiteralPath (Join-Path $runDirectory 'mitmdump.stdout.log') -Raw
            $stderr = Get-Content -LiteralPath (Join-Path $runDirectory 'mitmdump.stderr.log') -Raw
            Assert-True ($stdout.Contains("durable stdout marker: $Mode")) "$Name lost durable stdout."
            Assert-True ($stderr.Contains("durable stderr marker: $Mode")) "$Name lost durable stderr."
        }
        if ($Mode -eq 'ca_generation_failure') {
            $stdout = Get-Content -LiteralPath (Join-Path $runDirectory 'ca-generation.stdout.log') -Raw
            $stderr = Get-Content -LiteralPath (Join-Path $runDirectory 'ca-generation.stderr.log') -Raw
            Assert-True ($stdout.Contains('durable stdout marker: ca_generation_failure')) 'CA generation stdout was not durable.'
            Assert-True ($stderr.Contains('durable stderr marker: ca_generation_failure')) 'CA generation stderr was not durable.'
        }
        Write-Host "PASS: $Name"
    }
    finally {
        if ($null -ne $child) {
            if (-not $child.Process.HasExited) {
                $child.Process.Kill($true)
                $child.Process.WaitForExit()
            }
            $child.Process.Dispose()
        }
        if ($null -ne $occupier) {
            $occupier.Stop()
            Assert-True (-not (Test-LoopbackListener -Port $port)) "$Name port remained occupied after the unrelated fixture listener stopped."
        }
    }
}

try {
    Invoke-FailureCase -Name 'missing-executable' -ExpectedStage 'mitmdump_executable_resolution' -Mode 'unused' -Certificate 'none' -MissingExecutable
    Invoke-FailureCase -Name 'immediate-exit' -ExpectedStage 'port_listening_checks' -Mode 'exit_immediately'
    Invoke-FailureCase -Name 'never-binds' -ExpectedStage 'startup_timeout' -Mode 'never_bind'
    Invoke-FailureCase -Name 'port-occupied' -ExpectedStage 'port_availability_check' -Mode 'unused' -OccupyPort
    Invoke-FailureCase -Name 'ca-generation-failure' -ExpectedStage 'ca_generation' -Mode 'ca_generation_failure' -Certificate 'none'
    Invoke-FailureCase -Name 'ca-import-failure' -ExpectedStage 'ca_import' -Mode 'unused' -Certificate 'invalid' -ImportCertificate

    # Controlled local success fixture: use a fresh temporary CA, import it only for this
    # run, confirm durable readiness, then verify exact CurrentUser Root cleanup.
    $successRoot = Join-Path $testRoot 'controlled-real-mitmproxy'
    $successRun = Join-Path $successRoot 'run'
    $successConfig = Join-Path $successRoot 'config'
    $successStop = Join-Path $successRoot 'stop.signal'
    $null = [System.IO.Directory]::CreateDirectory($successRoot)
    $successPort = Get-FreeLoopbackPort
    $successChild = Start-CaptureChild `
        -RunDirectory $successRun `
        -ConfigDirectory $successConfig `
        -StopFile $successStop `
        -Port $successPort `
        -CertificateGenerationTimeoutSeconds 20 `
        -CertificateOperationTimeoutSeconds 10 `
        -StartupTimeoutSeconds 20 `
        -ShutdownTimeoutSeconds 10
    try {
        $ready = $false
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds(40)
        while ([DateTimeOffset]::UtcNow -lt $deadline -and -not $successChild.Process.HasExited) {
            $runPath = Join-Path $successRun 'run.json'
            if (Test-Path -LiteralPath $runPath -PathType Leaf) {
                try {
                    $run = Get-Content -LiteralPath $runPath -Raw | ConvertFrom-Json
                    if ($run.proxy_started -eq $true -and
                        $run.startup_status -eq 'PROXY_RUNNING' -and
                        (Test-LoopbackListener -Port $successPort)) {
                        $ready = $true
                        break
                    }
                }
                catch { }
            }
            Start-Sleep -Milliseconds 200
        }
        if (-not $ready) {
            if (-not $successChild.Process.HasExited) {
                [System.IO.File]::WriteAllText($successStop, "stop`n", $Utf8NoBom)
                $null = $successChild.Process.WaitForExit(15000)
            }
            $runState = if (Test-Path -LiteralPath (Join-Path $successRun 'run.json')) {
                Get-Content -LiteralPath (Join-Path $successRun 'run.json') -Raw
            } else { '<run.json missing>' }
            $failureState = if (Test-Path -LiteralPath (Join-Path $successRun 'startup-failure.json')) {
                Get-Content -LiteralPath (Join-Path $successRun 'startup-failure.json') -Raw
            } else { '<startup-failure.json missing>' }
            $journalState = if (Test-Path -LiteralPath (Join-Path $successRun 'startup-journal.jsonl')) {
                (Get-Content -LiteralPath (Join-Path $successRun 'startup-journal.jsonl') -Tail 12) -join [Environment]::NewLine
            } else { '<startup journal missing>' }
            throw "Controlled real-mitmproxy fixture did not publish durable readiness. run=$runState failure=$failureState journal_tail=$journalState"
        }
        [System.IO.File]::WriteAllText($successStop, "stop`n", $Utf8NoBom)
        $successResult = Wait-CaptureChild -Child $successChild -TimeoutSeconds 35
        Assert-True ($successResult.ExitCode -eq 0) "Controlled fixture failed: $($successResult.Stderr) $($successResult.Stdout)"
        $successMetadata = Get-Content -LiteralPath (Join-Path $successRun 'run.json') -Raw | ConvertFrom-Json
        Assert-True ($successMetadata.startup_status -eq 'CAPTURE_COMPLETE') 'Controlled fixture did not complete capture lifecycle.'
        Assert-True ($successMetadata.ca_imported_by_run -eq $true) 'Controlled fixture did not record its CA import.'
        Assert-True ($successMetadata.ca_removed_by_run -eq $true) 'Controlled fixture did not record its CA removal.'
        Assert-True (-not [string]::IsNullOrWhiteSpace([string] $successMetadata.proxy_termination_timestamp_utc)) 'Controlled fixture did not record proxy termination time.'
        Assert-True (-not [string]::IsNullOrWhiteSpace([string] $successMetadata.listener_release_timestamp_utc)) 'Controlled fixture did not record listener release time.'
        $successJournal = @(Get-Content -LiteralPath (Join-Path $successRun 'startup-journal.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
        Assert-True ($null -ne ($successJournal | Where-Object { $_.stage -eq 'proxy_termination' -and $_.event -eq 'completed' } | Select-Object -First 1)) 'Controlled fixture did not journal proxy termination.'
        Assert-True ($null -ne ($successJournal | Where-Object { $_.stage -eq 'listener_release' -and $_.event -eq 'completed' } | Select-Object -First 1)) 'Controlled fixture did not journal listener release.'
        Assert-True ((Get-RootCertificateMatchCount -Thumbprint $successMetadata.ca_thumbprint) -eq 0) 'Controlled fixture left its CA trusted.'
        Assert-True (Test-Path -LiteralPath (Join-Path $successConfig 'mitmproxy-ca-cert.cer') -PathType Leaf) 'Controlled fixture removed its CER evidence file.'
        Assert-True (Test-Path -LiteralPath (Join-Path $successConfig 'mitmproxy-ca-cert.pem') -PathType Leaf) 'Controlled fixture removed its PEM evidence file.'
        Assert-ManifestValid -RunDirectory $successRun
        Assert-True (-not (Test-LoopbackListener -Port $successPort)) 'Controlled fixture did not release its port.'
        Write-Host "PASS: controlled real mitmproxy import/start/stop/removal on port $successPort"
    }
    finally {
        if (-not $successChild.Process.HasExited) {
            $successChild.Process.Kill($true)
            $successChild.Process.WaitForExit()
        }
        $successChild.Process.Dispose()
    }
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        $fullTestRoot = [System.IO.Path]::GetFullPath($testRoot)
        $fullTempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        if (-not $fullTempRoot.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
            $fullTempRoot += [System.IO.Path]::DirectorySeparatorChar
        }
        $leaf = Split-Path -Leaf $fullTestRoot
        if (-not $fullTestRoot.StartsWith($fullTempRoot, [StringComparison]::OrdinalIgnoreCase) -or
            -not $leaf.StartsWith('egress-capture-lifecycle-', [StringComparison]::Ordinal)) {
            throw "Refusing unsafe lifecycle cleanup target: $fullTestRoot"
        }
        Remove-Item -LiteralPath $fullTestRoot -Recurse -Force
    }
}

Write-Host 'PASS: all offline capture lifecycle scenarios completed.'
