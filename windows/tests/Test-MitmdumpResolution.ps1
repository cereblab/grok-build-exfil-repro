#Requires -Version 7.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

if (-not $IsWindows) { throw 'This test supports Windows only.' }

$windowsRoot = Split-Path $PSScriptRoot -Parent
$captureScript = Join-Path $windowsRoot 'scripts\Start-EgressCapture.ps1'
$venvScripts = Join-Path $windowsRoot '.venv\Scripts'
$venvPython = Join-Path $venvScripts 'python.exe'
$venvMitmdump = Join-Path $venvScripts 'mitmdump.exe'
$pwsh = (Get-Process -Id $PID).Path
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

foreach ($path in @($captureScript, $venvPython, $venvMitmdump, $pwsh)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required test path is missing: $path" }
}

function Assert-True {
    param([Parameter(Mandatory)][bool] $Condition, [Parameter(Mandatory)][string] $Message)
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
}

function Get-FreeLoopbackPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
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

function Start-ResolutionChild {
    param(
        [Parameter(Mandatory)][string] $RunDirectory,
        [Parameter(Mandatory)][string] $ConfigDirectory,
        [Parameter(Mandatory)][string] $StopFile,
        [Parameter(Mandatory)][int] $Port,
        [Parameter(Mandatory)][string] $MitmdumpExecutable
    )

    $python = Get-Command python -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $git = Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $pwsh
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    # Deliberately construct a child PATH without the harness venv. The child
    # can locate Python and Git, but only the explicit mitmdump path may select
    # the recorder executable.
    $childPath = @(
        (Split-Path $python.Source -Parent),
        (Split-Path $git.Source -Parent),
        (Join-Path $env:SystemRoot 'System32'),
        $env:SystemRoot
    ) -join [System.IO.Path]::PathSeparator
    Assert-True (-not ($childPath -split ';' | Where-Object { $_ -eq $venvScripts })) 'Focused child PATH unexpectedly contains the harness venv.'
    $startInfo.Environment['PATH'] = $childPath
    foreach ($argument in @(
        '-NoProfile', '-File', $captureScript,
        '-RunDirectory', $RunDirectory,
        '-ListenPort', $Port.ToString(),
        '-StopFile', $StopFile,
        '-MitmproxyConfigDirectory', $ConfigDirectory,
        '-MitmdumpExecutable', $MitmdumpExecutable,
        '-SkipCertificateImport',
        '-StartupTimeoutSeconds', '20',
        '-ShutdownTimeoutSeconds', '10'
    )) { $startInfo.ArgumentList.Add($argument) }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw 'Focused resolution child did not start.' }
    return [pscustomobject]@{
        Process = $process
        StdoutTask = $process.StandardOutput.ReadToEndAsync()
        StderrTask = $process.StandardError.ReadToEndAsync()
    }
}

function Wait-ResolutionChild {
    param([Parameter(Mandatory)] $Child, [int] $TimeoutSeconds = 45)
    if (-not $Child.Process.WaitForExit($TimeoutSeconds * 1000)) {
        $Child.Process.Kill($true)
        $Child.Process.WaitForExit()
        throw "Focused resolution child exceeded $TimeoutSeconds seconds."
    }
    return [pscustomobject]@{
        ExitCode = $Child.Process.ExitCode
        Stdout = $Child.StdoutTask.GetAwaiter().GetResult()
        Stderr = $Child.StderrTask.GetAwaiter().GetResult()
    }
}

function Assert-ManifestValid {
    param([Parameter(Mandatory)][string] $RunDirectory)
    $previousPythonPath = [Environment]::GetEnvironmentVariable('PYTHONPATH', 'Process')
    [Environment]::SetEnvironmentVariable('PYTHONPATH', $windowsRoot, 'Process')
    try {
        $output = @(& $venvPython -m analysis.verify_manifest $RunDirectory 2>&1)
        Assert-True ($LASTEXITCODE -eq 0) "Manifest verification failed: $($output -join [Environment]::NewLine)"
    }
    finally { [Environment]::SetEnvironmentVariable('PYTHONPATH', $previousPythonPath, 'Process') }
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('egress-mitmdump-resolution-' + [Guid]::NewGuid().ToString('N'))
$null = [System.IO.Directory]::CreateDirectory($testRoot)
try {
    $missingRoot = Join-Path $testRoot 'missing-explicit-path'
    $missingRun = Join-Path $missingRoot 'run'
    $missingChild = Start-ResolutionChild `
        -RunDirectory $missingRun `
        -ConfigDirectory (Join-Path $missingRoot 'config') `
        -StopFile (Join-Path $missingRoot 'stop.signal') `
        -Port (Get-FreeLoopbackPort) `
        -MitmdumpExecutable (Join-Path $missingRoot 'does-not-exist.exe')
    try {
        $missingResult = Wait-ResolutionChild -Child $missingChild
        Assert-True ($missingResult.ExitCode -ne 0) 'Missing explicit mitmdump path unexpectedly succeeded.'
    }
    finally { $missingChild.Process.Dispose() }
    $missingMetadata = Get-Content -LiteralPath (Join-Path $missingRun 'run.json') -Raw | ConvertFrom-Json
    $missingJournal = @(Get-Content -LiteralPath (Join-Path $missingRun 'startup-journal.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
    Assert-True ($missingMetadata.failure_stage -eq 'mitmdump_executable_resolution') 'Missing explicit path did not fail at executable resolution.'
    Assert-True ($missingMetadata.ca_imported_by_run -eq $false) 'Missing explicit path reached CA import.'
    Assert-True ($null -eq ($missingJournal | Where-Object { $_.stage -eq 'ca_import' -and $_.event -eq 'started' } | Select-Object -First 1)) 'Missing explicit path reached the CA import stage.'
    Assert-ManifestValid -RunDirectory $missingRun
    Write-Host 'PASS: missing explicit mitmdump path fails before CA import.'

    $successRoot = Join-Path $testRoot 'explicit-path-no-inherited-venv-path'
    $successRun = Join-Path $successRoot 'run'
    $successStop = Join-Path $successRoot 'stop.signal'
    $successPort = Get-FreeLoopbackPort
    $successChild = Start-ResolutionChild `
        -RunDirectory $successRun `
        -ConfigDirectory (Join-Path $successRoot 'config') `
        -StopFile $successStop `
        -Port $successPort `
        -MitmdumpExecutable $venvMitmdump
    try {
        $ready = $false
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds(35)
        while ([DateTimeOffset]::UtcNow -lt $deadline -and -not $successChild.Process.HasExited) {
            $runPath = Join-Path $successRun 'run.json'
            if (Test-Path -LiteralPath $runPath -PathType Leaf) {
                try {
                    $run = Get-Content -LiteralPath $runPath -Raw | ConvertFrom-Json
                    if ($run.proxy_started -eq $true -and $run.startup_status -eq 'PROXY_RUNNING' -and (Test-LoopbackListener -Port $successPort)) {
                        $ready = $true
                        break
                    }
                }
                catch { }
            }
            Start-Sleep -Milliseconds 200
        }
        Assert-True $ready 'Explicit mitmdump path did not reach durable readiness without inherited venv PATH.'
        [System.IO.File]::WriteAllText($successStop, "stop`n", $Utf8NoBom)
        $successResult = Wait-ResolutionChild -Child $successChild
        Assert-True ($successResult.ExitCode -eq 0) "Explicit mitmdump path fixture failed: $($successResult.Stderr) $($successResult.Stdout)"
    }
    finally {
        if (-not $successChild.Process.HasExited) {
            $successChild.Process.Kill($true)
            $successChild.Process.WaitForExit()
        }
        $successChild.Process.Dispose()
    }
    $successMetadata = Get-Content -LiteralPath (Join-Path $successRun 'run.json') -Raw | ConvertFrom-Json
    $successJournal = @(Get-Content -LiteralPath (Join-Path $successRun 'startup-journal.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
    $resolution = $successJournal | Where-Object { $_.stage -eq 'mitmdump_executable_resolution' -and $_.event -eq 'completed' } | Select-Object -First 1
    Assert-True ($successMetadata.mitmdump_executable -eq [System.IO.Path]::GetFullPath($venvMitmdump)) 'Resolved explicit mitmdump path is absent from run metadata.'
    Assert-True ($resolution.details.resolved_executable_path -eq [System.IO.Path]::GetFullPath($venvMitmdump)) 'Resolved explicit mitmdump path is absent from the startup journal.'
    Assert-True ($successMetadata.ca_imported_by_run -eq $false) 'Focused resolution fixture imported a CA.'
    Assert-ManifestValid -RunDirectory $successRun
    Assert-True (-not (Test-LoopbackListener -Port $successPort)) 'Explicit mitmdump path fixture did not release its port.'
    Write-Host 'PASS: explicit mitmdump path starts without inherited harness venv PATH and is durably recorded.'
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        $fullTestRoot = [System.IO.Path]::GetFullPath($testRoot)
        $fullTempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        if (-not $fullTempRoot.EndsWith([System.IO.Path]::DirectorySeparatorChar)) { $fullTempRoot += [System.IO.Path]::DirectorySeparatorChar }
        if (-not $fullTestRoot.StartsWith($fullTempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw "Refusing unsafe cleanup target: $fullTestRoot" }
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

Write-Host 'PASS: focused mitmdump resolution tests completed.'
