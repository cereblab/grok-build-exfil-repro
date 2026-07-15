#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $CaptureRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'captures'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $MitmproxyConfigDirectory = (Join-Path $HOME '.mitmproxy')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

if (-not $IsWindows) {
    throw 'This launcher supports Windows 11 only.'
}

function Get-UnresolvedFullPath {
    param([Parameter(Mandatory)][string] $LiteralPath)

    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LiteralPath)
}

function Invoke-NativeForOutput {
    param(
        [Parameter(Mandatory)][string] $FilePath,
        [Parameter(Mandatory)][string[]] $Arguments
    )

    $output = @(& $FilePath @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    $text = ($output -join [Environment]::NewLine).Trim()
    if ($exitCode -ne 0) {
        $command = "$FilePath $($Arguments -join ' ')"
        throw "'$command' failed with exit code $exitCode. $text"
    }
    return $text
}

function Get-FreeLoopbackPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}

function Assert-LoopbackPortAvailable {
    param([Parameter(Mandatory)][int] $Port)

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
    try {
        $listener.Start()
    }
    catch {
        throw "127.0.0.1:$Port is unavailable. Stop the process using that port and retry."
    }
    finally {
        $listener.Stop()
    }
}

function Initialize-MitmproxyCertificateAuthority {
    param(
        [Parameter(Mandatory)][string] $MitmdumpPath,
        [Parameter(Mandatory)][string] $ConfigDirectory,
        [Parameter(Mandatory)][string] $CerPath,
        [Parameter(Mandatory)][string] $PemPath
    )

    if ((Test-Path -LiteralPath $CerPath -PathType Leaf) -and
        (Test-Path -LiteralPath $PemPath -PathType Leaf)) {
        return
    }

    $null = [System.IO.Directory]::CreateDirectory($ConfigDirectory)
    $generationPort = Get-FreeLoopbackPort
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $MitmdumpPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @(
        '--quiet', '--listen-host', '127.0.0.1',
        '--listen-port', $generationPort.ToString(),
        '--set', "confdir=$ConfigDirectory"
    )) {
        $startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw 'mitmdump did not start while generating its certificate authority.'
    }

    $created = $false
    try {
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds(20)
        while ([DateTimeOffset]::UtcNow -lt $deadline) {
            if ((Test-Path -LiteralPath $CerPath -PathType Leaf) -and
                (Test-Path -LiteralPath $PemPath -PathType Leaf) -and
                (Get-Item -LiteralPath $CerPath).Length -gt 0 -and
                (Get-Item -LiteralPath $PemPath).Length -gt 0) {
                $created = $true
                break
            }
            if ($process.HasExited) {
                break
            }
            Start-Sleep -Milliseconds 200
        }
    }
    finally {
        if (-not $process.HasExited) {
            $process.Kill($true)
        }
        $process.WaitForExit()
    }

    $standardError = $process.StandardError.ReadToEnd().Trim()
    $standardOutput = $process.StandardOutput.ReadToEnd().Trim()
    $process.Dispose()
    if (-not $created) {
        throw "mitmdump did not generate '$CerPath' and '$PemPath' within 20 seconds. $standardError $standardOutput"
    }
}

function Import-CaIntoCurrentUserRoot {
    param([Parameter(Mandatory)][string] $CertificatePath)

    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::Root,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $matches = $store.Certificates.Find(
            [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
            $certificate.Thumbprint,
            $false
        )
        if ($matches.Count -eq 0) {
            $store.Add($certificate)
        }
        return $certificate.Thumbprint
    }
    finally {
        $store.Close()
        $store.Dispose()
        $certificate.Dispose()
    }
}

$pythonCommand = Get-Command -Name 'python' -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($null -eq $pythonCommand) {
    throw 'Python 3.12 is required. Activate the documented virtual environment first.'
}
$pythonVersion = Invoke-NativeForOutput -FilePath $pythonCommand.Source -Arguments @(
    '-c', 'import sys; print(".".join(map(str, sys.version_info[:3])))'
)
if ($pythonVersion -notmatch '^3\.12(?:\.|$)') {
    throw "Python 3.12 is required; active python is $pythonVersion at $($pythonCommand.Source)."
}

$mitmdumpCommand = Get-Command -Name 'mitmdump' -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($null -eq $mitmdumpCommand) {
    throw "mitmproxy is not installed in the active environment. Run 'python -m pip install -r .\requirements.txt'."
}
$mitmdumpVersion = Invoke-NativeForOutput -FilePath $mitmdumpCommand.Source -Arguments @('--version')
if ($mitmdumpVersion -notmatch '(?m)^Python:\s+3\.12(?:\.|$)') {
    throw "mitmdump must run on Python 3.12. Reported version information: $mitmdumpVersion"
}

$projectRoot = Split-Path $PSScriptRoot -Parent
$addonPath = Join-Path $projectRoot 'addon\capture_requests.py'
if (-not (Test-Path -LiteralPath $addonPath -PathType Leaf)) {
    throw "mitmproxy addon not found: $addonPath"
}

$CaptureRoot = Get-UnresolvedFullPath -LiteralPath $CaptureRoot
$MitmproxyConfigDirectory = Get-UnresolvedFullPath -LiteralPath $MitmproxyConfigDirectory
$caCerPath = Join-Path $MitmproxyConfigDirectory 'mitmproxy-ca-cert.cer'
$caPemPath = Join-Path $MitmproxyConfigDirectory 'mitmproxy-ca-cert.pem'

Initialize-MitmproxyCertificateAuthority `
    -MitmdumpPath $mitmdumpCommand.Source `
    -ConfigDirectory $MitmproxyConfigDirectory `
    -CerPath $caCerPath `
    -PemPath $caPemPath
$caThumbprint = Import-CaIntoCurrentUserRoot -CertificatePath $caCerPath
Assert-LoopbackPortAvailable -Port 8080

$gitCommand = Get-Command -Name 'git' -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($null -eq $gitCommand) {
    throw 'Git is required to record the source repository commit SHA.'
}
$repositoryRoot = Split-Path $projectRoot -Parent
$repositoryCommitSha = Invoke-NativeForOutput -FilePath $gitCommand.Source -Arguments @(
    '-C', $repositoryRoot, 'rev-parse', 'HEAD'
)

$null = [System.IO.Directory]::CreateDirectory($CaptureRoot)
$runId = '{0}-{1}' -f (
    [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
), ([Guid]::NewGuid().ToString('N').Substring(0, 8))
$runDirectory = Join-Path $CaptureRoot $runId
$provenanceDirectory = Join-Path $runDirectory 'provenance'
$null = [System.IO.Directory]::CreateDirectory((Join-Path $runDirectory 'raw\http'))
$null = [System.IO.Directory]::CreateDirectory((Join-Path $runDirectory 'raw\websocket'))
$null = [System.IO.Directory]::CreateDirectory($provenanceDirectory)
$addonSnapshotPath = Join-Path $provenanceDirectory 'capture_requests.py'
[System.IO.File]::WriteAllBytes(
    $addonSnapshotPath,
    [System.IO.File]::ReadAllBytes($addonPath)
)
$addonSha256 = (Get-FileHash -LiteralPath $addonSnapshotPath -Algorithm SHA256).Hash.ToLowerInvariant()
$startedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')

$runMetadata = [ordered] @{
    run_id = $runId
    started_at_utc = $startedAtUtc
    listen_address = '127.0.0.1:8080'
    capture_directory = $runDirectory
    operating_system = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
    python_version = $pythonVersion
    mitmdump_version = $mitmdumpVersion
    repository_commit_sha = $repositoryCommitSha
    ca_certificate = $caCerPath
    ca_thumbprint = $caThumbprint
    ca_store = 'Cert:\CurrentUser\Root'
    addon = $addonSnapshotPath
    addon_source = $addonPath
    addon_sha256 = $addonSha256
}
$runJson = $runMetadata | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText(
    (Join-Path $runDirectory 'run.json'),
    "$runJson`n",
    [System.Text.UTF8Encoding]::new($false)
)

$oldCaptureDirectory = [Environment]::GetEnvironmentVariable('EGRESS_CAPTURE_DIR', 'Process')
[Environment]::SetEnvironmentVariable('EGRESS_CAPTURE_DIR', $runDirectory, 'Process')
try {
    Write-Host "mitmproxy CA trusted in Cert:\CurrentUser\Root ($caThumbprint)."
    Write-Host "Capture directory: $runDirectory"
    Write-Host 'Listening on 127.0.0.1:8080. Press Ctrl+C to stop.'

    $mitmdumpArguments = @(
        '--listen-host', '127.0.0.1',
        '--listen-port', '8080',
        '--set', "confdir=$MitmproxyConfigDirectory",
        '--set', 'store_streamed_bodies=true',
        '-s', $addonSnapshotPath
    )
    & $mitmdumpCommand.Source @mitmdumpArguments
    $mitmdumpExitCode = $LASTEXITCODE
    if ($mitmdumpExitCode -notin @(0, 130, -1073741510)) {
        throw "mitmdump exited with code $mitmdumpExitCode. Evidence may be incomplete: $runDirectory"
    }
}
finally {
    [Environment]::SetEnvironmentVariable('EGRESS_CAPTURE_DIR', $oldCaptureDirectory, 'Process')
}

Write-Host "Capture stopped. Evidence directory: $runDirectory"
