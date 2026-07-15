#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $CaptureRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'captures'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $MitmproxyConfigDirectory = (Join-Path $HOME '.mitmproxy'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $RunDirectory,

    [Parameter()]
    [ValidateRange(1, 65535)]
    [int] $ListenPort = 8080,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $StopFile,

    [Parameter()]
    [switch] $SkipCertificateImport,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int] $CertificateGenerationTimeoutSeconds = 20,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int] $CertificateOperationTimeoutSeconds = 20,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int] $StartupTimeoutSeconds = 35,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int] $ShutdownTimeoutSeconds = 30,

    [Parameter()]
    [string] $MitmdumpExecutable,

    [Parameter()]
    [string[]] $MitmdumpPrefixArguments = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

if (-not $IsWindows) {
    throw 'This launcher supports Windows 11 only.'
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)] $Value
    )

    $parent = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        $null = [System.IO.Directory]::CreateDirectory($parent)
    }
    $temporary = "$Path.$PID.$([Guid]::NewGuid().ToString('N')).tmp"
    $json = $Value | ConvertTo-Json -Depth 12 -Compress
    [System.IO.File]::WriteAllText($temporary, "$json`n", $Utf8NoBom)
    [System.IO.File]::Move($temporary, $Path, $true)
}

function Get-UnresolvedFullPath {
    param([Parameter(Mandatory)][string] $LiteralPath)

    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LiteralPath)
}

function Write-JsonLineDurable {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)] $Value
    )

    $json = $Value | ConvertTo-Json -Compress -Depth 12
    $bytes = $Utf8NoBom.GetBytes("$json`n")
    $stream = [System.IO.FileStream]::new(
        $Path,
        [System.IO.FileMode]::Append,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read,
        4096,
        [System.IO.FileOptions]::WriteThrough
    )
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

$script:StartupJournalPath = $null
function Write-StartupJournal {
    param(
        [Parameter(Mandatory)][string] $Stage,
        [Parameter(Mandatory)][ValidateSet('started', 'completed', 'failed', 'observed')]
        [string] $Event,
        [Parameter()][System.Collections.IDictionary] $Details = ([ordered] @{})
    )

    if ([string]::IsNullOrWhiteSpace($script:StartupJournalPath)) {
        return
    }
    $entry = [ordered] @{
        timestamp_utc = [DateTimeOffset]::UtcNow.ToString('o')
        stage = $Stage
        event = $Event
        details = $Details
    }
    Write-JsonLineDurable -Path $script:StartupJournalPath -Value $entry
}

function Read-BoundedText {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter()][int] $MaximumCharacters = 65536
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [ordered] @{ text = ''; truncated = $false }
    }
    $text = [System.IO.File]::ReadAllText($Path, $Utf8NoBom)
    if ($text.Length -le $MaximumCharacters) {
        return [ordered] @{ text = $text; truncated = $false }
    }
    return [ordered] @{
        text = $text.Substring(0, $MaximumCharacters)
        truncated = $true
    }
}

function Get-FileRecord {
    param(
        [Parameter(Mandatory)][string] $Root,
        [Parameter(Mandatory)][string] $Path
    )

    $relative = [System.IO.Path]::GetRelativePath($Root, $Path).Replace('\', '/')
    return [ordered] @{
        path = $relative
        sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        size = (Get-Item -LiteralPath $Path).Length
    }
}

function Write-EvidenceManifest {
    param(
        [Parameter(Mandatory)][string] $Directory,
        [Parameter(Mandatory)][bool] $CaptureEndedCleanly,
        [Parameter(Mandatory)][string] $RunStatus
    )

    $runMetadata = Get-Content -LiteralPath (Join-Path $Directory 'run.json') -Raw |
        ConvertFrom-Json
    $manifestPath = Join-Path $Directory 'evidence-manifest.json'
    $metadataFiles = @()
    $rawFiles = @()
    $addonFile = $null
    foreach ($file in Get-ChildItem -LiteralPath $Directory -Recurse -File | Sort-Object FullName) {
        if ($file.FullName -eq $manifestPath -or $file.Name -like '.evidence-manifest.json.*.tmp') {
            continue
        }
        $record = Get-FileRecord -Root $Directory -Path $file.FullName
        if ($record.path -like 'raw/*') {
            $rawFiles += $record
        }
        elseif ($record.path -eq 'provenance/capture_requests.py') {
            $addonFile = $record
        }
        else {
            $metadataFiles += $record
        }
    }
    if ($null -eq $addonFile) {
        throw 'The capture addon snapshot is missing while finalizing the evidence manifest.'
    }
    $manifest = [ordered] @{
        schema_version = 'egress-evidence-manifest/v1'
        run_id = $runMetadata.run_id
        capture_start_timestamp = $runMetadata.started_at_utc
        capture_stop_timestamp = [DateTimeOffset]::UtcNow.ToString('o')
        operating_system = $runMetadata.operating_system
        python_version = $runMetadata.python_version
        mitmproxy_version = $runMetadata.mitmproxy_version
        repository_commit_sha = $runMetadata.repository_commit_sha
        addon_file = $addonFile
        metadata_file_sha256 = [ordered] @{}
        metadata_files = @($metadataFiles)
        raw_evidence_files = @($rawFiles)
        capture_ended_cleanly = $CaptureEndedCleanly
        capture_error_count = 0
        run_status = $RunStatus
        integrity_scope = 'local_integrity_only_not_cryptographic_nonrepudiation'
    }
    foreach ($record in $metadataFiles) {
        $manifest.metadata_file_sha256[$record.path] = $record.sha256
    }
    Write-JsonFile -Path $manifestPath -Value $manifest
}

function Test-LoopbackPortListening {
    param([Parameter(Mandatory)][int] $Port)

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $task = $client.ConnectAsync('127.0.0.1', $Port)
        if (-not $task.Wait(200)) {
            return $false
        }
        return $client.Connected
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Test-LoopbackPortAvailable {
    param([Parameter(Mandatory)][int] $Port)

    $listener = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Loopback,
        $Port
    )
    try {
        $listener.Start()
        return $true
    }
    catch {
        return $false
    }
    finally {
        $listener.Stop()
    }
}

function Get-FreeLoopbackPort {
    $listener = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Loopback,
        0
    )
    try {
        $listener.Start()
        return ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}

function Resolve-ExecutablePath {
    param([Parameter(Mandatory)][string] $NameOrPath)

    $candidate = [System.IO.Path]::GetFullPath(
        [Environment]::ExpandEnvironmentVariables($NameOrPath),
        (Get-Location).Path
    )
    if ([System.IO.Path]::IsPathFullyQualified($NameOrPath) -or
        $NameOrPath.Contains([System.IO.Path]::DirectorySeparatorChar) -or
        $NameOrPath.Contains([System.IO.Path]::AltDirectorySeparatorChar)) {
        return $(if (Test-Path -LiteralPath $candidate -PathType Leaf) { $candidate } else { $null })
    }
    $command = Get-Command -Name $NameOrPath -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    return $(if ($null -eq $command) { $null } else { $command.Source })
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
        throw "'$FilePath' exited with code $exitCode. $text"
    }
    return $text
}

function Format-RedactedCommand {
    param(
        [Parameter(Mandatory)][string] $FilePath,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $Arguments
    )

    $parts = (@($FilePath) + @($Arguments)) | ForEach-Object {
        $value = [string] $_
        if ($value -match '[\s"]') {
            '"' + $value.Replace('"', '\"') + '"'
        }
        else {
            $value
        }
    }
    return $parts -join ' '
}

function Start-LoggedProcess {
    param(
        [Parameter(Mandatory)][string] $FilePath,
        [Parameter(Mandatory)][string[]] $Arguments,
        [Parameter(Mandatory)][string] $StandardOutputPath,
        [Parameter(Mandatory)][string] $StandardErrorPath,
        [Parameter()][System.Collections.IDictionary] $EnvironmentOverrides = ([ordered] @{})
    )

    $stdoutStream = [System.IO.FileStream]::new(
        $StandardOutputPath,
        [System.IO.FileMode]::Create,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read,
        4096,
        [System.IO.FileOptions]::WriteThrough
    )
    $stderrStream = [System.IO.FileStream]::new(
        $StandardErrorPath,
        [System.IO.FileMode]::Create,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read,
        4096,
        [System.IO.FileOptions]::WriteThrough
    )
    try {
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $FilePath
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        foreach ($name in $EnvironmentOverrides.Keys) {
            $startInfo.Environment[[string] $name] = [string] $EnvironmentOverrides[$name]
        }
        foreach ($argument in $Arguments) {
            $startInfo.ArgumentList.Add($argument)
        }
        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw "Process did not start: $FilePath"
        }
        $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdoutStream)
        $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderrStream)
        return [pscustomobject] @{
            Process = $process
            StandardOutputTask = $stdoutTask
            StandardErrorTask = $stderrTask
            StandardOutputStream = $stdoutStream
            StandardErrorStream = $stderrStream
            StandardOutputPath = $StandardOutputPath
            StandardErrorPath = $StandardErrorPath
        }
    }
    catch {
        $stdoutStream.Dispose()
        $stderrStream.Dispose()
        throw
    }
}

function Complete-LoggedProcessIo {
    param(
        [Parameter(Mandatory)] $LoggedProcess,
        [Parameter()][int] $TimeoutMilliseconds = 5000
    )

    $stdoutCompleted = $false
    $stderrCompleted = $false
    try {
        $stdoutCompleted = $LoggedProcess.StandardOutputTask.Wait($TimeoutMilliseconds)
        $stderrCompleted = $LoggedProcess.StandardErrorTask.Wait($TimeoutMilliseconds)
        if ($stdoutCompleted) {
            $LoggedProcess.StandardOutputTask.GetAwaiter().GetResult()
        }
        if ($stderrCompleted) {
            $LoggedProcess.StandardErrorTask.GetAwaiter().GetResult()
        }
    }
    finally {
        $LoggedProcess.StandardOutputStream.Flush($true)
        $LoggedProcess.StandardErrorStream.Flush($true)
        $LoggedProcess.StandardOutputStream.Dispose()
        $LoggedProcess.StandardErrorStream.Dispose()
    }
    return ,([pscustomobject] ([ordered] @{
        stdout_copy_completed = $stdoutCompleted
        stderr_copy_completed = $stderrCompleted
    }))
}

function Stop-ProcessTreeBounded {
    param(
        [Parameter(Mandatory)][System.Diagnostics.Process] $Process,
        [Parameter(Mandatory)][int] $TimeoutSeconds
    )

    if ($Process.HasExited) {
        return $true
    }
    $Process.Kill($true)
    return $Process.WaitForExit($TimeoutSeconds * 1000)
}

function Get-CertificateState {
    param(
        [Parameter(Mandatory)][string] $CerPath,
        [Parameter()][string] $KnownThumbprint
    )

    $state = [ordered] @{
        certificate_file_exists = Test-Path -LiteralPath $CerPath -PathType Leaf
        certificate_file_size = 0
        thumbprint = $KnownThumbprint
        current_user_root_matches = 0
        certificate_load_error = $null
        store_read_error = $null
    }
    if (-not $state.certificate_file_exists) {
        return $state
    }
    $state.certificate_file_size = (Get-Item -LiteralPath $CerPath).Length
    if ([string]::IsNullOrWhiteSpace($state.thumbprint)) {
        try {
            $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CerPath)
            try {
                $state.thumbprint = $certificate.Thumbprint
            }
            finally {
                $certificate.Dispose()
            }
        }
        catch {
            $state.certificate_load_error = "$($_.Exception.GetType().FullName): $($_.Exception.Message)"
            return $state
        }
    }
    try {
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', 'CurrentUser')
        try {
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $state.current_user_root_matches = $store.Certificates.Find(
                [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
                $state.thumbprint,
                $false
            ).Count
        }
        finally {
            $store.Close()
            $store.Dispose()
        }
    }
    catch {
        $state.store_read_error = "$($_.Exception.GetType().FullName): $($_.Exception.Message)"
    }
    return $state
}

function Invoke-BoundedCertificateWorker {
    param(
        [Parameter(Mandatory)][ValidateSet('Import', 'Remove')][string] $Operation,
        [Parameter(Mandatory)][string] $CerPath,
        [Parameter(Mandatory)][string] $ResultPath,
        [Parameter(Mandatory)][string] $StdoutPath,
        [Parameter(Mandatory)][string] $StderrPath,
        [Parameter(Mandatory)][int] $TimeoutSeconds
    )

    $certutilCommand = Get-Command -Name 'certutil.exe' -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $certutilCommand) {
        throw 'Windows certutil.exe was not found.'
    }
    $beforeState = Get-CertificateState -CerPath $CerPath
    if (-not [string]::IsNullOrWhiteSpace($beforeState.certificate_load_error)) {
        throw "Certificate could not be loaded. $($beforeState.certificate_load_error)"
    }
    $arguments = if ($Operation -eq 'Import') {
        @('-user', '-f', '-addstore', 'Root', $CerPath)
    }
    else {
        @('-user', '-f', '-delstore', 'Root', [string] $beforeState.thumbprint)
    }
    $journalStage = "ca_$($Operation.ToLowerInvariant())_native_process"
    Write-StartupJournal -Stage $journalStage -Event 'started' -Details ([ordered] @{
        executable_path = $certutilCommand.Source
        redacted_arguments = Format-RedactedCommand -FilePath $certutilCommand.Source -Arguments $arguments
        stdout_log_path = $StdoutPath
        stderr_log_path = $StderrPath
        timeout_seconds = $TimeoutSeconds
    })
    $logged = Start-LoggedProcess `
        -FilePath $certutilCommand.Source `
        -Arguments $arguments `
        -StandardOutputPath $StdoutPath `
        -StandardErrorPath $StderrPath
    $exitCode = $null
    $operationError = $null
    try {
        if (-not $logged.Process.WaitForExit($TimeoutSeconds * 1000)) {
            $null = Stop-ProcessTreeBounded -Process $logged.Process -TimeoutSeconds 5
            throw [TimeoutException]::new(
                "Certificate $Operation process exceeded $TimeoutSeconds seconds."
            )
        }
        $exitCode = $logged.Process.ExitCode
        if ($logged.Process.ExitCode -ne 0) {
            throw "Certificate $Operation process exited with code $($logged.Process.ExitCode)."
        }
    }
    catch { $operationError = $_ }
    finally {
        if (-not $logged.Process.HasExited) {
            $null = Stop-ProcessTreeBounded -Process $logged.Process -TimeoutSeconds 5
        }
        $null = Complete-LoggedProcessIo -LoggedProcess $logged
        $logged.Process.Dispose()
    }
    if ($null -ne $operationError) {
        $stdout = Read-BoundedText -Path $StdoutPath
        $stderr = Read-BoundedText -Path $StderrPath
        Write-StartupJournal -Stage $journalStage -Event 'failed' -Details ([ordered] @{
            exit_code = $exitCode
            exception_type = $operationError.Exception.GetType().FullName
            message = $operationError.Exception.Message
            stdout = $stdout.text
            stdout_truncated = $stdout.truncated
            stderr = $stderr.text
            stderr_truncated = $stderr.truncated
        })
        throw $operationError
    }
    $afterState = Get-CertificateState `
        -CerPath $CerPath `
        -KnownThumbprint ([string] $beforeState.thumbprint)
    $result = [ordered] @{
        operation = $Operation
        thumbprint = [string] $beforeState.thumbprint
        matches_before = [int] $beforeState.current_user_root_matches
        matches_after = [int] $afterState.current_user_root_matches
        changed = [int] $beforeState.current_user_root_matches -ne [int] $afterState.current_user_root_matches
        exit_code = $exitCode
    }
    Write-JsonFile -Path $ResultPath -Value $result
    Write-StartupJournal -Stage $journalStage -Event 'completed' -Details $result
    return [pscustomobject] $result
}

function Initialize-MitmproxyCertificateAuthority {
    param(
        [Parameter(Mandatory)][string] $ExecutablePath,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $PrefixArguments,
        [Parameter(Mandatory)][string] $ConfigDirectory,
        [Parameter(Mandatory)][string] $CerPath,
        [Parameter(Mandatory)][string] $PemPath,
        [Parameter(Mandatory)][string] $RunDirectory,
        [Parameter(Mandatory)][int] $TimeoutSeconds
    )

    $stdoutPath = Join-Path $RunDirectory 'ca-generation.stdout.log'
    $stderrPath = Join-Path $RunDirectory 'ca-generation.stderr.log'
    [System.IO.File]::WriteAllBytes($stdoutPath, [byte[]]::new(0))
    [System.IO.File]::WriteAllBytes($stderrPath, [byte[]]::new(0))
    $generationPort = Get-FreeLoopbackPort
    $arguments = @($PrefixArguments) + @(
        '--quiet', '--listen-host', '127.0.0.1',
        '--listen-port', $generationPort.ToString(),
        '--set', "confdir=$ConfigDirectory"
    )
    Write-StartupJournal -Stage 'ca_generation_process_launch' -Event 'started' -Details ([ordered] @{
        executable_path = $ExecutablePath
        redacted_arguments = Format-RedactedCommand -FilePath $ExecutablePath -Arguments $arguments
        stdout_log_path = $stdoutPath
        stderr_log_path = $stderrPath
        generation_port = $generationPort
    })
    $logged = Start-LoggedProcess `
        -FilePath $ExecutablePath `
        -Arguments $arguments `
        -StandardOutputPath $stdoutPath `
        -StandardErrorPath $stderrPath
    Write-StartupJournal -Stage 'ca_generation_process_launch' -Event 'completed' -Details ([ordered] @{
        process_id = $logged.Process.Id
    })
    $created = $false
    $exitCode = $null
    try {
        Write-StartupJournal -Stage 'ca_generation_file_wait' -Event 'started' -Details ([ordered] @{
            timeout_seconds = $TimeoutSeconds
        })
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
        while ([DateTimeOffset]::UtcNow -lt $deadline) {
            if ((Test-Path -LiteralPath $CerPath -PathType Leaf) -and
                (Test-Path -LiteralPath $PemPath -PathType Leaf) -and
                (Get-Item -LiteralPath $CerPath).Length -gt 0 -and
                (Get-Item -LiteralPath $PemPath).Length -gt 0) {
                $created = $true
                break
            }
            if ($logged.Process.HasExited) {
                $exitCode = $logged.Process.ExitCode
                break
            }
            Start-Sleep -Milliseconds 200
        }
        Write-StartupJournal -Stage 'ca_generation_file_wait' -Event $(if ($created) { 'completed' } else { 'failed' }) -Details ([ordered] @{
            certificate_created = $created
            process_exit_code = $exitCode
        })
    }
    finally {
        Write-StartupJournal -Stage 'ca_generation_shutdown' -Event 'started' -Details ([ordered] @{
            process_id = $logged.Process.Id
            process_still_running = -not $logged.Process.HasExited
        })
        $terminated = Stop-ProcessTreeBounded -Process $logged.Process -TimeoutSeconds 5
        if ($logged.Process.HasExited) {
            $exitCode = $logged.Process.ExitCode
        }
        $io = @(Complete-LoggedProcessIo -LoggedProcess $logged)[-1]
        Write-StartupJournal -Stage 'ca_generation_shutdown' -Event 'completed' -Details ([ordered] @{
            process_terminated = $terminated
            process_exit_code = $exitCode
            stdout_copy_completed = $io.stdout_copy_completed
            stderr_copy_completed = $io.stderr_copy_completed
        })
        $logged.Process.Dispose()
    }
    if (-not $created) {
        $stdout = Read-BoundedText -Path $stdoutPath
        $stderr = Read-BoundedText -Path $stderrPath
        throw "mitmdump did not generate the CA files within $TimeoutSeconds seconds. Exit code: $exitCode. stdout: $($stdout.text) stderr: $($stderr.text)"
    }
}

$projectRoot = Split-Path $PSScriptRoot -Parent
$repositoryRoot = Split-Path $projectRoot -Parent
$addonPath = Join-Path $projectRoot 'addon\capture_requests.py'
if (-not (Test-Path -LiteralPath $addonPath -PathType Leaf)) {
    throw "mitmproxy addon not found: $addonPath"
}

$CaptureRoot = Get-UnresolvedFullPath -LiteralPath $CaptureRoot
$MitmproxyConfigDirectory = Get-UnresolvedFullPath -LiteralPath $MitmproxyConfigDirectory
if ([string]::IsNullOrWhiteSpace($RunDirectory)) {
    $runId = '{0}-{1}' -f (
        [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
    ), ([Guid]::NewGuid().ToString('N').Substring(0, 8))
    $runDirectory = Join-Path $CaptureRoot $runId
}
else {
    $runDirectory = Get-UnresolvedFullPath -LiteralPath $RunDirectory
    $runId = Split-Path -Leaf $runDirectory
}
if (Test-Path -LiteralPath $runDirectory) {
    throw "Refusing to reuse capture directory: $runDirectory"
}
if (-not [string]::IsNullOrWhiteSpace($StopFile)) {
    $StopFile = Get-UnresolvedFullPath -LiteralPath $StopFile
    if (Test-Path -LiteralPath $StopFile) {
        throw "Stop file must not already exist: $StopFile"
    }
}

$runParent = Split-Path -Parent $runDirectory
$null = [System.IO.Directory]::CreateDirectory($runParent)
$bootstrapJournalPath = Join-Path $runParent ".$runId.startup-journal.bootstrap.jsonl"
if (Test-Path -LiteralPath $bootstrapJournalPath) {
    throw "Bootstrap startup journal already exists: $bootstrapJournalPath"
}
Write-JsonLineDurable -Path $bootstrapJournalPath -Value ([ordered] @{
    timestamp_utc = [DateTimeOffset]::UtcNow.ToString('o')
    stage = 'run_directory_creation'
    event = 'started'
    details = [ordered] @{ run_directory = $runDirectory }
})
$null = [System.IO.Directory]::CreateDirectory($runDirectory)
$script:StartupJournalPath = Join-Path $runDirectory 'startup-journal.jsonl'
[System.IO.File]::Move($bootstrapJournalPath, $script:StartupJournalPath)
Write-StartupJournal -Stage 'run_directory_creation' -Event 'completed' -Details ([ordered] @{
    run_directory = $runDirectory
})

$provenanceDirectory = Join-Path $runDirectory 'provenance'
$null = [System.IO.Directory]::CreateDirectory((Join-Path $runDirectory 'raw\http'))
$null = [System.IO.Directory]::CreateDirectory((Join-Path $runDirectory 'raw\websocket'))
$null = [System.IO.Directory]::CreateDirectory($provenanceDirectory)
$requestsPath = Join-Path $runDirectory 'requests.jsonl'
$websocketsPath = Join-Path $runDirectory 'websockets.jsonl'
$mitmdumpStdoutPath = Join-Path $runDirectory 'mitmdump.stdout.log'
$mitmdumpStderrPath = Join-Path $runDirectory 'mitmdump.stderr.log'
foreach ($path in @($requestsPath, $websocketsPath, $mitmdumpStdoutPath, $mitmdumpStderrPath)) {
    [System.IO.File]::WriteAllBytes($path, [byte[]]::new(0))
}
Write-StartupJournal -Stage 'stdout_log_path' -Event 'completed' -Details ([ordered] @{
    path = $mitmdumpStdoutPath
})
Write-StartupJournal -Stage 'stderr_log_path' -Event 'completed' -Details ([ordered] @{
    path = $mitmdumpStderrPath
})

$addonSnapshotPath = Join-Path $provenanceDirectory 'capture_requests.py'
[System.IO.File]::WriteAllBytes(
    $addonSnapshotPath,
    [System.IO.File]::ReadAllBytes($addonPath)
)
$addonSha256 = (Get-FileHash -LiteralPath $addonSnapshotPath -Algorithm SHA256).Hash.ToLowerInvariant()
$caCerPath = Join-Path $MitmproxyConfigDirectory 'mitmproxy-ca-cert.cer'
$caPemPath = Join-Path $MitmproxyConfigDirectory 'mitmproxy-ca-cert.pem'
$startedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
$runMetadata = [ordered] @{
    schema_version = 'egress-capture-run/v1'
    run_id = $runId
    started_at_utc = $startedAtUtc
    ended_at_utc = $null
    listen_address = "127.0.0.1:$ListenPort"
    capture_directory = $runDirectory
    operating_system = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
    python_version = $null
    mitmproxy_version = $null
    repository_commit_sha = $null
    ca_certificate = $caCerPath
    ca_pem_certificate = $caPemPath
    ca_thumbprint = $null
    ca_store = $(if ($SkipCertificateImport) { 'not imported (explicit test mode)' } else { 'Cert:\CurrentUser\Root' })
    ca_imported_by_run = $false
    ca_removed_by_run = $false
    addon = $addonSnapshotPath
    addon_source = $addonPath
    addon_sha256 = $addonSha256
    startup_journal = $script:StartupJournalPath
    mitmdump_stdout_log = $mitmdumpStdoutPath
    mitmdump_stderr_log = $mitmdumpStderrPath
    mitmdump_executable = $null
    mitmdump_redacted_arguments = $null
    mitmdump_process_id = $null
    mitmdump_exit_code = $null
    proxy_started = $false
    startup_status = 'STARTING'
    failure_stage = $null
    failure_exception_type = $null
    failure_message = $null
    cleanup = $null
}
$runJsonPath = Join-Path $runDirectory 'run.json'
Write-StartupJournal -Stage 'run_json_creation' -Event 'started' -Details ([ordered] @{
    path = $runJsonPath
})
Write-JsonFile -Path $runJsonPath -Value $runMetadata
Write-StartupJournal -Stage 'run_json_creation' -Event 'completed' -Details ([ordered] @{
    path = $runJsonPath
})

$captureLoggedProcess = $null
$capturedError = $null
$failureStage = 'post_run_metadata_initialization'
$startupCompleted = $false
$captureEndedCleanly = $false
$caThumbprint = $null
$caWasAbsentBeforeImport = $false
$caImportedByRun = $false
$caRemovedByRun = $false
$mitmdumpPath = $null
$mitmdumpArguments = @()
$portStateAtFailure = $null
$certificateStateAtFailure = $null
$processStillRunningAtFailure = $false
$mitmdumpExitCodeAtFailure = $null
$cleanupResult = [ordered] @{
    shutdown_started = $false
    graceful_stop_requested = $false
    forced_termination = $false
    process_stopped = $true
    port_released = $null
    ca_removal_attempted = $false
    ca_removal_succeeded = $null
    ca_files_preserved = $false
}
$oldCaptureDirectory = [Environment]::GetEnvironmentVariable('EGRESS_CAPTURE_DIR', 'Process')
$oldStopFile = [Environment]::GetEnvironmentVariable('EGRESS_CAPTURE_STOP_FILE', 'Process')

try {
    $failureStage = 'python_validation'
    Write-StartupJournal -Stage $failureStage -Event 'started'
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
    $runMetadata.python_version = $pythonVersion
    Write-StartupJournal -Stage $failureStage -Event 'completed' -Details ([ordered] @{
        executable_path = $pythonCommand.Source
        version = $pythonVersion
    })

    $failureStage = 'repository_metadata'
    Write-StartupJournal -Stage $failureStage -Event 'started'
    $gitCommand = Get-Command -Name 'git' -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $gitCommand) {
        throw 'Git is required to record the source repository commit SHA.'
    }
    $runMetadata.repository_commit_sha = Invoke-NativeForOutput -FilePath $gitCommand.Source -Arguments @(
        '-C', $repositoryRoot, 'rev-parse', 'HEAD'
    )
    Write-StartupJournal -Stage $failureStage -Event 'completed' -Details ([ordered] @{
        repository_commit_sha = $runMetadata.repository_commit_sha
    })

    $failureStage = 'mitmdump_executable_resolution'
    Write-StartupJournal -Stage $failureStage -Event 'started' -Details ([ordered] @{
        requested_executable = $(if ([string]::IsNullOrWhiteSpace($MitmdumpExecutable)) { 'mitmdump' } else { $MitmdumpExecutable })
    })
    $requestedMitmdump = if ([string]::IsNullOrWhiteSpace($MitmdumpExecutable)) {
        'mitmdump'
    }
    else {
        $MitmdumpExecutable
    }
    $mitmdumpPath = Resolve-ExecutablePath -NameOrPath $requestedMitmdump
    if ([string]::IsNullOrWhiteSpace($mitmdumpPath)) {
        throw "mitmdump executable was not found: $requestedMitmdump"
    }
    $runMetadata.mitmdump_executable = $mitmdumpPath
    Write-StartupJournal -Stage $failureStage -Event 'completed' -Details ([ordered] @{
        resolved_executable_path = $mitmdumpPath
    })

    $failureStage = 'mitmdump_version_check'
    Write-StartupJournal -Stage $failureStage -Event 'started'
    $mitmdumpVersion = Invoke-NativeForOutput `
        -FilePath $mitmdumpPath `
        -Arguments (@($MitmdumpPrefixArguments) + @('--version'))
    if ($mitmdumpVersion -notmatch '(?m)^Python:\s+3\.12(?:\.|$)') {
        throw "mitmdump must run on Python 3.12. Reported version information: $mitmdumpVersion"
    }
    $runMetadata.mitmproxy_version = $mitmdumpVersion
    Write-StartupJournal -Stage $failureStage -Event 'completed' -Details ([ordered] @{
        version = $mitmdumpVersion
    })

    $failureStage = 'ca_existence_check'
    Write-StartupJournal -Stage $failureStage -Event 'started' -Details ([ordered] @{
        certificate_path = $caCerPath
        pem_path = $caPemPath
    })
    $caExists = (Test-Path -LiteralPath $caCerPath -PathType Leaf) -and
        (Test-Path -LiteralPath $caPemPath -PathType Leaf) -and
        (Get-Item -LiteralPath $caCerPath).Length -gt 0 -and
        (Get-Item -LiteralPath $caPemPath).Length -gt 0
    Write-StartupJournal -Stage $failureStage -Event 'completed' -Details ([ordered] @{
        ca_exists = $caExists
    })

    if (-not $caExists) {
        $failureStage = 'ca_generation'
        Write-StartupJournal -Stage $failureStage -Event 'started'
        $null = [System.IO.Directory]::CreateDirectory($MitmproxyConfigDirectory)
        Initialize-MitmproxyCertificateAuthority `
            -ExecutablePath $mitmdumpPath `
            -PrefixArguments @($MitmdumpPrefixArguments) `
            -ConfigDirectory $MitmproxyConfigDirectory `
            -CerPath $caCerPath `
            -PemPath $caPemPath `
            -RunDirectory $runDirectory `
            -TimeoutSeconds $CertificateGenerationTimeoutSeconds
        Write-StartupJournal -Stage $failureStage -Event 'completed' -Details ([ordered] @{
            certificate_path = $caCerPath
            pem_path = $caPemPath
        })
    }
    else {
        [System.IO.File]::WriteAllBytes((Join-Path $runDirectory 'ca-generation.stdout.log'), [byte[]]::new(0))
        [System.IO.File]::WriteAllBytes((Join-Path $runDirectory 'ca-generation.stderr.log'), [byte[]]::new(0))
        Write-StartupJournal -Stage 'ca_generation' -Event 'completed' -Details ([ordered] @{
            skipped = $true
            reason = 'CA files already existed.'
        })
    }

    $failureStage = 'ca_import'
    Write-StartupJournal -Stage $failureStage -Event 'started' -Details ([ordered] @{
        skipped = [bool] $SkipCertificateImport
        store = 'Cert:\CurrentUser\Root'
    })
    $certificateState = Get-CertificateState -CerPath $caCerPath
    if (-not [string]::IsNullOrWhiteSpace($certificateState.certificate_load_error)) {
        throw "CA certificate could not be loaded. $($certificateState.certificate_load_error)"
    }
    $caThumbprint = [string] $certificateState.thumbprint
    $runMetadata.ca_thumbprint = $caThumbprint
    if ($SkipCertificateImport) {
        $runMetadata.ca_store = 'not imported (explicit test mode)'
        Write-StartupJournal -Stage $failureStage -Event 'completed' -Details ([ordered] @{
            skipped = $true
            thumbprint = $caThumbprint
        })
    }
    else {
        $caWasAbsentBeforeImport = [int] $certificateState.current_user_root_matches -eq 0
        $importResultPath = Join-Path $runDirectory 'ca-import-result.json'
        $importResult = Invoke-BoundedCertificateWorker `
            -Operation 'Import' `
            -CerPath $caCerPath `
            -ResultPath $importResultPath `
            -StdoutPath (Join-Path $runDirectory 'ca-import.stdout.log') `
            -StderrPath (Join-Path $runDirectory 'ca-import.stderr.log') `
            -TimeoutSeconds $CertificateOperationTimeoutSeconds
        if ([int] $importResult.matches_after -lt 1) {
            throw 'The CA import worker completed without a matching CurrentUser Root certificate.'
        }
        $caImportedByRun = $caWasAbsentBeforeImport -and [bool] $importResult.changed
        $runMetadata.ca_imported_by_run = $caImportedByRun
        Write-StartupJournal -Stage $failureStage -Event 'completed' -Details ([ordered] @{
            thumbprint = $caThumbprint
            matches_before = $importResult.matches_before
            matches_after = $importResult.matches_after
            imported_by_run = $caImportedByRun
        })
    }

    $failureStage = 'port_availability_check'
    Write-StartupJournal -Stage $failureStage -Event 'started' -Details ([ordered] @{
        listen_address = "127.0.0.1:$ListenPort"
    })
    if (-not (Test-LoopbackPortAvailable -Port $ListenPort)) {
        throw "127.0.0.1:$ListenPort is unavailable. Stop the process using that port and retry."
    }
    Write-StartupJournal -Stage $failureStage -Event 'completed' -Details ([ordered] @{
        port_available = $true
    })

    [Environment]::SetEnvironmentVariable('EGRESS_CAPTURE_DIR', $runDirectory, 'Process')
    [Environment]::SetEnvironmentVariable('EGRESS_CAPTURE_STOP_FILE', $StopFile, 'Process')
    $mitmdumpArguments = @($MitmdumpPrefixArguments) + @(
        '--quiet',
        '--listen-host', '127.0.0.1',
        '--listen-port', $ListenPort.ToString(),
        '--set', "confdir=$MitmproxyConfigDirectory",
        '--set', 'store_streamed_bodies=true',
        '-s', $addonSnapshotPath
    )
    $redactedCommand = Format-RedactedCommand -FilePath $mitmdumpPath -Arguments $mitmdumpArguments
    $runMetadata.mitmdump_redacted_arguments = $redactedCommand
    $failureStage = 'mitmdump_process_launch'
    Write-StartupJournal -Stage $failureStage -Event 'started' -Details ([ordered] @{
        resolved_executable_path = $mitmdumpPath
        redacted_arguments = $redactedCommand
        stdout_log_path = $mitmdumpStdoutPath
        stderr_log_path = $mitmdumpStderrPath
    })
    $captureLoggedProcess = Start-LoggedProcess `
        -FilePath $mitmdumpPath `
        -Arguments $mitmdumpArguments `
        -StandardOutputPath $mitmdumpStdoutPath `
        -StandardErrorPath $mitmdumpStderrPath `
        -EnvironmentOverrides ([ordered] @{
            EGRESS_CAPTURE_DIR = $runDirectory
            EGRESS_CAPTURE_STOP_FILE = $StopFile
        })
    $runMetadata.mitmdump_process_id = $captureLoggedProcess.Process.Id
    Write-StartupJournal -Stage $failureStage -Event 'completed' -Details ([ordered] @{
        process_id = $captureLoggedProcess.Process.Id
    })

    $failureStage = 'port_listening_checks'
    Write-StartupJournal -Stage $failureStage -Event 'started' -Details ([ordered] @{
        listen_address = "127.0.0.1:$ListenPort"
        timeout_seconds = $StartupTimeoutSeconds
    })
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($StartupTimeoutSeconds)
    $attempts = 0
    $ready = $false
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        $attempts += 1
        if (Test-LoopbackPortListening -Port $ListenPort) {
            $ready = $true
            break
        }
        if ($captureLoggedProcess.Process.HasExited) {
            $runMetadata.mitmdump_exit_code = $captureLoggedProcess.Process.ExitCode
            throw "mitmdump exited before listening with code $($captureLoggedProcess.Process.ExitCode)."
        }
        Start-Sleep -Milliseconds 200
    }
    if (-not $ready) {
        Write-StartupJournal -Stage 'startup_timeout' -Event 'started' -Details ([ordered] @{
            timeout_seconds = $StartupTimeoutSeconds
            attempts = $attempts
        })
        Write-StartupJournal -Stage 'startup_timeout' -Event 'completed' -Details ([ordered] @{
            port_listening = $false
            process_still_running = -not $captureLoggedProcess.Process.HasExited
        })
        $failureStage = 'startup_timeout'
        throw [TimeoutException]::new(
            "mitmdump remained alive but did not listen on 127.0.0.1:$ListenPort within $StartupTimeoutSeconds seconds."
        )
    }
    $startupCompleted = $true
    $runMetadata.proxy_started = $true
    $runMetadata.startup_status = 'PROXY_RUNNING'
    Write-StartupJournal -Stage $failureStage -Event 'completed' -Details ([ordered] @{
        attempts = $attempts
        process_id = $captureLoggedProcess.Process.Id
        port_listening = $true
    })
    Write-JsonFile -Path $runJsonPath -Value $runMetadata

    if ($SkipCertificateImport) {
        Write-Host "mitmproxy CA generated but not imported ($caThumbprint)."
    }
    else {
        Write-Host "mitmproxy CA trusted in Cert:\CurrentUser\Root ($caThumbprint)."
    }
    Write-Host "Capture directory: $runDirectory"
    Write-Host "Listening on 127.0.0.1:$ListenPort."

    $failureStage = 'capture_runtime'
    $captureLoggedProcess.Process.WaitForExit()
    $runMetadata.mitmdump_exit_code = $captureLoggedProcess.Process.ExitCode
    if ($captureLoggedProcess.Process.ExitCode -notin @(0, 130, -1073741510)) {
        throw "mitmdump exited with code $($captureLoggedProcess.Process.ExitCode)."
    }
    $captureEndedCleanly = $true
}
catch {
    $capturedError = $_
    if ($null -ne $captureLoggedProcess) {
        $processStillRunningAtFailure = -not $captureLoggedProcess.Process.HasExited
        if ($captureLoggedProcess.Process.HasExited) {
            $mitmdumpExitCodeAtFailure = $captureLoggedProcess.Process.ExitCode
        }
    }
    $portStateAtFailure = [ordered] @{
        listening = Test-LoopbackPortListening -Port $ListenPort
        available_for_bind = Test-LoopbackPortAvailable -Port $ListenPort
    }
    $certificateStateAtFailure = Get-CertificateState -CerPath $caCerPath -KnownThumbprint $caThumbprint
    Write-StartupJournal -Stage $failureStage -Event 'failed' -Details ([ordered] @{
        exception_type = $_.Exception.GetType().FullName
        message = $_.Exception.Message
        process_still_running = $processStillRunningAtFailure
        process_exit_code = $mitmdumpExitCodeAtFailure
        port_state = $portStateAtFailure
        certificate_state = $certificateStateAtFailure
    })
}
finally {
    $cleanupResult.shutdown_started = $true
    Write-StartupJournal -Stage 'shutdown' -Event 'started' -Details ([ordered] @{
        process_started = $null -ne $captureLoggedProcess
        process_still_running = $(if ($null -eq $captureLoggedProcess) { $false } else { -not $captureLoggedProcess.Process.HasExited })
    })
    if ($null -ne $captureLoggedProcess) {
        if (-not $captureLoggedProcess.Process.HasExited) {
            if (-not [string]::IsNullOrWhiteSpace($StopFile)) {
                if (-not (Test-Path -LiteralPath $StopFile)) {
                    [System.IO.File]::WriteAllText($StopFile, "stop`n", $Utf8NoBom)
                }
                $cleanupResult.graceful_stop_requested = $true
                $null = $captureLoggedProcess.Process.WaitForExit($ShutdownTimeoutSeconds * 1000)
            }
            if (-not $captureLoggedProcess.Process.HasExited) {
                $cleanupResult.forced_termination = $true
                $null = Stop-ProcessTreeBounded `
                    -Process $captureLoggedProcess.Process `
                    -TimeoutSeconds 5
            }
        }
        $cleanupResult.process_stopped = $captureLoggedProcess.Process.HasExited
        if ($captureLoggedProcess.Process.HasExited) {
            $runMetadata.mitmdump_exit_code = $captureLoggedProcess.Process.ExitCode
        }
        $ioResult = @(Complete-LoggedProcessIo -LoggedProcess $captureLoggedProcess)[-1]
        $captureLoggedProcess.Process.Dispose()
        $cleanupResult.stdout_copy_completed = $ioResult.stdout_copy_completed
        $cleanupResult.stderr_copy_completed = $ioResult.stderr_copy_completed
    }
    $portDeadline = [DateTimeOffset]::UtcNow.AddSeconds(5)
    while ([DateTimeOffset]::UtcNow -lt $portDeadline -and
        (Test-LoopbackPortListening -Port $ListenPort)) {
        Start-Sleep -Milliseconds 200
    }
    $cleanupResult.port_released = -not (Test-LoopbackPortListening -Port $ListenPort)
    Write-StartupJournal -Stage 'shutdown' -Event 'completed' -Details $cleanupResult

    [Environment]::SetEnvironmentVariable('EGRESS_CAPTURE_DIR', $oldCaptureDirectory, 'Process')
    [Environment]::SetEnvironmentVariable('EGRESS_CAPTURE_STOP_FILE', $oldStopFile, 'Process')

    Write-StartupJournal -Stage 'ca_removal' -Event 'started' -Details ([ordered] @{
        thumbprint = $caThumbprint
        imported_by_run = $caImportedByRun
        absent_before_import = $caWasAbsentBeforeImport
    })
    $postCaptureCertificateState = Get-CertificateState -CerPath $caCerPath -KnownThumbprint $caThumbprint
    $shouldRemove = $caWasAbsentBeforeImport -and
        [int] $postCaptureCertificateState.current_user_root_matches -gt 0
    if ($shouldRemove) {
        $cleanupResult.ca_removal_attempted = $true
        try {
            $removeResult = Invoke-BoundedCertificateWorker `
                -Operation 'Remove' `
                -CerPath $caCerPath `
                -ResultPath (Join-Path $runDirectory 'ca-removal-result.json') `
                -StdoutPath (Join-Path $runDirectory 'ca-removal.stdout.log') `
                -StderrPath (Join-Path $runDirectory 'ca-removal.stderr.log') `
                -TimeoutSeconds $CertificateOperationTimeoutSeconds
            $caRemovedByRun = [int] $removeResult.matches_after -eq 0
            $cleanupResult.ca_removal_succeeded = $caRemovedByRun
        }
        catch {
            $cleanupResult.ca_removal_succeeded = $false
            $cleanupResult.ca_removal_error = "$($_.Exception.GetType().FullName): $($_.Exception.Message)"
        }
    }
    else {
        $cleanupResult.ca_removal_succeeded = $true
    }
    $cleanupResult.ca_files_preserved = (Test-Path -LiteralPath $caCerPath -PathType Leaf) -and
        (Test-Path -LiteralPath $caPemPath -PathType Leaf)
    $finalCertificateState = Get-CertificateState -CerPath $caCerPath -KnownThumbprint $caThumbprint
    Write-StartupJournal -Stage 'ca_removal' -Event 'completed' -Details ([ordered] @{
        removal_attempted = $cleanupResult.ca_removal_attempted
        removal_succeeded = $cleanupResult.ca_removal_succeeded
        certificate_files_preserved = $cleanupResult.ca_files_preserved
        certificate_state = $finalCertificateState
    })

    $runMetadata.ended_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    $runMetadata.ca_thumbprint = $caThumbprint
    $runMetadata.ca_imported_by_run = $caImportedByRun
    $runMetadata.ca_removed_by_run = $caRemovedByRun
    $runMetadata.proxy_started = $startupCompleted
    $runMetadata.cleanup = $cleanupResult
    if ($null -eq $capturedError) {
        $runMetadata.startup_status = 'CAPTURE_COMPLETE'
    }
    else {
        $runMetadata.startup_status = $(if ($startupCompleted) { 'CAPTURE_FAILED' } else { 'CAPTURE_START_FAILED' })
        $runMetadata.failure_stage = $failureStage
        $runMetadata.failure_exception_type = $capturedError.Exception.GetType().FullName
        $runMetadata.failure_message = $capturedError.Exception.Message
    }
    Write-JsonFile -Path $runJsonPath -Value $runMetadata

    if ($null -ne $capturedError) {
        $stdoutRecord = Read-BoundedText -Path $mitmdumpStdoutPath
        $stderrRecord = Read-BoundedText -Path $mitmdumpStderrPath
        $failureRecord = [ordered] @{
            schema_version = 'egress-capture-start-failure/v1'
            run_id = $runId
            failure_stage = $failureStage
            exception_type = $capturedError.Exception.GetType().FullName
            exception_message = $capturedError.Exception.Message
            resolved_executable_path = $mitmdumpPath
            redacted_arguments = $(if ([string]::IsNullOrWhiteSpace($mitmdumpPath)) { $null } else { Format-RedactedCommand -FilePath $mitmdumpPath -Arguments @($mitmdumpArguments) })
            mitmdump_exit_code = $mitmdumpExitCodeAtFailure
            process_still_running_at_failure = $processStillRunningAtFailure
            stdout_log_path = $mitmdumpStdoutPath
            stderr_log_path = $mitmdumpStderrPath
            stdout = $stdoutRecord.text
            stdout_truncated = $stdoutRecord.truncated
            stderr = $stderrRecord.text
            stderr_truncated = $stderrRecord.truncated
            port_state_at_failure = $portStateAtFailure
            certificate_state_at_failure = $certificateStateAtFailure
            cleanup = $cleanupResult
            certificate_state_after_cleanup = $finalCertificateState
        }
        Write-JsonFile -Path (Join-Path $runDirectory 'startup-failure.json') -Value $failureRecord
    }

    Write-EvidenceManifest `
        -Directory $runDirectory `
        -CaptureEndedCleanly $captureEndedCleanly `
        -RunStatus ([string] $runMetadata.startup_status)
}

if ($null -ne $capturedError) {
    throw "Capture failed at stage '$failureStage'. Evidence directory: $runDirectory. $($capturedError.Exception.GetType().FullName): $($capturedError.Exception.Message)"
}

Write-Host "Capture stopped. Evidence directory: $runDirectory"
