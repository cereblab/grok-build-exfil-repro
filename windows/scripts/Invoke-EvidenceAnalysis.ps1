#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $RunDirectory,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $OutputRoot,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $ExpectedCanaryRepository,

    [Parameter()]
    [ValidateRange(1, 100)]
    [int] $MaximumExtractionDepth = 6,

    [Parameter()]
    [ValidateRange(1, [long]::MaxValue)]
    [long] $MaximumTotalExpandedBytes = 67108864,

    [Parameter()]
    [ValidateRange(1, 1000000)]
    [int] $MaximumDerivedArtifacts = 1000,

    [Parameter()]
    [ValidateRange(1, [long]::MaxValue)]
    [long] $MaximumSizePerDerivedArtifact = 16777216,

    [Parameter()]
    [ValidateRange(0.01, 1000000.0)]
    [double] $DecompressionRatioLimit = 100.0,

    [Parameter()]
    [ValidateSet(
        'CAPTURE_VALIDATED',
        'PARTIAL_CAPTURE',
        'TLS_INTERCEPTION_FAILED',
        'DIRECT_BYPASS_DETECTED',
        'NO_AGENT_TRAFFIC_OBSERVED',
        'CAPTURE_START_FAILED',
        'CLIENT_EXECUTION_FAILED',
        'CAPTURE_FAILED',
        'NOT_EVALUATED'
    )]
    [string] $CaptureStatus = 'NOT_EVALUATED'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$pythonCommand = Get-Command -Name 'python' -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($null -eq $pythonCommand) {
    throw 'Python 3.12 is required. Activate the documented virtual environment first.'
}
$pythonVersion = @(& $pythonCommand.Source -c 'import sys; print(".".join(map(str, sys.version_info[:3])))' 2>&1) -join ''
if ($LASTEXITCODE -ne 0 -or $pythonVersion -notmatch '^3\.12(?:\.|$)') {
    throw "Python 3.12 is required; active Python reported '$pythonVersion'."
}

$projectRoot = Split-Path $PSScriptRoot -Parent
$previousPythonPath = [Environment]::GetEnvironmentVariable('PYTHONPATH', 'Process')
[Environment]::SetEnvironmentVariable('PYTHONPATH', $projectRoot, 'Process')

function Invoke-AnalysisStage {
    param(
        [Parameter(Mandatory)][string] $Module,
        [Parameter(Mandatory)][string[]] $Arguments
    )

    Write-Host "Running $Module"
    $output = @(& $pythonCommand.Source -m $Module @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$Module failed with exit code $exitCode. $($output -join [Environment]::NewLine)"
    }
}

try {
    $layoutOutput = @(& $pythonCommand.Source -m analysis.output_layout $OutputRoot 2>&1)
    $layoutExitCode = $LASTEXITCODE
    if ($layoutExitCode -ne 0) {
        throw "Output layout preparation failed with exit code $layoutExitCode. $($layoutOutput -join [Environment]::NewLine)"
    }
    $layout = ($layoutOutput -join [Environment]::NewLine) | ConvertFrom-Json
    $analysisDirectory = [string] $layout.analysis_directory
    $controlDirectory = [string] $layout.control_directory
    $reportDirectory = [string] $layout.report_directory

    $extractionArguments = @(
        $RunDirectory,
        $analysisDirectory,
        '--maximum-extraction-depth', $MaximumExtractionDepth.ToString(),
        '--maximum-total-expanded-bytes', $MaximumTotalExpandedBytes.ToString(),
        '--maximum-derived-artifacts', $MaximumDerivedArtifacts.ToString(),
        '--maximum-size-per-derived-artifact', $MaximumSizePerDerivedArtifact.ToString(),
        '--decompression-ratio-limit', $DecompressionRatioLimit.ToString(
            [System.Globalization.CultureInfo]::InvariantCulture
        )
    )
    Invoke-AnalysisStage -Module 'analysis.extract_payloads' -Arguments $extractionArguments
    Invoke-AnalysisStage -Module 'analysis.classify_payloads' -Arguments @(
        $RunDirectory, $analysisDirectory
    )
    Invoke-AnalysisStage -Module 'analysis.validate_git_artifacts' -Arguments @(
        $RunDirectory, $analysisDirectory, $ExpectedCanaryRepository
    )
    Invoke-AnalysisStage -Module 'analysis.generate_report' -Arguments @(
        $RunDirectory,
        $analysisDirectory,
        '--control-directory', $controlDirectory,
        '--report-directory', $reportDirectory,
        '--capture-status', $CaptureStatus
    )
}
finally {
    [Environment]::SetEnvironmentVariable('PYTHONPATH', $previousPythonPath, 'Process')
}

Write-Host "Analysis complete. Output root: $OutputRoot"
