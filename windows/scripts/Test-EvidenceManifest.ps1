#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $RunDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$pythonCommand = Get-Command -Name 'python' -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($null -eq $pythonCommand) {
    throw 'Python 3.12 is required. Activate the documented virtual environment first.'
}

$projectRoot = Split-Path $PSScriptRoot -Parent
$previousPythonPath = [Environment]::GetEnvironmentVariable('PYTHONPATH', 'Process')
[Environment]::SetEnvironmentVariable('PYTHONPATH', $projectRoot, 'Process')
try {
    & $pythonCommand.Source -m analysis.verify_manifest $RunDirectory
    $verificationExitCode = $LASTEXITCODE
}
finally {
    [Environment]::SetEnvironmentVariable('PYTHONPATH', $previousPythonPath, 'Process')
}

exit $verificationExitCode
