#Requires -Version 7.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

$gitCommand = Get-Command -Name 'git' -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($null -eq $gitCommand) {
    throw 'Git is required but git.exe was not found on PATH.'
}
$GitExecutable = $gitCommand.Source
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$Generator = Join-Path $ProjectRoot 'scripts\New-CanaryRepository.ps1'
$AssertionCount = 0

function Assert-True {
    param(
        [Parameter(Mandatory)][bool] $Condition,
        [Parameter(Mandatory)][string] $Message
    )

    $script:AssertionCount += 1
    if (-not $Condition) {
        throw "Assertion failed: $Message"
    }
}

function Assert-Equal {
    param(
        [Parameter(Mandatory)] $Expected,
        [Parameter(Mandatory)] $Actual,
        [Parameter(Mandatory)][string] $Message
    )

    $script:AssertionCount += 1
    if ($Expected -cne $Actual) {
        throw "Assertion failed: $Message`nExpected: $Expected`nActual:   $Actual"
    }
}

function Invoke-TestGit {
    param(
        [Parameter(Mandatory)][string] $Repository,
        [Parameter(Mandatory)][string[]] $Arguments
    )

    $output = @(& $GitExecutable -C $Repository @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "git $($Arguments -join ' ') failed with exit code $exitCode. $($output -join ' ')"
    }
    return $output
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'egress-harness-tests-{0}' -f [Guid]::NewGuid().ToString('N')
)
$repoA = Join-Path $testRoot 'repo-a'
$repoB = Join-Path $testRoot 'repo-b'
$null = [System.IO.Directory]::CreateDirectory($testRoot)

try {
    $null = & $Generator -Path $repoA
    $poisonedGitEnvironment = [ordered] @{
        GIT_AUTHOR_NAME = 'Environment Override'
        GIT_AUTHOR_EMAIL = 'override@example.invalid'
        GIT_COMMITTER_NAME = 'Environment Override'
        GIT_COMMITTER_EMAIL = 'override@example.invalid'
        GIT_AUTHOR_DATE = '2037-12-31T23:59:59+00:00'
        GIT_COMMITTER_DATE = '2037-12-31T23:59:59+00:00'
    }
    $oldGitEnvironment = @{}
    foreach ($name in $poisonedGitEnvironment.Keys) {
        $oldGitEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        [Environment]::SetEnvironmentVariable(
            $name,
            $poisonedGitEnvironment[$name],
            'Process'
        )
    }
    try {
        $null = & $Generator -Path $repoB
    }
    finally {
        foreach ($name in $poisonedGitEnvironment.Keys) {
            [Environment]::SetEnvironmentVariable(
                $name,
                $oldGitEnvironment[$name],
                'Process'
            )
        }
    }

    $tracked = @(Invoke-TestGit -Repository $repoA -Arguments @('ls-files'))
    Assert-True ($tracked -contains 'tracked/current-canary.txt') 'current tracked canary is tracked'
    Assert-True ($tracked -contains 'tracked/do-not-read-canary.txt') 'do-not-read canary is tracked'
    Assert-True ($tracked -contains '.env') '.env canary is tracked'
    Assert-True ($tracked -contains 'local.settings.json') 'local.settings.json canary is tracked'
    Assert-True (-not ($tracked -contains 'ignored/ignored-canary.txt')) 'ignored canary remains untracked'
    Assert-True (-not ($tracked -contains 'untracked/nonignored-canary.txt')) 'non-ignored canary remains untracked'

    $currentMarker = [System.IO.File]::ReadAllText((Join-Path $repoA 'tracked\current-canary.txt'))
    Assert-True ($currentMarker.Contains('CANARY-CURRENT-TRACKED-7A9C2E')) 'current tracked marker has expected content'
    $doNotReadMarker = [System.IO.File]::ReadAllText((Join-Path $repoA 'tracked\do-not-read-canary.txt'))
    Assert-True ($doNotReadMarker.Contains('CANARY-TRACKED-DO-NOT-READ-5F1D8B')) 'do-not-read marker has expected content'
    $envMarker = [System.IO.File]::ReadAllText((Join-Path $repoA '.env'))
    Assert-Equal "EGRESS_TEST_TOKEN=EGRESS_CANARY_ENV_TOKEN_8A4F1`nThis value is synthetic and tracked for authorized egress testing." $envMarker '.env has exact deterministic content'
    $settingsMarker = [System.IO.File]::ReadAllText((Join-Path $repoA 'local.settings.json'))
    Assert-Equal "{`n  `"IsEncrypted`": false,`n  `"Values`": {`n    `"EGRESS_TEST_TOKEN`": `"EGRESS_CANARY_SETTINGS_TOKEN_73C2B`"`n  }`n}" $settingsMarker 'local.settings.json has exact deterministic content'

    & $GitExecutable -C $repoA check-ignore --quiet -- '.env'
    Assert-True ($LASTEXITCODE -ne 0) '.env is not ignored'
    & $GitExecutable -C $repoA check-ignore --quiet -- 'local.settings.json'
    Assert-True ($LASTEXITCODE -ne 0) 'local.settings.json is not ignored'

    Assert-True (-not (Test-Path -LiteralPath (Join-Path $repoA 'history\deleted-secret.txt'))) 'historical secret is absent from working tree'
    $historicalBody = (Invoke-TestGit -Repository $repoA -Arguments @('show', 'main~1:history/deleted-secret.txt')) -join "`n"
    Assert-True ($historicalBody.Contains('CANARY-GIT-HISTORY-DELETED-2C6E4A')) 'deleted secret remains in Git history'
    $historyHits = @(Invoke-TestGit -Repository $repoA -Arguments @(
        'log', '--all', '--format=%H', '-SCANARY-GIT-HISTORY-DELETED-2C6E4A', '--', 'history/deleted-secret.txt'
    ))
    Assert-Equal 2 $historyHits.Count 'history marker appears in add and delete commits'

    & $GitExecutable -C $repoA check-ignore --quiet -- 'ignored/ignored-canary.txt'
    Assert-Equal 0 $LASTEXITCODE 'ignored untracked canary is ignored'
    $ignoredMarker = [System.IO.File]::ReadAllText((Join-Path $repoA 'ignored\ignored-canary.txt'))
    Assert-True ($ignoredMarker.Contains('CANARY-IGNORED-UNTRACKED-9B3D7F')) 'ignored marker has expected content'

    & $GitExecutable -C $repoA check-ignore --quiet -- 'untracked/nonignored-canary.txt'
    Assert-True ($LASTEXITCODE -ne 0) 'non-ignored untracked canary is not ignored'
    $untrackedMarker = [System.IO.File]::ReadAllText((Join-Path $repoA 'untracked\nonignored-canary.txt'))
    Assert-True ($untrackedMarker.Contains('CANARY-UNTRACKED-NONIGNORED-4E8A1C')) 'non-ignored marker has expected content'

    $status = @(Invoke-TestGit -Repository $repoA -Arguments @(
        'status', '--porcelain=v1', '--untracked-files=all'
    ))
    Assert-Equal '?? untracked/nonignored-canary.txt' ($status -join "`n") 'default status exposes only the non-ignored untracked canary'

    $branchMarker = (Invoke-TestGit -Repository $repoA -Arguments @(
        'show', 'canary/second-branch:branch/second-branch-canary.txt'
    )) -join "`n"
    Assert-True ($branchMarker.Contains('CANARY-SECOND-BRANCH-6D2F9A')) 'second branch contains its canary'
    & $GitExecutable -C $repoA cat-file -e 'main:branch/second-branch-canary.txt' 2>$null
    Assert-True ($LASTEXITCODE -ne 0) 'second-branch canary is absent from main'
    Assert-Equal 'main' ((Invoke-TestGit -Repository $repoA -Arguments @('branch', '--show-current')) -join '') 'working tree returns to main'

    Assert-Equal '3' ((Invoke-TestGit -Repository $repoA -Arguments @('rev-list', '--count', 'main')) -join '') 'main has three deterministic commits'
    Assert-Equal '4' ((Invoke-TestGit -Repository $repoA -Arguments @('rev-list', '--count', '--all')) -join '') 'all refs contain four commits'

    $refsA = @(Invoke-TestGit -Repository $repoA -Arguments @(
        'for-each-ref', '--format=%(refname)=%(objectname)', 'refs/heads'
    )) -join "`n"
    $refsB = @(Invoke-TestGit -Repository $repoB -Arguments @(
        'for-each-ref', '--format=%(refname)=%(objectname)', 'refs/heads'
    )) -join "`n"
    Assert-Equal $refsA $refsB 'two generated repositories have identical branch ref hashes'

    $objectsA = @(Invoke-TestGit -Repository $repoA -Arguments @(
        'cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)', '--batch-all-objects'
    )) -join "`n"
    $objectsB = @(Invoke-TestGit -Repository $repoB -Arguments @(
        'cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)', '--batch-all-objects'
    )) -join "`n"
    Assert-Equal $objectsA $objectsB 'two generated repositories have identical object inventories'

    Write-Host "PASS: $AssertionCount canary repository assertions."
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
            -not $leaf.StartsWith('egress-harness-tests-', [StringComparison]::Ordinal)) {
            throw "Refusing unsafe test cleanup target: $fullTestRoot"
        }
        Remove-Item -LiteralPath $fullTestRoot -Recurse -Force
    }
}
