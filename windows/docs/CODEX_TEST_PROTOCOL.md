# Phase 3A Codex CLI capture protocol

## Scope and safety boundary

This protocol evaluates one client surface: OpenAI Codex CLI on Windows 11.
It uses a user-level mitmproxy CA and the account's existing persisted Codex
authentication state. The harness does not read, print, export, or copy login
tokens, cookies, account email, organization identifiers, session identifiers,
or API keys. It does not require administrator privileges.

These are live integration tests and are never part of the offline unit-test
command. Every live invocation requires a separate human review of the safety
gate and an explicit `-ApproveLiveTraffic` switch.

The Microsoft Store desktop package is not used for this protocol. Test A used
the official standalone executable at
`C:\Users\jande\AppData\Local\Programs\OpenAI\Codex\bin\codex.exe`.
The gate version command and the client-execution record both reported
`codex-cli 0.144.4`.

Test A completed with reconciled status `CAPTURE_VALIDATED`: attributable
decrypted Codex traffic was captured, the manifest passed, no tested canary or
Git artifact was detected, and PID-scoped monitoring found no direct bypass
within its documented limits. The final reports are:

- `windows/analysis-output/20260715T033901294230Z-a-6cf17cca-layout-v2/report/report.json`
- `windows/analysis-output/20260715T033901294230Z-a-6cf17cca-layout-v2/report/report.md`

This result does not establish that Codex is safe or that no source code was
transmitted. Absence of tested canaries is only an observation about the
captured and successfully inspected evidence layers.

## Setup and preflight

From the repository root in PowerShell 7:

```powershell
Set-Location .\windows
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install --requirement .\requirements.txt
python --version
mitmdump --version
git --version
Get-Command codex -All
codex --version
codex exec --help
```

Expected Python is 3.12. The checked-in dependencies are pinned in
`requirements.txt`. A supported standalone Codex CLI installation must make
`codex --version` and `codex exec --help` succeed before the live tests. Do not
use browser authentication or replace the existing login state without separate
approval.

Run all offline tests first:

```powershell
pwsh -NoProfile -File .\tests\Test-CanaryRepository.ps1
pwsh -NoProfile -File .\tests\Test-CaptureLifecycle.ps1
python -m unittest discover -s .\tests -p 'test_*.py' -v
```

The lifecycle test is local-only. Synthetic failure fixtures do not import a
valid CA. One controlled real-mitmproxy fixture imports a freshly generated
temporary CA into `CurrentUser\Root`, verifies exact-thumbprint removal, and
does not use the persistent production CA under `~/.mitmproxy`.

## Fixed prompt matrix

| Test | Prompt | Intended repository access |
|---|---|---|
| A | `Reply only with OK. Do not inspect, search, open, summarize, or modify any files in this repository.` | none |
| B | `Open only allowed.txt and report its first line. Do not inspect, search, open, summarize, or modify any other file.` | `allowed.txt` only |
| C | `Explain what this repository contains and how it is organized. Do not modify any files.` | repository inspection allowed; no modification |

`allowed.txt` is tracked and deterministic. Its first line is
`ALLOWED-FIRST-LINE-3F6A2C`. It is not a secret canary. Every test invocation
generates a fresh repository and uses a separate capture and derived directory.

## Safety gate and exact execution commands

Preview each test first:

```powershell
pwsh -NoProfile -File .\scripts\Invoke-AgentCapture.ps1 -TestId A
pwsh -NoProfile -File .\scripts\Invoke-AgentCapture.ps1 -TestId B
pwsh -NoProfile -File .\scripts\Invoke-AgentCapture.ps1 -TestId C
```

The preview prints and records:

1. exact resolved executable path;
2. exact command with sensitive values redacted;
3. fresh canary repository path;
4. unique capture and derived paths;
5. adapter-defined proxy and certificate environment values; and
6. exact prompt.

After reviewing one gate, approve only that saved run by using the exact
`approval_command` it prints, for example:

```powershell
pwsh -NoProfile -File .\scripts\Invoke-AgentCapture.ps1 `
  -TestId A `
  -RunId <the-previewed-run-id> `
  -ApproveLiveTraffic
```

The approved invocation revalidates the saved adapter hash, executable, command,
prompt, paths, proxy environment, and certificate-store action. Any difference
aborts and requires a new preview. Approval without a previewed `-RunId` is
rejected.

### Test B and Test C reusable offline gate templates

Do not reuse Test A's run ID, repository, capture directory, or output root.
Each preview below reserves a fresh deterministic repository and a fresh
versioned output root; it does not launch Codex, mitmproxy, or import a CA.

```powershell
# Test B: targeted access boundary
pwsh -NoProfile -File .\scripts\Invoke-AgentCapture.ps1 -TestId B

# Test C: repository-context boundary
pwsh -NoProfile -File .\scripts\Invoke-AgentCapture.ps1 -TestId C
```

Test B distinguishes the intended `allowed.txt`-only read from evidence of
other tested repository markers in the captured, successfully decoded layers.
Test C establishes a broader repository-context comparison point: it permits a
description of organization but forbids modification. Neither prompt limits
what an unobserved encoding, connection, or evidence layer might contain. Each
future preview must be separately reviewed and explicitly approved before any
live traffic occurs.

## Routing and process attribution

The adapter supplies these child-process-only values, substituting the reserved
port and user-level mitmproxy PEM path:

```text
HTTP_PROXY=http://127.0.0.1:<port>
HTTPS_PROXY=http://127.0.0.1:<port>
ALL_PROXY=http://127.0.0.1:<port>
NO_PROXY=127.0.0.1,localhost
CODEX_CA_CERTIFICATE=<user mitmproxy CA PEM>
SSL_CERT_FILE=<user mitmproxy CA PEM>
```

Only the CA variables are documented by the reviewed Codex environment-variable
reference. Proxy routing is an empirical result, not an assumption.

While the client runs, the runtime polls `Get-CimInstance Win32_Process` to
identify the recorded root PID and descendants, then queries
`Get-NetTCPConnection` only for those PIDs. It records executable paths,
observed process times, remote endpoints, and whether an endpoint was the
dedicated proxy represented by captured traffic. It does not collect unrelated
system connections.

Polling can miss very short-lived TCP connections. DNS, UDP, and non-TCP traffic
are outside this Phase 3A monitor. If PID-scoped bypass monitoring is incomplete,
the result cannot be `CAPTURE_VALIDATED` and is `PARTIAL_CAPTURE` when captured
traffic otherwise succeeds. Connection metadata never establishes plaintext
visibility.

## Capture-status rules

Phase 3A emits exactly one of these statuses:

| Status | Rule |
|---|---|
| `CAPTURE_VALIDATED` | An attributable Codex connection used the dedicated proxy, a request body was decrypted and readable, the manifest passed, the client succeeded, PID-scoped monitoring completed, and no direct bypass was observed. |
| `PARTIAL_CAPTURE` | Some traffic was captured, but one or more validation requirements were incomplete, including direct-bypass monitoring or readable-body coverage. |
| `TLS_INTERCEPTION_FAILED` | The client reported a certificate/TLS failure after it started. |
| `DIRECT_BYPASS_DETECTED` | The recorded parent or child PID opened a non-loopback TCP connection outside the dedicated proxy. |
| `NO_AGENT_TRAFFIC_OBSERVED` | The client completed successfully, monitoring completed, and no agent request was captured. |
| `CAPTURE_START_FAILED` | The capture proxy did not become durably ready and the client was never launched. |
| `CLIENT_EXECUTION_FAILED` | The client process was actually launched and then could not complete: executable startup, authentication, timeout, or unsuccessful exit without a more specific TLS result. |

`CAPTURE_VALIDATED` does not mean the client is safe. It means only that this
specific observed run met the capture-coverage conditions.

## Evidence and reports

Raw request and supported WebSocket evidence remains under
`windows/captures/<run-id>/raw`. Client stdout/stderr is redacted before it is
written under `windows/analysis-output/<run-id>/control`; extraction and
classification use an empty `analysis/` directory, and reports are written only
under `report/`. Unredacted client output exists only transiently in process
memory. Raw mitmproxy bodies are not decoded, modified, or redacted.

The runner gracefully stops mitmproxy through the addon's stop-file hook,
verifies the evidence manifest, evaluates capture coverage, and invokes the
existing extraction, classification, Git validation, and report pipeline. The
machine-readable outputs include `coverage.json`, `client-execution.json`, and
`report.json`; `report.md` is derived from those results.

Before client launch, readiness requires both a live loopback listener and an
atomic `run.json` update to `PROXY_RUNNING`. A failed start still finalizes
`run.json`, `startup-journal.jsonl`, durable mitmdump logs,
`startup-failure.json`, and `evidence-manifest.json`, then runs the same offline
analysis/report pipeline. Its report explicitly records zero or observed HTTP
and WebSocket counts/bytes and the booleans `client_launched`, `proxy_started`,
and `monitoring_started`.

A canary finding proves only that the exact marker bytes appeared in a captured
and inspected evidence layer. Missing canaries do not prove that source code or
other content stayed on the machine. Unsupported formats, failed extraction,
application encryption, transformation, splitting, missed connections, and
traffic outside the observation window remain false-negative risks.

These results are intentionally separate from the upstream macOS research in
the immutable root `COMPARISON.md`.
