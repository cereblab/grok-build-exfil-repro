# Agent adapter format

Adapters are versioned data files consumed by the generic
`scripts/Invoke-AgentCapture.ps1` runner. `codex.json` is the Phase 3A adapter.
`gemini.json` and `claude.json` are offline preparation templates only: neither
executable, version, login state, proxy behavior, CA behavior, nor live traffic
has been verified. No Grok Build or Antigravity adapter is included.

The schema is `schema/adapter.schema.json` and the current schema version is
`egress-adapter/v1`. Validate the checked-in adapter without launching a client:

```powershell
Set-Location .\windows
$env:PYTHONPATH = (Get-Location).Path
python -m analysis.agent_runtime validate `
  --adapter .\adapters\codex.json `
  --schema .\adapters\schema\adapter.schema.json
```

An adapter defines an executable, version arguments, a noninteractive argument
template, environment variables, timeout, expected hosts, authentication mode,
model, approval mode, sandbox mode, and limitations. `{working_directory}` and
`{prompt}` are required command placeholders. `{proxy_port}` and
`{ca_certificate}` can be used in adapter-defined environment values.

Credential environment variables are rejected. The runner constructs a child
environment from a small Windows runtime/location allowlist, removes inherited
proxy/certificate values, and then applies the adapter's exact environment. It
does not inherit arbitrary shell variables such as API keys. `USERPROFILE`,
`APPDATA`, `LOCALAPPDATA`, and optional `CODEX_HOME` remain available so existing
persisted Codex login state can be used without the harness reading or copying
it.

## Codex adapter basis

Validated Test A date: 2026-07-14/15 local time.

- Observed package: Microsoft Store package `OpenAI.Codex_26.707.9981.0_x64__2p2nqsd0c76g0`.
- Package version: `26.707.9981.0`.
- Bundled backend path: `C:\Program Files\WindowsApps\OpenAI.Codex_26.707.9981.0_x64__2p2nqsd0c76g0\app\resources\codex.exe`.
- Package manifest entry point: `app/ChatGPT.exe`; no `codex` application-execution alias is declared.
- The official standalone CLI was installed at user scope and Test A used
  `C:\Users\jande\AppData\Local\Programs\OpenAI\Codex\bin\codex.exe`.
- The preflight version command and the client-execution record both reported
  `codex-cli 0.144.4`.

The official command reference documents `codex exec` as the stable
noninteractive mode. It documents `--cd`, `--model`, `--ask-for-approval`,
`--sandbox`, `--json`, and a prompt argument (or `-` for stdin). The Phase 3A
template uses read-only sandboxing, no interactive approvals, JSONL output, and
the generated repository as `--cd`.

The official environment-variable reference documents
`CODEX_CA_CERTIFICATE` and fallback `SSL_CERT_FILE` for HTTPS, login, and
WebSocket clients. It does not list `HTTP_PROXY`, `HTTPS_PROXY`, or `ALL_PROXY`
among Codex's stable public variables. The adapter supplies those proxy values,
but Phase 3A must establish their actual behavior from capture and
PID-attributed connection evidence; configuration alone is not evidence.

Official references:

- <https://learn.chatgpt.com/docs/developer-commands?surface=cli>
- <https://learn.chatgpt.com/docs/config-file/environment-variables>
- <https://learn.chatgpt.com/docs/auth>

## Safety preview

This command creates an ignored, deterministic test fixture and prints the
safety gate. It does not launch Codex or mitmproxy:

```powershell
pwsh -NoProfile -File .\scripts\Invoke-AgentCapture.ps1 -TestId A
```

Only after reviewing the displayed executable, redacted command, paths, proxy
environment, and prompt may a human run the exact printed `approval_command`.
That command binds `-ApproveLiveTraffic` to the saved run ID; changed gate data
is rejected.

## Prepared Gemini and Claude templates

The Gemini and Claude templates use only their vendors' documented global npm
package, version, and noninteractive command syntax. The proposed user-scope
npm prefix is a local policy choice and must be reviewed before installation.
Their adapter fields deliberately state `UNVERIFIED` where local installation,
authentication, routing, certificate trust, or executable behavior has not been
tested. Validate each adapter offline before a separate installation gate.
