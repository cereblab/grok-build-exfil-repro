# Agent adapter format

Adapters are versioned data files consumed by the generic
`scripts/Invoke-AgentCapture.ps1` runner. The checked-in adapters describe the
tested Codex CLI 0.144.4, Claude Code 2.1.210, Gemini CLI 0.50.0 API-key-mode,
and Grok Build 0.2.101 command surfaces. Their final A-C statuses and run-scoped
limitations are recorded in `../../WINDOWS_COMPARISON.md`; failed preparatory
runs remain distinct from those final results.
No Antigravity adapter is included.

The schema is `schema/adapter.schema.json` and the current schema version is
`egress-adapter/v1`. Validate the checked-in adapter without launching a client:

```powershell
Set-Location .\windows
$env:PYTHONPATH = (Get-Location).Path
Get-ChildItem .\adapters\*.json | ForEach-Object {
  python -m analysis.agent_runtime validate `
    --adapter $_.FullName `
    --schema .\adapters\schema\adapter.schema.json
}
```

An adapter defines an executable, version arguments, a noninteractive argument
template, environment variables, timeout, expected hosts, authentication mode,
optional authentication-failure regular expressions, model, approval mode,
sandbox mode, limitations, and optional names of allowlisted inherited secret
environment variables. `{working_directory}` and `{prompt}` are required
command placeholders. `{proxy_port}` and `{ca_certificate}` can be used in
adapter-defined environment values. Authentication-failure patterns are applied
to the already-redacted client stdout and stderr.

Credential values in adapter environment variables are rejected. The runner constructs a child
environment from a small Windows runtime/location allowlist, removes inherited
proxy/certificate values, and then applies the adapter's exact environment. It
does not inherit arbitrary shell variables. An adapter may explicitly request a
supported secret name such as `GEMINI_API_KEY`; the runtime resolves it only for
the client child process and records only whether it was available. Secret
values are never placed in adapter preparation, safety gates, commands, logs, or
reports.

An adapter may also declare an `authentication_selection` consisting of a JSON
settings path, a field path, and an expected nonsecret value. Preview and live
execution both verify that selector and bind it into the saved safety gate.
`USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, and optional `CODEX_HOME` remain available so existing
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
`--sandbox`, `--json`, and a prompt argument (or `-` for stdin). The Codex
template uses the `read-only` policy, `never` approvals, JSONL output, and the
generated repository as `--cd`. On native Windows it explicitly selects the
documented `windows.sandbox="unelevated"` fallback. This avoids the
administrator-approved setup required by the elevated implementation without
weakening the read-only policy or granting write access.

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
For a non-Codex adapter, add `-AdapterPath .\adapters\<client>.json`. The printed
approval command binds `-ApproveLiveTraffic` to the saved run ID; changed gate
data is rejected.

## Gemini, Claude, and Grok adapters

Gemini CLI and Claude Code were installed at user scope using their vendors'
official distribution methods. Claude's preserved authenticated A-C runs used
the native Windows binary and the adapter's restricted tool configuration.
Gemini's final A-C runs used the explicitly verified `gemini-api-key` selector;
the key value was neither read nor serialized. Proxy routing, certificate trust,
attribution, and direct-bypass conclusions remain specific to each preserved
run and status.

Grok Build uses the explicit user-scoped executable at
`C:\Users\jande\.grok\bin\grok.exe`. Its validated Test A used single-turn JSON
output, an empty built-in-tool allowlist, and a catch-all tool-deny rule. The
current Test C template enables only `read_file` and `list_dir`, explicitly
denies shell, edit, write, search, web, MCP, and Agent classes, and retains
independent web, memory, and subagent controls. The installed xAI
sandbox documentation does not claim Windows enforcement. The corrected
approved Test A returned `OK` and reconciled to `CAPTURE_VALIDATED`; proxy
routing, CA trust, contacted hosts, and direct-bypass conclusions remain
specific to that preserved run.

Executable paths are observations from the test machine, not portable install
locations. A reviewer reproducing a run must point the local adapter at the
official executable, preview a fresh gate, and review any version/path change
before approving traffic. Raw captures and derived outputs remain local and are
not part of the adapter files.
