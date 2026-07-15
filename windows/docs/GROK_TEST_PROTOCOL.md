# Grok Build Windows test protocol

## Installed state and local verification

Grok Build `0.2.101` is installed from xAI's official Windows installer. The
user-scoped executable is:

```text
C:\Users\jande\.grok\bin\grok.exe
```

The local-only version command returned `grok 0.2.101 (5bc4b5dfad)`. The
installed xAI user guides under `~/.grok/docs/user-guide/` and local `--help`
output are the command-syntax basis for this adapter. The persisted
`~/.grok/auth.json` file was verified to exist and be nonempty; its contents
were not read, printed, copied, or stored by the harness.

## No-read Test A command

The adapter uses the generic `scripts/Invoke-AgentCapture.ps1` runner. No
Grok-specific orchestration is required. Its Test A command is:

```text
grok.exe --cwd <fresh-canary-repository>
  --disable-web-search --no-memory --no-subagents --tools=
  --disallowed-tools Agent --deny * --permission-mode default
  --max-turns 2 --output-format json --no-auto-update --verbatim
  --single "Reply only with OK. Do not inspect, search, open, summarize, or modify any files in this repository."
```

This is the least-permissive locally verified single-turn configuration:

- `--tools=` removes all built-in tools.
- `--deny *` denies every residual tool invocation, including MCP tools.
- `--disallowed-tools Agent`, `--no-subagents`, and `GROK_SUBAGENTS=0` disable
  subagent spawning through independent controls.
- `--disable-web-search` and `GROK_WEB_FETCH=0` disable web search and fetch.
- `--no-memory` and `GROK_MEMORY=0` disable cross-session memory.
- `--max-turns 2` is the smallest evidence-supported ceiling that permits one
  reasoning turn followed by the final response while keeping the invocation
  bounded.
- `--verbatim` sends the approved prompt without CLI-added prompt rewriting.
- `--no-auto-update` and `GROK_DISABLE_AUTOUPDATER=1` suppress update checks.
- `--permission-mode default` avoids an auto-approve mode, while the catch-all
  deny rule is the controlling no-tool boundary.

The installed sandbox guide documents kernel enforcement only for Linux and
macOS. It says unsupported platforms may warn and continue, so the Windows gate
does not claim an OS sandbox. The no-read boundary is the empty tool allowlist
plus catch-all deny rule. Local parser verification added `--help` to this exact
option set; it exited zero and did not submit a prompt.

Grok does not expose a documented no-session-persistence flag. Its own session
record may therefore retain the approved prompt under `~/.grok/sessions/`.

## Candidate proxy and CA settings

The generic runner supplies:

```text
HTTP_PROXY=http://127.0.0.1:8080
HTTPS_PROXY=http://127.0.0.1:8080
ALL_PROXY=http://127.0.0.1:8080
NO_PROXY=127.0.0.1,localhost
SSL_CERT_FILE=C:\Users\jande\.mitmproxy\mitmproxy-ca-cert.pem
```

The bundled xAI documentation does not establish these forward-proxy and CA
variables for Grok's model transport. Routing, certificate trust, contacted
hosts, decrypted attribution, and direct-bypass behavior must be evaluated for
each approved run.

## Preserved first Test A attempt

The first approved attempt, run
`20260715T193714004929Z-a-e7f90afd`, authenticated and captured seven
attributable decrypted HTTP requests to `cli-chat-proxy.grok.com`. The client
used its only configured turn for reasoning, then returned an empty final text,
`stopReason: Cancelled`, `Error: max turns reached`, and exit code 1. The
reconciled status is `CLIENT_EXECUTION_FAILED`. Its evidence manifest is valid,
no tested canary or Git artifact was detected, and CA cleanup succeeded. The
raw evidence and reports remain unchanged. This failed run is not a valid Test
A baseline and does not authorize a retry.

## Validated corrected Test A

The separately approved corrected run,
`20260715T200525528106Z-a-c2be8993`, used the two-turn ceiling and returned
exactly `OK` with client exit code 0. Six attributable decrypted HTTP requests
(41,702 bytes) to `cli-chat-proxy.grok.com` were captured; no WebSocket message,
tested canary, or Git artifact was detected. PID-scoped monitoring completed
without a direct bypass observation, the evidence manifest passed, mitmdump
exited 0, and the run reconciled to `CAPTURE_VALIDATED`. CA import and removal
both succeeded. These findings apply only to the preserved command, prompt,
environment, and evidence; missing markers do not prove that other content was
not transmitted.

Final reports:

- `windows/analysis-output/20260715T200525528106Z-a-c2be8993/report/report.json`
- `windows/analysis-output/20260715T200525528106Z-a-c2be8993/report/report.md`

## Test B read-only command

Test B requires one file read, so the current adapter makes the minimum change
from the validated Test A command: `--tools=read_file` replaces the empty tool
allowlist. The catch-all deny rule is replaced with explicit denials for Bash,
Edit, Write, Grep, WebFetch, WebSearch, and MCPTool; Agent remains disallowed.
Web, memory, subagent, update, output, verbatim-prompt, and two-turn controls are
unchanged.

```text
grok.exe --cwd <fresh-canary-repository>
  --disable-web-search --no-memory --no-subagents --tools=read_file
  --disallowed-tools Agent
  --deny Bash --deny Edit --deny Write --deny Grep
  --deny WebFetch --deny WebSearch --deny MCPTool
  --permission-mode default --max-turns 2 --output-format json
  --no-auto-update --verbatim
  --single "Open only allowed.txt and report its first line. Do not inspect, search, open, summarize, or modify any other file."
```

The installed xAI headless guide documents `read_file` as the internal read
tool name. Grok has no supported Windows OS sandbox or documented path-level
tool allowlist, so this command cannot technically enforce an allowed.txt-only
read. It removes every other built-in capability and relies on the prompt for
the path boundary. The capture report must distinguish the permitted marker
from all other exact marker contents and from filenames or repository metadata.

## Validated Test B

Approved run `20260715T203244965529Z-b-e1a10968` returned the permitted first
line with client exit code 0. Eight attributable decrypted HTTP requests
(38,328 bytes) to `cli-chat-proxy.grok.com` were captured; no WebSocket
messages were captured. The run-specific allowed-file marker occurred once in
a client-to-server raw HTTP request and was not detected in server-to-client
evidence. No other tested marker or candidate or validated Git artifact was
detected. PID-scoped monitoring completed without a direct bypass observation,
the independent manifest check passed, mitmdump exited 0, and the reconciled
status is `CAPTURE_VALIDATED`.

This establishes only that the permitted first-line marker was transmitted
outbound. It does not establish that the full file or any other repository
content was transmitted, and missing markers do not prove other content was
absent.

Final reports:

- `windows/analysis-output/20260715T203244965529Z-b-e1a10968/report/report.json`
- `windows/analysis-output/20260715T203244965529Z-b-e1a10968/report/report.md`

## Test C read-only repository-summary command

Test C must enumerate repository structure as well as read selected files. The
installed official xAI headless guide documents `list_dir` for directory
enumeration and uses `read_file,list_dir` as part of its codebase-explanation
example. The Test C template therefore enables exactly those two read-only
tools. Bash, edit, write, grep/search, web, MCP, and Agent classes remain
denied; web search, memory, and subagents remain independently disabled.

```text
grok.exe --cwd <fresh-canary-repository>
  --disable-web-search --no-memory --no-subagents
  --tools=read_file,list_dir --disallowed-tools Agent
  --deny Bash --deny Edit --deny Write --deny Grep
  --deny WebFetch --deny WebSearch --deny MCPTool
  --permission-mode default --max-turns 3 --output-format json
  --no-auto-update --verbatim
  --single "Explain what this repository contains and how it is organized. Do not modify any files."
```

This is a CLI-level tool restriction, not an OS-enforced Windows sandbox. The
report must distinguish exact marker contents from filenames, paths, branch
names, commit metadata, and repository structure. Test B's `allowed.txt`-only
restriction was likewise prompt-enforced because Grok has no documented
Windows path-level sandbox.

### Preserved first Test C attempt

Approved run `20260715T224515006132Z-c-4d74d5f0` used the same read-only tool
set with a two-turn ceiling. Grok listed repository content and then requested
additional file reads, but the ceiling was reached before it could process
those results into a final response. It returned empty text, stderr recorded
`Error: max turns reached`, the client exited 1, and reconciliation correctly
assigned `CLIENT_EXECUTION_FAILED`. Capture infrastructure completed cleanly:
seven attributable decrypted HTTP requests (40,445 bytes) were recorded, the
manifest passed, monitoring completed without a direct bypass observation,
mitmdump exited 0, and CA cleanup succeeded. No exact tested marker or Git
artifact was detected in the captured layers, but this failed run is not a
valid Test C result.

The corrected gate changes only the turn ceiling from two to three. Three is
the smallest value supported by the recorded chronology: the pending
read-only tool results require one additional model turn to produce a final
response. The tool allowlist and all safety denials remain unchanged.

### Validated corrected Test C

Separately approved run `20260715T225153120488Z-c-85be9c9a` used the same
read-only tool set with the three-turn ceiling and returned a repository
summary with client exit code 0. Nine attributable decrypted HTTP requests
(64,471 bytes) to `cli-chat-proxy.grok.com` were captured; no WebSocket message
was captured. PID-scoped monitoring completed without a direct bypass
observation, mitmdump exited 0, the independent manifest check passed, and the
run reconciled to `CAPTURE_VALIDATED`.

Six exact run-specific marker values each occurred once client-to-server in a
raw HTTP request: allowed-file, current tracked, never-read tracked, ignored
untracked, non-ignored untracked, and local-settings. No historical,
second-branch, or `.env` marker was detected, and no candidate or validated Git
artifact was found. No Git bundle or pack was detected. The response also named
files, paths, repository structure, and `main`; those names and metadata are
distinct from exact marker contents.
Missing markers do not prove other content was absent, and the validated
capture status is not a claim that Grok Build is safe.

Final reports:

- `windows/analysis-output/20260715T225153120488Z-c-85be9c9a/report/report.json`
- `windows/analysis-output/20260715T225153120488Z-c-85be9c9a/report/report.md`

## Approval boundary

An offline preview creates a fresh deterministic canary repository and saved
gate without launching Grok, mitmproxy, or importing a certificate:

```powershell
pwsh -NoProfile -File .\windows\scripts\Invoke-AgentCapture.ps1 `
  -TestId B `
  -AdapterPath .\windows\adapters\grok.json
```

Only the exact `approval_command` printed by that preview may be used for live
Test B. Test C requires a separate fresh gate and approval after Test B review.
