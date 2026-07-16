# Claude Code Windows test protocol

## Installed and tested state

Anthropic's official native Windows installer was downloaded from
`https://claude.ai/install.ps1`, inspected, and executed at user scope on
2026-07-15. The installer fetched its release manifest and checksum-verified
binary from `https://downloads.claude.ai/claude-code-releases`.

```powershell
pwsh -NoProfile -File C:\tmp\claude-install.ps1 latest
```

Observed local facts:

- Executable: `C:\Users\jande\.local\bin\claude.exe`
- Version: `2.1.210 (Claude Code)`
- Initial pre-authentication `claude auth status`: exit code 1,
  `loggedIn=false`, `authMethod=none`
- The installer directory is not currently on the inherited `PATH`; the adapter
  therefore uses the explicit executable path.

Authentication was later completed through Claude's first-party interactive
flow. The preserved A-C runs succeeded with that persisted session; account
details and credential material were not inspected, copied, or stored. Their
final statuses are `CAPTURE_VALIDATED`, with the run-scoped findings and caveats
recorded in `WINDOWS_COMPARISON.md`.

Official sources:

- <https://code.claude.com/docs/en/installation>
- <https://code.claude.com/docs/en/cli-usage>
- <https://code.claude.com/docs/en/authentication>
- <https://code.claude.com/docs/en/corporate-proxy>
- <https://code.claude.com/docs/en/permission-modes>

## Generic adapter command

The generic `scripts/Invoke-AgentCapture.ps1` runner consumes
`adapters/claude.json`; no Claude-specific orchestration is added. Local help
verified every argument in the prepared Test A command. The template uses
`--safe-mode`, rejects MCP configuration not supplied on the command line,
disables all built-in tools with `--tools=`, disables slash commands and Chrome
integration, suppresses session persistence, and retains plan mode. It does not
use bypass permissions.

```text
claude.exe --safe-mode --strict-mcp-config --tools= --disable-slash-commands
  --no-chrome --no-session-persistence --permission-mode plan
  --output-format json --add-dir <fresh-canary-repository>
  -p <approved-prompt>
```

The validated Test A run used that tool-disabled command. Tests B and C changed
only `--tools=` to `--tools=Read`. This permitted their approved read tasks
while leaving file discovery, search, shell, edit, write, and all other tools
unavailable.

Anthropic documents that native Windows sandboxing is not supported. The
adapter therefore makes no OS-sandbox claim; the no-read Test A gate instead
removes the client's tool surface. Enabling `Read` is a CLI tool restriction,
not a Windows path-level access boundary.

Run-scoped capture variables:

```text
HTTP_PROXY=http://127.0.0.1:<port>
HTTPS_PROXY=http://127.0.0.1:<port>
NO_PROXY=127.0.0.1,localhost
NODE_EXTRA_CA_CERTS=<mitmproxy-ca-pem>
```

The adapter also disables the auto-updater, telemetry, error reporting,
nonessential traffic, prompt history, Claude.ai MCP servers, and automatic IDE
connection using documented controls. These proxy and CA settings produced
attributable decrypted traffic in the preserved A-C runs. Expected hosts,
routing, trust, and direct-bypass conclusions remain specific to each run.

## Authentication and live-traffic gates

The documented first-party login command is interactive and may open a browser:

```powershell
& "$HOME\.local\bin\claude.exe" auth login
```

For reproduction, stop for user approval before running it. After login, verify
only the non-identifying fields from `claude auth status`; do not print account
or cached credential data. Create a fresh run ID, deterministic canary
repository, capture directory, and versioned output root for each test. Review
the exact command, prompt, proxy and CA variables, timeouts, certificate
import/removal, and port state before separately approving live traffic.
