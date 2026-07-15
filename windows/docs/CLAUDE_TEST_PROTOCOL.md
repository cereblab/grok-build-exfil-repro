# Claude Code offline preparation protocol

## Status and boundaries

This is an offline preparation document, not installation or authorization to
run Claude Code. The local executable path, installed version, authentication
state, proxy routing, certificate trust, and command behavior are all
**UNVERIFIED**. Do not install, authenticate, invoke, or send traffic until
separate approval.

The generic `scripts/Invoke-AgentCapture.ps1` runner and
`adapters/claude.json` represent the documented command shape; no
vendor-specific runner is added. Every eventual A, B, or C run must use a newly
generated canary repository, capture directory, and versioned output root.

## Official basis and installation gate

Anthropic documents the npm package `@anthropic-ai/claude-code` and advises
against `sudo npm install -g`. Its Windows documentation describes use through
WSL or native Windows with Git Bash. Do not infer PowerShell compatibility from
this preparation document.

```powershell
# Official vendor package command; do not run without installation approval.
npm install -g @anthropic-ai/claude-code
```

For a proposed per-user npm location, review and approve this user-environment
setting before executing the vendor command; it is not an observed local setup:

```powershell
$env:npm_config_prefix = "$env:LOCALAPPDATA\ClaudeCode"
npm install -g @anthropic-ai/claude-code
```

Expected executable: `claude`. Documented version command: `claude --version`.
The official documents reviewed describe interactive authentication choices but
not a standalone noninteractive authentication-status command; record it as
`UNVERIFIED` pending a separately approved documented check.

Official sources:

- <https://docs.anthropic.com/en/docs/claude-code/getting-started>
- <https://docs.anthropic.com/en/docs/claude-code/cli-usage>
- <https://docs.anthropic.com/en/docs/claude-code/corporate-proxy>

## Future live-traffic gate

The documented noninteractive mode is `claude -p <prompt>`; documented JSON
output uses `--output-format json`. The prepared adapter uses documented
`--add-dir`, `--permission-mode plan`, and `--max-turns` flags. After approved
installation, verify the actual shell launcher, `--version`, and `--help`
offline before any capture gate.

Candidate variables to test, not established capture facts:

```text
HTTP_PROXY=http://127.0.0.1:<port>
HTTPS_PROXY=http://127.0.0.1:<port>
SSL_CERT_FILE=<mitmproxy-ca-pem>
NODE_EXTRA_CA_CERTS=<mitmproxy-ca-pem>
```

Anthropic documents `HTTP_PROXY`, `HTTPS_PROXY`, `SSL_CERT_FILE`, and
`NODE_EXTRA_CA_CERTS`; it also documents that `NO_PROXY` and SOCKS proxies are
not supported. Whether this exact launcher routes through mitmproxy and trusts
the test CA must be empirically verified. The live gate must review a fresh
repository/output root, prompt, redacted command, port availability, certificate
import/removal, timeout, direct-bypass monitoring, and the absence of credential
variables.
