# Gemini CLI offline preparation protocol

## Status and boundaries

This is an offline preparation document, not installation or authorization to
run Gemini CLI. The local executable path, installed version, authentication
state, proxy routing, certificate trust, expected hosts, and command behavior
are all **UNVERIFIED**. Do not install, authenticate, invoke, or send traffic
until separate approval.

The generic `scripts/Invoke-AgentCapture.ps1` runner and
`adapters/gemini.json` are sufficient for preparation; no vendor-specific
runner is added. Every eventual A, B, or C run must use a newly generated
canary repository, capture directory, and versioned output root.

## Official basis and installation gate

Google's Gemini CLI installation documentation specifies the npm package
`@google/gemini-cli` and the global command below. It requires Node.js 20 or
newer and supports Windows and PowerShell.

```powershell
# Official vendor package command; do not run without installation approval.
npm install -g @google/gemini-cli
```

For a proposed per-user npm location, review and approve this user-environment
setting before executing the vendor command; it is not an observed local setup:

```powershell
$env:npm_config_prefix = "$env:LOCALAPPDATA\GeminiCli"
npm install -g @google/gemini-cli
```

Expected executable: `gemini`. Documented version command: `gemini --version`.
The official documents reviewed provide interactive sign-in and environment
authentication methods, but no standalone noninteractive authentication-status
command. Record authentication as `UNVERIFIED` until a separately approved,
non-credential-inspecting check is documented and tested.

Official sources:

- <https://geminicli.com/docs/get-started/installation/>
- <https://geminicli.com/docs/get-started/authentication/>
- <https://geminicli.com/docs/cli/cli-reference/>
- <https://google-gemini.github.io/gemini-cli/docs/troubleshooting.html>

## Future live-traffic gate

Documented headless syntax is `gemini --prompt <prompt>` (or `-p`) and JSON
output is requested with `--output-format json`. The prepared adapter also uses
the documented `--approval-mode plan` and `--include-directories` flags. Before
any live test, obtain approval to install, resolve the actual executable, run
`--version` and `--help` offline, review exact supported approval behavior, and
create a fresh generic-runner safety gate.

Candidate variables to test, not established routing facts:

```text
HTTP_PROXY=http://127.0.0.1:<port>
HTTPS_PROXY=http://127.0.0.1:<port>
NODE_EXTRA_CA_CERTS=<mitmproxy-ca-pem>
```

The official troubleshooting guide documents `NODE_EXTRA_CA_CERTS` for a
custom root CA. Whether the CLI routes through the proxy and accepts the CA must
be empirically shown with attributable capture and direct-bypass monitoring.
The gate must also review the prompt, fresh paths, port availability, CA import
and removal actions, expected timeout, redacted command, and absence of
credential variables.
