# Gemini CLI offline preparation protocol

## Status and boundaries

Gemini CLI was installed locally. An earlier live Test A launched version
0.50.0 under an approved gate, but it exited 41 before sending vendor traffic
because no authentication method was configured. That corrected versioned
report remains preserved as `authentication_failed=true` and
`CLIENT_EXECUTION_FAILED`.

The first attempted API-key-labeled Test A did not actually use API-key
authentication. Gemini reused its cached Google sign-in selection and returned
`IneligibleTierError` / `UNSUPPORTED_CLIENT` for the Gemini Code Assist
individual tier. Its raw evidence and original report remain preserved; the
corrected derived report classifies `authentication_failed=true` and identifies
the observed mode as cached Google sign-in. It is not an API-key-mode result.

The current preparation is explicitly **Gemini CLI 0.50.0, API-key mode**. It
is separate from the earlier unauthenticated result, the failed cached-Google-
sign-in result, Google-account/OAuth authentication, and Antigravity. The
preflight verifies both that a non-empty `GEMINI_API_KEY` exists in the Windows
user environment and that `~/.gemini/settings.json` records
`security.auth.selectedType=gemini-api-key`. It does not print, inspect, copy,
hash, or record the key value or unrelated settings. Whether the key is accepted
can be established only by the separately approved live Test A request.

The generic `scripts/Invoke-AgentCapture.ps1` runner and
`adapters/gemini.json` are sufficient for preparation; no vendor-specific
runner is added. Every eventual A, B, or C run must use a newly generated
canary repository, capture directory, and versioned output root.

Before it creates a live-run gate, the generic runner resolves the harness
proxy executable from `windows\\.venv\\Scripts\\mitmdump.exe` and records the
absolute resolved path in the gate. It passes that path explicitly to the
child capture process rather than relying on the child's inherited `PATH`. A
missing executable stops the run before any CA operation.

The adapter may declare an allowlisted inherited secret by name. The generic
runner resolves that value only when it builds the client child environment.
The value is excluded from adapter preparation, commands, gates, logs, and
reports; the gate records only `authentication_secret_available=true|false`.
Missing secrets stop the run before proxy startup or certificate import.
An adapter may also declare a nonsecret JSON settings selector and expected
value. The gate records and binds only that selected value; a changed or missing
selection stops the run before proxy startup or certificate import.

## Official basis and installation gate

Google's Gemini CLI installation documentation specifies the npm package
`@google/gemini-cli` and the global command below. It requires Node.js 20 or
newer and supports Windows and PowerShell. The locally configured global npm
prefix was already user-scoped (`C:\Users\jande\AppData\Roaming\npm`), so no
npm configuration was changed.

```powershell
# Executed from the official npm registry on 2026-07-15.
npm install -g @google/gemini-cli@latest
```

Installed local facts:

- Package source: `https://registry.npmjs.org/@google/gemini-cli/-/gemini-cli-0.50.0.tgz`
- Repository declared by the package: `https://github.com/google-gemini/gemini-cli.git`
- Executable: `C:\Users\jande\AppData\Roaming\npm\gemini.cmd`
- Version: `0.50.0`

The local help confirms `--prompt` headless mode, `--output-format json`,
`--approval-mode plan`, `--skip-trust`, `--include-directories`, and
`--sandbox`. `plan` is the documented read-only approval mode; the Test A
template uses it and does not enable sandboxing, YOLO, auto-edit, or any allowed
tools. This is the least-permissive documented configuration that is parseable
offline. Its actual tool behavior has not been tested because that would submit
a prompt to Gemini.

The official documents reviewed provide interactive sign-in and environment
authentication methods, but no standalone noninteractive authentication-status
command. Local help and a read-only installed-package search likewise found no
such command. API-key presence can be checked locally, but authentication
remains `UNVERIFIED` until approved traffic succeeds; no credential value is
read into evidence or inspected.

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
and removal actions, expected timeout, redacted command, the explicit API-key
mode label, and the boolean secret-availability result. It must never include
the API key.
