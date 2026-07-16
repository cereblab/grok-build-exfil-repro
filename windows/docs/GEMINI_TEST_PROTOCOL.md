# Gemini CLI Windows test protocol

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

The final tested mode is explicitly **Gemini CLI 0.50.0, API-key mode**. It
is separate from the earlier unauthenticated result, the failed cached-Google-
sign-in result, Google-account/OAuth authentication, and Antigravity. The
preflight verifies both that a non-empty `GEMINI_API_KEY` exists in the Windows
user environment and that `~/.gemini/settings.json` records
`security.auth.selectedType=gemini-api-key`. It does not print, inspect, copy,
hash, or record the key value or unrelated settings. Successful approved A-C
executions established that the key was accepted for those runs only.

Final statuses were Test A `PARTIAL_CAPTURE`, Test B `PARTIAL_CAPTURE`, and Test
C `CAPTURE_VALIDATED`. Test A lacked attributable client traffic under the
existing criteria; Test B had incomplete process monitoring; Test C met the
full reconciliation criteria. These statuses describe capture completeness,
not product safety.

The generic `scripts/Invoke-AgentCapture.ps1` runner and
`adapters/gemini.json` are sufficient; no vendor-specific runner is added.
Every reproduction of A, B, or C must use a newly generated
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
`--sandbox`. `plan` is the documented read-only approval mode; the adapter uses
it and does not enable sandboxing, YOLO, or auto-edit. The approved A-C runs
exercised this configuration, but no native Windows sandbox was enabled or
claimed.

The official documents reviewed provide interactive sign-in and environment
authentication methods, but no standalone noninteractive authentication-status
command. Local help and a read-only installed-package search likewise found no
such command. API-key presence and the nonsecret persisted selector are checked
locally; successful approved A-C executions established authentication for
those runs without reading the credential value into evidence.

Official sources:

- <https://geminicli.com/docs/get-started/installation/>
- <https://geminicli.com/docs/get-started/authentication/>
- <https://geminicli.com/docs/cli/cli-reference/>
- <https://google-gemini.github.io/gemini-cli/docs/troubleshooting.html>

## Reproduction safety gate

Documented headless syntax is `gemini --prompt <prompt>` (or `-p`) and JSON
output is requested with `--output-format json`. The adapter also uses the
documented `--approval-mode plan` and `--include-directories` flags. Before any
reproduction run, resolve the actual executable, run `--version` and `--help`
offline, verify only key presence and the nonsecret selector, and create a fresh
generic-runner safety gate.

Run-scoped proxy and CA variables:

```text
HTTP_PROXY=http://127.0.0.1:<port>
HTTPS_PROXY=http://127.0.0.1:<port>
NODE_EXTRA_CA_CERTS=<mitmproxy-ca-pem>
```

The official troubleshooting guide documents `NODE_EXTRA_CA_CERTS` for a
custom root CA. The variables above produced decrypted traffic in the preserved
A-C runs, but attribution and monitoring completeness varied by run and must be
re-established for every reproduction. The gate must review the prompt, fresh
paths, port availability, CA import and removal actions, expected timeout,
redacted command, the explicit API-key mode label, and the boolean
secret-availability result. It must never include the API key.
