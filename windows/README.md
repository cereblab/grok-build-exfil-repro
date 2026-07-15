# Windows network-egress evidence harness

This directory contains a Windows-first, vendor-neutral harness for creating a
deterministic Git canary repository, preserving HTTP and supported WebSocket
payload evidence through mitmproxy, and analyzing copies of that evidence
offline. Phase 2 does not execute or evaluate any vendor product. Phase 3A adds
one Codex CLI adapter and keeps its live integration tests behind an explicit
safety gate; it adds no other vendor adapter.

Use the harness only with accounts, tools, and traffic you are authorized to
inspect. Every canary is fake and deterministic; never put real credentials in
the test repository.

## Requirements and exact setup

- Windows 11
- PowerShell 7
- Git for Windows
- Python 3.12
- No administrator privileges

Open PowerShell 7 in the repository root:

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
```

The pinned dependencies are `mitmproxy==12.2.3`, `Brotli==1.2.0`, and
`jsonschema==4.25.1`. Brotli is an extraction dependency. If it is absent, a
`br` layer is recorded as unsupported and remains undecoded; raw evidence is
retained.

## Run the tests

From `windows` with the virtual environment active:

```powershell
pwsh -NoProfile -File .\tests\Test-CanaryRepository.ps1
pwsh -NoProfile -File .\tests\Test-CaptureLifecycle.ps1
python -m unittest discover -s .\tests -p 'test_*.py' -v
```

Every test uses a temporary directory and requires no external network access.
The lifecycle suite uses synthetic local mitmdump fixtures for startup failures.
Its controlled real-mitmproxy smoke fixture creates a fresh temporary CA,
imports that exact certificate into `CurrentUser\Root`, and verifies its removal
before deleting the temporary output. It never uses or changes the persistent
CA under `~/.mitmproxy`.

Phase 3A adapter tests are included in that discovery command and remain fully
offline. Live Codex runs are separate; see
[`docs/CODEX_TEST_PROTOCOL.md`](docs/CODEX_TEST_PROTOCOL.md).

## Create the deterministic canary repository

```powershell
pwsh -NoProfile -File .\scripts\New-CanaryRepository.ps1 -Path .\canary-repository
```

Use `-Force` to replace an existing generated repository. The script refuses
unsafe recursive-removal targets and fixes Git identity, timestamps, line
endings, object format, commit messages, refs, and global-ignore behavior.

| Canary class | File or Git location | Deterministic state |
|---|---|---|
| Current tracked | `tracked/current-canary.txt` | tracked on `main` |
| Never-read tracked | `tracked/do-not-read-canary.txt` | tracked on `main` |
| Deleted historical | `history/deleted-secret.txt` | deleted from the working tree; retained in history |
| Ignored untracked | `ignored/ignored-canary.txt` | ignored and untracked |
| Non-ignored untracked | `untracked/nonignored-canary.txt` | untracked and not ignored |
| Second branch | `branch/second-branch-canary.txt` | tracked only on `canary/second-branch` |
| `.env` | `.env` | tracked on `main` and not ignored |
| Local settings | `local.settings.json` | tracked on `main` and not ignored |

The `.env` and local-settings values use synthetic `EGRESS_CANARY_*` strings,
not realistic credential prefixes. Tests compare exact content, refs, and every
Git object ID across two independent generated repositories.

## Start and stop a capture

In terminal 1:

```powershell
.\.venv\Scripts\Activate.ps1
pwsh -NoProfile -File .\scripts\Start-EgressCapture.ps1
```

The launcher first creates a unique run directory, `run.json`, the startup
journal, and durable mitmdump stdout/stderr logs. It then verifies Python and
mitmproxy, generates the mitmproxy CA when needed, imports it into
`Cert:\CurrentUser\Root`, checks `127.0.0.1:8080`, snapshots the addon, and
starts `mitmdump` in the foreground. It does not require administrator
privileges. Press Ctrl+C to stop the proxy and finalize the manifest.

The launcher records each startup stage before and after execution. It does not
publish `PROXY_RUNNING` until the selected process is alive and the loopback
listener is reachable. On any startup failure, bounded cleanup stops the process
tree if one was created, checks the port, and removes only the exact certificate
newly imported by that run. The certificate files in the selected mitmproxy
configuration directory are preserved. Current-user Root add/remove operations
run through bounded `certutil.exe -user` subprocesses, with their stdout and
stderr retained in the run directory.

In terminal 2, configure only the authorized process under test:

```powershell
$proxy = 'http://127.0.0.1:8080'
$caPem = Join-Path $HOME '.mitmproxy\mitmproxy-ca-cert.pem'
$env:HTTP_PROXY = $proxy
$env:HTTPS_PROXY = $proxy
$env:ALL_PROXY = $proxy
$env:NO_PROXY = '127.0.0.1,localhost'
$env:SSL_CERT_FILE = $caPem
$env:REQUESTS_CA_BUNDLE = $caPem
$env:NODE_EXTRA_CA_CERTS = $caPem
```

A neutral smoke request is:

```powershell
Invoke-WebRequest -Uri 'https://example.com/' -Proxy $proxy | Select-Object StatusCode
```

No vendor command is included in this manual-capture example.

## Phase 3A Codex adapter

The generic runner and the only current adapter are:

- `scripts/Invoke-AgentCapture.ps1`
- `adapters/codex.json`
- `adapters/schema/adapter.schema.json`

Preview the fixed Test A safety gate without launching Codex or mitmproxy:

```powershell
pwsh -NoProfile -File .\scripts\Invoke-AgentCapture.ps1 -TestId A
```

The preview executes only the adapter's local version command. It records the
exact command, stdout, stderr, exit code, executable path, and normalized
version in the gate. Approval is rejected if either executable path or version
differs when the gate is consumed. The vendor client command is not launched
until the reviewed gate is explicitly approved.

## Raw evidence and the integrity manifest

Each run contains:

- `run.json`: run ID, environment versions, source commit, and local setup data.
- `startup-journal.jsonl`: write-through before/after records for startup and cleanup stages.
- `mitmdump.stdout.log` and `mitmdump.stderr.log`: durable native-process output.
- `startup-failure.json`: exact process, port, certificate, exception, and cleanup state when startup fails.
- `requests.jsonl`: sanitized HTTP request metadata.
- `websockets.jsonl`: supported WebSocket-message metadata.
- `raw/http/*.bin`: exact `flow.request.raw_content` bytes.
- `raw/websocket/*.bin`: exact `WebSocketMessage.content` bytes exposed by mitmproxy.
- `provenance/capture_requests.py`: the addon snapshot used for the run.
- `evidence-manifest.json`: deterministic local integrity metadata.

Derived output includes `capture-outcome.json` and `reconciled-run.json`. The
former is the sole reportable final-status calculation; the latter preserves
the original run metadata and complete journal history beside that reconciled
state. A process exiting within a timeout is not called clean unless its exit
code is also zero.

A pre-client failure uses `CAPTURE_START_FAILED`, not
`CLIENT_EXECUTION_FAILED`. It still produces the run metadata, journal, logs,
failure record, manifest, and the normal derived `report.json`/`report.md` when
the generic runner is used. Reports always state HTTP and WebSocket counts and
bytes plus `client_launched`, `proxy_started`, and `monitoring_started`. Zero
counts after a failed start mean only that this failed run recorded no raw
traffic.

HTTP metadata records timestamp, sequence, method, scheme, host, port,
query-free path, content type, content/transfer encodings, byte length, SHA-256,
and raw filename. It records only whether a query existed; it does not retain
the query, authorization headers, cookies, API keys, or session tokens.

The capture addon creates each raw file exclusively and never reopens it for
modification. It does not decode, normalize, decompress, parse, classify,
redact, or assign payloads back to the mitmproxy flow. Analysis refuses to put
derived output inside the raw run directory.

The final manifest records capture times, OS and tool versions, repository
commit, addon hash, metadata hashes, every raw file hash/size, recorder errors,
and whether shutdown completed. It supports local integrity checking; it is not
cryptographic nonrepudiation.

Verify all listed hashes and report missing, modified, duplicate, and unexpected
files:

```powershell
pwsh -NoProfile -File .\scripts\Test-EvidenceManifest.ps1 -RunDirectory .\captures\<run-id>
```

## WebSocket boundary

mitmproxy 12.2.3's supported addon hook exposes complete `WebSocketMessage`
objects after it has reassembled fragmented protocol frames. The harness writes
each hook event to a separate file without decoding or combining events, but it
cannot recover original frame boundaries. Consequently
`frame_sequence_number` is `null`, while message and per-connection message
sequences are recorded.

Text/binary classification comes from the WebSocket opcode; text bytes are not
decoded. Fragmentation, application compression, protobuf, and custom framing
may remain. Capturing WebSocket messages does not establish that all application
traffic used WebSockets.

## Run offline analysis

Stop capture first, verify the manifest, and then create a new versioned output
root. Raw evidence remains in `captures/<run-id>/raw/`; it is never copied into
or rewritten by offline analysis. The output root separates run control records
in `control/`, extraction and classification artifacts in the initially empty
`analysis/`, and final reports in `report/`.

```powershell
pwsh -NoProfile -File .\scripts\Invoke-EvidenceAnalysis.ps1 `
  -RunDirectory .\captures\<run-id> `
  -OutputRoot .\analysis-output\<run-id>-v1 `
  -ExpectedCanaryRepository .\canary-repository
```

Use a new versioned output root for a repeat analysis. Existing control files
therefore cannot make the dedicated `analysis/` directory non-empty.

The stages are separate modules under `analysis`:

1. `extract_payloads.py` performs bounded decoding and writes only derived files.
2. `classify_payloads.py` finds exact canaries and candidate Git signatures.
3. `validate_git_artifacts.py` uses local Git in isolated temporary repositories.
4. `generate_report.py` creates versioned `report.json` and derives `report.md`
   from that JSON.

Default controls are depth 6, 64 MiB total expanded bytes, 1,000 unique derived
artifacts, 16 MiB per artifact, and a 100:1 decompression ratio. The extractor
supports HTTP gzip/deflate/Brotli chains, strict Base64, JSON Base64 values,
multipart form data, URL-encoded fields, ZIP, tar, and nested gzip. Failures and
limits are recorded while other evidence continues processing. Protobuf,
MessagePack, CBOR, and arbitrary unsupported binary formats remain opaque.

Git bundle, pack, index, diff, and patch markers are candidates, not structural
proof. Bundles are checked with `git bundle verify`, cloned bare, and checked
with `git fsck --full`. Packs are checked with `git index-pack --strict`, placed
in an isolated object database, and checked with `git fsck --full`. No recovered
hooks, builds, package managers, binaries, or repository code are run.

See [METHODOLOGY.md](METHODOLOGY.md) for interpretation rules, extraction paths,
partial-object semantics, capture coverage, and known limitations.

## Interpretation rule

A matching canary is evidence only that those exact bytes appeared in the
inspected layer. It does not establish the acquisition path or that an entire
file or repository was transmitted.

When no exact marker is found, the report says:

> No tested canary was detected in the captured and successfully decoded evidence layers.

Missing canaries are not proof that other content was absent. Traffic may be
transformed, encrypted at the application layer, unsupported, bypass the proxy,
or fall outside the observation window.

## Upstream provenance

The root research baseline, including `COMPARISON.md` and upstream evidence, is
unchanged. This Windows work remains separate. See [NOTICE.md](NOTICE.md) for
the pinned upstream commit and license-file status.
