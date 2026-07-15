# Phase 2 evidence methodology

## Scope

Phase 2 validates the evidence pipeline, not a coding agent or vendor product.
It adds no execution adapters and draws no benchmark or vendor conclusions.

Phase 3A is a separate extension that adds one Codex CLI adapter. Its reports
must not be generalized to other Codex surfaces, versions, accounts, settings,
prompts, machines, or dates.

## Raw versus derived evidence

Raw files contain the exact payload bytes exposed by the supported mitmproxy
hooks. Capture code performs no payload decoding or classification. Every raw
file is created under a unique name with exclusive creation and is then treated
as immutable. The integrity manifest detects later local changes but does not
provide nonrepudiation or protect against an actor who can replace both evidence
and manifest.

Derived evidence is written to a different directory. Each operation records
its raw source, parent derived artifact, operation, depth, known offset, output
hash/size, success, and error. SHA-256 deduplication preserves every parent
relationship. The analysis code refuses a derived directory inside the raw run.
Phase 2 also rejects every non-empty derived directory. The Phase 3 runner uses
an explicit narrow exception for only its newly reserved `control/`,
`coverage.json`, and `client-execution.json`; any other preexisting entry still
aborts extraction.

## Extraction controls and opaque layers

Depth, total output, artifact count, per-artifact size, and decompression ratio
limits bound recursive processing. Strict Base64 requires the standard alphabet,
valid padding, a minimum decoded size, and successful validation; printable text
is not decoded indiscriminately. HTTP content encodings are reversed according
to HTTP semantics and are never guessed when the header is absent. A gzip magic
value can separately trigger the documented application-wrapper operation.

Malformed or unsupported layers remain available as raw evidence, are marked
undecoded, and do not stop other files. Brotli is explicitly optional at runtime.
Protobuf, MessagePack, CBOR, application encryption, and unknown binary framing
remain opaque unless a real bounded parser is added in a future phase.

## WebSocket evidence boundary

The supported mitmproxy hook exposes reassembled messages, not original frames.
The harness preserves each exposed message payload separately and records both
directions, but fragmentation boundaries cannot be reconstructed. Compression
and application framing can remain. WebSocket evidence does not demonstrate
that all application traffic used that protocol.

## Canary semantics

Classification searches exact known byte strings at every raw and successfully
derived layer. A finding establishes the presence of those bytes at that layer.
It does not reveal how they were obtained. In particular, a historical marker
does not by itself show that `.git/objects` was uploaded, and an ignored-file
marker does not show that the complete ignored file was uploaded. Context is
represented by a hash rather than unnecessary surrounding plaintext.

Absence is reported only as: "No tested canary was detected in the captured and
successfully decoded evidence layers." Unsupported, failed, unobserved, bypassed,
or out-of-window traffic remains a false-negative risk.

## Git candidates and validation

Bundle headers, `PACK`, `DIRC`, diff markers, and patch markers are byte-level
candidates. Accidental marker collisions are possible. Structural flags are set
only after Git validates an extracted copy in a temporary directory outside the
source checkout.

A validated pack can still be only a subset of repository objects. The report
keeps bundle validation, pack validation, partial recovery, complete expected
object recovery, expected-ref recovery, and full reconstruction separate. Full
reconstruction requires structural validity, all expected refs/commits/trees/
blobs, and successful repository integrity checks. Recovered content is treated
as untrusted and never executed or added to the source repository.

## Capture coverage

Phase 2 leaves capture status at `NOT_EVALUATED`. Future clients must each be
tested for proxy use, TLS interception, direct bypass, and observation-window
coverage. ETW and WFP can reveal connection paths and bypass but are not
plaintext payload capture tools. GUI and CLI surfaces can use different network
stacks and therefore require separate tests.

For Phase 3A, a dedicated loopback proxy is applied only to the launched client
environment. The root PID and observed descendants are polled with Windows
process metadata and `Get-NetTCPConnection`. One reconciliation stage inspects
the launcher and mitmdump exit codes, final lifecycle status and journal,
manifest validity, client launch, decrypted attributable traffic, and direct
bypass result. `CAPTURE_VALIDATED` requires all of these to pass with no
unresolved capture-runtime failure. Polling gaps, DNS, UDP, and non-TCP traffic
remain explicit limitations and cannot establish plaintext visibility.

A nonzero mitmdump exit during harness-initiated shutdown is benign only when
each recorded runtime error occurs at or after the recorded shutdown request,
the client had completed, metadata and raw files were flushed, the manifest
passed, every request is explicitly known not to be truncated, the listener was
released, and the process ended within the cleanup bound. The reconciled output
records every runtime-error timestamp alongside client completion, shutdown
request, proxy termination, and listener-release timestamps. Exception text
alone is never sufficient. A pre-shutdown error with otherwise valid evidence
is `PARTIAL_CAPTURE`; known evidence damage is `CAPTURE_FAILED`. The original
lifecycle status and journal remain intact in the reconciled output.

Before launching a client, the adapter version command must succeed. Its exact
command, stdout, stderr, exit code, and normalized output are copied into the
client execution record and both reports. The live safety gate is invalidated
when either the executable path or normalized version changes.

Capture startup is a separate evidence boundary. The launcher creates the run
directory, initial `run.json`, startup journal, and durable stdout/stderr logs
before it checks or changes certificate state or starts a process. Readiness is
published only after the selected mitmdump process is alive, the configured
loopback port accepts a connection, and `run.json` atomically records
`PROXY_RUNNING`. A port observation alone is not a readiness signal.

`CAPTURE_START_FAILED` means the vendor client was never launched. It covers CA
generation/import, executable resolution, process launch, immediate process
exit, occupied-port, and startup-timeout failures. `CLIENT_EXECUTION_FAILED` is
reserved for a client process that was actually launched and then failed. A
startup failure still has a verifiable manifest and analysis reports; absent raw
traffic files or zero HTTP/WebSocket counts are expected when no traffic was
captured and are not evidence about vendor behavior.

Offline analysis uses a versioned output root with separate `control/`,
`analysis/`, and `report/` directories. Safety-gate, client-execution, coverage,
and reconciliation records remain in `control/`; extraction and classification
receive an empty `analysis/` directory; and final reports are written only to
`report/`. Raw evidence remains under the capture run's `raw/` directory and is
never rewritten. A repeat analysis uses a new versioned output root.

Cleanup is bounded and runs in `finally`. It stops only the mitmdump process tree
started by the run, checks whether the requested port was released, and removes
only a CurrentUser Root certificate whose thumbprint was absent before and added
by that run. The CA files in the selected mitmproxy configuration directory are
preserved. Certificate add/remove uses bounded `certutil.exe -user` subprocesses
with durable output instead of the in-process `X509Store.Add` call observed to
hang in the controlled reproduction. An unrelated listener occupying the
requested port is reported but is never terminated.

## Known error risks

False positives include accidental Git signatures and exact canary bytes in
unrelated metadata. False negatives include unsupported encodings, encryption,
summary/transformation, payload splitting, capture failures, proxy bypass,
unobserved protocols, and data outside the capture window. Integrity verification
detects local inconsistency but does not attribute intent, retention, training,
sale, or any other vendor behavior.
