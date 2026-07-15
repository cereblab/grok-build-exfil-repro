# Phase 2 evidence methodology

## Scope

Phase 2 validates the evidence pipeline, not a coding agent or vendor product.
It adds no execution adapters and draws no benchmark or vendor conclusions.

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

## Known error risks

False positives include accidental Git signatures and exact canary bytes in
unrelated metadata. False negatives include unsupported encodings, encryption,
summary/transformation, payload splitting, capture failures, proxy bypass,
unobserved protocols, and data outside the capture window. Integrity verification
detects local inconsistency but does not attribute intent, retention, training,
sale, or any other vendor behavior.
