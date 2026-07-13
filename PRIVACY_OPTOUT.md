# Grok's `/privacy opt-out` is a retention flag, not a transmission block

**Subject:** Grok Build CLI **0.2.99** (`b1b49ccb71a7`), binary SHA-256 `01bcacec12e7c2a164d23975f1595400ff7f3cbd74f50b1858f6a5a14eb9ff81`
**Tested:** **2026-07-13 18:17 UTC** (2026-07-14 local), full-MITM capture (mitmproxy + trusted CA), real task on a throwaway canary repo.

## Context

After the original report, xAI stated that Grok Build now (a) defaults the codebase upload **off** and (b) adds a **`/privacy opt-out`** command to disable upload/traces. This tests what that opt-out actually does on the wire.

## What `/privacy` does

The TUI command `/privacy [opt-in|opt-out]` writes **nothing** to local config. It sends a single account-level request:

```
PUT cli-chat-proxy.grok.com/v1/privacy/coding-data-retention
opt-out →  {"codingDataRetentionOptOut": true}
opt-in  →  {"codingDataRetentionOptOut": false}
```

It is **one** account flag (`codingDataRetentionOptOut`). It does **not** independently toggle `trace_upload_enabled` or `disable_codebase_upload` (those are server-wide and already off).

## A/B result — the only difference is one status code

Same task, leader restarted between runs to force a fresh `/v1/settings` fetch:

| | Opted **IN** | Opted **OUT** |
|---|---|---|
| `POST /v1/traces` HTTP status | **`200`** ×2 | **`204`** ×2 |
| `/v1/traces` bytes **sent** by client | 7,586 + 10,559 | 7,582 + 11,082 |
| `POST /v1/responses` (model turn + contents of files it reads) | `200`, ~145 KB | `200`, ~145 KB |
| Telemetry (`_data/v1/events` + Mixpanel) | sent | sent |
| Whole-repo git bundle / never-read file / `.env` | none | none |
| Total bytes to xAI | 185,421 | 185,578 |

## Conclusion

**`/privacy opt-out` does not change what leaves your machine.** Your session traces are **POSTed to xAI in full in both states** (the opt-out bodies are even slightly larger); the model turns and telemetry are identical. The **only** observable effect is the server's response on `/v1/traces`: **`200` (stored) when opted in → `204` No Content (discarded) when opted out**.

So it is a **server-side retention switch, not a client-side transmission block.** You still transmit everything; you are trusting xAI's server to *discard* the opted-out traces rather than *store* them — verifiable only by that `204` status, not by anything staying on your machine.

## Fair scope

- This is a **genuine improvement** vs the original report, whose core criticism was that **no opt-out was surfaced at all.** A per-account opt-out now exists and is honored server-side (the `200 → 204` change is real).
- The whole-repo **codebase upload is off by default right now** (`disable_codebase_upload: true`, server-side). No repo-wide bundle uploaded in either state during this test.
- But "opt-out" ≠ "your data stays local." Session traces + model turns (including the contents of files the agent reads) are still sent to xAI regardless of the toggle.
- The upload *machinery* remains fully present in the 0.2.99 binary (`repo_state.archive.build`, `Enqueueing reference snapshot upload`, GCS multipart, the `grok-code-session-traces` bucket) — the default-off is a server flag, not removed code.

## Evidence (`evidence/privacy_optout/`)

- `PUT_coding-data-retention_optOUT.json` / `optIN.json` — the exact toggle payloads
- `wire_optin.log` / `wire_optout.log` — full request logs (host/path/status/size; no bodies)
- `SHA256SUMS.txt`
