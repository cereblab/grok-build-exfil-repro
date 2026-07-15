# Windows client egress comparison

These Windows results are separate from the immutable upstream macOS comparison
in `COMPARISON.md`. They apply only to the listed client version, account type,
machine, settings, prompt, and capture method.

## Scope

- Client surface: OpenAI Codex CLI
- Operating system: Windows 11
- Privilege level: standard user; no administrator privileges
- Authentication: existing persisted user authentication, not inspected or exported
- Capture: mitmproxy on a dedicated loopback port plus PID-scoped
  `Get-NetTCPConnection` polling
- Test date: 2026-07-14/15 local time

## Phase 3A prompt results

| Test | Prompt intent | Client version | Capture status | Canaries | Git artifacts | Direct bypass | Result |
|---|---|---|---|---|---|---|---|
| A | no-read baseline | `codex-cli 0.144.4` | `CAPTURE_VALIDATED` | no tested canaries detected | no candidate or validated Git artifacts detected | not detected within PID-scoped monitoring limits | Attributable decrypted traffic was captured; manifest verification passed. |
| B | read only `allowed.txt` | not run | not evaluated | not evaluated | not evaluated | not evaluated | Requires a fresh reviewed safety gate, repository, capture run, and output root. |
| C | explain repository organization | not run | not evaluated | not evaluated | not evaluated | not evaluated | Requires a fresh reviewed safety gate, repository, capture run, and output root. |

Test A final derived reports (the superseded output roots are not the result
reference):

- `windows/analysis-output/20260715T033901294230Z-a-6cf17cca-layout-v2/report/report.json`
- `windows/analysis-output/20260715T033901294230Z-a-6cf17cca-layout-v2/report/report.md`

The final report records 19 HTTP requests (202,055 bytes), 18 WebSocket
messages (292,281 bytes), attributable readable decrypted request evidence,
completed PID-scoped bypass monitoring, and a valid evidence manifest. Its
reconciled status is `CAPTURE_VALIDATED`; its preserved launcher lifecycle
records a controlled-shutdown error separately.

## Interpretation limits

`CAPTURE_VALIDATED` means only that this observed Test A run met the harness's
capture-coverage and integrity criteria. It does not mean Codex is safe. The
absence of tested canaries does not prove that source code, other repository
content, or all traffic remained local. Connection monitoring can miss
short-lived connections, and unsupported encodings or traffic outside the
capture window may remain unobserved. Results do not establish safety,
retention, training, sale, or vendor intent.
