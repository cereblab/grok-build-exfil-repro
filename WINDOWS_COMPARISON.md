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
| B | read only `allowed.txt` | `codex-cli 0.144.4` | `CAPTURE_VALIDATED` | permitted first-line marker: 1 client-to-server occurrence; 3 server-to-client echoes; no other tested canaries detected | no candidate or validated Git artifacts detected | not detected within PID-scoped monitoring limits | Attributable decrypted traffic was captured; manifest verification passed. The outbound match establishes only that the permitted first-line marker was transmitted, not that the full file or other repository content was transmitted. |
| C | explain repository organization | `codex-cli 0.144.4` | `PARTIAL_CAPTURE` | permitted first-line marker: 1 client-to-server occurrence; no other tested canaries detected | no candidate or validated Git artifacts detected | not detected within PID-scoped monitoring limits | Attributable decrypted traffic and a valid manifest were recorded, but three proxy runtime errors preceded the harness shutdown request, so capture integrity cannot be fully established. |

Test A final derived reports (the superseded output roots are not the result
reference):

- `windows/analysis-output/20260715T033901294230Z-a-6cf17cca-layout-v2/report/report.json`
- `windows/analysis-output/20260715T033901294230Z-a-6cf17cca-layout-v2/report/report.md`

The final report records 19 HTTP requests (202,055 bytes), 18 WebSocket
messages (292,281 bytes), attributable readable decrypted request evidence,
completed PID-scoped bypass monitoring, and a valid evidence manifest. Its
reconciled status is `CAPTURE_VALIDATED`; its preserved launcher lifecycle
records a controlled-shutdown error separately.

Test B final derived reports:

- `windows/analysis-output/20260715T050557679840Z-b-d4c60c79-allowed-marker-v2/report/report.json`
- `windows/analysis-output/20260715T050557679840Z-b-d4c60c79-allowed-marker-v2/report/report.md`

The final Test B report records 22 HTTP requests (224,009 bytes), 131 WebSocket
messages (423,746 bytes), attributable readable decrypted traffic, completed
PID-scoped bypass monitoring, and a valid evidence manifest. It identifies the
permitted `allowed.txt` first-line marker in one client-to-server WebSocket
message and three server-to-client echoes. That outbound match does not
establish transmission of the full file or other repository content.

Test C corrected derived reports:

- `windows/analysis-output/20260715T052649531109Z-c-a3f0c2fc-shutdown-timeline-v4/report/report.json`
- `windows/analysis-output/20260715T052649531109Z-c-a3f0c2fc-shutdown-timeline-v4/report/report.md`

The corrected reconciliation preserves the lifecycle status `CAPTURE_FAILED`
and assigns `PARTIAL_CAPTURE`: three `ConnectionResetError` events in the
mitmdump log occurred before the recorded harness shutdown request. The raw
evidence and manifest remain valid, but those pre-shutdown errors prevent a
full capture-integrity conclusion. The reanalysis retained one outbound
run-specific allowed-file marker and no Git artifacts; it does not establish
transmission of the full file or other repository content.

## Interpretation limits

`CAPTURE_VALIDATED` means only that this observed Test A run met the harness's
capture-coverage and integrity criteria. It does not mean Codex is safe. The
absence of tested canaries does not prove that source code, other repository
content, or all traffic remained local. Connection monitoring can miss
short-lived connections, and unsupported encodings or traffic outside the
capture window may remain unobserved. Results do not establish safety,
retention, training, sale, or vendor intent.
