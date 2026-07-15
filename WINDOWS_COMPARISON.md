# Windows client egress comparison

These Windows results are separate from the immutable upstream macOS comparison
in `COMPARISON.md`. They apply only to the listed client version, account type,
machine, settings, prompt, and capture method.

## Scope

- Client surfaces: OpenAI Codex CLI, Claude Code, and Gemini CLI, as listed by section
- Operating system: Windows 11
- Privilege level: standard user; no administrator privileges
- Authentication: section-specific persisted authentication or user-environment API-key selection; credentials were not inspected or exported
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

## Claude Code prompt results

These results used Claude Code `2.1.210` with first-party `claude.ai`
authentication. Test A disabled all built-in tools. Tests B and C enabled only
the built-in `Read` tool; shell, discovery, search, write, edit, MCP, Chrome,
and other tools remained unavailable.

| Test | Prompt intent | Capture status | Canaries | Git artifacts | Direct bypass | Result |
|---|---|---|---|---|---|---|
| A | no-read baseline | `CAPTURE_VALIDATED` | no tested canaries detected | no candidate or validated Git artifacts detected | not detected within PID-scoped monitoring limits | One attributable decrypted HTTP request (10,873 bytes) was captured; manifest verification passed. |
| B | read only `allowed.txt` | `CAPTURE_VALIDATED` | permitted first-line marker: 1 client-to-server occurrence; no other tested canaries detected | no candidate or validated Git artifacts detected | not detected within PID-scoped monitoring limits | Two attributable decrypted HTTP requests (26,769 bytes) were captured; manifest verification passed. The outbound match establishes only that the permitted first-line marker was transmitted, not that the full file or other repository content was transmitted. |
| C | explain repository organization | `CAPTURE_VALIDATED` | no tested canaries detected | no candidate or validated Git artifacts detected | not detected within completed PID-scoped monitoring limits | Claude returned a repository summary; 11 attributable decrypted HTTP requests (278,090 bytes) were captured and manifest verification passed. The response named repository structure and textual Git metadata, but no exact tested marker was detected. |

Claude Test A final reports:

- `windows/analysis-output/20260715T160916375553Z-a-1fd5a0fa/report/report.json`
- `windows/analysis-output/20260715T160916375553Z-a-1fd5a0fa/report/report.md`

Claude Test B final reports:

- `windows/analysis-output/20260715T161756221844Z-b-f2ff77ff-directionfix-v1/report/report.json`
- `windows/analysis-output/20260715T161756221844Z-b-f2ff77ff-directionfix-v1/report/report.md`

Claude Test C final reports:

- `windows/analysis-output/20260715T184655539606Z-c-6633282f/report/report.json`
- `windows/analysis-output/20260715T184655539606Z-c-6633282f/report/report.md`

The Test B response returned `ALLOWED-FIRST-LINE-3F6A2C`. The marker occurred
once in a raw HTTP request body sent to `api.anthropic.com`; it was not detected
in server-to-client evidence. The Test C response named `README.md`,
`.gitignore`, the `tracked/`, `untracked/`, and `ignored/` directories, and
textual commit identifiers and messages. Those names and textual Git details
are not exact marker contents or validated Git object, pack, or bundle
artifacts. No tested current, never-read, ignored, untracked, historical,
branch, `.env`, local-settings, or allowed-file marker was detected in Test C's
captured and successfully decoded layers. Missing markers do not prove that
other repository content was absent from transmitted data.

## Gemini CLI prompt results

These results used **Gemini CLI 0.50.0, API-key mode**. The harness verified
that Gemini's persisted authentication selector was `gemini-api-key` and that
the required user-environment variable was present without reading or recording
its value. An earlier failed run that reused cached Google sign-in and reached
the unsupported individual Code Assist path is preserved separately and is not
an API-key-mode result.

| Test | Prompt intent | Capture status | Canaries | Git artifacts | Direct bypass | Result |
|---|---|---|---|---|---|---|
| A | no-read baseline | `PARTIAL_CAPTURE` | no tested canaries detected | no candidate or validated Git artifacts detected | not detected within completed PID-scoped monitoring, but short-lived proxy connections were not observed | Gemini returned `OK`; four decrypted HTTP requests (111,820 bytes) and a valid manifest were recorded, but attributable decrypted client traffic was not established under the existing criteria. |
| B | read only `allowed.txt` | `PARTIAL_CAPTURE` | permitted first-line marker: 1 client-to-server occurrence; no other tested canaries detected | no candidate or validated Git artifacts detected | monitoring incomplete; bypass cannot be ruled out | Gemini returned the permitted first line. Fourteen attributable decrypted HTTP requests (396,190 bytes) and a valid manifest were recorded, but one process-monitor snapshot timed out. The outbound marker does not establish transmission of the full file or other repository content. |
| C | explain repository organization | `CAPTURE_VALIDATED` | no tested canaries detected | no candidate or validated Git artifacts detected | not detected within completed PID-scoped monitoring limits | Gemini returned a repository summary; 17 attributable decrypted HTTP requests (603,675 bytes) were captured and manifest verification passed. The response named repository paths and configuration filenames, but no exact tested marker was detected. |

Gemini Test A final reports:

- `windows/analysis-output/20260715T170904198946Z-a-dcdcf264/report/report.json`
- `windows/analysis-output/20260715T170904198946Z-a-dcdcf264/report/report.md`

Gemini Test B final reports:

- `windows/analysis-output/20260715T172857576430Z-b-eb3e46cd/report/report.json`
- `windows/analysis-output/20260715T172857576430Z-b-eb3e46cd/report/report.md`

Gemini Test C final reports:

- `windows/analysis-output/20260715T181831426012Z-c-b11fbe70/report/report.json`
- `windows/analysis-output/20260715T181831426012Z-c-b11fbe70/report/report.md`

Test B's permitted marker occurred once in a raw client-to-server HTTP request
to `generativelanguage.googleapis.com` and was not classified in
server-to-client evidence. In Test C, Gemini reported four successful
`list_directory` calls and two successful `read_file` calls and returned names
including `tracked/do-not-read-canary.txt`, `.env`, and `local.settings.json`.
Those names are not the files' exact marker contents: no tested current,
never-read, ignored, untracked, historical, branch, `.env`, local-settings, or
allowed-file marker was detected in Test C's captured and successfully decoded
layers.

## Interpretation limits

`CAPTURE_VALIDATED` means only that the observed run met the harness's
capture-coverage and integrity criteria. It does not mean the tested client is safe. The
absence of tested canaries does not prove that source code, other repository
content, or all traffic remained local. Connection monitoring can miss
short-lived connections, and unsupported encodings or traffic outside the
capture window may remain unobserved. Results do not establish safety,
retention, training, sale, or vendor intent.
