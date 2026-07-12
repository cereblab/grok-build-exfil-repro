# Evidence: deny blocks READS, not the UPLOAD

Wire-captured proof (grok 0.2.93) that permission-deny controls only what the
model **reads**, while the whole-repo **git-bundle upload happens regardless**.

## Run it yourself

Both `.bundle` files are the exact bytes Grok POSTed to `/v1/storage`. Clone one
and you recover a file that was **denied to the agent** but uploaded anyway:

```bash
git clone uploaded_repo_filedeny.bundle recovered && ls recovered
# -> tracked_secret.txt is present (a fake CANARY secret the agent was DENIED read on)
```

## Files

| File | What it shows |
|---|---|
| `permission_deny_findings.txt` | Full findings: CLI deny vs settings-file deny vs upload |
| `filedeny_works_transcript.txt` | Grok refusing the read under a `.claude/settings.json` deny |
| `tracked_deny_transcript.txt` | Grok refusing the read under a CLI `--deny` flag |
| `uploaded_repo_filedeny.bundle` | The `/v1/storage` upload — contains the denied `tracked_secret.txt` |
| `uploaded_repo_deny_gitignore.bundle` | Shows a **gitignored** file is the ONLY thing excluded from the bundle |
| `SHA256SUMS.txt` | Hashes of the above |

## The finding in one paragraph

Grok has two channels: **Channel A** (`POST /v1/responses`) = what the model reads
into the turn; **Channel B** (`POST /v1/storage`, a `# v2 git bundle` -> the GCS
bucket `grok-code-session-traces`) = the whole-repo upload. A permission **deny**
(CLI `--deny "Read(file)"` **or** a `.claude`/`.grok/settings.json` deny) stops
**Channel A** only — the agent genuinely refuses to read the file. **Channel B
ships the file anyway**, because it uploads every *tracked* file. The only thing
that keeps a file out of the bundle is **gitignoring** it (untracked). Gotcha:
`--always-approve` **bypasses the settings-file deny** (the file gets read); the
CLI `--deny` flag is a hard deny that survives `--always-approve`.
