#!/usr/bin/env bash
# Run Grok in the target repo, routed through the capture proxy, with a prompt
# that explicitly tells it NOT to open any files. Anything that leaves is on the
# wire regardless of what the model "reads".
set -euo pipefail
REPO="${1:?usage: run-capture.sh <repo-dir>}"
REPO="$(cd "$REPO" && pwd)"

export HTTPS_PROXY=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080
export ALL_PROXY=http://127.0.0.1:8080
export SSL_CERT_FILE="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"

GROK="${GROK_BIN:-$HOME/.grok/bin/grok}"
[ -x "$GROK" ] || { echo "grok not found at $GROK (set GROK_BIN)"; exit 1; }

echo ">>> setup-proxy.sh must be running in another terminal."
echo ">>> Running Grok in $REPO with: 'Reply with exactly: OK. Do not read or open any files.'"
"$GROK" -p "Reply with exactly: OK. Do not read or open any files." --cwd "$REPO"
echo ">>> done. Now run: ./scripts/verify.sh"
