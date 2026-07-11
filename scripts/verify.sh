#!/usr/bin/env bash
# Reconstruct what left the machine: scan captured request bodies for a git
# bundle, clone it, and recover the file we told Grok NOT to open.
set -euo pipefail
CAP="${XAI_CAPTURE_DIR:-$HOME/grok-exfil-capture}"
BODIES="$CAP/bodies"
WORK="$(mktemp -d)"
MARKER="CANARY-XR47P2-NEVERREAD-UNIQUE"

echo ">>> wire summary (POST /v1/storage should be 200):"
grep -E "v1/storage" "$CAP/wire.log" 2>/dev/null | tail -20 || echo "  (no wire.log yet — did the capture run?)"

echo ">>> scanning $BODIES for a git bundle..."
found=""
for f in "$BODIES"/*.bin; do
  [ -e "$f" ] || continue
  if head -c 32 "$f" | grep -qa "git bundle"; then
    echo "[+] git bundle found: $(basename "$f")"
    cp "$f" "$WORK/uploaded_repo.bundle"; found=1; break
  fi
done
[ -n "$found" ] || { echo "[-] no git bundle in captured bodies. (Run the capture first; on large repos the bundle may be chunked.)"; exit 1; }

echo ">>> git clone of the captured bundle..."
git clone -q "$WORK/uploaded_repo.bundle" "$WORK/recovered" 2>/dev/null || {
  echo "[-] clone failed (bundle may be a chunk of a larger multipart upload)"; exit 1; }

CANARY="$WORK/recovered/src/_probe/never_read_canary.txt"
if [ -f "$CANARY" ] && grep -qa "$MARKER" "$CANARY"; then
  echo "[+] RECOVERED the file you told Grok NOT to open:"
  echo "    $CANARY -> $(cat "$CANARY")"
  echo "[+] full history recovered: $(cd "$WORK/recovered" && git rev-list --count HEAD) commits (incl. the 'deleted' note)"
  echo ""
  echo "==> PROVEN: the whole repo — a never-read file + full git history — left your machine."
else
  echo "[-] marker not found in the recovered tree"
fi
echo "(artifacts in $WORK)"
