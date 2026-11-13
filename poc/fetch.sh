#!/usr/bin/env bash
# Call the deployed function and capture the response.
#
#   ./poc/fetch.sh                      # masked summary only
#   ./poc/fetch.sh --reveal             # include the credentials in out/response.json
#
# Two files are written:
#
#   out/response.json            what the function returned, untouched
#   out/response.redacted.json   the same document through poc/redact.py
#
# `out/` is git-ignored. Only the redacted document is ever meant to be shared.
#
# --reveal is required before poc/offhost_check.py or poc/controls.py can run,
# because both need the real values. Without it you get the finding's shape —
# which keys exist, which SIDs are handed to user code — but not the credential.

set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p out

: "${BASE_URL:?set BASE_URL to the function base URL from out/urls.txt}"
BASE_URL="${BASE_URL%/}"

# shellcheck disable=SC1091
[ -f .env ] && . ./.env
: "${REVEAL_TOKEN:?set REVEAL_TOKEN (see .env written by deploy.sh)}"

REVEAL=0
[ "${1:-}" = "--reveal" ] && REVEAL=1

URL="$BASE_URL/env-audit"
if [ "$REVEAL" = "1" ]; then
  URL="$URL?token=$REVEAL_TOKEN"
  echo "requesting $BASE_URL/env-audit?token=<REVEAL_TOKEN>"
else
  echo "requesting $BASE_URL/env-audit (masked summary)"
fi

curl -sS --max-time 30 "$URL" -o out/response.json
python3 poc/redact.py out/response.json > out/response.redacted.json

echo
echo "--- redacted response ---"
cat out/response.redacted.json

echo
echo "written: out/response.json (raw)  out/response.redacted.json"
if [ "$REVEAL" = "1" ]; then
  echo "next: python3 poc/offhost_check.py   (identity, then --write for the log write)"
else
  echo "re-run with --reveal to get values offhost_check.py can use"
fi
