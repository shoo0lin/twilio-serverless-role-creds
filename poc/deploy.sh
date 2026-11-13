#!/usr/bin/env bash
# Deploy the two functions to a Twilio Serverless environment you own.
#
# This is the whole bar the finding describes: a trial account, no payment
# method, and `twilio serverless:deploy`. Nothing here asks for an upgrade, a
# card, or a review.
#
#   export TWILIO_ACCOUNT_SID=AC...
#   export TWILIO_AUTH_TOKEN=...
#   ./poc/deploy.sh
#
# Optional:
#   SERVICE_SID=ZS...   deploy into an existing service instead of creating one
#   REVEAL_TOKEN=...    shared secret required to reveal credentials (generated
#                       if unset; it is written to .env so fetch.sh can reuse it)
#
# The deploy prints the function URLs. Save them: fetch.sh reads out/deploy.txt.

set -euo pipefail

cd "$(dirname "$0")/.."

: "${TWILIO_ACCOUNT_SID:?set TWILIO_ACCOUNT_SID (your own account)}"
: "${TWILIO_AUTH_TOKEN:?set TWILIO_AUTH_TOKEN (your own account)}"
command -v twilio >/dev/null || { echo "twilio CLI not on PATH (npm i -g twilio-cli)"; exit 1; }
command -v jq >/dev/null || { echo "jq not on PATH"; exit 1; }

mkdir -p out

if [ ! -f .env ]; then
  echo "REVEAL_TOKEN=${REVEAL_TOKEN:-$(openssl rand -hex 16)}" > .env
  chmod 600 .env
  echo "wrote .env with a fresh REVEAL_TOKEN (keep it out of git)"
fi
# shellcheck disable=SC1091
. ./.env

if [ -n "${SERVICE_SID:-}" ]; then
  echo "deploying into service $SERVICE_SID"
  twilio serverless:deploy --service-sid "$SERVICE_SID" --force | tee out/deploy.txt
else
  echo "no SERVICE_SID set — creating a new Serverless service"
  twilio serverless:deploy --friendly-name twilio-role-creds-poc --force | tee out/deploy.txt
fi

echo
echo "function URLs from that deploy:"
grep -Eo 'https://[a-z0-9-]+\.twil\.io/[A-Za-z0-9_-]+' out/deploy.txt | sort -u | tee out/urls.txt || true
echo
echo "next: ./poc/fetch.sh"
