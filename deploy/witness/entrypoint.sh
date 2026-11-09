#!/bin/sh
# Start `tine witness serve` from the environment (deploy/witness/witness.env.example).
# Keys: every /run/secrets/witness-*.key, in name order; the first is current, so
# name them witness-1-<date>.key, witness-2-<date>.key during a rotation.
set -eu

: "${WITNESS_NAME:?set WITNESS_NAME (e.g. witness.example.org)}"
: "${WITNESS_LOG_VKEYS:?set WITNESS_LOG_VKEYS (space-separated log vkeys)}"

set -- witness serve --name "$WITNESS_NAME" --listen "${WITNESS_LISTEN:-0.0.0.0:8080}" \
    --rate-limit "${WITNESS_RATE_LIMIT:-60}" --state "${XDG_STATE_HOME:-/var/lib/witness}/witness"
found=0
for key in /run/secrets/witness-*.key; do
    [ -f "$key" ] || continue
    set -- "$@" --key "$key"
    found=1
done
[ "$found" = 1 ] || { echo "no /run/secrets/witness-*.key mounted" >&2; exit 2; }
for vkey in $WITNESS_LOG_VKEYS; do
    set -- "$@" --log-vkey "$vkey"
done
exec tine "$@"
