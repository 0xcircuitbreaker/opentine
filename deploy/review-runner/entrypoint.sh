#!/bin/sh
# Run `tine review runner` on one push (docs/REVIEW-RUNNERS.md).
#   RUNNER_REVIEW  the Review that lists the runner key as a reviewer
#   RUNNER_FLEET   the reviewers' fleet.toml
#   RUNNER_EVENT   the push: a mirror sync's or a forge webhook's JSON
#   RUNNER_MODE    hosted | self-hosted (default self-hosted)
# Egress: run the container on a network that reaches only the model endpoints
# in .tine/runner.toml; the runner also refuses any other host in its own process.
set -eu

: "${RUNNER_REVIEW:?set RUNNER_REVIEW}"
: "${RUNNER_FLEET:?set RUNNER_FLEET}"
: "${RUNNER_EVENT:?set RUNNER_EVENT}"
key=/run/secrets/review-runner.key
[ -f "$key" ] || { echo "no $key mounted" >&2; exit 2; }

exec tine review runner "$RUNNER_REVIEW" --fleet "$RUNNER_FLEET" --trust \
    --event "$RUNNER_EVENT" --hosting "${RUNNER_MODE:-self-hosted}" \
    --out "${RUNNER_OUT:-/out}" --ed25519-key-file "$key" \
    --repo "${RUNNER_REPO:-/work}" --json
