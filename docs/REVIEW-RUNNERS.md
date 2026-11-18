# Review runners

A review runner runs `tine review run --fleet` on every push. It is **just
another reviewer**: what it signs is a third-party opinion, checked like any
other, and it counts only where you say it does. Everything here is free, and
nothing needs hosted infrastructure: the same command runs on your laptop, in
your CI, in a container you host, or on a host that offers it.

## The free local path

```sh
# 1. a key for the runner (its own key, never yours)
tine keygen --out runner.key
tine review runner-identity --ed25519-key-file runner.key --json > runner-identity.json

# 2. a Review that lists the runner as a reviewer
tine review create push --title "Every push" --reviewer RUNNER_PUBLIC_KEY_HEX \
    --ed25519-key-file me.key

# 3. one push: what a mirror sync or a forge webhook hands the runner
cat > push.json <<'JSON'
{"source": "webhook", "ref": "heads/main", "before": "<old commit>",
 "after": "<new commit>", "at": "2026-11-18T09:00:00Z"}
JSON

# 4. review, evaluate and attest it
tine review runner push --fleet reviewers/fleet.toml --trust --event push.json \
    --out runner-out --ed25519-key-file runner.key --json
```

`runner-out/` then holds `findings.json` (signed `opentine.review-finding`
records), `vsa.json` (the admission VSA, a DSSE envelope), `evals/<name>/`
(signed `tine-eval-verdict/1` verdicts from `.tine/evals.toml`) and
`report.json`. Each verifies air-gapped:

```sh
python tine-verify.pyz runner-out/findings.json --pubkey runner.pub
python tine-verify.pyz runner-out/evals/smoke --pubkey runner.pub
```

A code mirror (`tine serve --mirror`, see [PROJECTS.md](PROJECTS.md#tine-serve))
writes these push files for you: every successful sync spools one
`mirror-sync` push per moved ref under the tenant's mirror directory, in
`pushes/<digest>.json`, ready to pass to `--event`.

## What the runner emits

Only existing kinds: Review findings, eval verdicts and the admission VSA
(`verification_summary/v1`, `PASSED` only when no critical finding is open and
every eval passed). It adds no record kind and no wire format.

## Its identity, and why it is never trusted by default

The runner signs with its own key, published as a service identity labelled
`review runner` (`tine review runner-identity`). It never signs as a user.
Nothing trusts it until you say so:

* a finding counts only when the Review lists the runner key as a reviewer;
* a merge gate counts its verdicts and VSA only when your gate policy names it
  (`evals.signers` holds its fingerprint, `vsa.key` or `vsa.keys` its key). An empty
  `signers` list trusts no signer, so removing the runner key turns the gate
  unmet and changes nothing else.

To rotate, generate a new key and publish its identity with
`--previous-pubkey old.pub`; the identity lists the fingerprints it was
rotated from. Add the new key to your policy before removing the old one:
a VSA signed by any key in `vsa.key` or `vsa.keys` counts, as does a verdict
from any fingerprint in `evals.signers`.

## Model credentials and cost

Bring your own model credentials. `.tine/runner.toml` names the environment
variable that holds each one (see `deploy/review-runner/runner.toml.example`);
a credential written into the file is refused. The runner passes those
variables to the reviewers and records only whether each was present. A
`[[model]]` whose `name` is an `llm-judge` provider (say `anthropic` for
`llm-judge:anthropic:...`) also hands its credential to that eval judge.
Nothing is resold. The report's `cost` is the push's total: what the
reviewers recorded (`unknown_members` counts the ones that recorded none) plus
the eval judges' calls (`cost.evals`).

## The sandbox

The runner's sandbox policy is derived from `runner.toml`: egress to the
configured model endpoints and nothing else. Its digest
(`sandbox_policy`) is recorded in every step's evidence and in the VSA's
policy, so a reader knows which policy produced a decision.

* Inside the runner's own process, any lookup, connect or UDP datagram outside
  the allowlist is refused.
* Only the push's own fields (`source`, `ref`, `before`, `after`, `at`, `run`)
  reach the report; anything else in a webhook body is dropped.
* The model endpoints are resolved once, when the runner starts, and connects
  are pinned to those addresses: a later DNS answer cannot widen the
  allowlist. A private, loopback or reserved address is allowed only for a
  loopback endpoint (`http://127.0.0.1:PORT`).
* **Reviewer processes are not covered by the in-process guard.** They are
  held to the allowlist only by the network the container runs on, so that
  network is a requirement, not a recommendation: run it on a network with no
  route out except through an egress proxy that allows only the model
  endpoints (`--network` with an internal network, a Kubernetes
  NetworkPolicy, or firewall rules).
* Hosted mode enforces this. `--hosting hosted` refuses to start unless
  `OPENTINE_RUNNER_NETWORK=allowlist` is set (the operator's statement that
  the network above is in place) **and** a direct TCP connect to the probe
  address (`OPENTINE_RUNNER_PROBE`, default `1.1.1.1:443`) fails. Self-hosted
  mode does not check: on your own machine the reviewers are yours.

## The container

`deploy/review-runner/Dockerfile` packages the runner once for hosted and
self-hosted use:

```sh
docker build -f deploy/review-runner/Dockerfile -t opentine-review-runner .
docker run --rm --network review-runner-net \
    -v "$PWD:/work" -v "$PWD/runner-out:/out" \
    -v "$PWD/runner.key:/run/secrets/review-runner.key:ro" \
    -e RUNNER_REVIEW=push \
    -e RUNNER_EVENT=/work/push.json -e RUNNER_MODE=self-hosted \
    -e OPENTINE_RUNNER_NETWORK=allowlist \
    -v "$PWD/reviewers:/fleet:ro" -e RUNNER_FLEET=/fleet/fleet.toml -e RUNNER_TRUST_FLEET=1 \
    -e MODEL_API_KEY opentine-review-runner
```

The image does not trust the fleet manifest by default. Set
`RUNNER_TRUST_FLEET=1` only for a manifest you control and mount from outside
the pushed tree: a manifest taken from the push would let whoever pushed choose
the commands the runner key signs for.

`RUNNER_MODE=hosted` and `RUNNER_MODE=self-hosted` sign byte-identical
findings for the same push and the same deterministic reviewers: every
finding's time is the push time, not the wall clock. Keep the checkout
and the output directory writable.
