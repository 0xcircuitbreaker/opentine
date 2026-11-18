# Eval statistics and signed promotion

`tine eval compare --ci` says whether one eval beats another, with a stated
test and a reproducible number. `tine promote TARGET --baseline LABEL` moves a
label to a candidate run only when signed eval verdicts beat the baseline under
that test. Both emit only existing kinds: `attestation` objects and the
admission VSA. The two claim conventions below are documentation, not new
object kinds, wire formats or vector families. No verifier reads them to reach
a verdict: `tine verify`, the pyz and the TS verifier check the envelope
signature and report the claim `unchecked` (FREEZE.md, ruling (b)). The
checks live in `tine eval compare` and `tine promote`.

## `tine eval compare A B --ci paired-bootstrap|permutation`

```
tine eval compare A B --ci paired-bootstrap [--alpha 0.05] [--seed 0] [--resamples 2000]
                      [--export FILE] [--attest KEY --out FILE] [--signed-at TIME] [--json]
```

Both eval folders are verified first. The items both evals scored are paired.
Two metrics are compared: `score` (the mean verdict score) and `pass_rate` (the
share of items that passed). For each metric the report gives:

- `a` and `b`, the two means;
- `delta`, which is `b - a`;
- `ci`, the bootstrap interval of the delta, or `p_value` for a permutation test;
- `significant`, `regression` and `improvement`.

`regressions` lists the metrics that regressed. `--exit-code` exits 1 on any
regression.

| Test | Resample | Significant when |
|------|----------|------------------|
| `paired-bootstrap` | n paired differences with replacement, `R` times | the interval `[floor(alpha/2 R), ceil((1-alpha/2) R) - 1]` of the sorted sums excludes 0 |
| `permutation` | flip the sign of every difference, `R` times | `p = (k + 1) / (R + 1) < alpha`, where k counts sums at least as far from 0 as the observed one |

The arithmetic is exact. Scores have at most six decimal places, so they are
counted in integer micro-units. The only randomness is Python's
`random.Random` seeded with the string
`"opentine.eval-compare/1:<seed>:<metric>"`. Decimals are printed with six
places, rounded half-even. The same evals with the same seed always give the
same numbers.

`--export FILE` writes the input the numbers come from:

```json
{"convention": "opentine.eval-compare/1", "method": "paired-bootstrap", "alpha": "0.05",
 "seed": 0, "resamples": 2000, "a_eval": "sha256:…", "b_eval": "sha256:…",
 "items": [{"item": "q1", "a": "0.5", "b": "1", "a_passed": false, "b_passed": true}]}
```

`python scripts/eval_compare_reproduce.py FILE` is a standalone script that
uses only the standard library and imports nothing from opentine. It prints the
same `stats` object, byte for byte.

### Claim convention `opentine.eval-compare/1`

`--attest KEY --out FILE` writes an `attestation` on eval B's id, signed with
Ed25519. Its claim is:

```json
{"schema": "opentine.eval-compare/1", "a": "sha256:<eval A>", "b": "sha256:<eval B>",
 "export_sha256": "<sha256 of the JCS export>", "stats": { … }}
```

## `tine promote TARGET --baseline LABEL`

```
tine promote RUN --baseline LABEL --approve --key KEY --out APPROVAL.json [--state DIR]
tine promote promote.toml --sign-policy --key POLICY_KEY --out POLICY.json
tine promote RUN --baseline LABEL --key KEY --policy promote.toml --out DIR \
    --baseline-evals DIR --evals DIR --holdout BASE_DIR CAND_DIR \
    --approval APPROVAL.json --spent USD [--policy-attestation POLICY.json]
    [--loop LOOP] [--state DIR] [--at TIME]
tine promote RUN --baseline LABEL --revert --reason TEXT --key KEY --policy promote.toml --out DIR
tine promote RUN --baseline LABEL --canary DIR --baseline-evals DIR --key KEY --policy promote.toml --out DIR
```

Without `--baseline`, `tine promote TARGET --name NAME` is still the
compare-and-swap `promotions/<name>` ref update.

The promotion policy is a `[promote]` TOML table. It is local configuration,
like `.tine/evals.toml`:

```toml
[promote]
label_policy = "labels.json"   # an opentine.admission-policy covering labels/<LABEL>
test = "paired-bootstrap"      # or "permutation"
alpha = "0.05"
seed = 0
resamples = 2000
min_n = 30                     # paired items, on the main set and the holdout
metric = "pass_rate"           # or "score"
budget_usd = "10"              # the spend cap; --spent is checked against it
approvers = ["sha256:<key fingerprint>"]
min_approvals = 1
require_holdout = true
eval_signers = ["sha256:<key fingerprint>"]   # the keys trusted to sign verdicts
```

### What the gate checks

A label moves only when every check passes. Each refusal names its reason:

| Code | Refused when |
|------|--------------|
| `promote.eval-invalid` | an eval folder does not verify |
| `promote.untrusted-eval` | a verdict is signed by a key not in `eval_signers` |
| `promote.evals-not-candidate` | the candidate's verdicts do not all score the candidate run |
| `promote.evals-not-baseline` | the baseline's verdicts do not all score the label's current holder; on a first promotion (no holder), they do not all score one run other than the candidate |
| `promote.dataset-mismatch` | the two sides scored different datasets |
| `promote.n-below-minimum` | there are fewer than `min_n` paired items |
| `promote.ci-crosses-zero` | the bootstrap interval of the delta does not lie above 0 |
| `promote.not-significant` | the permutation test shows no significant gain at `alpha` |
| `promote.missing-holdout` | the policy requires a holdout and none was given |
| `promote.holdout-not-held-out` | the holdout is the main dataset |
| `promote.missing-approver` | there are fewer valid approvals than `min_approvals` from keys in `approvers`, for this run and this label; an approval signed by the promoting key or by an `eval_signers` key never counts, so a loop cannot approve itself |
| `promote.approval-stale` | an approval for this run and label names another holder (`previous`) or label `sequence` than the label state now has: every move appends to the history, so an approval counts for one move and a revert retires it |
| `promote.policy-unsigned` | the key roles name a `policy` role only in the unsigned `.tine/key-roles.toml` (`roles: unpinned`, 0.59: no policy key counts), or the pinned roles name one and no `--policy-attestation` is an `opentine.promotion-policy/1` attestation, signed by a `policy` key that is neither the promoting key nor an `optimizer` key, over this policy file and its label admission policy (both sha256) |
| `promote.over-budget` | `--spent` is above `budget_usd` (`--spent` is required and must be a non-negative decimal) |
| `promote.item-mismatch` | the two sides of a pair scored different item sets: n is always the full paired set, so a candidate cannot drop the items it fails |
| `promote.key-separation` | the repository's key-role policy (`.tine/key-roles.toml`, see `tine keys lint`) lists the promoting key in a scorer, dataset, verdict or approver role; with no policy file nothing is refused |
| `promote.loop-stopped` | `--loop LOOP`, or the candidate run's metadata (`opentine.loop`, or `opentine.task` naming a loop generation), names a stopped loop (`tine loop stop`: its coord record or the hold that keeps the stop); `--revert` stays allowed |
| `promote.label-policy` | the admission policy does not cover `labels/LABEL`, or its `subjects` do not list the promoting key |
| `promote.already-current` | the run already holds the label |
| `promote.not-current` | the run to revert does not hold the label |

The holdout must beat the baseline under the same test as the main set.
Advisory findings never block by default (owner decision D12). Only these
facts do: hashes, signatures and the policy.

### Signing the policy

The promotion policy and the label admission policy are files a
self-improving loop may be able to edit. When the key roles name a `policy`
role, only a signed policy counts. A holder of a `policy` key signs
the exact files:

```
tine promote promote.toml --sign-policy --key POLICY_KEY --out policy.json
tine promote RUN --baseline prod ... --policy promote.toml --policy-attestation policy.json
```

The attestation covers the sha256 of `promote.toml` and of the label policy
it names, so any edit (a raised `budget_usd`, a new approver, a wider
`labels/*`) needs a new signature. The promoting key and `optimizer` keys
never count, and `tine keys lint` refuses an optimizer key that also holds a
`policy` key. The decision records the attestation (`policy_attestation`) and
the VSA lists it as `policy:<signer>` in `inputAttestations`.

### Pinning the key roles (0.59)

`.tine/key-roles.toml` is a file in the repository, so a loop that can write
it could name its own key a `policy`, `scorer` or `stopper` key. Roles grant
those powers only when an owner-signed trust bundle (SPEC 8.26) carries them
and the owner key is pinned outside the repository:

```
tine trust bundle create --key OWNER_KEY --name example.com/trust --serial 1 \
  --pin SIGNER_FP --key-roles .tine/key-roles.toml --out .tine/trust-bundle.note
export OPENTINE_TRUST_OWNER='example.com/trust+...'   # or $XDG_CONFIG_HOME/opentine/trust-owner
```

The bundle is read from `$OPENTINE_TRUST_BUNDLE` or `.tine/trust-bundle.note`;
a lower serial than the highest one seen is refused (rollback, as in 0.51)
and a pinned owner with a bad bundle refuses outright. With only the unsigned
file the roles are `unpinned` (`tine keys lint` prints `roles: unpinned`,
`--json` `pinning`): they still refuse (key separation), but a `policy` role
refuses every policy with `promote.policy-unsigned`, a `scorer` role pins no
lineage signer (`signers: unpinned`), a `stopper` role verifies no stop, and
no policy key can pin the integrity protected list.

A run with an integrity taint (docs/INTEGRITY.md) is refused with
`promote.score-tainted` whether the taint is filed or held: from 0.59 the taint
is also a `tine hold` that `tine hold release` refuses, so deleting the file
does not launder the score.

`--sealed-holdout DIR` (0.60, repeatable) names a sealed holdout whose
exposure budget must hold: a holdout revealed past its budget, or whose
access records do not chain, is refused with `promote.holdout-exposed`
(docs/HOLDOUTS.md). Holdouts kept under `REPO/.tine/holdouts/` are checked
whether or not they are named. `--canary-lengths FILE` (0.60) runs `tine dataset
canary-check` on a scoring run's code lengths and refuses with
`promote.canary-failed` when it does not pass.

### Approvals are bound to one move

`--approve` reads the label state (`--state`, default `.tine/promotion/`) and
signs the holder the candidate would replace (`previous`) and the state's
`sequence` (the length of its history). The gate counts an approval only when
both still match, so an approval cannot be replayed after a revert or reused
for a second move.

### What a promotion writes

- `vsa.json` is the existing admission VSA: a DSSE envelope with predicate
  `verification_summary/v1`. Its fields are:
  - the subject: the candidate run;
  - `resourceUri`: `tine://promotion/labels/LABEL`;
  - the admission policy's URI and digest;
  - `verifiedLevels`: the policy's levels;
  - `inputAttestations`: every eval folder (`eval:<id>`, the sha256 of its
    `verdicts.jsonl`), every approval and every comparison. This is the
    frozen-safe lineage: VSA evidence plus verdict references.
- `decision.json` is an attestation on the candidate run (claim
  `opentine.promotion-decision/1`).
- `compare.json` and `holdout-compare.json` are the signed comparisons.

`--revert` writes only a `decision.json` with `action: "revert"` and the
`reason`. The label goes back to the run it held before. A canary
(`--canary DIR`) compares a trusted, signed canary eval against the baseline.
The baseline eval is checked like the gate's: signed by an `eval_signers` key
and scoring the run the candidate replaced (or, when it replaced none, one
run other than the candidate).
On a significant regression in the policy's metric, it reverts automatically
and signs a decision with `reason: "canary-regression"` that carries the
statistics.

The label state is `STATE/LABEL.json` (default `.tine/promotion/`). It holds
the current holder and the history, each step with the sha256 of its decision.
It is local state, like the merge queue's, not a wire format.

### Claim conventions

```json
{"schema": "opentine.promotion-approval/1", "candidate": "run:sha256:…", "label": "prod",
 "previous": "run:sha256:…" | null, "sequence": 2}
{"schema": "opentine.promotion-policy/1", "policy_sha256": HEX, "label_policy_sha256": HEX}
{"schema": "opentine.promotion-decision/1", "action": "promote" | "revert",
 "label": "prod", "candidate": "run:sha256:…", "previous": "run:sha256:…" | null,
 "vsa_sha256": "…", "inputs": [ … ], "stats": {"main": { … }, "holdout": { … }},
 "spent_usd": "…", "budget_usd": "…", "policy_sha256": HEX,
 "label_policy_sha256": HEX, "policy_attestation": {"signer", "sha256"} | null,
 "sequence": 2}
```

A policy attestation's `target_id` is `sha256:` + the policy's sha256.

A revert decision carries `reason` and `stats`, and no `vsa_sha256` or
`inputs`.

### Limits

- `--spent` is a declared value: the gate checks it against the cap but does
  not measure spend.
- Label state is local state. Approval binding and the history are as
  trustworthy as the directory that holds them.
- A loop is stopped in one repository; there is no remote loop stop.
- The loop stop's hold lives in `.tine/holds`: `tine hold release` refuses it,
  but a process that can write that file directly can remove it, as it can
  any local file.

### Offline verification

Every object is an existing kind, so a promote, revert, promote sequence
verifies offline in the Python reference, `tine-verify.pyz` and the TS
verifier:

- the VSA through `vsa.verify`;
- each decision, approval and comparison through `sig.verify` in the
  attestation family.

The shared fixture is `tests/data/promotion_chain.json`. The tests that read
it are `tests/test_058_promotion_offline.py` and
`ts/verifier/test/promotion.test.ts`.
