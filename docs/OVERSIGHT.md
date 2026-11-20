# Oversight queue and k-of-n gates (0.64)

A self-improving loop can produce candidates, integrity findings and monitor
verdicts faster than a person reads them. The oversight queue routes the ones
that matter into risk tiers, and each tier needs k signed approvals from n
named approvers before the item clears. `tine promote` checks the policy, so a
routed candidate does not move a label until enough distinct people approve
it.

Nothing here adds an object kind or a `tine verify` code. Decisions are
existing `annotation` objects chained by `previous_id`; the policy and the
queue item names are conventions described on this page.

## The policy: `.tine/oversight.toml`

```toml
version = 1

[tiers.high]
k = 2
approvers = ["sha256:<a1>", "sha256:<a2>", "sha256:<a3>"]

[tiers.low]
k = 1
approvers = ["sha256:<a1>", "sha256:<a2>"]

[humans]                        # optional: keys one person holds count once
alice = ["sha256:<a1>", "sha256:<a1-laptop>"]

[[route]]
source = "promotion"            # lineage promotions
label = "prod*"                 # a label glob (default "*")
tier = "high"

[[route]]
source = "eval"                 # threshold-crossing evals on a promotion
label = "*"
metric = "pass_rate"            # pass_rate | mean_score of the candidate's evals
above = 0.9                     # and/or below = ...
tier = "high"

[[route]]
source = "monitor"              # held monitor verdicts (0.62)
actions = ["flag", "defer", "block"]
tier = "low"

[[route]]
source = "integrity"            # held integrity taints (fail: findings)
tier = "low"

[[route]]
source = "organism"             # untagging a model organism (0.72)
tier = "high"
```

`budget` and `containment` items route the same way. An `organism:ATTESTATION`
item names a model-organism tag record. An untag takes effect only while that
item is `approved`, and with no `organism` route an untag never takes effect
(docs/MODEL_ORGANISMS.md).

A `custody:ATTESTATION|BLOB` item (0.72, route `source = "custody"`) names a
weight custody event that a `fail:` finding of `tine custody check` points at
(a gap, a broken chain or an unapproved load), or a refused load of a tagged
artifact: an `opentine.weight-custody-refusal/1` entry held by `tine custody
gate` (hold `custody:weights-refused:NAME`, never released) or an
`opentine.organism-access/1` entry whose `outcome` is `refused`. Custody items
are recomputed from the held records on every read. Approving one records a
review; it never allows a load, which still needs a custody or organism
approval (docs/CUSTODY.md).

An item routed into several tiers must satisfy each of them.

### Pinning

The file is in the repository, so a loop that can write the repository can
edit it. It counts only when `.tine/oversight.sig.json` covers its exact
bytes: an attestation-shaped document whose claim is
`{"schema": "opentine.oversight-policy/1", "policy_sha256": HEX}`, signed with
Ed25519 by a `policy`-role key from the owner-pinned trust bundle
(`tine trust bundle create --key-roles`, see docs/LINEAGE.md) that is not an
`optimizer` key. `tine oversight sign-policy --key KEY` writes it.

An unsigned, edited or wrongly signed policy is `unpinned` and grants
nothing: every routed promotion is refused with
`promote.oversight-insufficient` and the reason. A missing file means no
oversight gate (the state before 0.64).

### Owner-pinned k floors

A signed policy can still be rolled back to an older, validly signed copy
with a lower k. The owner can pin a floor per tier in the trust bundle, next
to the key roles:

```json
"oversight": {"version": 1, "tiers": {"high": {"k": 2}}}
```

Each pinned tier's k is then at least the pinned value: the file may raise it
but never lower it. A pinned tier the file lacks leaves the policy `unpinned`
(it grants nothing), and a bad or rolled-back bundle under a pinned owner
refuses with `promote.oversight-insufficient`. `tine oversight policy` and
`queue` report `"floors": true` when a floor section is in force. There is no
`tine trust bundle create` flag for this section yet; it is added to the
bundle payload by hand before signing.

### Who counts

A decision counts only when all of these hold:

* it is signed with Ed25519 and the signature verifies;
* the signer is in the tier's `approvers` **and** holds the `approver` role of
  the owner-pinned trust bundle (an unsigned `.tine/key-roles.toml` grants no
  approver);
* the signer holds none of the `optimizer`, `monitor` or `scorer` roles (key
  separation; these roles refuse even when unpinned);
* for a promotion, it is bound to the current candidate, label holder and
  history length (see below).

Distinct approvers are counted per person: the same key twice counts once,
keys listed for one person under `[humans]` count once, and keys whose
decisions declare the same `--human` count once. A signer's newest decision
replaces its earlier ones, so an approver can change a rejection into an
approval and back.

## Items and decisions

An item is named by a string:

| Item | Source |
| --- | --- |
| `promotion:LABEL:run:sha256:HEX` | a candidate for a label; `promotion` and `eval` routes |
| `monitor:attestation:sha256:HEX` | a held monitor verdict whose action a `monitor` route lists |
| `integrity:attestation:sha256:HEX` | a held integrity taint (a `fail:` finding) |

Each item has an anchor blob holding the canonical JSON
`{"convention": "opentine.oversight-item/1", "item": ITEM}`, so its id follows
from the name alone. A decision is an `annotation` on the anchor:

```json
{"target_id": "blob:sha256:<anchor>",
 "previous_id": "annotation:sha256:<the item's previous decision> | null",
 "value": {"convention": "opentine.oversight-decision/1",
           "item": "promotion:prod:run:sha256:...",
           "decision": "request | approve | reject",
           "bind": {"label", "candidate", "previous", "sequence"} | null,
           "human": "alice | null", "note": "...",
           "decided_at": "2026-12-03T10:00:00Z"},
 "signer": "sha256:<fingerprint>",
 "signature": {"...": "tine-attest block, Ed25519"}}
```

The `value` follows `docs/schemas/opentine-oversight-decision-1.schema.json`.
`request` puts an item in the queue (it may carry the candidate's eval
`metrics` in `bind`, so `eval` routes apply in the queue view) and never counts
as an approval.

### Binding

A promotion decision's `bind` names the label, the candidate, the holder it
replaces (`previous`) and the label state's history length (`sequence`), read
from `.tine/promotion/LABEL.json` (or `--state`). Every promote and revert
appends to that history, so an approval counts for one move only. An approval
for another candidate is another item; one for an older holder or sequence is
stale and `promote` says so with `promote.oversight-stale`.

### Holds

Every decision is kept by a `tine hold` row whose target starts
`oversight-decision:`. `tine hold release` refuses it, so `gc` and `prune`
never delete an approval, a rejection or a request a loop would want gone.

Every decision on an item counts, ordered by `decided_at`, not only those on
one `previous_id` chain: a fork of the chain (two writers at once, or a
decision forged to start before a rejection) hides nothing. A signer's newest
decision replaces its earlier ones.

## The gate in `tine promote`

When the policy routes a candidate, `tine promote` reads the decisions from
the annotation objects (not from the holds file, so editing that file hides
nothing) and refuses with:

| Code | Meaning |
| --- | --- |
| `promote.oversight-rejected` | a counted approver's newest decision is `reject` |
| `promote.oversight-key-separation` | short of k, and an approval was signed by an `optimizer`, `monitor` or `scorer` key (it never counts) |
| `promote.oversight-stale` | short of k, and approvals are bound to another holder or sequence |
| `promote.oversight-insufficient` | fewer than k distinct approvers in a routed tier, the policy is unpinned, or `.tine/oversight.toml` is gone while oversight decisions exist |

These are promotion refusals, like the 0.58 codes in docs/EVALS-PROMOTION.md;
they are not `tine verify` codes.

## The queue

`tine oversight queue` lists every routed item with, per tier, `k`, `n`, the
number of distinct approvers and who they are, the item's state (`pending`,
`approved`, `rejected`, or `unrouted` when decisions exist but no route
applies) and the decisions that do not count, each with a reason
(`unsigned`, `key-separation`, `stale`, `policy-unpinned`, `not-an-approver`).
It reads the held decision ids; `--from-objects` rebuilds the same answer
from the annotation objects alone, and the two are equal. `--json` prints
`tine-cli-oversight/1`.

The queue is computed with the same tally function the gate uses, over the
same decision annotations, so it cannot report `approved` where `tine
promote` refuses. The body also carries `counts` per state, each item's
`opened_at` (its first `request` decision's `decided_at`, else its first
decision's), a `counted` flag and any `viewed` evidence per decision, and a
`digest` (sha256 of the canonical JSON of the rest). A candidate that already
holds its label is judged as it stood when it was promoted, so its approvals
stay counted. `--only STATE` filters the text output.

### `tine ui` queue view

`tine ui --repo PATH` serves `/queue.html` and `/api/oversight/queue`. The API
answers the same JSON object `tine oversight queue --json` prints, recomputed
from the repository on each request. The page renders that object as text
nodes and shows its digest, so a reviewer can compare it with the CLI's.

## Approver fatigue (advisory)

`approve` and `reject` take `--viewed OID` (repeatable) and `--viewed-at
TIME` to record, inside the signed decision, the evidence the approver opened
and when. `tine oversight fatigue --repo PATH [--min-review-seconds N] [--at
TIME]` reports, over counted decisions only:

- time to decision: `decided_at` minus the item's `opened_at` (median and
  max, in seconds), taken from the records and not from when the command runs;
- rubber stamps: approvals with no viewed evidence, or decided less than
  `--min-review-seconds` (default 30) after `viewed.at`, and their rate;
- approvals, rejections, rubber stamps and median time to decision per
  approver;
- pending items and the oldest one's age against `--at` (default: the
  current time; tests inject a fixed time).

The report is advisory (owner decision D12): it has `"advisory": true`, no
`fail:` findings, and the command exits 0 whatever the numbers are. Nothing
reads it to gate.

## Limits

* Decisions name an item, not a lineage record: `tine lineage check` does not
  read the queue.
* With no `.tine/oversight.toml` and no decision yet, nothing is gated, and
  an older validly signed policy can be restored: without trust-bundle k
  floors, the policy is not pinned by sequence outside the repository, and
  floors do not pin routes.
* The held-id `queue` omits decisions written straight to the object store
  without a hold row; they never change a verdict, but the two listings can
  then differ (`--from-objects` and the gate see them).
* A loop with direct filesystem access can delete a decision object outright;
  holds stop `tine hold release` and gc, not that.
* Approver-fatigue metrics are advisory and never gate.
* The `--from-objects` rebuild and the promote gate scan the repository's
  annotation objects.
