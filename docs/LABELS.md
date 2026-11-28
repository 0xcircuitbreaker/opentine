# Rubric label queues and judge agreement

New in 0.89. A label queue collects human labels for items under one rubric,
and measures how well reviewers agree with each other and how well a judge
agrees with them. The judge's agreement can gate `tine promote`.

## Queues

A queue lives in `REPO/.tine/labels/NAME/`:

| Path | What it holds |
| --- | --- |
| `log.jsonl` | One signed entry per line, append-only and hash-chained |
| `items/<sha256>.json` | Each item, named by the SHA-256 of its canonical JSON |
| `judge/<sha256>.jsonl` | Judge outputs filed by `tine label reveal`, named by their SHA-256 |

Every entry is an existing attestation shape (`claim`, `signer`, `target_id`,
`signature`) whose claim follows one of these conventions. None of them is a
new object kind. Every claim carries `seq` (its line index) and `prev` (the
SHA-256 of the previous line's canonical JSON). Every entry after the first
also carries `queue`, the SHA-256 of the first entry. The first entry holds the
queue name and a random nonce, so two queues never share a chain even when
their rubrics are the same.

| Convention | Signed by | Fields |
| --- | --- | --- |
| `opentine.label-rubric/1` | pinned `policy` key | `name`, `nonce`, `rubric` (`name`, `labels`, `instructions`), `rubric_sha256` |
| `opentine.label-assign/1` | pinned `policy` key | `item_sha256`, `reviewer`; for a reassignment, `from` and `reason` |
| `opentine.label/1` | pinned `reviewer` key | `item_sha256`, `label`, `reviewer` (the signer), `rubric_sha256` |
| `opentine.label-reveal/1` | pinned `policy` key | `judge` (the `jp1+sha256:` pin), `outputs_sha256` |

Keys come only from the owner-pinned trust bundle (`tine keys lint`,
`.tine/key-roles.toml`). The new `reviewer` role is for people who sign labels.
An assignment never names the key that signs it (`labels.self-assign`), so a key
holding both `policy` and `reviewer` cannot hand itself items.

A key the bundle also names as `optimizer` cannot act as a reviewer or a policy
key, even when it is listed in that role.

Each entry is checked when it is written and every time the queue is read. A
queue is invalid as a whole (it fails closed) when any of these happens:

- a signature does not verify, or the signer does not hold the role;
- an entry is out of place, which covers a line that was replayed, moved, or
  copied from another queue (`labels.chain`);
- a label names a reviewer other than its signer, or a rubric other than the
  queue's;
- a reviewer labels an item twice (`labels.duplicate`), labels an item they are
  not assigned (`labels.unassigned`), or uses a label outside the rubric
  (`labels.bad-label`);
- revealed judge outputs are missing or altered.

These codes belong to the command. None of them is a `tine verify` code.

An item is reassigned with `from`, `to` and a `reason`, and the reassignment is
logged. An item that is already labelled cannot be taken from its reviewer.

## Blind labelling

`tine label next` lists a reviewer's unlabelled items. It never shows judge
output. Judge outputs reach the queue only through `tine label reveal`, and
only labels recorded *before* a judge's first reveal count toward that judge.
That way, no counted label was given while the judge's answer was available in
the queue.

## Agreement

`tine label agree NAME` reports:

- **human agreement**: Krippendorff's alpha (nominal) over items with two or
  more labels, which works with any number of reviewers and with missing
  labels. Fleiss' kappa is also reported when every such item has the same
  number of labels, and Cohen's kappa when exactly two reviewers labelled. The
  primary statistic is Cohen's kappa for two reviewers and alpha otherwise.
- **judge agreement**, for each revealed judge: Cohen's kappa between the
  judge's label and the item's human *consensus*, which is its unique most
  frequent label. Ties are left out and counted.

Intervals are percentile bootstraps over items, seeded with
`opentine.label-agreement/1:<seed>:<metric>`, and computed in exact rational
arithmetic. A statistic is *undefined* (`null`, with a `reason`) when its
denominator is zero, for example when only one category is used. An interval is
undefined when more than `floor(alpha/2 * R)` resamples are undefined. An
undefined value never passes a floor.

The judge's output lines are `{"item_sha256", "label"}` or an explicit
abstention, `{"item_sha256", "abstain": true}`. Anything else is an *error*:
unparsable lines, labels outside the rubric, and items named twice. An
abstention or an error is never scored as a label or as 0. Both lower
`coverage`, the share of consensus items the judge labelled.

A judge meets the floor when:

- its kappa lower bound is defined and at least `--floor` (default `0.6`);
- `coverage` is at least `--min-coverage` (default `0.8`);
- at least `--min-items` (default 20) items were compared.

`agree` reports the outcome as advice and exits 0. With `--strict` it exits 1
when a floor fails. A queue that does not verify always exits 1.

## Promotion

When the candidate's signed verdicts name an `llm-judge` pin as
`scorer_version`, `tine promote` looks for that judge's first reveal in
`REPO/.tine/labels/*`. It re-verifies the queue and recomputes the report with
the policy's `seed` and `resamples`. No stored report is trusted. The policy
keys are:

```toml
judge_agreement = "advisory"   # or "required"; profile = "rsi" implies "required"
agreement_floor = "0.6"
agreement_min_items = 20
agreement_min_coverage = "0.8"
```

Under `"required"`, the promotion is refused with `promote.judge-agreement` in
three cases: no queue revealed the judge, the queue does not verify, or the
floor fails. A missing record never passes. Otherwise the same finding is the
advisory `advisory:promote.judge-agreement` and does not block (D12). A
candidate whose verdicts name no judge is not affected.

## Example

```sh
tine label init helpful --rubric rubric.json --key policy.key
tine label assign helpful --items items.jsonl --reviewer sha256:... --reviewer sha256:... --key policy.key
tine label next helpful --reviewer sha256:...
tine label submit helpful --item <sha256> --label good --key reviewer.key
tine label reveal helpful --judge eval/judge.json --outputs judge-labels.jsonl --key policy.key
tine label agree helpful --json
```

`--json` prints `tine-cli-label/1`.

## Limits

The log is a file under `.tine`, so anyone with write access can delete it.
If they do, the gate fails closed. Truncating the log after a reveal does not
change that judge's agreement, because only earlier labels count for it.
Truncating it before the reveal removes the reveal too. The consensus is a
majority over nominal labels, so ordinal or weighted agreement is not computed.
