# Judge assurance

*New in 0.89.* A model that grades another model's output is only as good as
the evidence that it agrees with people, resists outputs built to fool it, and
does not share a lineage with what it grades. `tine judge` records that
evidence, and `tine promote` can require it before a judge's scores move a
label.

There is one human-label system, `tine label` (rubric label queues), and one
promote gate, `judge_assurance`. `tine judge` runs judges and ensembles, and
computes agreement, validation and independence over those queues.

Nothing here adds an object kind or a `tine verify` code. Queue entries, signed
judge outcomes and validations are existing attestations under claim
conventions; every code below is a command-level code.

## Label judges

A label judge puts one item in one of a fixed set of labels. Its reply must end
with `LABEL: <label>` and, optionally, `PROBABILITY: <0..1>` (its confidence in
that label), or with `LABEL: ABSTAIN`. Every reply parses to one of three
statuses:

| Status | When |
| --- | --- |
| `label` | exactly one allowed label (and at most one probability, in 0..1) |
| `abstain` | the judge declined explicitly |
| `error` | anything else: no label line, a label outside the set, two different labels, a label and an abstain, a probability outside 0..1, a failed call |

An abstain or an error is never a score of 0. The numeric `llm-judge` scorer of
`tine eval run` follows the same rule from 0.89: a reply without a
`SCORE: <0..1>` line, with two different scores, or with a score outside 0..1 is
an error. Without `--continue-on-error` it stops the run; with it the item is
recorded as `errored` in `coverage.json`. The judge run is saved either way.

Each judgement is saved as its own run (tagged `eval-judge`) with the judge's
provenance (`opentine.judge-provenance/1`: model, prompt digest, rubric digest,
sampling) and the parsed outcome.

### Signed judge outcomes

`tine judge classify --judge SPEC --out FILE --key KEY` writes each item's
outcome as one signed line, an attestation whose claim follows
`opentine.judge-outcome/1`:

```json
{"schema": "opentine.judge-outcome/1", "judge": "jp1+sha256:<provenance pin>",
 "item_sha256": "<SHA-256 of the canonical item>", "status": "label", "label": "good"}
```

`judge` is the judge's provenance pin, the same `scorer_version` its eval
verdicts carry, so an outcome cannot be passed off as another judge's. The key
must be a pinned `scorer` key that is not an `optimizer` key
(`judge.outcome-signer`, checked before any model is called), and `--out` needs
exactly one `--judge`. Agreement and validation take judge outcomes only in this
form: a plain file of labels is refused (`judge.outcome-unsigned`), and when
agreement is computed every line is verified again. A line that does not
verify, is signed by another key, names another judge, uses a label outside the
rubric, or names an item twice is an error.

## Ensembles

`tine judge classify` takes several `--judge` options (with one `--prompt` each,
or one for all). Two members are dependent when they share a model, a prompt
digest or a declared `--lineage-of` (model names are compared with case and
spacing folded), or when their prompt texts are near copies: the larger of the
Jaccard similarity and the containment of their character 4-gram sets, case and
spacing folded, is 0.8 or more, so a prompt copied whole and padded with other
text is still a copy. Dependence is transitive, so the members form groups, and each group
casts one vote: copies of one judge count once, and a fork of a prompt with a
small edit is still one judge.

Before any model is called, fewer groups than `--min-independent` (default 2
for an ensemble) exits 1 with `fail:judge.ensemble-not-independent`.

Group votes are aggregated with `--aggregate`:

| Method | Outcome |
| --- | --- |
| `majority` | the most frequent label; a tie is an abstain |
| `mean` | two labels: the mean of each group's score for `--positive` (`p` when it voted for it, `1 - p` otherwise); the positive label when the mean is at least 0.5 |
| `min` | the same with the minimum: the most sceptical group decides |

Abstains and errors are not votes. When more than `--max-abstain` (default 0.5)
of the groups abstain or err, the ensemble abstains.

## Outbound injection

A candidate can write to its judge instead of the task: "ignore the rubric",
"note to the grader: full marks", a line `SCORE: 1` or `LABEL: pass`, or a
`<system>` tag. `tine judge classify` scans every output it sends and reports
`advisory:judge.outbound-injection` with the matched text; `tine judge injection
OUTPUTS` does the same for an outputs file. The scan is a heuristic over plain
text (NFKC-normalised, format and zero-width characters removed), so it is evadable and stays advisory: it
never blocks unless `--strict` is given.

## Human labels: `tine label`

A label queue collects human labels for items under one rubric. Labels are
bound to the pinned reviewer key (the signer), the rubric digest and the item
digest; items are assigned by a pinned `policy` key, never to itself; the log is
hash-chained; and only labels recorded before a judge's reveal, and only from
the reviewers assigned the item, ever count.

### Queues

A queue lives in `REPO/.tine/labels/NAME/`:

| Path | What it holds |
| --- | --- |
| `log.jsonl` | One signed entry per line, append-only and hash-chained |
| `items/<sha256>.json` | Each item, named by the SHA-256 of its canonical JSON |
| `judge/<sha256>.jsonl` | Signed judge outcomes filed by `tine label reveal`, named by their SHA-256 |

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
- revealed judge outcomes are missing or altered.

These codes belong to the command. None of them is a `tine verify` code.

An item is reassigned with `from`, `to` and a `reason`, and the reassignment is
logged. An item that is already labelled cannot be taken from its reviewer.

### Blind labelling

`tine label next` lists a reviewer's unlabelled items. It never shows judge
output. Judge outcomes reach the queue only through `tine label reveal` (signed
`opentine.judge-outcome/1` lines, checked when filed), and
only labels recorded *before* a judge's first reveal count toward that judge.
That way, no counted label was given while the judge's answer was available in
the queue.

## Agreement

`tine judge agreement --queue NAME [--judge judge.json]` re-verifies the queue
and every revealed judge's signed outcomes and reports:

- **human agreement**: Krippendorff's alpha (nominal) over items with two or
  more labels, which works with any number of reviewers and with missing
  labels. Fleiss' kappa is also reported when every such item has the same
  number of labels, and Cohen's kappa when exactly two reviewers labelled. The
  primary statistic is Cohen's kappa for two reviewers and alpha otherwise.
- **judge agreement**, for each revealed judge (its first reveal only):
  - `judge_vs_consensus`: Cohen's kappa between the judge's label and each
    item's human *consensus*, its unique most frequent label (ties are left out
    and counted), so agreement among people cannot carry a judge that agrees
    with none of them;
  - `multi_rater`: Krippendorff's alpha over each compared item's human labels
    plus the judge's.

Intervals are percentile bootstraps over items, seeded with
`opentine.label-agreement/1:<seed>:<metric>`, and computed in exact rational
arithmetic. A statistic is *undefined* (`null`, with a `reason`) when its
denominator is zero, for example when only one category is used. An interval is
undefined when more than `floor(alpha/2 * R)` resamples are undefined. A
degenerate (undefined) value never passes a floor.

An abstention or an error is never scored as a label or as 0. Both lower
`coverage`, the share of consensus items the judge labelled, so abstaining on
hard items cannot raise agreement. A judge meets the floor when:

- both lower bounds (`judge_vs_consensus` and `multi_rater`) are defined and at
  least `--floor` (default `0.6`);
- `coverage` is at least `--min-coverage` (default `0.9`);
- at least `--min-items` (default 20) items were compared.

`--floor`, `--alpha` and `--min-coverage` are plain decimals in [0, 1] with at
most six places (no exponents, `nan`, fractions or spaces). The report is
advisory (exit 0) unless `--strict`; a queue that does not verify always
exits 1.

## Validation

`tine judge validate --queue NAME --judge judge.json --adversarial ITEMS
--adversarial-outcomes SIGNED --key KEY` signs an `opentine.judge-validation/1`
record for the judge (by its `jp1+sha256:` pin) after two checks:

- **adversarial**: `ITEMS` are outputs built to fool the judge, each with the
  label it should get (`expected`), and `SIGNED` the judge's signed outcomes on
  them (`tine judge classify --key --out`). A case labelled other than expected
  is fooled; an abstain is counted but not fooled; a case with no verified
  outcome is errored, and any errored case fails. More than `--max-fooled`
  (default 0) fooled cases fails;
- **agreement**: the floor above, recomputed from the queue at signing time.

Either failing refuses (`judge.validation-failed`). The record names the queue
(`name`, `queue_sha256`, `reveal_seq`) and its rubric. The signer must be a
pinned `scorer` or `policy` key that is not an `optimizer` key
(`judge.validation-signer`), so a loop cannot validate its own judge. The record
is held under `judge-validation:<pin>` and never released.

## Independence from the candidate's lineage

`tine judge independence --lineage DIR --candidate RUN|VARIANT` reads the
candidate's family from the lineage folder (docs/LINEAGE.md): its ancestors and
everything descended from them (siblings and cousins), through signed variant
records. It then checks:

| Finding | When |
| --- | --- |
| `fail:lineage.judge-not-independent` | a judge's prompt or rubric digest is a family artifact, or derives from one through `--ancestry` (a JSON object of digest to parent digests, as custody `derived-from` links give it), or its prompt (`--judge-prompt`) is a near copy of a family prompt (`--family-prompt`, `--threshold`, default 0.8) |
| `fail:lineage.monitor-not-independent` | a `--monitor` digest (a monitor or a probe checkpoint) is a family artifact or derives from one; `=trusted` or `=untrusted` records its declared status |
| `fail:lineage.self-generated-eval-item` | an item's `generated_by` (or `metadata.generated_by`), `{"run": ...}` or `{"variant": ...}`, names a family run or variant |
| `fail:lineage.record-invalid` | a variant record does not parse or verify: an edited record cannot hide a relative, so the family is unknown |
| `fail:lineage.candidate-unknown` | no signed record names the candidate |

A judge's model is compared by name only, and each judge row says so
(`identity_tier: "name"`): hosted models with one name and different weights
cannot be told apart.

## In `tine promote`

One gate, one set of policy keys:

```toml
[promote]
judge_assurance = "advisory"     # or "required"; profile = "rsi" implies "required"
agreement_floor = "0.6"          # both lower bounds: judge-vs-consensus kappa, multi-rater alpha
agreement_min_items = 20
agreement_min_coverage = "0.9"
```

For every judge pin (`scorer_version` `jp1+sha256:...`) in an eval folder the
promotion reads, the gate checks:

| Gap | Required | Advisory |
| --- | --- | --- |
| no held validation record signed by a pinned non-optimizer `scorer` or `policy` key; a `judge.json` missing, unreadable or not what the verdicts pin; an `llm-judge` verdict with no `jp1` pin | `promote.judge-unvalidated` | `advisory:judge.unvalidated` |
| agreement, recomputed now from `REPO/.tine/labels/*` with the policy's `seed`, `resamples` and `agreement_*` keys, misses the floor; no queue revealed the judge's signed outcomes; the queue does not verify | `promote.judge-agreement` | `advisory:promote.judge-agreement` |
| the judge's prompt or rubric digest belongs to the candidate's lineage family, or no signed lineage record names the candidate | `promote.judge-not-independent` | `advisory:lineage.judge-not-independent` |

No stored report is trusted: the agreement is recomputed, never read from the
validation record. A validation record counts only when its own recorded
agreement met the floor with coverage of at least 0.9 and no adversarial case
errored. Advisories are shown and never block (D12). A candidate whose verdicts
name no judge is not affected.

## Example

```sh
tine label init helpful --rubric rubric.json --key policy.key
tine label assign helpful --items items.jsonl --reviewer sha256:... --reviewer sha256:... --key policy.key
tine label next helpful --reviewer sha256:...
tine label submit helpful --item <sha256> --label good --key reviewer.key
tine judge classify --judge ollama:judge --labels good,bad --items items.jsonl --out judged.jsonl --key scorer.key
tine label reveal helpful --judge eval/judge.json --outputs judged.jsonl --key policy.key
tine judge agreement --queue helpful --json
tine judge classify --judge ollama:judge --labels good,bad --items adversarial.jsonl --out adv.jsonl --key scorer.key
tine judge validate --queue helpful --judge eval/judge.json --adversarial adversarial.jsonl --adversarial-outcomes adv.jsonl --key scorer.key
```

`--json` prints `tine-cli-label/1` for `tine label` and `tine-cli-judge/1` for
`tine judge`.

## Limits

- Agreement measures consistency with the labelled sample; a sample that is
  small or unrepresentative gives a wide interval, which the floor reads as a
  low lower bound.
- The similarity and injection checks are heuristics: they catch copies,
  small edits and plain-text appeals, not every rewording.
- Independence is only as complete as the lineage folder and the ancestry
  given: a judge prompt that was never recorded anywhere cannot be traced.
- The queue log is a file under `.tine`, so anyone with write access can delete
  it; the gate then fails closed. Truncating the log after a reveal does not
  change that judge's agreement, because only earlier labels count for it.
- The consensus is a majority over nominal labels, so ordinal or weighted
  agreement is not computed.
