# Judge assurance

*New in 0.89.* A model that grades another model's output is only as good as
the evidence that it agrees with people, resists outputs built to fool it, and
does not share a lineage with what it grades. `tine judge` records that
evidence, and `tine promote` can require it before a judge's scores move a
label.

Nothing here adds an object kind or a `tine verify` code. Human labels and
validations are existing attestations under two claim conventions, held so a
loop cannot delete them; every other code is a command-level code.

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

## Ensembles

`tine judge classify` takes several `--judge` options (with one `--prompt` each,
or one for all). Two members are dependent when they share a model, a prompt
digest or a declared `--lineage-of`, or when their prompt texts are near copies
(Jaccard similarity of character 4-grams, case and spacing folded, of 0.8 or
more). Dependence is transitive, so the members form groups, and each group
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
text (zero-width characters removed), so it is evadable and stays advisory: it
never blocks unless `--strict` is given.

## Human labels and the queue

A human label is an attestation whose claim follows
`opentine.rubric-label/1`:

```json
{"convention": "opentine.rubric-label/1", "rubric": "sha256:<rubric file bytes>",
 "item": "ID", "item_digest": "sha256:<canonical item>", "label": "pass",
 "reviewer": "sha256:<key fingerprint>", "at": "2026-12-01T10:00:00Z"}
```

It is held under `rubric-label:<rubric digest>` and `tine hold release` refuses
it. A label counts only when:

- its Ed25519 signature verifies, the payload `signer` is the key that signed,
  and `reviewer` is that same key;
- that key holds the `reviewer` role in the owner-signed trust bundle
  (docs/SECURITY_MODEL.md, `tine trust bundle create --key-roles`) and is not
  also an `optimizer` key;
- it names the rubric asked about, and its `item_digest` is the digest of the
  item with that id in the dataset asked about. Editing an item, or the rubric,
  leaves its old labels behind.

`tine judge label` refuses an unpinned or optimizer reviewer up front
(`judge.label-signer`). One reviewer who gives one item two different labels
has a conflict: neither label counts, and the conflict is listed.

`tine judge queue --per-item N` assigns every item to N pinned reviewers in the
order of `sha256(item_digest || reviewer)`, so the assignment is reproducible
and no reviewer chooses their own items. It lists each reviewer's assigned and
pending items and any label made outside the assignment.

## Agreement

`tine judge agreement` compares a judge's outcomes (the `--out` file of
`tine judge classify`) with the counted human labels. The raters of an item are
its reviewers plus the judge:

- Cohen's kappa when every item has one reviewer;
- Fleiss' kappa when every item has the same number of reviewers, more than one;
- Krippendorff's alpha (nominal) otherwise.

The interval is a percentile bootstrap over items, seeded (`--seed`,
`--resamples`), so a report is reproducible. The floor is met when the lower
bound of the 95% interval is at least `--floor` (default 0.6) and the judge
decided at least `--min-coverage` (default 0.9) of the labelled items. Items the
judge abstained on or erred on are left out of the statistic and lower its
coverage, so abstaining on hard items cannot raise agreement. A statistic that
is undefined (one label everywhere) does not meet the floor. The report is
advisory (exit 0) unless `--strict`.

## Validation

`tine judge validate` signs an `opentine.judge-validation/1` record for a judge
(`--judge judge.json`, by its `jp1+sha256:` pin) or a monitor (`--monitor
DIGEST`) after two checks:

- **adversarial**: the judge's outcomes on adversarial cases (rows of `id`,
  `expected` and `outcome`, as `tine judge classify` writes them for a set of
  outputs built to fool it). A case labelled other than expected is fooled; an
  abstain is counted but not fooled; any errored case fails. More than
  `--max-fooled` (default 0) fooled cases fails;
- **agreement**: the floor above, recomputed from the held labels at signing
  time, never read from a report.

Either failing refuses (`judge.validation-failed`). The signer must be a pinned
`scorer` or `policy` key (also `monitor` for a monitor) that is not an
`optimizer` key (`judge.validation-signer`), so a loop cannot validate its own
judge. The record is held under `judge-validation:<subject>` and never released.

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

```toml
[promote]
judge_assurance = "advisory"   # or "required"; profile = "rsi" implies "required"
judge_floor = "0.6"
```

For each eval folder the gate reads that an `llm-judge` scored, the judge needs
a validation record that counts at `judge_floor`, and must be independent of the
candidate's lineage family. Under `"required"` a gap refuses
(`promote.judge-unvalidated`, `promote.judge-not-independent`); a judge-pinned
eval without its `judge.json`, or a `judge.json` the verdicts do not pin, is
refused as unvalidated. Otherwise the gaps are the advisories
`advisory:judge.unvalidated` and `advisory:lineage.judge-not-independent`, shown
and never blocking.

## Limits

- Agreement measures consistency with the labelled sample; a sample that is
  small or unrepresentative gives a wide interval, which the floor reads as a
  low lower bound.
- The similarity and injection checks are heuristics: they catch copies,
  small edits and plain-text appeals, not every rewording.
- Independence is only as complete as the lineage folder and the ancestry
  given: a judge prompt that was never recorded anywhere cannot be traced.
