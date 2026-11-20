# Uplift and capability trends (0.73)

`tine uplift` records how well people and AI systems do on a fixed, versioned
set of tasks, and turns those records into a **50%-success time horizon**: the
task length, in human-expert minutes, at which a subject succeeds half the
time. Records are signed and held, and every reported number can be
recomputed byte for byte from an export, so a trend line in a capability report
can be audited.

The horizon is a statistical estimate from a model of success against task
length. It describes performance on one suite; it is not a general measure of
capability.

## Suites

A suite is a JSON file with exactly four fields:

```json
{"name": "toy-re", "version": "1", "scoring": "binary pass/fail by hidden tests",
 "tasks": [{"id": "t00", "minutes": "1"}, {"id": "t01", "minutes": "15.5"}]}
```

`minutes` is the task length (typically the human-expert baseline time) as a
positive decimal string. The suite is addressed by its **digest**:
`sha256:` over `opentine.uplift-suite/1`, a NUL byte and the canonical JSON of
the suite object. Changing any task, length or the scoring text gives a new
digest, so results from two suite versions are never mixed.

```
tine uplift suite suite.json                       # print the digest only
tine uplift suite suite.json --run RUN --key KEY   # sign and hold the suite
```

The signed form is an attestation claim (`opentine.uplift-suite/1`, schema
`docs/schemas/opentine-uplift-suite-1.schema.json`):
`{"convention", "digest", "suite", "at"}`.

## Records

```
tine uplift record --suite DIGEST --type baseline|run|speed --task ID --subject ID \
    --condition human|ai|ai-assisted|unassisted [--success yes|no] [--minutes D] \
    [--perceived-minutes D] [--generation N] --run RUN --key KEY [--at TIME]
```

Each record is an attestation claim (`opentine.uplift-record/1`, schema
`docs/schemas/opentine-uplift-record-1.schema.json`) on a run:

```json
{"convention": "opentine.uplift-record/1", "record": "run",
 "suite": "sha256:...", "task": "t01", "subject": "model-a", "condition": "ai",
 "success": true, "minutes": null, "perceived_minutes": null, "generation": 3,
 "at": "2026-12-01T10:00:00Z"}
```

* `baseline`: a human attempt (`condition: human`), with measured `minutes`.
* `run`: an `ai` (autonomous), `ai-assisted` (a person with AI help) or
  `unassisted` (a person without AI help) attempt; `minutes` is optional.
* `speed`: perceived vs measured time: `perceived_minutes` is the subject's own
  estimate of how long the task took, `minutes` the measured time.
* `generation` is the lineage generation of the subject (for the trend), or null.

Rules:

* A record counts only when signed with Ed25519 by a key in the `scorer` or
  `eval` role of the owner-pinned trust bundle, and the signer field names the
  key that signed it. Roles come only from that bundle.
* A pinned `optimizer` key is refused (`uplift.key-separation`): the system
  being measured cannot sign its own results.
* The suite must already be recorded and counted (`uplift.unknown-suite`), and
  the task must be one of its tasks (`uplift.unknown-task`).
* Every suite and record is held by a `tine hold` row with target
  `uplift:<digest hex>` that is never released, so a loop cannot delete a
  result it dislikes.

These are claim conventions on an existing object kind. No object kind and no
`tine verify` code is added.

## The export

`tine uplift horizon` and `tine uplift compare` read the suite's **export**
and nothing else. `--export FILE` writes it; `--from FILE` recomputes from it
without a repository:

```json
{"format": "opentine-uplift-export/1", "suite": "sha256:...",
 "definition": {"name": "...", "version": "...", "scoring": "...", "tasks": [...]},
 "records": [{"oid": "attestation:sha256:...", "record": "run", "task": "t01",
              "subject": "model-a", "condition": "ai", "success": true,
              "minutes": null, "perceived_minutes": null, "generation": 3}],
 "findings": [{"level": "advisory", "code": "advisory:uplift.signer-unpinned",
               "oid": "attestation:sha256:...", "message": "..."}]}
```

Rows are sorted by `oid` and the file is canonical JSON plus a newline. Records
that do not count are left out of `records` and listed in `findings`:

| Code | Meaning |
| --- | --- |
| `fail:uplift.malformed` | Signed by a pinned key but not a valid record |
| `fail:uplift.key-separation` | Signed by a pinned optimizer key |
| `advisory:uplift.signer-unpinned` | Unsigned, or the signer is not a pinned scorer or eval key |
| `advisory:uplift.unknown-task` | The task is not in the suite |

Reports carry `export_digest` (`sha256:` over the format name, a NUL byte and
the canonical export), the `seed`, the `resamples` count and `alpha`, so the
same export and parameters give the same bytes.

## The time-horizon fit

```
tine uplift horizon (--suite DIGEST | --from FILE) [--condition ai] [--subject ID] \
    [--seed N] [--resamples N] [--alpha A] [--strict] [--export FILE]
```

Success is modelled as `p = 1 / (1 + exp(-(a + b * log2(minutes))))`, fitted by
maximum likelihood (Newton's method, pure standard library). The horizon is
`2 ** (-a / b)` minutes. The interval is a percentile bootstrap: `--resamples`
resamples of the records with replacement, drawn by Python's
`random.Random(seed)`. Resamples whose fit is refused are counted in
`bootstrap_failed` and left out.

The fit is refused (status other than `ok`, horizon null,
`fail:uplift.fit-refused`, exit 1) when there are fewer than 10 points, fewer
than 3 distinct task lengths, no successes or no failures
(`no-variation`), Newton's method does not converge (`not-converged`, which
includes perfect separation), or success does not fall with length
(`no-decline`). When more than a tenth of the resamples fail, the report adds
`advisory:uplift.unstable-bootstrap`.

`trend` repeats the fit for each lineage `generation` present, with the same
seed and resample count. A generation with too few records shows its refusal
status there without failing the report.

Numbers are fixed 6-decimal strings. The fit uses floating point and the
platform's `log2` and `exp`; rounding to 6 decimals keeps results the same on
the platforms we test, but bytes are guaranteed only for the same Python build.

### Checking the fit

`opentine/_uplift_synth.py` generates attempts from a known logistic (24 tasks
from 1 to 960 minutes, 8 attempts each, planted horizon 60 minutes, slope
-0.8 per doubling) from a seed. `scripts/gen_uplift_synthetic.py` writes the
committed copy for seed 0 to `tests/data/uplift_synthetic.json`.
`tests/test_073_uplift_fit.py` fits seeds 0..99 with 500 resamples each and
requires the planted horizon to lie inside the 95% interval in at least 95 of
the 100 seeds (at the time of writing it does in 98).

## Compare

```
tine uplift compare (--suite DIGEST | --from FILE) --a CONDITION[:SUBJECT] \
    --b CONDITION[:SUBJECT] [--seed N] [--resamples N] [--alpha A] [--strict]
```

For each group: attempts, successes and success rate; `perceived_over_measured`
(total perceived minutes over total measured minutes across its speed records:
below 1 means the work felt faster than it was); and its horizon fit.
`b_over_a_minutes` compares the mean measured minutes of successful attempts on
the tasks both groups solved (`paired_tasks`): above 1 means group B took
longer. A typical pair is `--a unassisted --b ai-assisted`.

`compare` exits 1 on a `fail:` finding; advisory findings block only with
`--strict` (D12).

`--json` prints `tine-cli-uplift/1` for every verb.
