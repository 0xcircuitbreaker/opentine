# Experiment manifests and reproduce

An experiment manifest states what an experiment was, what it found, and which
signed evidence backs each result. `tine reproduce` reruns a deterministic sample
of it and signs whether the reruns agree. Both are **file conventions**: no object
kind is added and `tine verify` has no new code. Experiment checks live in
`tine experiment check`, with their own `experiment.*` codes.

## The manifest (`opentine.experiment-manifest/1`)

```json
{
  "convention": "opentine.experiment-manifest/1",
  "experiment": "exp-1",
  "hypothesis": "the patch raises exact-match accuracy",
  "code_digest": "sha256:...",
  "container_digest": "sha256:...",
  "model": {"id": "example-model", "version": "2026-10-01"},
  "sampling": {"temperature": 0, "max_tokens": 256},
  "seeds": [7],
  "data": [{"name": "dev", "commitment": "sha256:..."}],
  "compute": {"usd": 1.25, "gpu_hours": null, "tokens": 12000},
  "results": [
    {"id": "item0", "verdict": "sha256:...", "path": "verdicts/item0.json",
     "score": "1", "passed": true, "input": {"x": 0}}
  ],
  "conclusion": "accuracy 0.5625 on dev",
  "created_at": "2026-11-20T10:00:00Z",
  "signer": "sha256:...",
  "signature": {"...": "tine-sig/3 block"}
}
```

- `results[].verdict` is the digest of a signed `tine-eval-verdict/1`
  (`tine eval run` writes them) and `path` is where that verdict file sits,
  relative to the manifest, in POSIX form. `score` and `passed` restate the
  verdict's values; `input` is optional data a reproduce runner may use.
- `container_digest` may be null; `compute` values may be null when unknown.
- The signature is an Ed25519 `tine-sig/3` block over the domain
  `opentine.experiment-manifest.v1:` and the JCS of every field but `signature`.

Write a draft without `signer` and `signature`, then sign it:

```
tine experiment sign exp.json --key author.key
```

## `tine experiment check`

```
tine experiment check exp.json [--repo PATH] [--strict] [--json]
```

| Code | Meaning |
| --- | --- |
| `fail:experiment.malformed` | The fields are not the convention's |
| `fail:experiment.unsigned` | The manifest carries no signature |
| `fail:experiment.bad-signature` | The signature is not by the named signer, or the manifest changed after signing |
| `fail:experiment.reference-missing` | A row's verdict file is absent, unreadable or not a verdict |
| `fail:experiment.reference-unsigned` | A row's verdict does not verify |
| `fail:experiment.result-mismatch` | A row's digest, score or passed differs from its verdict |
| `fail:experiment.key-separation` | A verdict is signed by a key in the pinned `optimizer` role |
| `advisory:experiment.signer-unpinned` | A verdict signer is not in a pinned `scorer`, `eval` or `verdict` role |

A `fail:` finding exits 1. Advisory findings are reported and block only with
`--strict` (D12). Roles are read only from the owner-pinned trust bundle of the
repository named by `--repo`; without one every verdict signer is unpinned.
Given a reproduce report instead of a manifest, `check` verifies its signature.

## `tine reproduce`

```
tine reproduce exp.json --sample 20 --key reproducer.key \
  [--seed N] [--tolerance 0.05] [--repeats 2] [--runner verdict|FILE.py:FUNC|MODULE:FUNC] \
  [--out report.json]
```

The manifest must be well formed and signed. The sample is
`random.Random(seed).sample` over the sorted result-row ids; the seed defaults to
the first 13 hex digits of the manifest digest, so the same manifest always picks
the same rows. The report records the seed, `k`, the population size and the
chosen ids.

A runner reruns one row:

```python
def run(manifest: dict, row: dict) -> dict:
    return {"score": 0.75, "observed": {"model": {...}, "seed": 7, "sampling": {...}}}
```

`observed` may report `model`, `sampling`, `seed`, `code_digest` and
`container_digest` as they were during the rerun. The built-in `verdict` runner
rescores from the referenced verdict file (it checks that the stated evidence is
there and consistent, not that the model behaves the same).

Each row is run `--repeats` times. A row agrees when every rerun score is within
`--tolerance` of the row's score. `nondeterministic` lists:

- each `observed` field that differs from the manifest (`seeds` when the rerun
  seed is not among the manifest's seeds);
- `score` when repeats of one row scored differently;
- `seeds` (and `sampling`, for a nonzero `temperature`) when the manifest lists
  no seeds.

The signed report (`opentine.reproduce-report/1`, domain
`opentine.reproduce-report.v1:`) names the manifest digest, runner, selection,
tolerance, repeats, per-row results, `agreed`/`disagreed` and `verdict`
(`agree` or `disagree`). `tine reproduce` exits 1 on `disagree`.

## Schemas

`opentine-experiment-manifest-1`, `opentine-reproduce-report-1`,
`tine-cli-experiment-1` and `tine-cli-reproduce-1` in `docs/schemas`.
