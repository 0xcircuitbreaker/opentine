# RL-scale capture: sealed segments and sampling audits (0.84)

RL training produces millions of episodes a day. Signing each one and having a
person read each one are both too expensive. 0.84 builds on batched ingest
(docs/INGEST.md, 0.77) with three steps:

1. **Seal**: the batches since the last segment are rolled into one *segment*.
   The segment holds a Merkle root over the episode digests and is signed once
   by a pinned runner key.
2. **Commit**: the root is written to the repository's op log before the
   segment exists.
3. **Audit**: a sample of episodes is checked against the root. The sample
   seed comes from the op log tree that follows the seal, so nobody can know
   it when the episodes are written. The sample size comes from a stated
   guarantee. The verdict is signed and records the bound.

This adds no new object kinds and no new `tine verify` codes. Segments and
audits are claim conventions in the `value` of existing `annotation` objects.
The codes below are `tine ingest segments` findings.

## Quick start

```sh
tine ingest policy --stream rl-train --rate 1 --no-redact --key policy.key
tine ingest --batch rollouts-0001.jsonl --stream rl-train --key runner.key
tine ingest --batch rollouts-0002.jsonl --stream rl-train --key runner.key
tine ingest seal --stream rl-train --key runner.key            # -> SEGMENT
# ... any later op log entry (the next seal, a commit, a ref move) ...
tine ingest audit SEGMENT --key auditor.key --confidence 0.99 --max-bad 0.005
tine ingest audit SEGMENT --key auditor.key --episodes exported-train-set.jsonl
tine ingest prove SEGMENT --index 4711 --json > proof.json
tine ingest segments rl-train                                   # exit 1 on a fail finding
```

## Segments: `opentine.ingest-segment/1`

```json
{"convention": "opentine.ingest-segment/1", "stream": "rl-train", "seq": 0,
 "previous": null, "batches": ["annotation:sha256:..."],
 "first_index": 0, "next_index": 100000, "episodes": 100000,
 "root": "sha256:...", "log": {"origin": "opentine.local/log/op", "index": 41},
 "sealed_at": "2027-01-15T08:00:00Z"}
```

* **Episodes and leaves.** Each captured event of the sealed batches is one
  episode. Its leaf is `SHA-256(0x00 || line)`, where `line` is the stored
  line `{"e": EVENT, "i": INDEX, "k": KIND}` exactly as the batch holds it,
  with no trailing newline. Leaves are in stream-index order. `root` is the
  RFC 6962 Merkle tree hash over them, the same tree the op log and every
  `opentine-log/1` use.
* **Range.** A segment covers every batch after the previous segment's last
  batch, up to the stream's head (or up to `--through BATCH`). The `batches`
  must continue the 0.77 hash chain with nothing skipped (at most 65,536
  batches per segment).
* **Signer.** The signer must hold the pinned `runner` role and must not hold
  the `optimizer` role. Roles are read from the owner-pinned trust bundle
  only. Without a pinned bundle, `seal` refuses.
* **Commitment.** Before the annotation is written, `seal` appends an op log
  entry whose `note` is `ingest seal STREAM #SEQ ROOT through LAST-BATCH`. The
  segment records that entry's index in `log.index`.
* **Holds.** The newest segment is held as `ingest-segment:STREAM`.
  Segments chain through `previous`, so the held head keeps every segment
  reachable. `tine hold release` refuses the hold.

## Audits: `opentine.ingest-audit/1`

```json
{"convention": "opentine.ingest-audit/1", "segment": "annotation:sha256:...",
 "stream": "rl-train", "root": "sha256:...", "episodes": 100000,
 "guarantee": {"confidence": "0.99", "max_bad": "0.005"},
 "bound": {"method": "hypergeometric", "sample": 913, "tolerated": 500,
           "threshold": 501, "miss_probability": 0.00998},
 "checkpoint": {"origin": "opentine.local/log/op", "seal_index": 41, "size": 43,
                "root": "<64 hex>", "note": "<signed checkpoint>"},
 "seed": "<64 hex>", "positions": "sha256:...",
 "source": {"kind": "repository"} | {"kind": "file", "sha256": "sha256:..."},
 "checked": 913, "ok": 913, "missing": 0, "altered": 0, "failures": [],
 "verdict": "pass", "at": "2027-01-15T09:00:00Z"}
```

### Seed: commit, then reveal

Let `K` be the segment's seal entry in the op log. The seed is

    SHA-256("opentine.ingest-audit/1" || 0x00 || SEGMENT-ID || 0x00 || R)

where `R` is the op log's Merkle root at size `K + 2`. That is the first log
tree that is strictly later than the seal. `R` does not exist until an entry
after the seal has been appended, so it cannot be known when the episodes are
written or sealed. The auditor cannot choose a checkpoint either: `R` depends
only on the log.

To read `R`, the audit opens a signed checkpoint: `--checkpoint FILE` (for
example a witness-cosigned copy) or, by default, the log's own. The audit
refuses a checkpoint that:

* is not signed by the op log key;
* has size `K + 1` or less (**earlier**: the log has no entry after the
  seal yet);
* has a root that disagrees with the log's entries, or a size larger than the
  log (**ambiguous**: a fork or a checkpoint from elsewhere);
* covers a log whose entry `K` does not commit to this segment's root.

The audit records the checkpoint it used (`checkpoint.note`), along with the
size and root the seed was derived from.

**Limit.** The op log is local. A sealer that controls the log could write the
entry at `K + 1` many times and re-seal until the sample misses its
tampering. Each attempt leaves a log entry and a segment, so this kind of
grinding is visible, but it is not prevented. For adversarial settings, take
the checkpoint from a log the sealer does not control (a remote's
witness-cosigned audit log, docs/INTEGRITY.md), or keep the auditor's
`--checkpoint` from a witness.

### Sample size from a stated guarantee

The guarantee is "with confidence `c`, at most a fraction `p` of the `N`
episodes are tampered with or missing". If more than `t = floor(p * N)` are
bad, there are at least `b = t + 1` bad episodes. A uniform sample of `n`
without replacement then misses all of them with probability

    P(miss) = prod_{i=0}^{n-1} (N - b - i) / (N - i)

This is the hypergeometric probability of drawing zero bad episodes. More bad
episodes only make it smaller. The audit uses the smallest `n` with
`P(miss) <= 1 - c`, and computes it in exact integer arithmetic. `bound`
records `n`, `t`, `b` and `P(miss)`. For large `N` the sample is close to the
binomial bound `ln(1 - c) / ln(1 - p)`, rounded up, and never above it. For
`c = 0.99, p = 0.005` the binomial bound is 919. `N = 100,000` needs 913 and
`N = 1,000,000` needs 919. When `b > N` no violation is possible and the sample is empty. When
`n` reaches `N`, every episode is checked.

Sampled positions are drawn with Floyd's algorithm. Each draw is uniform, by
rejection from `SHA-256(seed || draw || attempt)`. `positions` is the digest
of the sorted positions.

### What is checked

The audit looks up each sampled episode in the **source**:

* the repository's batches (the default), which checks that the stored copy
  still matches what was sealed; or
* `--episodes FILE`, JSON Lines of stored lines. This is typically the
  training set derived from the stream and handed to a trainer. Lines are
  matched by index `i` and re-encoded canonically (sorted keys, no spaces),
  so formatting does not matter but content does.

An episode whose index is absent is `missing`. An episode whose leaf fails the
RFC 9162 inclusion proof against the signed root is `altered`; conflicting
duplicate copies also count as altered. The verdict is `pass` only when every
sampled episode passes. Up to 1,000 failures are listed by position and index.

The audit's signer must hold the pinned `auditor` role and must not hold the
`optimizer` role. Without a pinned trust bundle, the audit refuses. Every
audit is held as `ingest-audit:SEGMENT` and never released.

### Acceptance fixture

`tests/test_084_rl_acceptance.py` seals 10 segments of 1,000 episodes, which
gives 10 audit seeds. For each segment it builds 10 tampered copies: 1% of
episodes, half dropped and half altered, in shuffled order. That is 100
trials. Each copy is audited for `c = 0.99, p = 0.005`. At least 99 of the
100 trials must fail the audit, and every reported failure must be a tampered
episode. The test checks counts only, never timings.

## Proofs: `tine ingest prove`

`tine ingest prove SEGMENT --index I --json` prints a self-contained proof:

```json
{"segment": "annotation:sha256:...", "root": "sha256:...", "size": 100000,
 "position": 4711, "index": 4711, "leaf": "<64 hex>", "proof": ["<64 hex>", ...]}
```

Anyone holding the episode's stored line can check the proof with
`opentine._rl_audit.check_proof(proof, line)` or any RFC 9162 verifier
(leaf = `SHA-256(0x00 || line)`). No repository is needed. To trust the
`root`, check the segment's signature and its op log entry.

## `tine ingest segments STREAM`

This command walks the segments from the held head and re-derives everything
they claim.

| Code | Level | Meaning |
| --- | --- | --- |
| `ingest.segment-missing` | fail | A segment in the chain is unreadable, or the chain loops |
| `ingest.segment-unsigned` / `-role` / `-optimizer-key` | fail | The sealer is not a pinned runner key, or is an optimizer key |
| `ingest.policy-unpinned` | fail | No owner-pinned trust bundle: roles cannot be checked |
| `ingest.segment-chain` | fail | `seq`, `previous` or the anchor is out of order |
| `ingest.segment-batches` | fail | The batches skip, repeat or do not continue the previous segment |
| `ingest.segment-root` | fail | The root, episode count or index range does not match the batches |
| `ingest.segment-log` | fail | The op log is unreadable, or its entry `log.index` does not commit to this segment |
| `ingest.audit-unsigned` / `-role` / `-optimizer-key` | fail | The auditor is not a pinned auditor key, or is an optimizer key |
| `ingest.audit-target` | fail | The audit names another segment |
| `ingest.audit-recompute` | fail | The checkpoint, seed, bound, sample or (for a repository source) the counts do not recompute |
| `ingest.audit-failed` | fail | The audit found missing or altered episodes |
| `ingest.segment-unaudited` | advisory | The segment has no audit |
| `ingest.segment-pending` | advisory | Batches after the last segment are not sealed yet |

Advisory findings block only with `--strict`. An audit of a file source is
re-checked for everything except its counts, because the file is not in the
repository. Re-run `tine ingest audit --episodes FILE` to recheck them.

## Performance

`scripts/bench/rl_capture.py` measures ingest, seal and audit end to end for
synthetic episodes. Results and hardware are in
docs/bench/0.84-rl-capture.md. The target (1M episodes per hour) is a
reference-machine number. Tests never assert it.

## JSON

`--json` prints `tine-cli-ingest/1` (commands `ingest seal`, `ingest audit`,
`ingest prove`, `ingest segments`). The claim values follow
`opentine-ingest-segment-1` and `opentine-ingest-audit-1` in docs/schemas/.
