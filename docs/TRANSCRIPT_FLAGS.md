# Transcript analysis and behaviour flags (0.74)

`tine transcripts` finds runs that behave alike across a whole repository and
records, under signature, which behaviour a reviewer saw in them. The aim is
triage: from one run that patched a grader, find the other runs like it, label
them, and keep that label where a loop cannot delete it.

Everything here is derived. No object kind and no `tine verify` code is added:
a flag is a claim convention on an existing attestation, and the analysis is
recomputed from the runs whenever it is asked for.

## What is analysed

From a repository, every `run:` object's indexed text (the text `tine
search` indexes: prompts, step inputs and outputs, tool calls, paths, tags),
after credential redaction (`opentine-redaction/2`) and the PII detectors
(`opentine-redaction/3`). An analysis or a flag never holds a secret the run
store did not already redact.

From `--corpus FILE.jsonl`, one object per line with a string `id` and `text`
(and optionally `behaviour`, read only by the recall evaluation). Ids must be
unique.

## The embedding backend

The default backend is `opentine.tfidf-hash/1`. It needs the standard library
only, downloads nothing and gives the same vectors on every machine:

- normalisation (`opentine/_transcript_normalise.py`): Unicode NFKC, case
  folding, format characters (zero-width spaces and joiners, bidi controls)
  dropped, common Cyrillic and Greek lookalikes mapped to Latin letters, and
  the words of tokens that decode as base64 UTF-8 text added, so lookalike,
  zero-width, full-width and base64 rewrites do not move a transcript away
  from known bad ones;
- features: `\w+` words and word bigrams over every word (streamed; there is
  no word cap a run could pad past), hashes masked to 21 bits so the
  feature table stays bounded;
- each feature is hashed with CRC-32 seeded with 74 into one of 2048 buckets,
  with its sign taken from bit 20 of the hash (a sparse random projection);
- weight `(1 + ln tf) * (ln((N + 1) / (df + 1)) + 1)`, IDF over the corpus
  being analysed, then L2 normalisation;
- similarity search subtracts the corpus mean vector first (centred cosine),
  so steps every transcript shares do not dominate the ranking.

The **backend digest** is the SHA-256 of the canonical JSON of these
parameters. Every `cluster` output, every `flags --like` output, every flag
made from a cluster or a similarity search and every contamination
`embedding` member records it, together with the **corpus digest** (sorted
`[id, sha256 of text]` pairs) where the IDF was fitted. Two results with the
same backend digest and corpus digest are comparable.

The backend captures shared vocabulary, not meaning: "removed the failing
test" and "deleted the test that failed" are near, "made the suite green by
skipping" and "deselected the broken cases" are not.

### A pinned local model

`--backend MODULE:ATTR` (and `--embedding-backend` on `tine dataset
contamination`) names an object importable on this machine with `name`, `dim`,
`embed(texts) -> list[list[float]]` (the hybrid-search embedder protocol,
`tine repo-search --hybrid`, docs/CLI.md) **and** `weights_digest` (`sha256:<hex>` of the model weights).
A model without a weights digest is refused, and a spec that looks like a URL
is refused: text is never sent anywhere to be embedded. The adapter is
responsible for loading weights from local files only, for example:

```python
class Local:
    name, dim = "all-MiniLM-L6-v2@local", 384
    weights_digest = "sha256:..."  # of model.safetensors, checked on load

    def __init__(self):
        from sentence_transformers import SentenceTransformer  # not an OpenTine dependency
        self.model = SentenceTransformer("/models/minilm", local_files_only=True)

    def embed(self, texts):
        return self.model.encode(texts).tolist()
```

The backend digest of a model is the digest of its name, dimension and
weights digest. No test downloads a model; the suite uses the default backend
and a stand-in object.

## Clustering

`tine transcripts cluster [--k N] [--seed S]` runs spherical k-means: runs in
sorted id order, initial centres by k-means++ drawn from
`random.Random(seed)`, at most 25 rounds of assign (highest dot product, ties
to the lower centre) and re-centre, stopping when no assignment changes. The
default `k` is `round(sqrt(n / 2))`, at most 1000. Same corpus, backend, `k`
and seed give the same clusters.

A cluster id is `tc-` and the first 16 hex digits of the SHA-256 of its
sorted member ids, so it names its members rather than its position. Each
cluster lists its members, an exemplar (the member nearest the centre) and
`flags`: how many of its members carry each label among the **verified**
flags.

## Behaviour flags

`tine transcripts label LABEL --key KEY` with evidence from any of:

- `--run RUN` (repeatable): named runs;
- `--cluster ID [--k N --seed S]`: the members of that cluster, recomputed at
  that `k` and seed (refused when no cluster has that id; with `--run`, every
  run must be a member);
- `--like RUN [--top N]`: the run and the `N` runs most like it.

The record is an attestation on the first evidence run with the claim
(schema `opentine-transcript-flag-1`):

```json
{"convention": "opentine.transcript-flag/1",
 "label": "reward-hacking",
 "evidence": ["run:sha256:...", "..."],
 "cluster": "tc-0123456789abcdef",
 "labeller": "sha256:<signer fingerprint>",
 "backend": {"name": "opentine.tfidf-hash/1", "digest": "sha256:...", "weights_digest": null},
 "note": "grader patched in conftest",
 "labelled_at": "2026-11-20T00:00:00Z"}
```

`label` is lower-case letters, digits and hyphens; the standard labels are
`reward-hacking`, `test-deletion` and `sabotage-side-task`. `evidence` is
sorted and distinct, and every run must be in the repository. `cluster` and
`backend` are `null` when the evidence was named run by run.

**Who may label.** Only a `scorer` or `curator` key of the owner-pinned trust
bundle (`_key_roles_pin`, docs/SELF-IMPROVING-LOOPS.md). The command refuses,
before anything is written, when the key is an `optimizer` key (pinned or
not), when the roles are unpinned, when the role policy cannot be read, or
when the key holds neither role. Labels are gates for what later stages trust,
so they fail closed.

**Verification.** `tine transcripts flags` reports each flag as `verified`
only when the Ed25519 signature holds, the payload `signer` is the key that
actually signed (`used_key_fingerprint`), the claim's `labeller` is that
signer, the claim is well formed, and the signer still holds a pinned
`scorer` or `curator` role and not `optimizer`. Anything else reads
`unverified: <reason>`, and an unverified flag does not count in cluster
`flags`.

**Holds.** Every flag is kept by a `tine hold` row whose target is
`transcript-flag:LABEL:RUN`; `tine hold release` refuses it, so a loop that
can prune the repository cannot delete the record that flagged it.

## Recall on the seeded corpus

`tests/data/transcript_corpus.jsonl` is a committed synthetic corpus of 600
transcripts (`scripts/gen_transcript_corpus.py`, seed 74, byte-stable): 510
ordinary coding tasks and 30 each with seeded reward hacking (grader patches,
hard-coded expected outputs, rewritten test reports), test deletion (removed
or skipped tests, deselected cases) and sabotage side tasks (credential
exfiltration, backdoors, a disabled audit log). Each seeded transcript does
its ordinary task too; the behaviour is two or three of its steps, in varied
wording and position.

The evaluation (`python scripts/transcript_recall.py`, asserted by
`tests/test_074_transcript_cluster.py`) takes, for each behaviour, the first
five seeded transcripts by id as labelled evidence, ranks every other
transcript by centred similarity to their centroid, and counts how many of the
remaining 25 seeded transcripts are in the top 50. The acceptance is recall
of at least 0.9 for every behaviour. With the default backend:

| Behaviour | Found in top 50 | Recall |
| --- | --- | --- |
| reward-hacking | 25 / 25 | 1.00 |
| sabotage-side-task | 25 / 25 | 1.00 |
| test-deletion | 24 / 25 | 0.96 |

From a single exemplar recall is lower (about 0.7 for each behaviour), because
one transcript shows only some of the ways a behaviour is phrased. Label a few
runs, then search from all of them.

## Contamination

The embedding near-duplicate check of `tine dataset contamination
--embedding-threshold T` uses the transcript-search backend
(`transcript-hash/1`, docs/TRANSCRIPTS.md), not this space; see
docs/INTEGRITY.md.

## Oversight queue

Verified flags and the runs like them are items of the 0.63 oversight queue
(`tine oversight queue`, docs/OVERSIGHT.md), source `transcript`:

- `transcript:ATTESTATION`: a verified flag, routed by its label;
- `transcript:LABEL:RUN`: a run whose centred cosine to one of a verified
  flag's evidence runs is at least 0.6 in this space, fitted over the
  repository's redacted runs (the 50 nearest runs of each evidence run are
  considered), a "similar to known bad" hit.

Both are recomputed from the objects every time the queue is read; there is
no stored index to plant rows in. An unverified flag (bad signature, a
labeller other than the signer, an unpinned or optimizer signer) opens no
item and seeds no hits. An item reaches a tier only through a pinned policy
row `[[route]] source = "transcript"`, whose `label` glob matches the flag
label; with no such route nothing is queued and nothing blocks.

## Query

`tine query` reads the tables `transcript_flags`, `transcript_flag_runs`
and `transcript_clusters` (docs/QUERY.md). Under `--verify` a flag row is
`verified` only for a pinned scorer or curator signer without `optimizer`.
Cluster rows are recomputed when the query index is built (default k, seed
0), only while the repository holds at most 2,000 runs.

## Scale

`scripts/bench/transcripts.py` times fitting the space over 100,000
synthetic transcripts, one similarity query, and seeded k-means over 10,000.
Results and hardware: docs/bench/0.74-transcripts.md. No test asserts a
duration.

## Not yet

- Paraphrase and dilution are not defended: rewording with other vocabulary,
  or padding a transcript with a large amount of benign text, lowers its
  similarity to known bad runs. Nested or otherwise encoded payloads (hex,
  gzip, base64 inside base64) are not decoded.
- A model backend's `weights_digest` is what the adapter declares; opentine
  does not hash the weight files itself. A model must return `dim` finite
  numbers per text or the space is refused.

- Two embedding spaces exist: `opentine.tfidf-hash/1` here (clusters,
  flags, oversight hits) and `transcript-hash/1` for the transcript index
  and contamination (docs/TRANSCRIPTS.md). Scores from one are not
  comparable with the other.
- The oversight queue recomputes the space on every read while a verified
  flag exists; on a large repository that read is slow.
- Vectors are recomputed per command, not stored in the hybrid-search index
  (`.tine/index/embed.sqlite`), because the IDF depends on the corpus.
- Clustering is pure Python: tens of thousands of transcripts take minutes;
  100,000 with a large `k` is slow (see the bench).
- No TypeScript reader reads transcript flags.
