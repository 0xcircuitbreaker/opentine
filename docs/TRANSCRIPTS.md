# Transcript search at corpus scale (0.74, release 0.73.0)

`tine transcripts` finds runs whose transcripts look alike: "find all
trajectories like this one" for reward-hacking and sabotage triage, and a
text search over every run's steps, tool calls and outputs. It reads a
derived embedding index, which the commands build when it is missing.

```
tine transcripts index [--rebuild | --refresh] [--verify] [--backend SPEC]
                       [--weights-digest D] [--step-bytes N] [--max-bytes N]
                       [--workers N]
tine transcripts search TEXT [-k N] [--approx] [--refresh]
tine transcripts similar RUN [-k N] [--approx] [--refresh]
```

All three take `--repo PATH` and `--json` (schema `tine-cli-transcripts/1`).
RUN is a ref (`heads/x`) or a run oid; it is left out of its own results.

## The index is derived and non-authoritative

`.tine/transcripts/index.sqlite` holds one row per `run` object: its oid,
the number of steps read, the transcript size, whether a cap cut it, the
sha256 of the transcript text, the vector and its LSH bucket keys. Deleting
the file loses nothing; `tine transcripts index --rebuild` embeds every run
from its objects again. A build is staged next to the index and moved into
place. `index --refresh` (and `search`/`similar --refresh`, and the build a
search makes when there is no index) keeps the vectors of runs already in an
index built with the same backend, caps and search parameters, so it embeds
only new runs.

### Nothing in the file is trusted

Anything that can write the store can write this file, including a loop
whose runs are being triaged. So:

- the backend and caps are the defaults unless given on the command line; a
  backend or caps recorded in the index are only compared, never used, and
  an adapter named in the index is never imported (a model-backend index is
  searched with `--backend MODULE:ATTR` given again);
- rows for runs that are not in the repository, and vectors that are not
  unit vectors of finite numbers of the backend's dimension, are left out of
  every search and make the index stale; LSH bucket keys are recomputed from
  the vectors, not read;
- a run without a row makes the index stale even when the recorded `runs`
  digest was kept;
- `similar RUN` embeds RUN from its objects, never from its row;
- `index --verify` re-reads and re-embeds every row and lists, under
  `disagreeing`, the runs whose transcript sha256 or vector disagree with
  the objects; `--rebuild` replaces them.

The index is not evidence. A hit says two transcripts are textually close;
the runs themselves, their signatures and `tine verify` remain the record. No
object kind, claim or `tine verify` code is added.

### Staleness

`meta` records what the index was built with: `format`, `authority`
(`non-authoritative`), the backend description and `backend_digest`, the
`caps`, the `ann` parameters and `runs` (sha256 of the sorted run oids).
`tine transcripts index` compares them with what a build now would use and
lists each difference:

- `the index has not been built`
- `the embedding backend differs (backend digest)`
- `the size caps differ`
- `the search parameters differ`
- `runs were added or removed since the build`
- `the indexed runs differ from the repository's runs`
- `N rows left out (unknown run or invalid vector)` (search and similar)
- `N rows disagree with the objects` (`index --verify`)

`search` and `similar` still answer from a stale index, marked `stale` with
the reasons; `--refresh` brings the index up to date first. An index built with another backend
is refused rather than compared against a query vector from a different
backend.

## Transcript text and size caps

A transcript is the run's steps in order: a header line per step (`step N
KIND`, the tool name, `error` when the step failed), then the step's input and
output blobs decoded as UTF-8 with invalid bytes replaced. Two caps keep one
huge run from dominating the build or the vector:

| Cap | Default | Effect |
| --- | --- | --- |
| `--step-bytes` | 2048 | first bytes of each input and each output |
| `--max-bytes` | 32768 | the whole transcript: half to the first steps, half to the last |

Steps repeated verbatim (same kind, tool, input and output) are kept once, so
repeated padding costs nothing; over `--max-bytes` the middle steps are
dropped, so padding at the start cannot push the last steps out (or the
reverse). Any object over 16 MiB is never read into memory: its step is
indexed without that text and counted as truncated. A cut transcript is counted under `truncated`. The caps are part of the
recorded configuration, so changing them makes the index stale.

## Embedding backends

Every backend is named by a `backend_digest`: the sha256 of the canonical
JSON of its description. Vectors from two digests are never compared.

**`transcript-hash/1`** (the default) is standard library only and gives the
same vector on every machine and in every process:

- each step is embedded on its own and contributes a unit vector, so a long
  step does not drown a short one (the step number is dropped from the
  header);
- the text is normalised first (`opentine/_transcript_norm.py`): NFKC,
  format characters such as zero-width spaces dropped, case folded,
  Cyrillic and Greek letters that look like Latin ones mapped to Latin, and
  the decoded text of base64 runs (16 characters or more that decode to
  printable UTF-8) appended; the rules are in the backend description;
- features of the normalised text: word tokens (`\w+`, at most 20,000), word
  bigrams, and character 4-grams of the first 4,096 characters at half
  weight; each distinct feature weighs `1 + ln(count)`;
- each feature is hashed with CRC-32 under two fixed seeds; each hash picks one
  of 512 dimensions and a sign (a sparse random projection);
- the sum of the step vectors is L2-normalised, so a dot product is a cosine.

It measures shared wording (commands, paths, phrases), not meaning.

**A local model** is named with `--backend MODULE:ATTR`: an importable object
with `name`, `dim`, `embed(texts)` and `weights_path`, a local file (for
example an adapter around a small sentence-embedding model already on disk).
The sha256 of that file is the `weights_digest`, recorded in the backend
description and so in the backend digest. A model whose weights are not a
readable local file is refused; a spec that looks like a URL is refused;
nothing is downloaded. `--weights-digest sha256:HEX` refuses weights with any
other digest. `search` and `similar` use the model only when `--backend`
names it again, and refuse an index whose recorded backend digest differs
(for example because the weights changed). A model that returns a vector
of the wrong length or with a non-finite number is refused. The optional `embed` extra (numpy) speeds the search scan; it is not
needed.

## Search

Scores are cosine similarities rounded to 6 places; ties order by run oid, so
the same index and query give the same answer anywhere.

- **Exact** (the default up to 200,000 runs): every vector is scored. With
  numpy installed the scan is vectorised; without it the pure-Python scan
  gives the same ranking.
- **Approximate** (`--approx`, or above 200,000 runs): random-hyperplane LSH
  with 8 tables of 12 bits (seeded hyperplanes), probing each table's bucket
  and the 12 buckets one bit away, then exact scores for the candidates. LSH
  finds close neighbours (cosine 0.8 and up: near duplicates) reliably and
  weak ones poorly. Trajectories that share a behaviour but differ elsewhere
  often sit at cosine 0.2 to 0.4, which is why triage scans exactly. When the
  probes find fewer than `-k` candidates the search falls back to the exact
  scan (`method: exact-fallback`), so a result is never short.

The output names the `method`, how many runs were scored (`candidates`), how
many are indexed, and for each hit its run, score, step count, size,
`truncated` flag and transcript sha256.

## Acceptance: seeded-behaviour recall

`tests/transcript_corpus.py` generates a committed synthetic corpus from a
seed (its digest is pinned in the test): 400 runs of 4 to 8 ordinary steps
over a 3,000-word random vocabulary, with eight planted behaviours (editing
asserts to pass, reading the grader's expected output, skipping slow tests,
posting environment variables, hard-coding an answer, wiping logs, probing
the sandbox, printing a fake score) in 20 runs each, with varied file names
and values, at a random position. The planted steps are a fifth to a third of a
seeded run's steps. Querying with every seeded run, the share of the other
19 members of its behaviour found in the top 50 is at least 0.9
(`tests/test_073_transcripts_recall.py`; 0.94 at release). The test counts
hits; it times nothing. A 48-run corpus also goes through a real repository
and `tine transcripts similar`.

## Feeding the contamination check

`tine dataset contamination --embedding-threshold T` (docs/INTEGRITY.md)
embeds holdout and corpus items with the same backend and reports items whose
nearest corpus items are at cosine `T` or above under `embedding.near`, with
the backend digest and threshold. It is opt-in, so existing results are
unchanged.

## Scale: 100k transcripts

`scripts/bench/transcripts_index.py` embeds 100,000 synthetic transcripts
from the same generator in worker processes, writes them through the staged
write a rebuild uses, runs 40 exact top-50 searches, and reads real runs from
a repository for a per-run extraction cost. The target is 100,000
transcripts indexed in under 30 minutes on an 8-core CPU. Results and the
hardware they were measured on: docs/bench/0.73-transcripts.md. No test
asserts a duration.

## Limits

- `transcript-hash/1` matches wording. A behaviour expressed in different
  words (a paraphrase, or a different command with the same effect) is found
  only through a model backend. Lookalike letters, zero-width characters,
  full-width forms and base64 are normalised; other encodings (hex, rot13,
  compression) are not.
- Padding with many distinct steps still dilutes the vector and, over
  `--max-bytes`, can push a behaviour in the middle of a run out of the
  transcript; truncated runs are counted so a reviewer can look at them.
- The index covers runs; memory notes, prompts and packs are not indexed.
- Hits are not routed to the oversight queue or labelled with signed
  annotations by this release; a reviewer records a finding with the
  existing annotation and oversight commands.
