# SQL query over a derived index (0.65)

`tine query "SELECT ..."` answers questions across a whole repository -- cost
by model, how often a monitor blocked, an eval's pass rate -- with one
read-only SQL statement. It reads a derived SQLite index, not the repository
itself.

The index is **non-authoritative**. It is a cache built from the repository's
objects and files, every row carries the `oid` it was read from, and deleting
it loses nothing: `tine query index --rebuild` writes it again. The objects
stay the record. To rely on a row, run the query with `--verify`, which goes
back to each row's object and checks it.

Nothing here adds an object kind, a signed document or a `tine verify` code.
The index format is not frozen (docs/FREEZE.md) and its tables may change in
any release. It uses `sqlite3` from the Python standard library; nothing new
is installed.

## Commands

| Command | What it does |
| --- | --- |
| `tine query SQL [--repo PATH] [--limit N] [--max-steps N] [--refresh] [--json]` | Runs one read-only statement; builds the index first when it is missing |
| `tine query SQL --verify [--strict]` | Also re-checks the object behind each returned row: `verified`, `unverified` or `failed` |
| `tine query index [--repo PATH] [--check] [--json]` | Reports where the index is, its row counts and whether it is stale (`--check` compares object ids even when the cheap check matches) |
| `tine query index --rebuild [--evals DIR]... [--experiments DIR]...` | Rebuilds the index; `--evals` adds eval folders and `--experiments` folders of experiment manifests and reproduce reports to read, and both are remembered for later rebuilds |

`--json` prints `tine-cli-query/1` (docs/schemas/tine-cli-query-1.schema.json).
The text form starts with a line saying the index is derived and
non-authoritative, then prints tab-separated rows.

Exit codes: 0 on success; 1 when `--verify` finds a `failed` row (with
`--strict`, also an `unverified` one) or the statement is refused or invalid.

## Tables

The index lives at `.tine/query/index.sqlite`.

| Table | One row per | Columns |
| --- | --- | --- |
| `runs` | `run` object | `oid`, `status`, `model`, `created_at`, `steps`, `source_run_id` |
| `steps` | step of a run (`event` object) | `oid` (the event), `run`, `seq`, `kind`, `model`, `provider`, `cost`, `duration`, `time_unix`, `input_tokens`, `output_tokens`, `error` |
| `costs` (view) | step | `oid`, `run`, `model`, `provider`, `cost`, `input_tokens`, `output_tokens` |
| `monitor_verdicts` | `opentine.monitor-verdict/1` attestation | `oid`, `target`, `signer`, `signed`, `monitor`, `session`, `tool`, `action`, `score`, `threshold`, `enforced`, `mode`, `decided_by`, `decided_at` |
| `oversight_decisions` | `opentine.oversight-decision/1` annotation | `oid`, `item`, `anchor`, `previous`, `signer`, `signed`, `decision`, `human`, `decided_at` |
| `lineage_variants` | record in `.tine/lineage/variants/` | `oid`, `variant`, `signer`, `signed`, `loop` |
| `lineage_edges` | parent of a lineage variant | `oid` (the child's record), `child`, `parent` |
| `evals` | `tine-eval-verdict/1` line | `oid`, `source`, `line`, `eval`, `dataset`, `item`, `run`, `scorer`, `score`, `threshold`, `passed`, `signer`, `signed`, `created_at` |
| `experiments` | `opentine.experiment-manifest/1` file | `oid`, `source`, `experiment`, `signer`, `signed`, `model`, `model_version`, `result_rows`, `passed_rows`, `usd`, `created_at` |
| `experiment_results` | result row of a manifest | `oid` (the manifest), `experiment`, `id`, `verdict`, `path`, `score`, `passed` |
| `reproductions` | `opentine.reproduce-report/1` file | `oid`, `source`, `experiment`, `manifest`, `signer`, `signed`, `sample`, `agreed`, `disagreed`, `verdict`, `tolerance`, `repeats`, `created_at` |
| `sabotage_tasks` | `opentine.sabotage-task/1` attestation | `oid`, `target` (the run), `signer`, `signed`, `task`, `class`, `main_task`, `main_score`, `main_passed`, `side_task`, `attempted`, `achieved`, `verdicts` (linked monitor verdicts), `at` |
| `elicit_links` | `opentine.elicit-link/1` file in `.tine/elicit/links/` | `oid`, `source`, `task`, `safety_relevant`, `condition`, `kind`, `cue`, `monitored`, `model`, `model_version`, `signer`, `signed`, `items`, `mean_score`, `attempts`, `tokens`, `usd`, `gpu_hours`, `created_at` |
| `elicit_items` | item score of an elicitation link | `oid` (the link), `task`, `condition`, `id`, `score` |
| `history_merges` | `opentine.history-merge/1` attestation | `oid`, `target` (the run), `signer`, `signed`, `ref` (the merge target ref), `base`, `sides` (JSON list of side digests), `merged`, `conflicts` (count). Under `--verify` a row is `verified` only for a pinned `policy` signer without `optimizer`; `tine merge-history verify` re-runs the merge itself |
| `sandbox_policies` | `opentine.sandbox-policy/1` attestation | `oid`, `target` (the run), `signer`, `signed`, `policy_digest`, `recorded_at`. Under `--verify` a row is `verified` only for a pinned `runner` signer without `optimizer`; `tine containment check` decides a mismatch |
| `containment_findings` | `opentine.containment-finding/1` attestation (advisory) | `oid`, `target` (the run), `signer`, `signed`, `category`, `step`, `detail`, `evidence_digest`, `found_at` |
| `budget_ledger` | `opentine.budget-ledger/1` annotation | `oid`, `previous`, `signer`, `signed`, `subject`, `entry` (`spend`, `policy` or `flag`), `run`, `cost`, `tokens`, `code` (a flag's code), `at`. Under `--verify`: a pinned `runner` or `policy` signer without `optimizer`; `tine budget status` decides |
| `weight_custody` | `opentine.weight-custody/1` attestation (0.72) | `oid`, `target`, `signer`, `signed`, `artifact`, `event`, `seq`, `prev`, `location`, `digest`, `size`, `run`, `tags` (comma-separated), `recorded_at`. Every custody attestation in the store, held or not. Under `--verify`: a pinned `runner` or `policy` signer without `optimizer`; `tine custody check` decides |
| `organism_records` | `opentine.organism-tag/1`, `-approval/1` or `-untag/1` attestation (0.72) | `oid`, `target`, `signer`, `signed`, `record` (`tag`, `approval` or `untag`), `artifact`, `run` (an approval's run), `at`. Under `--verify`: a pinned `policy`, `curator` or `approver` signer without `optimizer`; `tine organism status` decides |
| `transcript_flags` | `opentine.transcript-flag/1` attestation (0.74) | `oid`, `target`, `signer`, `signed`, `label`, `evidence` (sorted run ids, comma separated), `cluster`, `labeller`, `labelled_at`. Under `--verify`: a pinned `scorer` or `curator` signer without `optimizer`; `tine transcripts flags` decides |
| `policy_admissions` | `opentine.policy-admission/1` attestation (0.75) | `oid`, `target`, `signer`, `signed`, `subject` (the run the claim names), `decision` (`allow` or `deny`), `policy` (name), `policy_digest`, `input_digest`, `at` (self-claimed). Every admission in the store, held or not. Under `--verify`: a pinned `policy` signer without `optimizer`; `tine policy show RUN --policy P` decides |
| `ingest_policies` | `opentine.ingest-policy/1` annotation (0.77) | `oid`, `target` (the stream anchor), `signer`, `signed`, `stream`, `rate`, `seed_source`, `redact`, `captures` and `drops` (the policy's `capture` and `drop` kinds, comma joined), `policy_digest`, `issued_at`. Under `--verify`: a pinned `policy` signer without `optimizer`; `tine ingest verify` decides |
| `ingest_batches` | `opentine.ingest-batch/1` annotation (0.77) | `oid`, `target`, `signer`, `signed`, `stream`, `seq`, `previous`, `policy`, `policy_digest`, `first_index`, `next_index`, `received`, `captured`, `dropped`, `dropped_kind`, `dropped_rate`, `at`. Every batch in the store, held or not (a batch that lost a head race is listed until `tine gc`). Under `--verify`: a pinned `runner` signer without `optimizer`; `tine ingest verify` decides whether the chain holds |
| `transcript_flag_runs` | the same attestation, one row per evidence run (0.74) | `oid` (the flag), `run`, `label`; join with `runs` on `run = runs.oid` |
| `transcript_clusters` | the runs, clustered when the index is built (0.74) | `oid` (the run), `cluster` (`tc-...`), `size`, `exemplar`, `k`, `seed`, `backend_digest`: seeded k-means (default k, seed 0) over the `opentine.tfidf-hash/1` space of the redacted runs; empty above 2,000 runs (use `tine transcripts cluster`). Content-derived, never `verified` |
| `dataset_versions` | `opentine.dataset-version/1` attestation (0.75) | `oid`, `target`, `signer`, `signed` (1 only when the offline check holds: signature, signer and curator binding, claim shape and members digest), `name`, `version`, `previous`, `selection`, `members` and `excluded` (counts), `mode`, `justification`, `members_digest`, `curator`, `created_at`. Under `--verify`: a pinned `curator` signer without `optimizer`; `tine dataset versions` decides |
| `dataset_members` | the same attestation, one row per member run (0.75) | `oid` (the version), `run`, `content` (the member's chunk digest); join with `runs` on `run = runs.oid` |
| `dataset_tombstones` | `opentine.dataset-tombstone/1` attestation (0.75) | `oid`, `target`, `signer`, `signed` (1 only when the signature holds, the signer is the claim's `curator`, the record is on the tombstoned run and the claim is well formed), `dataset`, `version` (the version that held the run), `run`, `withdrawal`, `curator`, `at`. Under `--verify`: a pinned `curator` signer without `optimizer` |
| `uplift_suites` | `opentine.uplift-suite/1` attestation (0.73) | `oid`, `target`, `signer`, `signed`, `digest` (the suite digest), `name`, `version`, `tasks` (count), `at`. Under `--verify`: a pinned `scorer` or `eval` signer without `optimizer` |
| `uplift_records` | `opentine.uplift-record/1` attestation (0.73) | `oid`, `target`, `signer`, `signed`, `record` (`baseline`, `run` or `speed`), `suite`, `task`, `subject`, `condition`, `success` (1, 0 or null), `minutes`, `perceived_minutes` (decimal strings), `generation` (the lineage generation the record names), `at`. Every uplift attestation in the store, held or not. Under `--verify`: a pinned `scorer` or `eval` signer without `optimizer`; `tine uplift` decides |
| `trend_points` | variant of the lineage folder, as `tine trends` reads it (0.73) | `oid` (the variant's lineage record, so it joins `lineage_variants`), `variant`, `signer`, `signed` (of the lineage record), `loop`, `generation` (depth in the 0.58 parent graph), `parents` (comma-separated), `n`, `score`, `pass_rate`, `cost_per_success` (decimal strings, null when no items), `flags` (comma-separated lineage codes), `withheld` (1 when the eval evidence is missing or its signers are not pinned). Point estimates only: intervals, horizons and regressions stay in `tine trends`. `--verify` re-derives the point from the lineage folder and fails it on any difference. The index is stale when the pinned key roles change |
| `meta` | key | `authority` (always `non-authoritative`), `format`, `counts` and what the index was built from |

`oid` is the object id for repository objects. Lineage records and eval
verdicts live in files, so their `oid` is `sha256:` of the record's bytes (an
eval verdict: of its line, without the newline). `signed` is 1 when the
record's Ed25519 signature verifies against the key it names; it says nothing
about whether that key is trusted.

Eval verdicts are read from the lineage folder's `evals/*.jsonl` and from the
`verdicts.jsonl` of each folder given with `--evals DIR`. A line that is not
JSON, or is nested deeper than 200 levels, is skipped.

Experiment manifests and reproduce reports (docs/EXPERIMENTS.md) are read from
every `*.json` under `.tine/experiments/` and under each folder given with
`--experiments DIR`; other JSON files there are skipped. Their `oid` is the
document digest (signature included), the same digest a report names in its
`manifest` field, so `reproductions.manifest = experiments.oid` joins a report to
its manifest. A result row shares its manifest's `oid` and adds `id`; with
`--verify`, a row that carries `id` is checked against that result row of the
manifest file, and one without it against the manifest. A manifest or report is
`verified` when the file still has that digest, the signature holds and the
signer has a pinned role; a report signed by a key that holds `optimizer` is
`unverified`. Changing an experiment file makes the index `stale`
("an experiment folder changed"). Index rows are not `tine experiment check`:
run that for the result-mismatch and report checks.

Sabotage task records (docs/SABOTAGE.md) are read from the object store; their
`signed` is 1 only when the signature verifies and the record's `signer` names
the key that signed it. Elicitation links (docs/ELICITATION.md) are read from
`.tine/elicit/links/`; their `oid` is the record digest and an item row shares
it and adds `id`. With `--verify`, both are `verified` only when the signer
holds a pinned `scorer` or `eval` role (elicitation links also accept
`verdict`) and not `optimizer`. Changing an elicitation record makes the index
`stale` ("the elicitation folder changed"). The rows carry no findings: run
`tine elicit report` and `tine sabotage report` for the advisory statistics.

## Read-only

A statement cannot change anything. The index is opened read-only, `PRAGMA
query_only` is on, and an authorizer allows only `SELECT`, column reads,
functions and recursive CTEs. These are refused with `query.refused`:
`INSERT`, `UPDATE`, `DELETE`, `CREATE`, `DROP`, `ALTER`, `ATTACH`, `DETACH`,
every `PRAGMA`, transactions, `VACUUM`, `REINDEX` and `load_extension`. One
statement per call (`SELECT 1; DELETE ...` is refused).

Each statement may run at most `--max-steps` thousand SQLite virtual-machine
steps (default 1,000,000), then stops with `query.too-many-steps`. The limit
counts work, not time, so the same statement stops at the same place on
every machine. `--limit` (default 1000) caps the rows returned; `truncated`
says when more were left. A string or blob longer than 1,000,000 bytes stops
the statement with `query.too-large` (`SELECT randomblob(500000000)` would
otherwise allocate it), and a result that names a column twice is refused
with `query.duplicate-column`, so every row has one `oid`.

## Staleness

The index records what it was built from. Before each query it is compared
with the repository:

- a stat fingerprint of the object store (the modification times of the
  object folders, the names and sizes of the packs), and when that differs,
  the sorted list of object ids, so a repack that moves objects without
  changing them does not count;
- a digest of the lineage folder;
- a digest of the remembered eval folders' verdict files.

A stale index still answers, with `"stale": true` and the reasons, so a large
repository is never rebuilt without being asked. `--refresh` rebuilds a stale
index before the query; a missing index is always built.

## `--verify`

For each returned row that has an `oid` column, `--verify` reads the source
again and derives the row it would index now:

| Status | Meaning |
| --- | --- |
| `verified` | the source is intact, gives the values the row shows, its Ed25519 signature verifies, and its signer holds the role the table needs in the owner-pinned key roles (docs/SECURITY_MODEL.md, `tine keys`): `scorer` for `evals`, `monitor` for `monitor_verdicts`, `approver` for `oversight_decisions`, any role for lineage records; a signer that also holds `optimizer` never verifies the first three |
| `unverified` | intact and consistent, but unsigned (runs and steps are content-addressed, not signed), or signed by a key without that role, or the row has no `oid` |
| `failed` | the object or record is missing or changed, its signature does not verify, or the index row disagrees with what the source gives |

Only columns named like an index column are compared. `SUM(cost) AS total`
is not checked; `cost` is. Roles come only from the owner-pinned trust
bundle: a `key-roles.toml` without a pinned bundle gives no roles, so its
signers are `unverified`. Columns that place a row are checked too: a step's
`run`/`seq` must hold that step in the run object, an eval row's `run` must
match its verdict, and an eval row's `source` must be one of the indexed eval
files (a planted path is `failed`, not read).

`--verify` checks rows, not aggregates. An edited index answers an
aggregate (`AVG(score)`) with whatever the file holds, and staleness only
compares the index's own `meta` with the repository, so an index edited
together with its `meta` is not reported stale. Read a number you will act
on as rows with `--verify --strict`, or rebuild with `--rebuild` first.

`unverified` is advisory and does not change the exit code unless `--strict`
is given (D12). `failed` exits 1.

## Examples

```sh
tine query "SELECT model, SUM(cost) AS total, SUM(input_tokens) AS tokens_in
            FROM costs GROUP BY model ORDER BY total DESC"
tine query "SELECT oid, action, session FROM monitor_verdicts
            WHERE action = 'block'" --verify
tine query "SELECT eval, AVG(passed) AS pass_rate, COUNT(*) AS n FROM evals GROUP BY eval"
tine query "SELECT e.parent, COUNT(*) AS children FROM lineage_edges e GROUP BY e.parent"
tine query index --rebuild --evals evals/nightly
```

## Scale

`scripts/bench/query_index.py` writes a synthetic one-million-run index and
times typical aggregate queries; it also stores real runs and rebuilds from
them to measure the cost of reading objects. The recorded results are in
docs/bench/0.65-query.md. Tests count rows and steps; none asserts a
duration.
