# Batched streaming ingest (0.77)

Large episode streams, such as RL training rollouts, produce far more events
than any reviewer reads. `tine ingest` takes them in batches, keeps what a
signed sampling policy says to keep, and records for every batch what was
captured and what was dropped, so an auditor can check that nothing was
dropped, reordered or replayed outside the policy.

No new object kinds: the policy and every batch are claim conventions in the
`value` of an existing `annotation` object on the stream's anchor blob
(`{"convention": "opentine.ingest-stream/1", "stream": NAME}`). `tine verify`
gains no new codes; the codes below are `tine ingest verify` findings.

## Quick start

```sh
tine ingest policy --stream rl-train --rate 0.1 --drop debug --key policy.key
tine ingest --batch rollout-0001.jsonl --stream rl-train --key runner.key
tine ingest verify rl-train
```

A batch is JSON Lines, one object per line. An event's kind is its `kind`
field, else its `type` field, else `event` (`[A-Za-z0-9][A-Za-z0-9._:/-]*`, at
most 64 characters). Lines are parsed with a nesting bound; a line that is not
a JSON object refuses the whole batch.

## Sampling policy: `opentine.ingest-policy/1`

```json
{"convention": "opentine.ingest-policy/1", "stream": "rl-train",
 "capture": ["*"], "drop": ["debug"], "rate": 0.1,
 "seed_source": "random", "seed": "<64 hex>", "redact": true,
 "issued_at": "2027-01-15T08:00:00Z"}
```

* `capture`: `["*"]` (every kind) or the kinds to keep; `drop`: kinds always
  dropped.
* `rate`: the share of the remaining events kept, in (0, 1].
* `seed`: fixed before any event is seen. `seed_source` is `operator` when
  `--seed` gave it and `random` when it was drawn from the OS.
* `redact`: run the stored-blob credential scrubber over each batch's captured
  events before it is signed (default). `--no-redact` turns it off for streams
  of plain numeric steps; the signed policy then says so.

The event at stream index `i` (counted from 0 over every event the stream ever
received, kept or not) with kind `k` is captured when `k` is captured, is not
in `drop`, and `u < rate`, where `u` is the first 8 bytes of
`SHA-256(seed || stream || 0x00 || decimal(i))` read as a fraction of 2^64.
The decision depends only on the signed policy and the index, so it is
recomputed for every stored event. The policy digest is SHA-256 over the
claim's canonical JSON.

**Who may sign it.** The signer is the key that signed (`used_key_fingerprint`),
never a field a writer fills in. A policy counts only when that key holds the
`policy` role in the owner-pinned trust bundle (`key-roles.toml` signed into
`trust-bundle.note`, docs/SELF-IMPROVING-LOOPS.md) and no `optimizer` role. With
no pinned bundle, verification fails closed (`ingest.policy-unpinned`).

## Batches: `opentine.ingest-batch/1`

```json
{"convention": "opentine.ingest-batch/1", "stream": "rl-train", "seq": 41,
 "previous": "annotation:sha256:...", "policy": "annotation:sha256:...",
 "policy_digest": "sha256:...", "first_index": 410000, "next_index": 420000,
 "received": 10000, "captured": 1003, "dropped": 8997,
 "dropped_by": {"kind": 12, "rate": 8985}, "input_sha256": "sha256:...",
 "events": "{\"e\":{...},\"i\":410007,\"k\":\"step\"}\n...", "at": "2027-01-15T08:00:03Z"}
```

`events` holds one line per captured event (sorted keys, no spaces).
`input_sha256` is the digest of the batch exactly as received, so whoever
keeps the raw stream can match it. The annotation's `previous_id` is the
previous batch, so batch ids form a hash chain.

**Durability.** A batch is written inside one write batch
(`opentine.repository._write_batch`): one durability point per batch. The
stream's held head (`ingest-head:STREAM`) moves only after the batch is
durable, by compare and swap, so two writers cannot fork the chain: the
second fails with `moved while this batch was written; retry` and its
unreferenced batch is reclaimed by `tine gc`. Policies are held as
`ingest-policy:STREAM`. Neither hold is ever released (`tine hold release`
refuses both), and the held head keeps every batch reachable through the
chain, so deleting a ref or file hides nothing.

## `tine ingest verify`

| Code | Level | Meaning |
| --- | --- | --- |
| `ingest.batch-unsigned` | fail | a batch signature does not verify against its recorded signer |
| `ingest.batch-missing` | fail | a batch in the chain is missing or unreadable |
| `ingest.batch-malformed` | fail | a count is not an integer |
| `ingest.batch-links` | fail | `previous_id` or the target disagrees with the claim |
| `ingest.chain-order` | fail | `seq` or `first_index` does not follow the previous batch (a drop, reorder or replay) |
| `ingest.chain-cycle` | fail | the chain loops |
| `ingest.counts` | fail | captured + dropped, the index range, `dropped_by` or the stored events do not add up |
| `ingest.events-malformed` | fail | `events` is not JSON Lines of objects |
| `ingest.events-order` | fail | stored indexes are not increasing inside the batch's range |
| `ingest.sampling` | fail | a stored event is one the policy drops |
| `ingest.sampling-hidden` | fail | an index the policy keeps is not stored and is not covered by the claimed kind drops, or more rate drops are claimed than the seed allows (with `capture: ["*"]` and no `drop`, every kept index must be stored) |
| `ingest.policy-switch` | fail | a batch names a policy issued no later than the one its predecessor used (policy shopping) |
| `ingest.batch-role` | fail | the batch signer does not hold the pinned `runner` role |
| `ingest.batch-optimizer-key` | fail | an optimizer key signed the batch |
| `ingest.policy-digest` | fail | the batch names another policy digest |
| `ingest.policy-missing` | fail | no held policy, or the named policy is unreadable |
| `ingest.policy-malformed` | fail | the policy claim is not valid |
| `ingest.policy-not-held` | fail | the named policy is not held for the stream |
| `ingest.policy-stream` | fail | the policy belongs to another stream |
| `ingest.policy-unsigned` | fail | the policy signature does not verify |
| `ingest.policy-unpinned` | fail | no owner-pinned trust bundle |
| `ingest.policy-optimizer-key` | fail | an optimizer key signed the policy |
| `ingest.policy-role` | fail | the signer does not hold the pinned `policy` role |
| `ingest.duplicate-input` | advisory | two batches received identical bytes (blocks only with `--strict`) |

What verification cannot see: the content of dropped events (only their
count and reason are recorded), and a writer that withholds a batch before
signing it. The rate decision is checked for every stored event; whether the
right number of events was dropped by rate is the writer's signed count.

The walk reads the chain once backwards for ids and once forwards to check,
so a long stream never sits in memory whole.

## The loopback endpoint

`tine ingest serve --stream NAME --key KEY` listens on 127.0.0.1 only.
`POST /v1/ingest` with a JSON Lines body appends one batch and answers its
summary; `GET /v1/ingest` answers the held head. Bodies over `--max-bytes`
are refused with 413 before they are read, and appends are serialized.

## Packs on object storage for `tine serve`

`TINE_REMOTE_PACK_STORE=s3://<bucket>[/<prefix>]` (or `file://<dir>`) makes
`tine serve` keep each tenant's objects as packs rather than one key per
object. Each push lands as one pack, the same `TINELP1` format local
repositories use, sealed per tenant:

```
<tenant>/packs/<sha256>.tpk    sealed pack body, named by the plain body's SHA-256
<tenant>/packs/<sha256>.tidx   sealed body size + pack index, written after the body
```

* **Atomic upload with a digest check.** A body larger than one part (8 MiB)
  is a multipart upload; every part carries its SHA-256 checksum, and the
  completed upload's ETag must equal the one computed locally, or the upload
  is removed and the write fails. A smaller body is one `PutObject` with the
  same checks. Readers re-hash each body against its name and every object
  against its id.
* **Never overwrite.** Every upload is sent with `If-None-Match: *`; an
  existing name is never replaced (the filesystem backend links into place,
  which refuses an existing name).
* **Listing races.** The index is written last. A listed index whose body is
  not there yet (or any more) is skipped and looked for again on the next
  miss; a read that loses a race with a delete re-reads the listing once.
* **Push, pull, purge and fsck** use the same index: `install_pack` writes the
  whole push as one pack, `fetch_pack` reads through it, a purge `delete`
  rewrites the object's pack without it (new name first, then the old index
  and body go) and refuses held objects, and `tine ingest packs --tenant T`
  re-reads every pack and object. A purge treats pack-stored objects like the
  WORM store's: it keeps no per-object age, so it defers instead of
  purging early.
* **Buckets with SSE-KMS** return ETags that are not MD5s; construct
  `S3PackBlobs(..., check_etag=False)` there (the per-part SHA-256 checksums
  and the read-side digest check still apply).

### Live S3 test (owner-run)

`tests/test_077_pack_store.py::test_live_s3_bucket_round_trip` runs only when
`TINE_TEST_S3_BUCKET` names a bucket the ambient AWS credentials can write:

```sh
export TINE_TEST_S3_BUCKET=my-scratch-bucket AWS_PROFILE=...
uv run pytest tests/test_077_pack_store.py -k live
```

It writes under a random `opentine-test-<uuid>/` prefix and deletes what it
wrote. Every other test uses moto's in-process S3 and never reaches the
network.

## Performance

`scripts/bench/ingest_stream.py` measures sustained events/s, batch commit
latency and the verify time; the acceptance target (10,000 events/s for one
hour, every batch signed) is a reference-machine number recorded here, never
asserted by tests. A full run:

```sh
uv run python scripts/bench/ingest_stream.py --events 100000000 --batch 10000
uv run python scripts/bench/ingest_stream.py --seconds 3600 --batch 10000 --no-redact
```

Recorded results are in docs/bench/0.77-ingest.md.

## Review hardening

* Batches must be signed by a key holding the pinned `runner` role and no
  `optimizer` role; `append` refuses an optimizer key outright.
* `issued_at` is `YYYY-MM-DDTHH:MM:SSZ`; a stream never moves back to an older
  policy, so a writer cannot pick, batch by batch, the seed that drops an episode.
* Event lines with duplicate keys, `NaN`, `Infinity` or numbers that overflow
  to infinity are refused.
* `tine ingest serve` answers 403 to a request with an `Origin` header or a
  `Host` that is not loopback (DNS rebinding), drops a client that stops sending
  after 30 s, and serves at most 8 connections at once (others get 503).
* Not detectable: a rollback of the held head to an earlier batch by someone who
  can edit the holds file. Record the head id (`tine ingest verify --json`)
  somewhere the loop cannot write, and compare.
