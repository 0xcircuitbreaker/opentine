# Tiled appends and the witness protocol: log/1 or log/2? (0.45)

Status: decided for 0.45. Owner: transparency. Roadmap: §10 "0.45", tiled log
and witness HTTP protocol.

## Question

The roadmap says tiles "change `opentine-log/1` storage and proofs" and asks the
release to decide, in writing, whether O(log n) appends need a new
`opentine-log/2` or are a compatible extension of `log/1`.

## Finding

`opentine-log/1` was already *stored* in the C2SP tlog-tiles layout from 0.36:
`checkpoint` (signed note), `tile/<L>/<N>[.p/<W>]` hash tiles, 256 hashes per
tile, and `tile/entries/<N>[.p/<W>]` entry bundles with `uint16` length
prefixes. Proofs (RFC 9162 inclusion and consistency) were already computed from
the hash tiles. What was O(n) was only the *writer*: each append re-read every
entry bundle, re-hashed every leaf, re-checked every tile and rewrote nothing
more than the right edge.

## Decision: keep `opentine-log/1`; no log/2

- The 0.45 writer (`opentine/repository/_tlog_append.py`) recomputes the signed
  root from the hash tiles of the right edge (at most about 256 hashes per tile
  level), checks the last entry against its leaf hash, then writes the one
  changed entry bundle and, per level, the one changed partial tile.
- The bytes it writes are the bytes `_tlog.write_tiles` writes for the same
  entries; `tests/test_045_tlog_tiles.py` pins that byte for byte. Checkpoints,
  leaf and node hashing, entry encoding, receipts
  (`opentine-tlog-receipt/1`) and proofs are unchanged, so every existing reader
  (0.36 to 0.44, the TS verifier and `tine-verify.pyz`) reads a 0.45 log.
- Older partial tiles (`.p/<W>` with a smaller `W`) are left in place. The
  tlog-tiles specification allows this, and no reader looks at a tile the
  checkpoint's size does not name.
- No new conformance vectors are needed, because no format changed: the
  existing `vectors/57-tlog.json` family still describes every byte. The
  witness HTTP protocol is a wire protocol (C2SP tlog-witness), not a stored
  format; its request parsing is covered by Python tests. Cross-language
  vectors for it are deferred until the TS verifier speaks it.

### What the append no longer does

The 0.44 append re-verified the whole log (every entry against every tile)
before each write. The 0.45 append verifies only that the right edge it extends
is the one the checkpoint signs. Tampering with an *old* entry is still caught
by `verify_log` (`tine log verify`, receipts, witnesses' consistency checks),
not by the next append. This is the same trust model as other tile logs.

### Migration and compatibility

None needed. A log written by 0.36 to 0.44 is appended to by 0.45 in place, and
a 0.45 log is read by every earlier release. The 0.34 peer-compatibility job is
unaffected, because the HTTP audit log endpoints are unchanged.

## Witness protocol

`tine witness serve` implements `POST /add-checkpoint` from C2SP tlog-witness
(`opentine/_witness_http.py`) on top of the 0.44 witness decisions
(`opentine/_witness.py`): 200 with cosignature lines, 409 `text/x.tlog.size`,
404, 403, 422 (fork or rollback) and 400. `tine witness submit` speaks the
client side and gathers cosignatures for `verify --witnesses N-of-M`.

Not yet implemented: the `tlog-witness` `GET` endpoints of later drafts,
rate limiting, TLS (put the witness behind a reverse proxy) and a witness
config file. The listener binds `127.0.0.1` by default.

## Audit append failures

0.44 printed a warning when the remote's audit row committed but its
transparency entry did not append. From 0.45 `remote/_audit_tlog.publish`
retries three times with short backoff and then raises `PublishError`, which
fails the request. The audit row itself stays committed: it is the record of
truth, and the gap is visible to a monitor because each log entry carries the
row's `row_hash`. A backfill of missing entries on start-up is deferred.

## Benchmark

`uv run python scripts/bench_tlog_append.py` seeds a 1,000,000-entry log and
times 200 appends, failing if p95 is 10 ms or more. On the development machine
it measured p50 4.2 ms and p95 6.1 ms. The pinned-runner gate is not wired
into CI yet.
