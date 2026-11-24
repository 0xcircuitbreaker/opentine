# Live tail: `tine log -f` and `GET tail` (0.77)

Both follow run events as they become durable. They use the same engine
(`opentine/_tail.py`) and produce the same rows, `tine-tail/1`
([schema](schemas/tine-tail-1.schema.json)).

## What is shown, and when

A writer moves a ref only after the objects it names are durable (the write
batch is flushed first). The follower reads refs. For each followed ref
whose run grew, it walks the new entries of the run's `events` list in
order. An event is shown only when its ref already points past it **and**
its bytes can be read. If an event's bytes cannot be read yet, the follower
holds it and every later event of that run back, and retries on the next
poll. A non-durable event is never shown.

Each event row is checked when it is shown and carries its status:

| `status` | Meaning | `verified` |
|---|---|---|
| `verified` | the stored bytes hash to the event id, the payload is well formed, and every object it links (parents, causal links, blobs) is present | `true` |
| `unverified` | the bytes hash to the id, but a linked object is not held here (a shallow fetch, a purge) | `false` |
| `invalid` | the bytes do not decode to the id, or the payload is malformed | `false` |

The text form prints `[verified]`, `[UNVERIFIED]` or `[INVALID]`. These
statuses are not `tine verify` codes. They say what the tail checked, which is
integrity, not signatures. Run `tine verify` on the run for signatures and
attestations.

Other row types:

- `rewrite`: a followed ref no longer extends the run the follower saw before
  (a rewind or a forced move). It is reported once, and following continues
  from the new tip. The rewritten history is not replayed. The follower
  compares a digest of every event id up to its position, not only the last
  one, so a rewrite that drops or replaces an earlier event is reported too,
  including across a resume.
- `truncated`: more run refs exist than are followed (`--all` follows at most
  1024). Reported when the number left out changes.
- `reset` (SSE only): the resume point could not be read. The stream starts at
  the present.
- `dropped` (SSE only): the server cut off a slow consumer (see below).

## `tine log -f [RUN|--all] [--json]`

```
tine log -f                  # heads/main
tine log -f my-branch        # heads/my-branch
tine log -f --all --json     # every run ref (heads/, experiments/, promotions/, tags/, remotes/)
```

| Option | |
|---|---|
| `--lines N`, `-n N` | first show the last N events of each followed run (default 10) |
| `--interval S` | poll interval in seconds when nothing is new (default 0.2, at most 60) |
| `--max-events N` | stop after N rows (scripts) |
| `--json` | one `tine-cli-log-follow/1` record per row: `{"command":"log","schema":"tine-cli-log-follow/1","row":{...}}` ([schema](schemas/tine-cli-log-follow-1.schema.json)) |

`-f` does not combine with `--graph`, `--oneline` or `--search`. Ctrl-C
stops it. With `--all`, at most 1024 refs are followed, the first in name
order, and a `truncated` row says how many were left out. A ref created while following is followed from its first event, except that
history already shown under another followed ref (a tag, branch or pulled ref
onto the same run) is not replayed.

## `GET /v1/tenants/<tenant>/tail` (Server-Sent Events)

Advertised as `caps.tail_sse` (`{"format": "tine-tail/1", "path": "tail"}`).

**Authorization.** The same as the other tenant reads. It needs `read_ref`
(the ref listing) and `fetch` (the events), both tenant-wide, so a
namespace-limited token is refused, as on `GET events`. The server's
per-object read policy hides objects exactly as on `GET objects`, a caller
who may not read the tenant gets the uniform `404`, and opening a stream is
audited.

**Query.** `ref=<name>` (default `heads/main`) or `all=1`; `lines=N` (0-1000,
events already there to send first); `last_event_id=<cursor>` or the
`Last-Event-ID` header to resume.

**Frames.** Each row is one `event: <type>` / `data: <row JSON>` frame. The
last frame of every batch also has `id: <cursor>`. A cursor is opaque (`c1.`
then base64url of compressed JSON, at most 16 KiB). A client that reconnects
with it continues from the end of that batch. Delivery is at least once (a
connection lost mid-batch repeats that batch), so deduplicate on `event_id`.

**Limits and liveness.**

- At most 32 tail streams in all (`503` with `Retry-After: 5`) and 4 per
  caller, by tenant and subject (`429` with `Retry-After: 5`).
- A `: heartbeat` comment every 10 s. The stream closes after 25 s, inside
  the server's request deadline, with a `retry:` hint. Clients reconnect with
  the last id.
- A ref move on the server wakes waiting streams at once. A ref moved by
  another process is seen within 0.5 s.

**Backpressure.** Nothing is queued per stream. Rows are read from storage
when the client can take them, so a slow client never grows server memory.
A client that stays more than 20,000 rows behind (batches of 500), or takes
more than 10 s to accept one batch, gets `event: dropped`
(`detail`: `consumer lagging` or `slow consumer`) and the stream ends. It
reconnects with its last id and loses nothing.

## Performance

`scripts/bench/tail_latency.py` measures the time from a writer's ref move
returning (the event is durable) to the follower yielding the row, through
`tine log -f` (`--mode cli`) and through `GET tail` (`--mode sse`). The target
is under 1 s. Results and hardware are in
[bench/0.77-tail.md](bench/0.77-tail.md). The tests check correctness only.
