# Monitor verdicts and the intervention log (0.63)

An inline monitor scores each tool call an agent proposes, before or while it
runs. opentine records every decision a monitor makes that changes or flags an
action as a signed **monitor verdict**, keeps it from deletion, and checks
offline that every blocked action has one. The same gate runs in two places:

- the MCP proxy (`tine mcp-proxy --monitor CONFIG`), on every `tools/call`,
  stdio and Streamable HTTP;
- the agent hook path (`tine monitor gate`), which an agent CLI runs before
  each tool call (Claude Code and Codex `PreToolUse`, Gemini CLI `BeforeTool`,
  or the generic `opentine-monitor/1` payload).

Nothing here adds an object kind or a `tine verify` code (owner decision E7
was refused): a verdict and a stop token are existing attestations whose
claims follow a convention.

## Modes

| Mode | What happens | Default |
| --- | --- | --- |
| `advisory` | The call is relayed unchanged at once. The monitor scores it afterwards (proxy) or before the hook returns (hook path). A verdict that is not `allow` is recorded. Nothing is blocked. | yes (D12) |
| `gate` | The call waits for the monitor, up to `deadline_ms`. `block` blocks; `resample` and `defer` replace the call with an alternate; `allow` and `flag` relay it. | only when the config says `mode = "gate"` |

In gate mode a missed deadline or a monitor error blocks when `fail_closed =
true` and relays otherwise. A **stop token** blocks in both modes: a stop is a
signed operator decision, not an advisory finding.

## Configuration

`--monitor CONFIG` (proxy) and `--config CONFIG` (hook path) read TOML:

```toml
version = 1
mode = "gate"            # advisory (default) or gate
deadline_ms = 250        # 1..600000
fail_closed = true       # gate mode: block when the deadline is missed or the monitor fails
reasoning = "captured"   # or "redacted": what reasoning text the monitor is shown

[monitor]
id = "shell-rules"
kind = "rule"            # rule, command (local model), http (remote API) or probe (0.83)
threshold = 0.5          # score >= threshold takes `action`
action = "block"         # flag, resample, defer or block

[[monitor.rules]]
tool = "shell*"          # fnmatch on the tool name
pattern = "rm -rf"       # regular expression over the canonical JSON of the arguments
score = 0.9
# action = "defer"       # optional, overrides [monitor].action for this rule
# category = "destructive"  # optional: recorded on the verdict ([a-z0-9._-], at most 64)
# severity = "high"         # optional: low, medium, high or critical

[alternate]
command = ["python", "trusted.py"]   # resample/defer source (optional)
```

- `kind = "rule"`: the highest matching rule's score. `model_digest` is the
  digest of the rules, so a rule monitor is deterministic and named by its rules.
- `kind = "command"`: `command = [ARGV...]` is run per call with the request
  on stdin; it prints `{"score": 0..1, "action"?: ...}`. Declare the model with
  `model_digest = "sha256:..."`.
- `kind = "http"`: `url = "https://..."`; the request is POSTed as JSON and the
  reply has the same shape.
- `kind = "probe"` (0.83): a linear probe on the model's activations, keyed to a
  checkpoint digest and a signed calibration; the verdict's `monitor` records
  `probe`, `checkpoint`, `layer`, `threshold` and `calibration`. See
  docs/INTERPRETABILITY.md.

A command or http monitor's reply may also name a `category` and a `severity`;
when the score crosses the threshold both are recorded on the verdict, and a
malformed one makes the reply a monitor error.

The request a monitor receives is `{"tool", "method", "arguments",
"reasoning"}`. `[alternate].command` receives the same request plus `"role":
"resample"|"trusted"` and prints `{"params": {...}}`: the replacement MCP
`params`. A resample is scored again and blocked if it still crosses the
threshold; a trusted alternate (defer) is taken as given. Without an alternate,
`resample` and `defer` block.

## The verdict claim: `opentine.monitor-verdict/1`

Schema: `opentine-monitor-verdict-1` (docs/schemas).

| Field | Meaning |
| --- | --- |
| `monitor` | `{"id", "kind", "model_digest"}` |
| `input_digest` | `sha256:` of the canonical JSON of the redacted `{"method", "params"}`: what the proxy run records for the step, so an offline check recomputes it |
| `reasoning` | `{"state": "captured"\|"redacted"\|"unavailable", "digest"}`: whether the monitor saw the agent's reasoning or scratchpad text, and the digest of exactly what it saw (`null` when unavailable). Backtests compare runs with the same state. |
| `score`, `threshold` | The monitor's score (`null` when it gave none) and the threshold |
| `action` | `allow`, `flag`, `resample`, `defer` or `block` |
| `enforced` | Whether the call was changed (blocked or replaced) |
| `mode`, `deadline_ms`, `fail_closed` | The gate's settings |
| `decided_by` | `monitor`, `deadline`, `error`, `stop-token` or `alternate` |
| `latency_ms` | How long the monitor took |
| `trajectories`, `chosen` | The original action's digest first, then the resample or trusted alternate's (`role`, `digest`, and a resample's `score`); `chosen` is `original`, `resample`, `trusted` or `none` (blocked) |
| `stop` | The stop token that blocked the call, if any |
| `tool`, `session`, `decided_at` | The tool name (redacted), the proxy or hook session, the time |

A verdict is an Ed25519-signed attestation on a small control run. It is
`verified` only when its signer is in the `monitor` role of the owner-pinned key
roles (a trust bundle, docs/SELF-IMPROVING-LOOPS.md); otherwise `unverified:
WHY`. The `monitor` role is guarded: the optimizer key may not hold it
(`fail:key-separation.shared` from `tine keys lint`).

**What is recorded.** Every verdict that is not `allow`, and every enforced
one, is signed and kept by a hold whose target starts `monitor-verdict:`.
`tine hold release` refuses it, so a loop cannot delete the record of what
blocked it. An `allow` costs one monitor call and no signature. Gate mode
refuses to start without a repository and a key.

**What the proxy run shows.** A blocked call is answered with a JSON-RPC error
(code `-32001`) whose `data["opentine.monitor"]` is `{"verdict", "action",
"outcome": "block"}`; the run records the blocked request and that error as one
step. A replaced call is relayed with `params._meta["opentine/monitor"] =
{"verdict"}`.

## Stop tokens: `opentine.monitor-stop/1`

`tine monitor stop --scope SCOPE --key KEY [--reason T] --repo PATH` signs an
attestation with claim `{"convention": "opentine.monitor-stop/1", "scope",
"reason", "stopped_at"}` and holds it (`monitor-stop:SCOPE`, never released).
`SCOPE` is `*`, `agent:NAME` (`--monitor-agent` on the proxy, `--agent` on the
hook path) or `session:ID`. The proxy and the hook read the holds before every
gated call; an unreadable holds file counts as a stop. `verification` is
`verified` when the signer is in the owner-pinned `stopper` role (or no
stopper role is named); an unverified token still stops.

## Offline verification

`tine monitor verify [--run RUN]... [--strict] --repo PATH` reads only the
repository and the given runs (`.tine` files or run ids):

| Finding | Meaning |
| --- | --- |
| `fail:monitor.verdict-invalid` | A held verdict is unreadable, malformed or its signature does not verify |
| `fail:monitor.blocked-without-verdict` | A blocked or replaced step names no verdict |
| `fail:monitor.verdict-not-held` | The verdict it names is not kept by a `monitor-verdict:` hold |
| `fail:monitor.verdict-mismatch` | The verdict does not record this step's action (input digest, chosen trajectory, `enforced`) |
| `fail:monitor.holds-unreadable` | The holds file cannot be read |
| `advisory:monitor.verdict-unpinned` | The signer is not a pinned monitor key |
| `advisory:monitor.stop-unverified` | A stop token's signer is not a pinned stopper key |

`fail:` findings exit 1; advisories only with `--strict` (D12). These are CLI
findings, not `tine verify` codes. `tine monitor verdicts` and `tine monitor
stops` list what the holds keep. `--json` prints `tine-cli-monitor/1`.

## The hook path

```sh
tine monitor gate --config monitor.toml --key monitor.key --repo . --agent claude-code
```

reads one tool call on stdin and prints one JSON object (exit 0):

- `claude-code`, `codex`: `{}` to proceed; a block sets
  `hookSpecificOutput.permissionDecision = "deny"`; a replacement is `allow`
  with `updatedInput`;
- `gemini`: `{}` or `{"decision": "deny", "reason"}`; there is no replacement,
  so `resample` and `defer` block;
- `generic`: `{"protocol": "opentine-monitor/1", "decision":
  "allow"|"block"|"replace", "verdict", "input", "reason"}` (schema
  `opentine-monitor-hook-1`).

A payload may carry `reasoning`, the text the agent showed before the call;
without it the verdict says `unavailable`. A payload or config that cannot be
read proceeds unless `--fail-closed`; an error while deciding blocks in gate
mode.

## Monitors as evidence: coverage, heartbeats, operating points

A monitor's verdicts say what it blocked. The records in this section say what
it *saw*, that it was alive, and how good it is at its threshold. All of them
are existing object kinds (annotations and attestations) under claim
conventions; no object kind and no `tine verify` code is added. Every record is
signed with Ed25519, bound to the key that signed it, and counts only when that
key holds the `monitor` role (coverage, heartbeats) or a `scorer` or `policy`
role (operating points) in the owner-pinned trust bundle and is not also an
`optimizer` key. Chain heads are held under `monitor-ledger:`,
`monitor-heartbeat:` and `monitor-validation:`, which `tine hold release`
refuses.

### The asynchronous runner and the coverage ledger

`tine monitor run --config CONFIG --stream S --key KEY` reads the ingest
stream's batches (docs/INGEST.md) after the last one its ledger records, in
order, and scores every captured event (an event's `tool`, `arguments`,
`reasoning`, `agent`, `session` and `run` fields are read when present). For
each batch it writes one `opentine.monitor-coverage/1` record: the monitor's
id, kind and **config digest** (mode, deadline, fail mode, reasoning, threshold,
action and the monitor's identity), the batch it evaluated, counts by outcome
(`allow` included) and by category, and one line per evaluated event (index,
score, outcome, input digest, latency, subject, category, severity) with the
digest of those lines. Allow verdicts are a count plus a digest list, not one
signature each, so the holds file does not grow with traffic. Every outcome
that is not `allow` is also an `opentine.monitor-verdict/1` attestation, held
as the gate's verdicts are, and so appears in the oversight queue.

The runner never blocks anything (owner decision D12): the events already
happened. A verdict's latency is the time from the batch's ingest to the
verdict; each record carries the p95 and the SLO (`slo_ms = 30000`).

`--follow` keeps running, polls every `--poll` seconds and signs a heartbeat
every `--interval` seconds (default 60).

### Coverage

`tine monitor coverage --config CONFIG --stream S` computes, offline:

- the denominator: every event index the stream's batches captured. Coverage is
  of *captured* events; an action that was never ingested is invisible here;
- the numerator: the captured indices the monitor's verified records evaluated,
  given exactly as `covered = "E/C"` and `percent` to four decimals;
- `gaps`: the uncovered index ranges (at most 100 listed).

Findings that are facts about records are `fail:` in every profile:
`monitor.coverage-unsigned` (no pinned monitor key, or a pinned monitor key the
trust bundle does not bind to this monitor), `monitor.coverage-chain`
(a broken record or batch chain), `monitor.coverage-forged` (a record naming a
batch the stream does not hold, an index the batch did not capture or one
twice, a line whose input digest is not that of the captured event, a
threshold that is NaN, infinite or not a number, counts
and digests that do not match its lines, or a record written for another
monitor or stream), `monitor.heartbeat-unsigned`, `monitor.heartbeat-backfilled`,
`monitor.heartbeat-replayed` and `monitor.heartbeat-future`. An event the
monitor errored on (a timeout, a crash, a malformed reply) is not covered. These are advisory by default and `fail:` under
`--profile rsi`: `monitor.coverage-gap`, `monitor.config-changed`,
`monitor.stale`, `monitor.latency-slo`, `monitor.unvalidated-threshold` and
`monitor.signer-unbound` (below; under `rsi` none of an unbound monitor's
records or heartbeats count). The command exits 1 on a `fail:` finding (`--strict`: on any finding).

### Which key speaks for which monitor

A pinned `monitor` key proves a record came from *a* monitor, not from the one
it names. The owner-signed trust bundle binds each monitor id to its signer
keys (`tine trust bundle create --monitors FILE`):

```json
{"version": 1,
 "signers": {"rules": ["sha256:<fingerprint>"]},
 "required": ["rules"]}
```

A fingerprint may be bound to one monitor id only, and a `required` id must be
bound; a bundle that breaks either is refused whole. A coverage record or
heartbeat of a bound monitor counts only when its signer is one of that
monitor's keys and still a pinned, non-`optimizer` `monitor` key: another
monitor's key is `monitor.coverage-unsigned` / `monitor.heartbeat-unsigned`.
A monitor id with no binding (including a renamed id) is
`monitor.signer-unbound`, advisory by default (D12); under `--profile rsi`
nothing it signed counts. `required` names the monitors `tine promote` must
see (docs/EVALS-PROMOTION.md).

### Heartbeats

`opentine.monitor-heartbeat/1` records form a hash chain per monitor and
stream. Each carries the monitor's config digest, the interval and the ingest
stream's head batch (id, sequence number, time) when it was signed, and the
monitor's ledger head. A monitor is `stale` after three missed intervals
(three minutes by default); `coverage` reports every such window, the last one
against the current time (`--at` sets it).

A heartbeat cannot be written in the past: signing one older than the previous
heartbeat or older than the batch it binds to is refused. One that names an
older head while newer batches had already arrived more than one interval
before its time, or a batch the stream does not hold, is
`monitor.heartbeat-backfilled`; one that belongs to another monitor or stream,
or whose chain link does not match, is `monitor.heartbeat-replayed`; one dated
more than an interval after the time checked is `monitor.heartbeat-future`.
Neither counts as liveness, and nor does a heartbeat carrying another config
digest (`monitor.config-changed`). Liveness
is therefore proven relative to the ingest stream: while nothing is ingested,
a heartbeat's time is only as good as the monitor's clock.

### Validated operating points

`tine monitor validate --config CONFIG --labelled FILE --key KEY` scores a
labelled set (JSON Lines `{"tool", "arguments", "label": "attack"|"benign"}`,
both classes required) at the configured threshold and signs an
`opentine.monitor-operating-point/1` attestation: the monitor's config digest,
the threshold, the set's digest and class counts, the confusion counts, and the
true- and false-positive rates with 95 % Wilson and Clopper-Pearson intervals.
A monitor error counts against the monitor (a miss on an attack, a false alarm
on a benign item). The signer must be a pinned `scorer` or `policy` key that is
not an `optimizer` key (`monitor.validation-signer`); the monitor's own key
cannot validate it.

A record counts only for the exact config digest and threshold it names, and
only when its rates and intervals follow from its counts. Changing the
threshold or the config therefore leaves the monitor unvalidated until it is
validated again. Under `--profile rsi` an unvalidated monitor counts as no
coverage at all.

### Cumulative suspicion and doom loops

`tine monitor suspicion` reads every verified coverage record (all monitors
and streams, or `--stream`) and accumulates per `agent:`, `session:` and `run:`
subject, per ingest stream (`stream:`), per action digest, and per normalized
action (`shape:`: the tool name and argument keys, each value bucketed: a
string's first word, case-folded, without its directory and with digits folded, a number's or other value's type),
recomputed from the captured event. Splitting work
across sessions does not reset an agent's total; rotating agent ids does not
reset a session's; and since the subject ids are claimed by the agent itself,
the stream, which it cannot name, still counts near-threshold scores when every
id is rotated (doom-loop flags only; a stream's summed score is not flagged). Three
advisory flags follow:

- `advisory:monitor.cumulative-suspicion`: a subject's summed score reaches
  `--budget` (3.0);
- `advisory:monitor.doom-loop-near-threshold`: `--repeats` (3) or more scores
  within `--margin` (0.1) below the threshold;
- `advisory:monitor.doom-loop-repeated-failure`: the same action or the same
  normalized action, whatever subject sends it, `--repeats` or more times with
  an outcome other than `allow`. Changing one argument per retry
  (`rm -rf /srv/1`, `rm -rf /srv/2`, ...) is still the same `shape:`; different
  tools, argument keys or commands (`sudo ...`, `find ...`) are not, and allowed
  calls never count.

Only records signed by a key bound to their monitor count. A record whose
threshold or a score is NaN, infinite or not a number is never read: it is
listed in `invalid` (`--strict` exits 1) and is `monitor.coverage-forged` in
`coverage`, so it fails closed instead of crashing or hiding a flag.

Each flag names the coverage record in which it was first reached, and the
oversight queue opens a `suspicion:RECORD` item for it (docs/OVERSIGHT.md), so
escalation goes through the existing k-of-n review. Flags block only with
`--strict`.

## Limits

- Only `tools/call` is gated on the proxy. In gate mode a client line longer
  than 16 MiB cannot be decided and is dropped.
- In gate mode the proxy also gates `tools/call` notifications (no `id`; a
  blocked one is dropped), drops a client message it cannot parse strictly
  (invalid UTF-8, duplicate keys, `NaN`; over HTTP the answer is 403), and
  removes a client-supplied `_meta["opentine/monitor"]` mark: only the gate
  writes that mark. A monitor reply that is not a finite score in 0..1 with a
  known non-`allow` action counts as a monitor error.
- The gate sees only what passes through the proxy or the hook. An agent that
  can reach a tool another way, or that can rewrite `.tine/holds` or the
  recorded runs, is outside what `tine monitor verify` can catch.
- The hook path decides synchronously in both modes (the hook is one process
  per call), so an advisory monitor's latency is added to the call there.
- Each held verdict is one row in `.tine/holds` (at most 4 MiB, about 25 000
  rows).
- Offline backtests (including against these verdict records with
  `tine monitor backtest --repo`), collusion tests and catch-rate metrics are
  in docs/MONITOR_BACKTESTS.md.
- Coverage counts captured events only; sampling (docs/INGEST.md) and actions
  that never reach the ingest stream lower what any monitor can be shown to
  cover. A coverage record holds one line per evaluated event, so a very large
  batch makes a large record.
- `tine promote` does not read coverage yet; the `rsi` profile is applied by
  `tine monitor coverage --profile rsi`.
