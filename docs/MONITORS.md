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
