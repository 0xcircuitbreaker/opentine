# Budgets and the spend ledger

A budget caps what one loop or agent may spend. The subject is `loop:NAME` or
`agent:NAME`. Five limits can be set: `tokens`, `gpu_hours`, `wall_clock_s`,
`egress_bytes` and `money_usd`. Spend goes on a signed, append-only ledger
built from recorded costs. Agent hooks and the MCP proxy read that ledger and
refuse the next action once a limit is reached.

## Policy

```sh
tine budget sign-policy loop:opt --serial 1 --tokens 200000 --money-usd 25 \
  --wall-clock-s 86400 --on-limit escalate --key policy.key --out budget.json
tine budget apply budget.json --key runner.key --repo .
```

A policy is an `opentine-budget-policy/1` document:

```json
{"schema": "opentine-budget-policy/1", "subject": "loop:opt", "serial": 1,
 "limits": {"tokens": 200000, "gpu_hours": null, "wall_clock_s": 86400,
            "egress_bytes": null, "money_usd": 25.0},
 "on_limit": "escalate", "issued_at": "2027-01-15T08:00:00Z",
 "signature": {"...": "tine-sig/3, Ed25519, domain opentine.budget-policy.v1:"}}
```

A `null` limit is not capped. The file itself grants nothing. `apply` writes
it to the ledger as a `policy` entry, and the policy takes effect only when
all of these hold:

- its signature verifies. The signer is the key that signed
  (`used_key_fingerprint`), not a name in the document;
- the signer is not an `optimizer` key;
- its `serial` is higher than the serial of the policy in force (no rollback);
  a pinned `policy` key is compared only with the highest serial a pinned
  `policy` key put in force, so another key cannot lock the owner out with a
  very large serial;
- if it raises or removes any limit, the signer holds the `policy` role in
  the owner-pinned trust bundle (`tine trust bundle create --key-roles`; see
  the key-separation section of docs/CLI.md). A policy that only lowers limits needs no role. The first
  policy for a subject only adds caps, so it needs no role either.

A policy that fails any of these checks is refused, and the policy in force
stays. The refusal is reported as a `fail:` finding: `budget.policy-unsigned`
(no signature, or the document was edited after signing),
`budget.policy-optimizer-key`, `budget.policy-rollback`, `budget.limit-raise`
or `budget.policy-subject`. In other words, an agent that tries to raise its
own limit cannot do it. Editing the file, signing a new policy with its own
key or replaying an older policy each leaves the old limits in place, and the
attempt is routed to oversight (below).

## Ledger

```sh
tine budget record loop:opt run1.tine run2.tine --key runner.key --repo .
tine budget ledger loop:opt --repo . --json
```

Each entry is an existing `annotation` object. Its `value` follows the claim
convention `opentine.budget-ledger/1`:

| `entry` | Fields |
| --- | --- |
| `spend` | `run`, `cost` (the run's `tine cost` aggregate as recorded: `total_cost`, `total_tokens`, `input_tokens`, `output_tokens`, `by_model`, `by_kind`), `gpu_hours`, `egress_bytes` |
| `policy` | `policy` (the signed document) |
| `flag` | `code`, `detail`, `about` (the entry it flags) |

Every entry also carries `subject`, `at` and `at_ms`. `target_id` is an anchor
blob that names the subject. `previous_id` is the entry before it, so the ids
form a hash chain. Each entry is Ed25519-signed and held under
`budget-ledger:SUBJECT`. `tine hold release` refuses those holds, so a loop
cannot delete its own spend. The ledger is read from the holds, not from a
ref.

Totals count every held `spend` entry: unsigned entries, entries off the chain
and forked entries all count, so a bad entry cannot hide spend. Such entries
are reported as `fail:budget.ledger-unsigned`, `fail:budget.ledger-fork` or
`fail:budget.ledger-optimizer-key`. When a `runner` role is pinned, an entry
signed by any other key is reported as `advisory:budget.ledger-signer`.
`runner` is a new key role (0.69) and is guarded like the other guarded
roles: an optimizer key that also holds it is a `fail:key-separation.shared`
finding in `tine keys lint`.

`money_usd` is the `math.fsum` of the recorded `cost.total_cost` values. That
is the same number `tine cost RUN --statement` exports for each run, so the
ledger total equals the cost export. Tokens are summed the same way.
`gpu_hours` and `egress_bytes` are recorded as given to `record`.
`wall_clock_s` is measured from the first accepted policy entry to the
caller's clock (`--at`).

## Deciding the next action

```sh
tine budget check loop:opt --repo .        # exit 1 when refused
tine budget status loop:opt --repo . --json
```

The decision is `allow` until a limit is reached. After that it is the
policy's `on_limit`:

- `deny` refuses the action;
- `escalate` refuses it as well and records a `budget.limit-reached` flag
  that goes to the oversight queue. The subject resumes only under a new
  signed policy.

Under owner decision D12, findings are reported but do not refuse actions;
only an over-budget subject has its next action refused. A refused
limit-raise keeps the lower limit in force, so the over-budget check still
denies.

With `--key`, `status` and `check` record each new `fail:` finding as a held
`flag` entry, once per flagged entry. The flag is also held under
`budget-flag:SUBJECT`, and the oversight queue lists it as item
`budget:ANNOTATION` with source `budget`. To route those items, add a route
to `.tine/oversight.toml`:

```toml
[[route]]
source = "budget"
tier = "high"
```

## Hooks and the MCP proxy

```sh
tine budget gate loop:opt --key runner.key --agent claude-code --repo .   # PreToolUse hook
tine mcp-proxy --budget loop:opt --budget-key runner.key --repo . -- my-mcp-server
```

The gate reads the hook payload from stdin and exits 0. When it refuses, the
output depends on the agent:

- Claude Code / Codex: `permissionDecision: "deny"`;
- Gemini CLI: `{"decision": "deny"}`;
- anything else: `{"protocol": "opentine-budget/1", "decision", "reason",
  "over"}`.

An error while deciding refuses (fail closed), and so does a subject with no
policy in force (never applied, or its entries removed from the holds). The proxy answers a refused
`tools/call` with JSON-RPC error `-32002` and
`data["opentine.budget"] = {"decision", "over"}`. When the proxy also runs a
monitor, the budget check runs first.

Spend is recorded after each step (`tine budget record`). The step that
crosses a limit completes, and the next action is refused, so the subject is
denied within one step.

## The model path: `tine record --budget`

```sh
tine budget sign-policy agent:bot --serial 2 --tokens 500000 --money-usd 10 \
  --allow-model gpt-4o-mini --allow-model 'claude-haiku-4*' \
  --model-alias fast=gpt-4o-mini --judge-tokens 50000 --judge-money-usd 1 \
  --key policy.key --out policy.json
tine budget apply policy.json --key runner.key --repo .
tine record --budget agent:bot --budget-key runner.key --repo . -- python agent.py
```

With `--budget`, the `tine record` proxy checks every model call against the
subject's ledger before forwarding it. It uses the same policy, ledger, lock
and decision as the hook and MCP gates. Without `--budget`, the proxy behaves
as before.

The policy's optional `model_path` section (`--allow-model`,
`--model-alias`, `--judge-tokens`, `--judge-money-usd`, `--max-output-tokens`)
adds the following:

- **Allowlist.** Each model a call names (the body's `model`, a Gemini
  `models/NAME:method` path, an Azure deployment, every request of an inline
  batch) is canonicalised and then matched. Canonicalisation applies Unicode
  NFKC, folds case, removes all whitespace, strips provider and routing
  prefixes (`openai/`, `models/`, `us.anthropic.`, ...) and then applies the
  policy's aliases. A trailing `*` in an allowlist entry matches a prefix. A
  model name with any other character never matches.
- **Reservation.** Before forwarding a call, the proxy appends a `spend`
  entry with `phase: "reserve"` holding a pessimistic estimate. Input tokens
  are estimated as the request's byte length. Output tokens are the largest
  output limit the request names (or `max_output_tokens`, default 32768),
  times `n` or `candidateCount`. Money is the catalog price of that usage. The
  read, the decision and the append happen under one lock
  (`budget-ledger.lock` in the repository, held across processes), so
  concurrent calls cannot both pass a cap that only one of them fits under.
  A call is refused when the totals plus its estimate would exceed `tokens` or
  `money_usd`.
- **Settlement.** After the reply, a `phase: "settle"` entry records the usage
  the provider reported, priced from the catalog. A reply with no usage
  settles at the estimate, and so does a stream cut before its end-of-stream
  event. A call that never reached the provider settles at zero. A settle
  entry replaces its reservation only when the same key signed both and every
  entry for that call is signed. Otherwise the larger value counts, so a
  forged settle entry cannot hide spend.
- **Judge spend.** A call that sends `X-Opentine-Call-Role: judge` (or
  `scorer`) also counts toward `model_path.judge`. That cap refuses only
  tagged calls, and their spend still counts toward the subject's overall
  limits. The header is not forwarded. `tine budget status` shows
  `judge_tokens` and `judge_money_usd`.

Each refusal is a signed, held `deny` ledger entry with `code`, `detail`,
`about` (the policy entry in force), `model`, `path`, `role`, `run` and
`call`. The child receives HTTP 403 with
`{"error": {"type": "opentine_budget", "code", "message", "entry"}}`, and the
recorded run keeps the refused call as an errored model step. These are the
command-level codes:

| code | meaning |
|---|---|
| `budget.no-policy` | no policy in force for the subject |
| `budget.limit-reached` | a limit is reached, or the ledger forked |
| `budget.model-not-allowed` | a named model is not on the allowlist |
| `budget.model-unidentified` | an allowlist is set and the call names no model |
| `budget.call-unverifiable` | the body is not one JSON object (or repeats a key), the path traverses, the batch is upload-based (`/batches`, `/files`, `/uploads`), or an output limit or fan-out is invalid |
| `budget.model-unpriced` | a money cap is set and the catalog has no price for the model |
| `budget.would-exceed` / `budget.judge-would-exceed` | the estimate does not fit the remaining cap |
| `budget.ledger-unreachable` | the ledger could not be read or written (HTTP 503) |

The proxy fails closed. If a ledger or policy error makes a call impossible to
decide, the call is refused. If even the `deny` entry cannot be written, the
child gets HTTP 503 and the refusal is kept only in the recorded run. Requests
with no body and `GET`, `HEAD`, `OPTIONS` and `DELETE` requests carry no model
spend and are forwarded ungated. `count_tokens` / `countTokens` calls are
checked against the allowlist but reserve nothing.

### Limits

- The proxy sees only the calls the child sends through it. A child that
  ignores its base-URL variables, or opens its own connection, is not stopped.
  Pair `--budget` with network containment (docs/CONTAINMENT.md) when that
  matters.
- The input estimate counts bytes in the request. Context the provider holds
  server-side (`previous_response_id`, cached contents, assistants threads) is
  not in the request, so that call's reservation can be low. Its settlement
  uses the reported usage.
- An OpenAI-style batch that refers to an uploaded file cannot be checked, so
  it is refused under any policy.
- Canonicalisation cannot tell two different models served under the same
  name apart.
