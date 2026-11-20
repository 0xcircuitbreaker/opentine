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
  docs/KEYS.md). A policy that only lowers limits needs no role. The first
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
