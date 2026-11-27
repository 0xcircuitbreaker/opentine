# Containment evidence (0.69)

OpenTine records what sandbox a run was given, what the run tried to do
outside it, and (with `tine budget`, docs/BUDGETS.md) what it spent. Every
containment record is an **attestation** (an existing object kind) with a
claim convention; nothing here adds an object kind or a `tine verify` code.
Every record is kept by a `tine hold` row that `tine hold release` refuses,
so a loop cannot delete a policy or a finding.

| Record | Claim convention | Hold target | Signed by |
| --- | --- | --- | --- |
| Sandbox policy of a run | `opentine.sandbox-policy/1` | `containment:policy:RUN` | runner or hook (`runner` role) |
| Containment finding | `opentine.containment-finding/1` | `containment:finding:RUN` | runner, hook or gate key |
| Budget ledger entry (docs/BUDGETS.md) | `opentine.budget-ledger/1` annotation | `budget-ledger:SUBJECT` | runner (`runner` role) |
| Limit-raise violation or reached limit | a ledger `flag` entry | `budget-flag:SUBJECT` | the `tine budget check` key |

A record counts as signed only when its Ed25519 signature verifies and its
`signer` field names the key that signed (`used_key_fingerprint`). Roles come
only from the owner-pinned trust bundle (docs/INTEGRITY.md); the new `runner`
role is guarded like the others, so `tine keys lint` fails when an optimizer
key also holds it, and a record signed by an optimizer key is never
`verified`.

Owner decision D12 applies: detectors are **advisory**. Only two containment
checks are hard: a policy digest mismatch (`tine containment check`) and an
over-budget deny (`tine budget`'s gate on the hook path and `tine mcp-proxy
--budget`).

## Sandbox policy

A runner describes the sandbox as JSON:

```json
{
  "network_allowlist": ["pypi.org", "*.pythonhosted.org"],
  "mounts": [{"path": "/workspace", "mode": "rw"}, {"path": "/usr", "mode": "ro"}],
  "privileges": ["no-new-privileges"],
  "image_digest": "sha256:<64 hex>",
  "seccomp_digest": "sha256:<64 hex>"
}
```

The policy is canonicalised (hosts lower-cased, sorted and unique; mounts
sorted by path; privileges sorted and unique) and digested as `sha256:` of its
canonical JSON, so equal sandboxes give equal digests. `seccomp_digest` may be
`null` when no profile is applied.

```
tine containment record RUN --policy policy.json --key runner.key
tine containment check RUN --policy declared.json     # or --digest sha256:...
```

`check` exits 1 with the command-level code `sandbox-policy-mismatch` when the
recorded digest differs from the declared one, when a declared policy has no
signed record, or when a record is malformed (its digest does not match its
policy, or its signer field names another key). A record signed by a key
outside the pinned `runner` role is `advisory:containment.runner-unpinned`.
Two valid records on one run with different digests are also a
`sandbox-policy-mismatch`, and the allowlist the detectors use is the
intersection of the recorded allowlists, so a later, wider record cannot widen
the evidence.

## Detectors

`tine containment scan RUN [--key KEY]` reads every tool step of a recorded
run (as the hook path and `tine mcp-proxy --save` record them) and reports
`advisory:containment.<category>`:

| Category | Signals |
| --- | --- |
| `egress` | a URL or network tool aimed at a host outside the run's recorded `network_allowlist` (every host when none is recorded) |
| `credential-access` | SSH keys, cloud credential files, token stores, `/proc/*/environ`, keychains |
| `self-replication` | copying the agent's own code or model weights; fetching weights |
| `unmonitored-process` | `nohup`, `setsid`, `disown`, a trailing `&`, `systemd-run`, `docker run -d`, detached `screen`/`tmux` |
| `persistence` | cron, systemd units, shell start-up files, launch agents, scheduled tasks |
| `limit-edit` | seccomp, capabilities, cgroups, `ulimit`, key roles, the trust bundle, sandbox policies, budgets and limit files; from 0.85 also the oversight and protected lists, `.tine/integrity/`, monitor config, policy files, agent hook settings (`.claude/settings*.json`, `.codex/hooks.json`, `.gemini/settings.json`, `.cursor/hooks.json`, `disableAllHooks`), MCP and proxy config, and setting or unsetting `OPENTINE_*`/`TINE_*` |

With `--key`, each new finding is signed and held; a rescan records nothing
twice. Findings carry the step index and a `sha256:` digest of the step text,
not the text. The detectors are pattern matches: they report attempts recorded
in the evidence, they are not proof of intent, and a run that hides its actions
from the recorder is not seen. `--strict` exits 1 on any finding.

The gate (`tine monitor gate` on the hook path, and `tine mcp-proxy` with a
monitor) runs the same detectors on every action it sees and, when it has a
repository and a key, signs and holds each finding on its session run. A
finding never changes the gate's decision.

The test fixture `tests/containment_fixture.py` is a RepliBench-style probe
run: it copies itself, fetches weights, spawns an unmonitored process, reads
credentials, installs a cron entry and edits a limit file, all as recorded
tool calls. Nothing is copied or fetched; the spawn probe runs one harmless
child process inside the test's temporary directory and waits for it.

## Oversight and query

The oversight queue (`tine oversight queue`, docs/OVERSIGHT.md) lists every
held containment finding, and every policy record of a run whose
`tine containment check` fails without a declared digest (a malformed record
or two disagreeing records), as a `containment:ATTESTATION` item; the
oversight policy routes them with `source = "containment"`. Budget flags (a
limit-raise violation, a reached `escalate` limit) are `budget:ANNOTATION`
items (docs/BUDGETS.md). Listing an item blocks nothing (D12).

`tine query` indexes the records as `sandbox_policies`,
`containment_findings` and `budget_ledger` (docs/QUERY.md); `--verify` marks a
row `verified` only for a pinned `runner` signer (a budget policy entry: a
pinned `policy` signer) that holds no `optimizer` role.

## Output

`--json` prints `tine-cli-containment/1`. The claim shapes are published as
`opentine-sandbox-policy-1` and `opentine-containment-finding-1`
(docs/schemas).
