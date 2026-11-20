# Model organisms

A model organism is a checkpoint or weight file trained to misbehave on
purpose, for alignment research (a sleeper agent, a reward hacker, a model with
a planted backdoor). OpenTine does not store or upload weights. It names an
artifact by its sha256 digest and keeps signed, held records about it:

- a **tag** that marks the digest as a model organism;
- **approvals** that let one run load it;
- an **access log** with one entry per gated load, allowed or refused;
- **untag** records, which take effect only with k-of-n oversight approval.

A hook and an MCP-proxy gate refuse a tool call that loads a tagged artifact
unless an approval names that artifact and the requesting run.

## Records

Each record except the access log is an attestation (an existing object kind)
on a small anchor run. Each is kept by a `tine hold` row whose target starts
with `organism:`, and `tine hold release` refuses those rows. No object kind
and no `tine verify` code is added: these are claim conventions with schemas in
`docs/schemas/`.

| Convention | Fields | Signed by | Hold |
| --- | --- | --- | --- |
| `opentine.organism-tag/1` | `artifact`, `names`, `reason`, `tagged_at` | a pinned `policy` or `curator` key that is not an `optimizer` key | `organism:tag:HEX` |
| `opentine.organism-approval/1` | `artifact`, `run`, `why`, `approved_at` | a pinned `approver` key with no `optimizer`, `monitor` or `scorer` role | `organism:approval:HEX` |
| `opentine.organism-untag/1` | `artifact`, `releases` (tag records), `untagged_at` | as a tag | `organism:untag:HEX` |
| `opentine.organism-access/1` | `artifact`, `run`, `outcome` (`allowed` or `refused`), `tool`, `approval`, `at` | none (a held blob) | `organism:access:HEX` |

A record counts as signed only when its Ed25519 signature verifies and the
`signer` field names the key that signed it. Roles come only from the
owner-pinned trust bundle (`tine trust bundle create --key-roles`). Without a
pinned bundle, `tag`, `approve` and `untag` are refused.

An artifact is **tagged** while at least one tag record names it and no
effective untag releases that record. A tag record that does not verify still
counts as a tag, because over-restricting is the safe failure. `tine organism
status` shows each record's verification.

## Loading a tagged artifact

```sh
tine organism tag ./ckpt/sleeper.safetensors --reason "sleeper-agent organism" \
    --name sleeper.safetensors --key policy.key
tine organism approve sha256:... --run SESSION_ID --why "probe study 12" --key approver.key
```

The gate looks at every string in the tool call's arguments, and at each word
of a string after splitting on whitespace, quotes and `=`. A call references a
tagged artifact when a string or word:

- contains the artifact's 64-hex digest; or
- equals one of the tag's `names` or its last path segment, or ends with
  `/NAME` or `/SEGMENT` (backslashes are read as `/`). A short, common file
  name therefore over-matches; that errs on the refusing side.

Tagging a file adds its path as a name. A call that references a tagged
artifact goes through only when a valid approval binds that artifact to the
requesting run. Every such call is recorded in the access log and held,
whether it was allowed or refused.

The requesting run is `--run` (or `--organism-run` on the proxy), else the
agent's `session_id`. A `run` field in the hook payload is ignored: it is a
claim the caller makes about itself. For an
MCP proxy with no `--organism-run`, it is the proxy's session name.

### The hook

```json
{"hooks": {"PreToolUse": [{"hooks": [{"type": "command",
  "command": "tine organism gate --agent claude-code --repo /path/to/repo"}]}]}}
```

The payload and response shapes are the same as `tine monitor gate`
(docs/MONITORS.md): Claude Code and Codex `PreToolUse`, Gemini CLI
`BeforeTool`, or the generic `opentine-monitor/1` payload. A refusal is
`permissionDecision: "deny"` (Gemini: `decision: "deny"`). The command always
exits 0.

### The MCP proxy

`tine mcp-proxy --organism-gate --repo PATH -- CMD` answers a refused
`tools/call` with JSON-RPC error `-32003`. The error's `data` has
`{"opentine.organism": {"artifacts": [...]}}`. Other messages are relayed
unchanged, and a monitor or budget guard still runs on whatever the gate lets
through.

### Failing closed

If the tag registry cannot be read, every gated call is refused. That covers
an unreadable holds file, a held tag or untag record that cannot be read, and
a repository that cannot be opened. Tags are also read from the object store,
so dropping a tag's hold row (or deleting the holds file) does not untag an
artifact; only an effective untag record does. A hook payload that cannot be parsed is let
through by default, as with every OpenTine hook (D12). Pass `--fail-closed` to
refuse it instead.

## Untagging

Removing a tag needs the oversight policy (docs/OVERSIGHT.md) to route
`source = "organism"` to a tier:

```toml
[[route]]
source = "organism"
tier = "high"
```

Each tag record has an oversight item `organism:attestation:sha256:...`. Use
`tine oversight request|approve ITEM` on it. `tine organism untag` writes an
untag record only when every live tag's item is `approved`. The registry checks
this again every time it reads the untag, so a later rejection makes the tag
live again. If no route covers organisms, untagging is refused.

## Limits

- The gate matches digests and recorded names. It does not hash files on each
  call, so it will not catch a renamed copy or a re-encoded or converted copy
  of the weights. Use `--name` for every path the artifact is loaded from, and
  pair the gate with containment evidence (docs/CONTAINMENT.md).
- The gate only sees tool calls that go through the hook or the proxy. A
  process with direct filesystem access is not mediated.
- Access-log entries are found through their hold rows. A process that can
  rewrite the holds file can hide an entry from `status` (the blob remains
  until garbage collection). Keep the repository out of the loop's write reach.
- Access-log entries are held but unsigned. They show what the gate decided.
  They do not prove who made the call.
