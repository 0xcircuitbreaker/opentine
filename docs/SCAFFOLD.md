# Scaffold manifests and MCP tool pins

A run's behaviour depends on more than its prompt: the harness also reads
instruction files, settings, hooks, skills, commands, agent definitions, rules
and MCP configuration, and an MCP server can change a tool's definition while
keeping its name. OpenTine records both, file by file and tool by tool, so a
change shows up as a precise, reviewable difference.

## Scaffold manifest

```bash
tine agent scaffold --harness claude-code --root . --json
tine agent scaffold --record RUN --key agent.key --repo .   # sign it onto a stored run
tine agent scaffold-diff before.json after.json
```

- The manifest is an `opentine.scaffold-manifest/1` document: one entry per
  scaffold file (`path`, `kind`, `sha256`, `bytes`, `target`, `resolved`,
  `via`) sorted by path, and `tree_sha256` over all entries. Content is never
  stored, only digests.
- Default file lists come from the harness code (`opentine/_scaffold_files.py`):
  for `claude-code` they are `CLAUDE.md`, `CLAUDE.local.md`, `.claude/CLAUDE.md`,
  `.mcp.json`, `.claude/settings*.json`, `.claude/hooks/**`, `.claude/agents/**`,
  `.claude/commands/**`, `.claude/skills/**`, `.claude/rules/**` and
  `.claude/output-styles/**`; `codex`, `gemini`, `opencode` and `cursor` have
  their own lists.
- Symlinks are recorded, never followed out of the root: a `link` entry keeps
  the link text, and its `sha256` is the target's only when the target is a
  regular file inside the root. A symlinked directory is one entry and is not
  descended into. A FIFO or device is a `special` entry and is never opened.
- `@path` imports in `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` (and the files they
  import, up to depth 5) are followed inside the root, outside code fences and
  inline code. An import outside the root (`~/...`, `/...`, `../...`) is an
  `external` entry, named but never read. An import that names no file is a
  `missing` entry, so planting it later is a visible change.
- At most 4096 entries (`scaffold.too-many-files` past it).
- `scaffold-diff` lists added, removed and changed paths; editing one skill
  file is a one-file change. A manifest file whose `tree_sha256` does not
  match its entries is refused.

**Per run.** A harness capture records `metadata.scaffold` (schema, harness,
source, file count, `tree_sha256`). `--record RUN --key KEY --repo PATH` signs
the full manifest onto the stored run: an existing `attestation` whose claim
follows `opentine.scaffold-manifest/1` (the manifest plus `run`), held as
`scaffold-manifest:RUN`, which `tine hold release` refuses. The record counts
as signed only when the signature verifies under the key its `signer` names.
A manifest whose paths or link targets read as credentials would be stored
altered by the scrubber, so it is refused (`scaffold.redaction`).

**Pinned list.** `tine agent scaffold-pin --harness H --glob G... --key KEY`
signs `.tine/scaffold/files.json` (an `attestation` under
`opentine.scaffold-files/1`) with a `policy`-role key from the owner-pinned
trust bundle that is not an `optimizer` key. A filed list replaces the
defaults for every harness it names. A filed list that does not verify, or
that names no entry for the harness, is refused (`scaffold.files-unpinned`):
it never falls back to the defaults.

## MCP tool-definition pins

`tine mcp-proxy` pins the first complete `tools/list` answer of a session (all
pages): `metadata.mcp_proxy.tool_defs.pinned` maps each tool name to its
`tool_def_digest`.

- `tool_def_digest` is `sha256:` over a domain tag and a canonical, lossless
  spelling of the definition as the server sent it: keys sorted, no
  whitespace, ASCII escapes, numbers as parsed (`1` and `1.0` differ). An
  object with duplicate keys keeps every pair in order, so it never hashes like
  a duplicate-free definition.
- Each `tools/call` step records `tool_def_digest` in `tool_info`, plus the
  server's `serverInfo` from the result `_meta` when present.
- A later listing that differs is recorded on its step
  (`advisory:mcp.tool-def-changed`, with `tool_def_changes`) and in
  `tool_defs.changes`. A call whose definition differs from the pin carries
  the same code; a call to a tool never listed carries
  `advisory:mcp.tool-unpinned`.
- Digests are taken before redaction. `tool_defs.redacted` names tools whose
  recorded definition the scrubber changed; their digest cannot be recomputed
  from the recording.
- `--tool-defs advisory` (default) only records and never blocks.
  `--tool-defs block` (stdio only) refuses such calls with JSON-RPC error
  `-32004` before they reach the server, including calls made before any
  listing (fail closed).

## The MCP server's protocol versions

`python -m opentine.mcp_server` speaks MCP 2026-07-28 (negotiated per request,
SDK 2.x) and keeps 2025-11-25 through the `initialize` handshake. An
`initialize` asking for a version newer than 2025-11-25 is refused with
`-32022` and the supported versions, instead of being answered with
2025-11-25, so a client that can speak 2026-07-28 is not moved to the older
version without noticing. An `initialize` for an older version is answered
with 2025-11-25. MCP tasks remain a 2025-11-25 feature. `serverInfo.version`
is the installed OpenTine version. With SDK 1.x only the handshake is
available.

## Limits

- The manifest proves which files were present and their digests at the time
  it was built, not that the harness read them, and not files the harness
  reads from outside the root (user-level settings, `~/...` imports).
- Default file lists follow harness releases and can lag behind them; pin a
  list when a harness reads more.
- Tool pins cover one proxied session; a definition that changed between
  sessions is a new pin, not a change.
- Blocking is stdio only; over Streamable HTTP the proxy records advisories.
- No new object kind and no new `tine verify` code: the records are claim
  conventions on existing attestations, and the codes are command-level.
