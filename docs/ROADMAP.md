# OpenTine roadmap: audit findings (0.34.0, November 2026)

The goal is to make OpenTine the universal version-control layer for agents and agent fleets.
This roadmap combines four audits: security, storage and scale, code quality and agent experience,
and competition. Every item names its source location so it can be picked up directly.

## Already strong

These areas were reviewed and found sound. They need no immediate work:

- **Canonical form and signatures:** RFC 8785 canonical form; signature blocks that reject
  algorithm confusion, re-encoded hex and null fields.
- **Untrusted input handling:**
  - Normalised ref names.
  - Bounded decompression and size caps on every untrusted input.
  - A hardened git bridge (no shell).
  - Hooks off by default and pinned to their file digests.
  - MCP server paths confined to the runs directory.
  - AEAD in the encrypted remote binds purpose, tenant, oid and size.
- **Concurrency:** under 16 concurrent writer processes the repository did not corrupt. `fsck`
  stayed clean and the reflog matched the updates that succeeded.
- **Integrations that competitors still lack:**
  - Import from and export to OpenTelemetry's GenAI semantic conventions.
  - Keyless Sigstore signing.
  - in-toto attestations and RFC 3161 timestamps.
  - A worktree per agent.
  - A multi-tenant HTTP remote with OIDC login and compare-and-swap ref updates.
  - Importers for Claude Code, Codex, Gemini, Cursor, Entire and others.

## Done

- `fix/ref-recovery-signature-hardening`:
  - A stale `<ref>..lock` staging file left by a crash no longer blocks every ref update.
  - Signature sidecars are locked during writes and capped at the size readers accept.
  - Signature blocks inside bundles are checked for shape and size.

## P0: correctness and security

| # | Item | Where | Fix |
|---|------|-------|-----|
| S1 | Breaking a stale lock can leave two holders, or delete a live lock (when `os.link` fails, or containers share a hostname and PID) | `repository/_lockfile.py:83-122` | Re-check `(st_dev, st_ino)` before the rename; treat a failed link-back as fatal; use `flock`/`LockFileEx` where available; add a boot id or PID-namespace id to the lock stamp |
| S2 | Bundle refs `heads/tags/x` and `tags/x` map to the same tracking ref; the import aborts after the pack is installed | `_bundle.py:174` | Keep the namespace in tracking refs, or reject collisions in `verify` |
| S3 | Bundle signatures are installed before the ref update; a failed unbundle leaves orphaned blocks | `_bundle_sigs.py` and its caller | Install signatures after the refs are updated; verify blocks against trusted keys |
| S4 | `tine rewind` can restore an imported run's writes into `.git/`, `.tine/` or `.github/workflows/` | `_rewind.py:191-207` | Refuse these locations by default; open files with `O_NOFOLLOW` relative to the directory to close the race between the symlink check and the write |
| S5 | The encrypted remote still opens `TINEAES1`/`2` ciphertexts that are not bound to a slot | `remote/_sealed.py` | Add an option to refuse these formats once a reseal is done; length-prefix the AAD |
| S6 | `atomic_write_text` follows a symlink when it copies the file mode | `_canon.py:155` | Use `lstat` |

## P0: agent fleets

| # | Item | Where | Fix |
|---|------|-------|-----|
| F1 | 178 of 320 writes to a shared ref failed under 16 writers: lock contention fails immediately and there is no retry | `_ref_txn.locked_after_recovery`, `_migration_preflight.py:133` | Retry with a bounded backoff and jitter; document one ref per agent plus a fan-in |
| F2 | Run-history merge is missing; branches from different agents cannot be reconciled | new | A merge-run object with several parents, a three-way semantic merge, conflict records, and a merge queue gated on `replay --verify` |
| F3 | Copies of one fleet agent (`count>1`) share one `cwd` and one identity | `fleet/_runner.py:91` | A manifest option `worktree = true` that reuses the fan-out worktree code; derive a child `agt_` identity and key for each member |
| F4 | `fleet up` killed with SIGKILL leaves its members marked "running" forever; `stop` writes a file nobody polls | `parallel/_state.py` | Record the supervisor's pid, start time and a heartbeat; report "orphaned"; add a cross-process lock on state |
| F5 | No live coordination between agents | new | Leases on refs; ref subscriptions and webhooks on the remote; agent-to-agent handoff (A2A) |

## P0: interface agents can rely on

| # | Item | Fix |
|---|------|-----|
| A1 | Errors go to stdout as Rich text even with `--json` (`_cli_common.py:44`, about 92 places) | One shared `fail()` that writes to stderr and emits `{"error":{"code","message"}}` under `--json`; it replaces the 16 duplicated `_fail` helpers |
| A2 | Every failure exits with code 1 | Documented exit codes: 3 not found, 4 verification failed, 5 budget exhausted, 6 trust required |
| A3 | Only 31 of 69 CLI modules support `--json`; `fleet up` accepts `--json` but ignores it | Add `--json` everywhere; add a test that runs every command with `--json` and parses the output |
| A4 | MCP exposes 14 tools against about 90 CLI commands | Add verify, log, fleet and fanout status, cost and agent show; generate MCP tools from the same command registry as the CLI |

## P1: storage and performance

Measured on 200 similar runs: 15,113 objects, 17.8 MB in canonical form.

| # | Item | Measured | Fix | Expected gain |
|---|------|----------|-----|---------------|
| P1 | Loose objects take one 4 KiB disk block each | 45 MB on disk for 3.8 MB of objects | Append-only loose pack log, or autopack based on object count and bytes | About 10x less disk before gc |
| P2 | One file plus one fsync per object; every save re-validates the whole run | About 57 events/s | Write each run as one pack with one fsync; skip re-validating links | 10x or more |
| P3 | Pack blocks are compressed independently, with no dictionary and no cross-run delta | 1.72 MB after gc, against 0.84 MB for one zstd stream | A zstd dictionary per kind, trained at gc time (2.2x better than zstd per object); long-distance matching; binary deltas for blobs that share a prefix | 1.5-2x smaller packs and transfers |
| P4 | One file per ref and per reflog; `list_refs` opens every ref | About half the disk after gc | A `packed-refs` file or reftable written by gc | About 2x smaller; listing becomes one read |
| P5 | Fetch sends every local oid as a "have" (up to 4M, cut off silently) | Up to about 300 MB per request | Negotiate on ref tips and stop at runs the server already knows; optionally a bloom filter | Request size proportional to refs, not objects |
| P6 | No chunking or lazy fetch for large blobs | Every edit stores the whole blob again | FastCDC chunks for payloads over 1 MiB; promisor-style lazy fetch | Near-total dedup |
| P7 | Every pack index is loaded into one dictionary at process start | Memory and time proportional to the number of objects | A sorted index with a fanout table, mmap'd | Fast cold start |
| P8 | zstd needs the `opentine[zstd]` extra on 3.11-3.13 and is not in `all`; without it OpenTine silently falls back to zlib | None | Add zstd to `all`, or make it a core dependency | Better default ratios |

## P1: features (from the competitive review)

| Item | Why | Effort |
|------|-----|--------|
| TypeScript SDK (capture, plus a v4 reader and verifier), then Go and Rust | Most agent frameworks are written in TS; the conformance vectors already exist | 3-5 weeks for TS |
| A live web UI served by the remote | Hosted UIs are where LangSmith, Langfuse and Entire win; `tine view` is a static page | 3-4 weeks |
| A native two-way LangGraph checkpointer | Lets users go back to and fork earlier states inside LangGraph | 1-2 weeks |
| SLSA provenance and a published in-toto predicate | Lets existing supply-chain verifiers check runs | 1 week |
| Import from durable-execution engines (Temporal, Restate, DBOS) | Fork a production workflow from its own history | 2-3 weeks |

## P2

- **Data and provenance:**
  - C2PA manifests for media that agents produce.
  - Interop with DVC, lakeFS and Oxen for large artifacts.
- **jj-style history:** an operation log and first-class conflict objects, after F2.
- **Evaluation workflows:** evaluation datasets, annotation queues and dashboards.

## Maintenance

- **Make tests work out of the box:**
  - Move `dev` to `[dependency-groups]` so `uv sync && uv run pytest` works.
  - Add `pytest-xdist`. The serial suite takes about 8 minutes.
  - Skip `test_the_command_cannot_read_the_supervisors_fds_memory_or_environment` when euid is 0.
  - Exclude the `live` markers by default.
- **Type checking:** add mypy or pyright, starting with `kernel.py`, `parallel/` and `fleet/`.
- **Startup time:** load `asyncio` and the runtime lazily (PEP 562) to save 70-150 ms per `tine` call.
- **Module size cap:** relax the 250-line cap (`scripts/check_architecture.py:11`). There are 55 `# fmt: skip` workarounds. Move the CLI into an `opentine/cli/` package.
- **Error handling:** narrow the roughly 50 `except Exception` sites.
- **Fix outdated docs:**
  - "0.9.x supports" in `README.md:53`.
  - `tine pricing install`, which does not exist, in `docs/PRICING.md:256` and `docs/SECURITY_MODEL.md:120`.
  - "later 0.3.x" notes.
  - Add a docs lint test that runs `--help` for every `tine` command the docs mention.

## Suggested order

1. Security and robustness: S1-S6, F1.
2. Interface agents can rely on: A1-A3, plus the maintenance quick wins.
3. Storage: P8, P2, P1, P3, P4.
4. Fleets: F3, F4, then F2 (merge).
5. Network: P5, P6.
6. Ecosystem: the TS SDK, the web UI and the LangGraph checkpointer.
