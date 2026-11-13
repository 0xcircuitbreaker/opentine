# OpenTine roadmap: 0.35 to 0.60

*Status, 2026-11-13: 0.35–0.50 are delivered (§8, §10) and 0.51 is delivered (§12). §11 covers the web platform and §12 plans 0.51–0.60, with the owner decisions of 2026-11-13; 0.60 is a waypoint on the way to 1.0, not 1.0 itself. Status, 2026-11-07: §10 planned 0.45–0.50 and §11 the web platform. Original baseline: v0.34.0, November 2026. Horizon: about **7–9 months**. Each release below is 3–5 weeks of work, not the 1–3 weeks the earlier draft claimed. Work that does not fit has moved to "0.45+" or the 1.0 track and is not hidden inside a release. Every claim that OpenTine "lacks" something was grep-checked in `opentine/`. Claims about competitors come from a survey of a subset of tools and are stated with that caveat.*

## 1. Prior roadmap items, copied inline

These come from `docs/audit-roadmap:docs/ROADMAP.md`.

| ID | Finding | Location | Fix | Release |
|---|---|---|---|---|
| S1 | Breaking a stale lock can leave two holders, or delete a live lock (failed `os.link`, or containers sharing a hostname and PID) | `repository/_lockfile.py:83-122` | Re-check `(st_dev, st_ino)` before the rename; treat a failed link-back as fatal; use `flock`/`LockFileEx` where available; add boot_id and the PID-namespace inode to the lock stamp | 0.35 |
| S2 | Bundle refs `heads/tags/x` and `tags/x` collide in the tracking namespace; the import aborts after the pack is installed | `_bundle.py:174` | Keep the namespace in tracking refs, or reject collisions in verify | 0.35 |
| S3 | Bundle signatures are installed before the refs are updated | `_bundle_sigs.py` | Install them after the refs; verify against trusted keys | 0.35 |
| S4 | `rewind` can write into `.git/`, `.tine/` or `.github/workflows/` | `_rewind.py:191-207` | Deny these paths by default; open files with `O_NOFOLLOW` relative to a directory fd | 0.35 |
| S5 | TINEAES1/2 open without slot binding | `remote/_sealed.py` | Opt-out after reseal; length-prefix the AAD | 0.35 |
| S6 | `atomic_write_text` follows a symlink when copying the file mode | `_canon.py:155` | Use `lstat` | 0.35 |
| F1 | 178 of 320 writes to a shared ref failed under 16 writers; contention fails with no retry | `_ref_txn.locked_after_recovery` | Bounded backoff with jitter | 0.36 (re-measured as a gate) |
| F2 | No merge of run histories | new | `parents[]`, three-way merge, conflict objects, merge queue | 0.45+ (design in 0.43) |
| F3 | Fleet members with `count>1` share one cwd and one identity | `fleet/_runner.py:91` | Per-member worktree and derived `agt_` key | 0.43 |
| F4 | A SIGKILLed `fleet up` leaves members "running" forever | `parallel/_state.py` | Supervisor heartbeat and orphan report | 0.43 |
| F5 | No live coordination | new | Leases, subscriptions, webhooks | 0.43 / 0.44 |
| A1 | Errors go to stdout as Rich text even with `--json` (about 92 sites, 16 `_fail` copies) | `_cli_common.py:44` | One shared `fail()` that writes to stderr | 0.36 |
| A2 | Every failure exits with code 1 | — | Exit codes 3 (not found), 4 (verify failed), 5 (budget exhausted), 6 (trust required) | 0.36 |
| A3 | Only 31 of 69 modules support `--json` | — | `--json` on every *subcommand* (counted from the registry, not by module) | 0.36 |
| A4 | MCP has 14 tools against about 90 commands | `mcp_server.py:213-230` | Generate tools from the registry, **read-only unless they are annotated as writes** | 0.36 |
| P1 | Each loose object takes one 4 KiB disk block | — | Autopack by object count and bytes | 0.37 |
| P2 | One fsync per object; every save re-validates the run | ~57 events/s | One pack per run; skip re-validating links | 0.40 |
| P3 | Per-kind dictionaries | — | **Demoted to the 1.0 track** (long mode beats them, see §3) | 1.0 track |
| P4 | One file per ref | — | `packed-refs`, written by gc | 0.37 |
| P5 | Fetch sends every local oid as a "have" | up to ~300 MB | Negotiate on ref tips | 0.37 |
| P6 | No chunking or lazy fetch | — | Decided by the CDC bake-off in 0.40 | 0.40 / 1.0 track |
| P7 | All pack indexes loaded into one dict at start-up | — | mmap'd fanout index, and `has()` asks the pack index first (`_paths.py:55`) | 0.37 |
| P8 | zstd needs an extra on Python 3.11–3.13 | — | Add zstd to `all` (not a core dependency, see §6) | 0.37 |

---

## 2. Invariants for every release

1. **Old formats stay readable for ever.** This covers `.tine` v1–v4, pack v1/v3, TINEPACK4, tine-sig/1–3 and TINEAES1–4.
   - **Writer defaults change only after a deprecation window.** A new file format, which cannot be negotiated, becomes the default no earlier than two minor releases after its reader ships.
   - Wire formats may switch sooner, but only toward a peer that advertises support for them.
2. **Digests and signatures cover canonical RFC 8785 bytes only.**
   - Stored forms (compression, deltas, chunks) must be reversible, and they are checked against the oid on read.
   - Any change that alters the canonical bytes for the same input, such as a new redaction ruleset, must say so in its release notes.
   - Each run records the `redaction_ruleset` version that produced it.
3. **Offline verification never touches the network.** From 0.35 an audit hook enforces this on every platform. On Linux and macOS a hermetic re-exec enforces it as well (see 0.35 for Windows).
4. **Agnostic first.**
   - The generic hook protocol, OTLP and the MCP proxy are the primary capture paths.
   - Vendor adapters are thin. Each one ships with fixtures and a named owner.
5. **Standing CI jobs.**
   - A **0.34 peer compatibility** job: the 0.34 CLI reads every new file, and a 0.34 HTTP client talks to the current server.
   - Hardware-pinned performance gates (GitHub `ubuntu-24.04` 4-vCPU runners, single-threaded unless stated). Gates are *relative*: a new path is compared against the old path on the same runner.
6. **Deletion is hold-aware** from 0.35 onward.

These invariants are published as the deprecation policy in [DEPRECATION.md](DEPRECATION.md) (0.50, criterion 7).

---

## 3. Competitor landscape (subset surveyed; cells left blank where the research shows nothing)

| Capability | OpenTine 0.34 | Entire | Claude Code / Cursor checkpoints | GitButler | git-ai | jj | Langfuse / LangSmith / Braintrust / Phoenix | Xet / lakeFS / Dolt | Release |
|---|---|---|---|---|---|---|---|---|---|
| Signed, content-addressed run graph | Yes | Git shadow refs, unsigned | Local, expiring | No | git notes | Op log, unsigned | No | Data only | — |
| Offline verification | Yes, guard bypassable | not found | not found | not found | not found | n/a | not found | not found | 0.35, 0.39 |
| Per-agent-turn workspace snapshots | No (session end only) | Yes (hooks) | Yes | Yes (Pre/PostToolUse) | | Snapshot on command, not per turn | | | 0.38 |
| Line attribution that survives rebase | No | Yes | | | Yes | | | | 0.42 |
| Push preview / separate transcript remote | No | Yes | | | | | | | 0.36 |
| Undo / op log | No | | Yes (rewind) | | | Yes | | | 0.36 |
| Persistent search | No (scan, 10k cap) | Search reported | | | | | Yes | | 0.44 |
| Leases / task claims | No | | Agent teams (mutable JSON) | | | | | | 0.43 |
| Eval runner / datasets | No | | | | | | Yes | | 0.45+ |
| Transparency log with witnesses | No | | | | | | | | 0.44 |

Sources: entireio/cli README, docs.entire.io, code.claude.com/docs/en/checkpointing, docs.gitbutler.com, github.com/git-ai-project/git-ai, the jj operation-log docs, langfuse.com/self-hosting, huggingface.co/docs/xet/deduplication, docs.dolthub.com, blog.sigstore.dev/rekor-v2-ga, datatracker.ietf.org/wg/scitt. The earlier draft's cells "Entire Web UI = Yes", "Entire Undo", "GitButler Undo" and "jj per-turn snapshots" were not supported by the research and have been removed. We do not claim any capability is "unique". We say only that it was not found in the tools we surveyed.


### 3a. Update, 2026-11-07

The table above describes the 0.34-era survey and is kept as written. The facts below were re-collected for the 0.45–0.50 plan. A fact with a single secondary source, or that is a vendor claim, is marked (unverified). We still make no "unique" claims: "not found" means not found in the tools and pages we checked, as of this date.

| Tool | What it is now | Relevant to | Source |
|---|---|---|---|
| Entire | "The Git forge for agent-human collaboration". Founded and led by Thomas Dohmke, GitHub's CEO until August 2025. $60M seed led by Felicis (reported $300M valuation). MIT-licensed Go CLI that captures checkpoints under `refs/entire/checkpoints/*` with an `Entire-Checkpoint` trailer, plus `entire blame` and `entire why`. Hosted forge: git hosting and GitHub mirrors, Trails (a PR replacement with approvals and gates), Continuous Memory (entire-brain, entire-graph), Agentic Search, CI, and hosted agents billed per token. Hosting, Trails, sessions, memory, search and the CLI are free during the preview. Redaction is documented as "best effort", and the HTTP API as "internal, subject to change". Checkpoints are git refs protected by git commit signing; gittuf RSL covers Entire-hosted repos only. Forge launch about 2026-10-26 with four regions and "418 pushes/s" (unverified). Opus 5.5 at $4/$20 per million tokens on the pricing page (unverified) | 0.45 blame/attach/importer, 0.46 hosted beta, 0.47 Reviews | entire.com, entire.com/company, entire.com/pricing, entire.com/features/trails, docs.entire.com (privacy-and-redaction, reference-state-log), github.com/entireio/cli; TechCrunch 2026-02-10; SiliconANGLE |
| Git AI | `git ai blame`, a commit-time AI share, and Git AI Standard v3 notes. Its builders reportedly joined OpenAI's Codex team around 2026-09 (unverified: one X post and one outlet; OpenAI's post does not describe an acquisition). Whether its paid platform winds down is also unverified | 0.45.x v3 notes reader and writer | github.com/git-ai-project/git-ai, usegitai.com; The New Stack |
| Traces | Hosted session sharing, plus `refs/notes/traces` | 0.46 share links | traces.com |
| AgentLogs | Hosted transcript sharing; pushes transcripts by default (unverified) | 0.45 pre-push redaction gate, 0.46 share links | to verify against its own docs |
| GitHub artifact attestations | `actions/attest-build-provenance`: Sigstore-backed signed build provenance on github.com. Signed provenance therefore exists at the platform level; it covers build artifacts, not agent runs | 0.46 CI Action, 0.46 in-toto `agent-run/v1` predicate | docs.github.com (artifact attestations) |
| Aegis Ledger SDK, AIR blackbox / ProofTrail | Each claims signed or tamper-evident agent logs (unverified, not analysed). Until they are checked, we do not say that nobody signs agent runs | 0.46: analyse before any comparison claim | to verify |

The harness vendors' own sharing (Claude Code session sharing, Codex cloud task logs, Devin replay, Amp threads) also competes with share links, and users get it free inside the tool.

---

## 4. Compression: middle-out, honestly

Pied Piper's "middle-out" algorithm is fiction, and so is the Weissman score (IEEE Spectrum: https://spectrum.ieee.org/a-madefortv-compression-algorithm). We took two real ideas from it:

- **Layering.** Structure-aware transforms run first and the entropy coder runs last.
- **A literal reading of "middle-out".** Keep the shared prefix and suffix of two versions and store only the middle. As a stand-alone format this gains little (58.3x against 54.0x). It is useful as a **heuristic for choosing delta bases**, so that is how we use it.

### Layered stack (every layer is reversible; the oid covers L0)

| Layer | Content | Release |
|---|---|---|
| L0 identity | Canonical JSON, sha256, signatures. A hash-algorithm tag is reserved in the spec only. | 0.41 (spec) |
| L1 semantic | RUN_DELTA and EVENT_SLIM (existing). New: BLOB_PREFIX_DELTA (zstd patch-from, base chosen by middle-out matching) **or** 2–64 KiB CDC, whichever wins the bake-off. Text blobs in `.tine` v5. | 0.40 |
| L1b at record time | Split shared prompt prefixes (system prompt, tool definitions) into their own blobs at capture time | 0.38 |
| L2 structural | TINEPACK5 in recording order; 4 MiB blocks; reads in block order; packed-refs | 0.37 |
| L3 corpus | zstd long-distance matching, window_log=27. Dictionaries move to the 1.0 track. | 0.37 |
| L4 entropy | zstd-3 for autopack, zstd-9 for wire, zstd-19 for gc. `--level` on gc and autopack. xz archival profile. | 0.37 |

### Benchmark: 209.8 MB synthetic corpus, 9,868 objects, hardware not recorded

Log: benchmark scripts and raw log to be committed under `scripts/bench/` in 0.37

Speeds are indicative only. 0.37 re-measures them on the pinned runner.

| Method | Size | Ratio | Compress MB/s | Access |
|---|---|---|---|---|
| Default pack v1, zstd-19 | 31.0 MB | 6.77x | 30 | block |
| `gc --upgrade` pack v3 | 16.3 MB | 12.87x | 2.2 | block |
| TINEPACK4 wire, zstd-9 | 26.1 MB | 8.02x | 65 | stream |
| zstd-19 + per-kind dictionary, 1 MiB blocks | 20.0 MB | 10.48x | 4.0 | block |
| zstd-9 `--long=27` (proposed wire) | 5.15 MB | 40.8x | 185 | stream |
| zstd-19 `--long=27` | 3.89 MB | 54.0x | 5.3 | stream |
| Middle-out delta + zstd-19 long | 3.60 MB | 58.3x | 6.2 | stream |
| Patch-from + run-ordered **1 MiB** blocks, zstd-9 | 7,327,910 B | 28.63x | ~25 | object |
| Patch-from + run-ordered **4 MiB** blocks, zstd-9 | ~6.88 MB | ~30.5x | ~25 | object |
| xz `-6`, 256 MiB dictionary (archival) | 3.44 MB | 60.9x | 2.1 | stream |

The earlier draft gave a decompression figure for pack v3 (2.9 MB/s). That number was not in the verified research and has been dropped.

Real corpus: 11 transcripts.

- `.tine` blobs stored as text instead of base64: -26% (zstd-3) and -43% (zstd-19).
- Recording-order wire pack: -28%.
- Semantic delta against patch-from on a growing snapshot: 47x against 187x.

### Conflicting CDC evidence, settled by a gate rather than by choice

Three measurements disagree:

- One researcher measured **6.1x** for 2–64 KiB CDC on transcripts and rated it P0.
- The bench measured low dedup on *edited files* and rated it P2.
- The compression research says CDC pays off only above about 1 MiB.

All three can be true, because they measured different corpora. **0.40 runs a bake-off on the real transcript corpus**, plus at least 50 real Claude Code and Codex sessions collected with consent:

- CDC (2/8/64 KiB) against BLOB_PREFIX_DELTA against both combined.
- Measured on size, CPU and random-access latency.
- The winner becomes the default, and the loser stays behind a flag or is cut.

### Targets (one wire figure everywhere)

- **Wire and bundles: ≤6.0 MB on the synthetic corpus, a 77% cut from 26.1 MB.** We also gate on at least 20% smaller on the real corpus.
- Local packs after gc: ≥25x on the synthetic corpus, plus a gate on the real corpus.
- `.tine` v5: -26% or better.
- Autopack writing delta packs is conditional. It becomes the default only if autopack p95 latency stays ≤1.5x the 0.36 latency. Otherwise delta packing happens in gc only.

### Ruled out or deferred

- LLM and context-mixing compressors (ts_zip, nncp, cmix): too slow, and tied to exact model weights. They are never readable by verify.
- Brotli: capped at 14.9x by its window.
- Trained dictionaries (codec 3, signed catalog, per-tenant sealing): **1.0 track**. They measured 10.5x, below long mode, and add a large security surface.
- **Never deduplicate across tenants.** This is a hard rule for the sealed remote and for any future shared store.
- An oid token table in wire packs and an OpenZL numeric spike: 1.0 track.

---

## 5. Security and gap register

### Security items

**P0**

| ID | Finding (evidence) | Release |
|---|---|---|
| X1 | Retired TSA still verifies (`_verify_timestamp.py:43`, `_tsp_verify.py:93-103`; PoC) | 0.35 |
| X2 | KMS writes unbound TINEAES2 (`remote/security.py:216-241`; PoC). **Changes the stored ciphertext**, with a reseal path. | 0.35 |
| X3 | Offline guard bypassable through `_socket`, `sendto` or subprocess (`_offline_guard.py`) | 0.35 |
| X4 | `prune --delete` races a concurrent link (`_gc_prune.py:109-160`) | 0.35 |
| X5 | Shell allowlist checks argv[0] only (`tools/shell.py:80`) | 0.35 (argument policy), 0.41 (OS sandbox) |
| X6 | Redaction misses about 17 shapes (`_redact_shapes.py`). **Changes canonical bytes for new captures.** | 0.35 |
| X20 | Timestamp binds the run root, not the signature (`_timestamp_sidecar.py:35-40`) | 0.39 |
| X21 | Capture tier never surfaced (`trace/_transcript_common.py:57`) | 0.39 |
| X32 | Fleet identity is self-asserted (`_agent_identity.py:16-17`) | 0.43 |
| X33 | Audit log verifiable only by the server (`remote/_audit.py`) | 0.44 |

**P1**

| ID | Finding (evidence) | Release |
|---|---|---|
| X8 | OTLP receiver: DNS rebinding, crash on a scalar body, unbounded resources (`_otlp_http.py`) | 0.35 |
| X12 | Replay sends an untrusted recorded prompt to a live agent (`_cli_replay.py:50-63`) | 0.35 |
| X13 | 1000:1 ratio cliff (`_codec.py:135-141`) | 0.35 (reader), 0.37 (writer, peer ≥0.35) |
| X15 | Remote: no quota; OIDC not wired; 16-byte tokens; 500s leak exception class | 0.36 (OIDC, tokens, 500s), 0.44 (quota) |
| X17 | New compression modes need decoder window caps, delta chain limits and length padding | 0.37, 0.40 |
| X22 | Verify report is not itself evidence (`_verify_report.py:33-84`) | 0.39 |
| X23 | No key lifecycle | 0.41 |
| X24 | Keys stored as plaintext hex | 0.41 |
| X29 | No PQ or hybrid signatures; no hash agility | 0.41 |
| X34 | Keyless verification hard-wired to Rekor v1 | 0.44 |

**P2**

| ID | Finding (evidence) | Release |
|---|---|---|
| X9 | Record proxy: negative Content-Length reads to EOF (`_record_proxy.py:69-70`) | 0.35 |
| X10 | MCP write tools on by default (`mcp_server.py:206-211`) | 0.35 |
| X11 | `tine view` has no re-scrub and no CSP | 0.35 |
| X14 | Stale claim in SECURITY_MODEL (`docs/SECURITY_MODEL.md:637`) | 0.35 |
| X16 | No SBOM, pip-audit, Dependabot, CodeQL, zizmor or Scorecard | 0.36 |
| X18 | Temp files left by killed writers never reclaimed | 0.37 |
| X19 | No F_FULLFSYNC on macOS | 0.37 |
| X25 | Per-agent key scoping ignored (`_agent_keys.py:151-157`) | **0.35** (moved up, needed by X12) |
| X26 | RFC 3161 verifier gaps | 0.41 |
| X27 | tine-attest/2 record not bound to the envelope signer | 0.41 |
| X28 | TINEAES has no key id or epoch | 0.41 (TINEAES5) |
| X30 | No FIPS mode | 0.41 |
| X31 | Stale TUF root never flagged | 0.41 |

### Other verified gaps not in the security table (each grep-checked as absent)

| Gap | Evidence | Release |
|---|---|---|
| `tine stats` reads only the legacy `.tine_runs` index; v3 repos are wrong. This is a **correctness** bug. | `_cli_render.py`, `_cli_export.py` reference `.tine_runs` | 0.36 |
| fsck performance budget (target ≤2.5 ms per event) | none | 0.37 |
| `has()` should ask the pack index first | `_paths.py:55` | 0.37 |
| Hold-aware deletion | `RetentionHook` interface only (`remote/interfaces.py:85`) | 0.35 (minimal), 0.39 (policy) |
| Prompt-prefix splitting at record time | none | 0.38 |
| Generic hook protocol, per-turn tree snapshots | snapshot only at session end | 0.38 |
| MCP proxy capture | none | 0.38 |
| External blob pointer `{uri, sha256, size}` (no S3 needed) | none | 0.40 |
| `tine explain RUN` (offline summary stored as an annotation) | no `explain` command | 0.42 |
| Entire **export** (`--format entire`) plus fixtures captured from the current entireio/cli | import only | 0.42 |
| Roo and Cline VS Code globalStorage importers (a Cline *CLI* harness exists, `harnesses/_harness_rows.py:182`) | no globalStorage reader | 0.42 |
| Windsurf and Jules importers | grep = 0 | 0.42 (Windsurf), 0.45+ (Jules, cloud API) |
| Bedrock: decide whether the proxy runs in CONNECT/local-CA mode or Bedrock routes through OTel | none | 0.42 (decision: OTel; CONNECT proxy on the 1.0 track) |
| OTLP metrics from cost aggregates; signed cost-statement attestation; webhook/OTLP alerts | none | 0.44 (metrics, statement), 0.45+ (alerts) |
| Direct export/import to Langfuse, Phoenix, Braintrust or LangSmith (only OTel attributes today, `trace/exporters.py`) | none | 0.45+ |
| Datasets: `tine dataset add --from-run`, JSONL/HF/Langfuse I/O | none | 0.45+ |
| Air-gapped audit kit | none | 0.39 (pyz plus report), 0.45+ (full kit) |
| S3 Object Lock / Azure immutable-blob retention backends | `remote/` has none | 0.45+ |
| C2PA `tine media sign` | none | 1.0 track |
| Pluggable snapshot providers; `rewind --with-side-effects` | none | 1.0 track |
| PQ re-timestamping, `attest --renew` (RFC 4998) | none | 1.0 track |

---

## 6. Compatibility treatment (verified or gated)

- **Unknown fields inside events and runs** (`tree` links, fleet sub-records). Of the schemas grepped, only `_verify_report.py:43,72` and `tools/__init__.py:48` set `additionalProperties: False`. Run and event validation must still be **tested** against the 0.34 CLI in the 0.34 peer compatibility job before 0.38 ships tree links.
- **New object kinds** (tree in 0.38). 0.34 fsck and the pack reader are tested against a repo containing them. If 0.34 rejects unknown kinds, trees go into a separate pack that 0.34 skips, and the release notes say so.
- **Extra signatures** (hybrid in 0.41). How the 0.34 tine-sig/3 verifier treats an unknown signature entry is **unknown**, and must be tested against 0.34 before 0.41. If 0.34 rejects them, hybrid signatures go into a detached sidecar (additive), never into the envelope.
- **zstd window_log=27.** The decoder default limit in both python-zstandard and the stdlib/backports is believed to be 27. This must be checked with a 0.34 decoder in CI. If it fails, long mode is tied to TINEPACK5 and `.tine` v5 only. Until 0.39, `.tine` v4 exports do *not* use long mode.
- **`.tine` v5 is a file format and cannot be negotiated.**
  - The reader ships in 0.40.
  - The writer default stays v4 until 0.42. From 0.42, `--for-legacy` (and `evidence export`) still write v4.
- **HTTP remote capability matrix.** The server advertises `caps` (ref-txn, tlog, 429, SSE). A 0.34 client must still work against every server version up to 0.44. Any new behaviour is gated on the client's advertised version.
- **Op log gaps.** Older clients do not write `.tine/oplog`. `undo` compares the op log against the reflogs, and refuses to cross a gap until the user passes `--force`.
- **Hook installation changes the user's agent config.**
  - `tine enable --dry-run` shows the diff before anything is written.
  - `tine disable` removes the hooks and is tested to restore the config byte for byte.
  - The generic `tine hook` protocol is primary. Vendor configs only point at it.
- **zstd dependency.**
  - zstd is added to the `all` extra, not made a core dependency, so `pip install opentine` stays stdlib-only.
  - `evidence export` defaults to the archival profile (zlib or xz).

---

## 7. One log primitive

The earlier draft built three separate append-only logs (op log, custody, tlog). This plan builds one.

- **0.36:** `opentine-log/1`. A hash-chained record log stored in the C2SP tlog-tiles layout, with signed-note checkpoints. The op log is its first user.
- **0.39:** chain of custody reuses it (signed and timestamped entries).
- **0.44:** reflog, remote audit and witnesses reuse it. That release adds publishing and cosigning, not a format migration.

---

## 8. The ten releases

**Status (2026-11-07):** all ten are delivered on `feat/transparency-search-0.44`. The scope and acceptance text below is kept as planned; deviations are recorded in `CHANGELOG.md`.

| Release | Status |
|---|---|
| 0.35.0 | Delivered |
| 0.36.0 | Delivered |
| 0.37.0 | Delivered |
| 0.38.0 | Delivered |
| 0.39.0 | Delivered |
| 0.40.0 | Delivered |
| 0.41.0 | Delivered |
| 0.42.0 | Delivered |
| 0.43.0 | Delivered |
| 0.44.0 | Delivered |
| 0.45.0 | Delivered (§10) |
| 0.45.1 | Delivered (§10, 0.45.x) |
| 0.46.0 | Delivered (§10) |
| 0.46.1 | Delivered (§11, project formats) |
| 0.47.0 | Delivered (§10, §11 projects second half) |
| 0.48.0 | Delivered (§10; counsel sign-off and the 72 h fuzz run outstanding) |
| 0.49.0 | Delivered (operator kit and test paths; the public witness, independent operators and live MinIO/AWS/Azure runs outstanding) |
| 0.50.0 | Delivered (freeze candidate; criterion 7 met; the audit engagement, 30 nightly green days, green CI runs of the parity, peer-compat, audit-kit and bench jobs, counsel sign-off and the 72 h fuzz outstanding) |
| 0.51.0 | Delivered (§12; the browser verifier reads bundles and trust bundles, TS codec-3, gates produce evidence, D1 in force with no predicate granted; outstanding: tag-locked npm packages and the tineyard version-lag CI check, Firefox/WebKit harness runs, three consecutive green main runs, the audit engagement letter) |

**Status:** 0.50.0 ended the §10 plan; §12 plans 0.51–0.60 toward 1.0, and 0.51.0 is its first release.

### 0.35.0: Security hardening (about 5 weeks)

**Scope:**

- **X1–X4**, as specified in the prior draft.
  - X2 envelope-encrypts with a KMS-wrapped DEK. This **changes the stored KMS ciphertext**. `tine serve reseal --from aes2` converts existing data.
  - X3 adds a PEP 578 audit hook (socket, subprocess, exec) on every OS, plus `--hermetic`:
    - Linux: `unshare -rn` or bwrap.
    - macOS: `sandbox-exec`.
    - **Windows: `--hermetic` is unsupported and exits with code 6. The audit hook alone is documented as best-effort.**
  - X4 deletes through a quarantine directory with a reachability re-check.
- **Minimal hold.**
  - `tine hold add/list/release <oid|ref>` writes `.tine/holds`.
  - gc, prune, rewind and remote delete refuse to touch held objects.
  - **gc stops deleting unreachable objects by default** (it needs `--prune=now`) until 0.39 adds retention policy.
- **S1–S6** (§1). S1 covers the PID-namespace inode, boot_id and `flock`/`LockFileEx`.
- **X25, moved here.** A verified key must belong to the claimed agent, so that X12's "trusted signature" means *that agent's* key.
- **X5 (argument level):** per-executable argument denylists and path confinement.
- **X6:**
  - Vendored gitleaks rules, normalization and an entropy fallback.
  - Each run records `redaction_ruleset`.
  - Release notes state that the same input may get a different oid than under 0.34.
- **X8–X12:**
  - X10: MCP is read-only by default, including every tool generated later (0.36).
  - X12: replay needs `--prompt`, a signature from the claimed agent, or `--trust-recorded-prompt`.
- **X13 (reader)** and **X14**.

**Acceptance:**

- poc_tsa and poc_kms fail closed.
- Linux: `strace -f -e trace=network` shows zero network syscalls under `--hermetic`. macOS: the sandbox profile denies network and a probe test confirms it. Windows: the probe test is blocked by the audit hook.
- 1,000 rounds of prune against link lose 0 objects. The hold matrix (gc, prune, rewind, remote delete) deletes 0 held objects.
- Redaction is measured three ways:
  - Recall of 100% on the vendored-rule fixture.
  - Recall of ≥95% on a **held-out** corpus (SecretBench samples and synthetic shapes not taken from gitleaks).
  - Under 1 false positive per 10k lines on a clean corpus of code and transcripts. False positives change canonical bytes, so this budget is a hard gate.
- An OTLP fuzz run of 10k bodies causes 0 crashes.
- In the 0.34 peer compatibility job, 0.34 reads every 0.35 output.

### 0.36.0: Agent contract, log primitive and undo (about 4 weeks)

**Scope:**

- A1–A4 (§1).
  - A4 tools are generated from the registry. Any tool annotated `writes=True` is hidden unless `--allow-writes`.
- F1 retry.
- `opentine-log/1` (§7), with `tine op log` and `tine undo`. Undo is a forward transaction, and it detects gaps (§6).
- `tine push --dry-run/--outgoing` with a signed push manifest; `tine.transcriptRemote`.
- **`tine stats` over v3 repos**, fixing the legacy-index correctness bug.
- X15: OIDC in `tine serve`, a 32-byte token floor, backoff after repeated 401s, and a generic 500 with a request id.
- X16: SBOM, pip-audit, Dependabot, CodeQL, zizmor and Scorecard; the build job is split from the test extras.

**Acceptance:**

- 100% of *subcommands* (counted from the registry) return parseable `--json` and documented exit codes.
- The read-only MCP default exposes 0 write tools. `--allow-writes` exposes exactly the annotated set.
- F1 is **re-measured** on the pinned runner (prior figure: 178 of 320 failed). After the fix, 16 writers × 20 updates produce 0 failures.
- `undo` round-trips every ref-moving command. A mixed-version test with 0.34 detects the op log gap.
- On a v3 repo, `tine stats` matches a ground-truth count.

### 0.37.0: Long-window, recording-order packs (about 4 weeks)

**Scope:**

- **Long mode.** window_log=27 with long-distance matching. Decoders cap the window at 27 (X17).
- **TINEPACK5** in recording order, allowing EVENT_SLIM and RUN_DELTA forms. It is negotiated, and **sent only to peers advertising ≥0.37**. Peers at 0.34–0.36 get TINEPACK4.
- **Writer fix for X13.** Codec v2 frames are written only to peers advertising ≥0.35, and are never written into `.tine` v4.
- **Pack layout and indexes:**
  - Reads in block order; 4 MiB blocks.
  - P1 autopack, P4 packed-refs, P5 tip negotiation.
  - P7 mmap'd fanout index; `has()` asks the pack index first.
- **Codecs and levels:**
  - Codec 4 = xz.
  - `--archival` produces stdlib-only output.
  - `--level` on gc and autopack.
- **Housekeeping:**
  - P8: zstd added to `all`.
  - X18 temp-file reaping. It is hold-aware, but temp files are never held.
  - X19 F_FULLFSYNC on macOS.
  - fsck budget.
- **CI:** compression bench and nightly stress runs (SIGKILL, concurrency, prune race) on Linux, macOS and Windows.

**Acceptance (pinned `ubuntu-24.04` 4-vCPU runner, single-threaded):**

- Synthetic wire ≤6.0 MB (-77%). Real corpus ≤80% of TINEPACK4.
- TINEPACK5 compression throughput ≥2x TINEPACK4 on the same runner.
- Push or bundle read of a v3 repo is ≥10x faster than 0.36 on the same runner (the earlier draft's 66 s to ≤4 s was on unpinned hardware).
- fsck takes ≤2.5 ms per event.
- Oversized-window fuzz inputs are rejected 100% of the time.
- The 0.34 CLI reads every `.tine` and bundle 0.37 writes for it.
- An `--archival` export verifies with only Python 3.11 and the stdlib.

### 0.38.0: Per-turn capture (about 5 weeks)

The earlier draft shipped capture in 0.41. It moves before assurance tiers, because tier T1 needs these hooks.

**Scope:**

- **Generic `tine hook` protocol** (JSON over stdin and stdout) for UserPromptSubmit/PostToolUse/Stop-style events.
  - Claude Code, Codex and Gemini configs are thin shims that point at it.
  - `tine enable --dry-run` and `tine disable`.
- **Tree object kind.** Per-turn workspace snapshots, content-addressed and linked from each step's event.
  - A crash still leaves a partial run.
  - Rewind restores an exact tree with `O_NOFOLLOW`.
- **`tine mcp-proxy -- <cmd>`** for stdio and Streamable HTTP. It redacts before hashing.
- **Prompt-prefix splitting at record time.** System prompts and tool definitions become their own blobs.
- **Faster recording:**
  - Redaction memoized by content hash, using one combined regex with a literal prefilter.
  - Directories validated once using `openat`.

**Acceptance:**

- When a session with K completed tool steps is SIGKILLed, the partial run holds ≥K steps (K counts steps finished before the signal).
- Rewind restores changes made through the shell byte for byte.
- Over a 100-turn session, snapshot bytes are ≤10% of **workspace size × turns** after dedup (measured against the repo's growth).
- Recording throughput rises from 3.2 to **≥8 steps/s** on the pinned runner. The earlier ≥15 target sat at the theoretical ceiling; this is re-profiled before release.
- The 0.34 fsck and pack reader accept a repo that contains trees (§6).
- `tine disable` restores each agent config byte for byte.

### 0.39.0: Assurance tiers, evidence, and the start of the TS verifier (about 5 weeks)

**Scope:**

- **X21 tiers:**
  - T0: self-reported import.
  - T1: hook-captured (from 0.38).
  - T2: witnessed by the proxy or MCP proxy, signed with a **separate proxy key** generated by `tine proxy keygen` under the existing key store. The PKCS#11 and KMS backends arrive in 0.41.
  - T3: T2 plus a timestamp.
  - Each tier is shown in every report. `--min-assurance` enforces a floor. A divergence report compares the proxy capture with the imported transcript.
- **X20 and X22:**
  - X20: `sig:sha256:` timestamp binding.
  - X22: tine-verify-report/2, signed and timestamped.
  - This release only establishes the *verified signing time*. Key-validity checks against that time arrive in 0.41, with their own gate.
- **Replay and custody:**
  - in-toto `replay/v1` predicate.
  - Custody records on `opentine-log/1`.
- **Retention:**
  - TOML `RetentionPolicy` implementing `RetentionHook`.
  - gc goes back to pruning unreachable objects by default, but never held ones.
- **`tine evidence report --format html|pdf`.**
  - HTML is canonical and deterministic.
  - PDF/A-3 is generated with a pinned **pikepdf/qpdf**-based writer, with fixed `CreationDate`/ID, the embedded JSON and no system fonts (bundled DejaVu). If this cannot be made deterministic, PDF ships as a separate signed derivative, and only the HTML is gated on byte identity.
- **`tine-verify.pyz` with no native code.**
  - Vendors a pure-Python Ed25519 verify-only routine (RFC 8032 reference, about 300 lines, verified against Wycheproof vectors) and uses the stdlib for SHA-256, HMAC, zlib and xz.
  - It is reproducibly built with SLSA provenance.
  - zstd-coded evidence is re-exported in archival form by `evidence export --with-verifier`.
- **TS/WASM verifier, phase 1:** tine-sig/3 and `.tine` v4, sharing the conformance vectors. Starting now lets format bugs surface before the 0.40 formats spread.

**Acceptance:**

- An import reports T0. `--min-assurance T2` exits with code 4. A capture through the MCP proxy reports T2.
- Two independent pyz builds are byte-identical.
- The pyz verifies an evidence bundle offline on air-gapped VMs: Debian 12 with Python 3.11, macOS 14 with Python 3.12, and Windows Server 2022 with Python 3.13. No pip and no network.
- The HTML report is byte-identical across runs (and the PDF too, if the pikepdf path holds).
- The TS verifier passes 100% of the v4 vectors.

Note: the claim that trace self-rewriting is a risk rests on arXiv 2609.30266, which has not been verified. Tiers are justified on their own terms: captures that the agent itself can write cannot be told apart from honest ones.

### 0.40.0: Blob deltas, CDC bake-off and `.tine` v5 reader (about 4 weeks)

**Scope:**

- **CDC bake-off gate** (§4) on the real corpus decides between BLOB_PREFIX_DELTA, CDC and both.
  - The winner ships, limited by `MAX_DELTA_DEPTH`, with cycle detection and oid checks.
  - Transcript `put_transcript` growth becomes delta-stored.
- **External blob pointer** `{uri, sha256, size}`, verified on fetch.
- **`.tine` v5 reader**, with text blobs and rules for rebuilding canonical bytes. The writer stays behind `--format 5`, and v4 remains the default (§6).
- **Local delta pack** in gc. Autopack writes it only if it meets the latency gate in §4.
- **P2:** one pack and one fsync per run.

**Acceptance:**

- The bake-off report is published.
- Local packs reach ≥25x synthetic and ≥1.5x better than 0.37 on the real corpus.
- gc **end to end** (not build only) is ≥4x faster than v3 gc on the pinned runner.
- Every stored form round-trips 10k random objects to the original oid.
- Deep or cyclic chains are rejected.
- `.tine` v5 is -26% or better on the transcript corpus.
- The TS verifier reads v5.

### 0.41.0: Keys, post-quantum and FIPS (about 5 weeks)

**Scope:**

- **Key lifecycle (X23):** `not_before`, `not_after` and `revoked_at`, checked against the *verified signing time* from 0.39; `tine key rotate/revoke`.
- **Key storage (X24):** encrypted PKCS#8; a `Signer` protocol with PKCS#11, KMS and ssh-agent backends. The T2 proxy key can migrate to one of them.
- **Verifier hardening:** X26, X27 and X31.
- **Post-quantum (X29):**
  - ml-dsa-65 and composite ed25519+ml-dsa-65, carried in a **detached sidecar** unless the 0.34 compatibility test passes (§6).
  - A hash-algorithm tag is reserved in SPEC. **Acceptance includes a spec test that a tagged oid is rejected with a clear error.**
- **TINEAES5 (X28):** key_id, epoch, a 32-byte master and XAES-256-GCM. Padmé length padding is an option of **TINEAES5 only**.
- **FIPS (X30):** `--fips`.
- **X5 (OS level):** bwrap/landlock, sandbox-exec and OCI sandbox backends.

**Acceptance:**

- A signature dated after `not_after` or `revoked_at` fails, and an earlier one passes. This is the gate 0.39 deferred.
- The hybrid signature verifies, and stripping either part fails. The 0.34 verifier still accepts the run, through its classical signature.
- The `--fips` CI job uses `cryptography` linked against OpenSSL 3.0.9 with the FIPS provider enabled (Red Hat UBI 9 image).
  - It *accepts* HMAC-SHA256 and Ed25519 (FIPS 186-5).
  - It refuses non-approved primitives (for example ChaCha, and xz-only integrity paths).
  - It records the provider in reports.
- `find -exec` fails under the sandbox backend.

### 0.42.0: Protocol capture, importers and attribution (about 5 weeks)

**Scope:**

- **OTLP and HTTP capture:**
  - OTLP/HTTP protobuf with a stdlib varint decoder, fuzzed.
  - **gRPC is an optional extra (`opentine[grpc]`, grpcio)** with its own security review.
  - `tine record --upstream` for openai, anthropic, gemini and Azure dialects.
  - **Bedrock routes through OTel.** A CONNECT/local-CA proxy is on the 1.0 track.
  - `import --format har`.
- **Importers:**
  - Entire: `refs/entire/checkpoints/*` with fallback, `--all`, and **`export --format entire`**, with fixtures captured from the current entireio/cli.
  - Roo and Cline globalStorage; Windsurf.
- **`tine explain RUN`:** a deterministic offline summary stored as an annotation. An optional local-model narrative is labelled as such.
- **Line attribution:** signed notes under `refs/notes/tine`, `notes.rewriteRef`, Agent Trace output, `stats --ai-share`.
- **`.tine` v5 becomes the writer default.** It has been readable since 0.40. `--for-legacy` and `evidence export` stay on v4.

**Ownership:** each framework fixture has a named owner, recorded in `tests/fixtures/OWNERS`. Fixtures for TS frameworks (Vercel `ai.*`, Mastra) are captured by a small Node harness in `tests/fixtures/ts/` that CI runs.

**Acceptance:**

- OTLP protobuf exports from Pydantic AI, ADK, Strands, Semantic Kernel, DSPy, Vercel and Mastra import with no configuration.
- Attribution survives `rebase -i` and amend.
- An Entire export round-trips through the current entireio/cli.

### 0.43.0: Fleet record, delegation and leases (about 5 weeks)

**Scope:**

- **Fleet record:**
  - Capture reads `OPENTINE_FLEET_*`.
  - A signed fleet record and an in-toto `fleet/v1` predicate.
- **X32 delegation:** `opentine-delegation/1` certificates, verified offline.
- **`opentine-coord/1` tasks and leases:**
  - A claim is a compare-and-swap ref move with a lease and a fencing token.
  - `tine task add/claim/heartbeat/done`.
- **Mailbox and steering:**
  - Mailbox messages are annotations.
  - `fleet send` is injected by a hook.
  - **Steer messages are recorded as events.**
- **Fleet UX:** F3 and F4; `fleet resume/logs/send`.
- **Remote:** a POST ref-txn applied all-or-nothing, gated on server `caps`.
- **Merge:** F2 design doc and `parents[]` (omitted when empty). Merge itself is in 0.45+.

**Acceptance:**

- Lease correctness is tested **on both backends**: local filesystem compare-and-swap and the HTTP remote. 1,000 simulated agents × 50 claims produce 0 lost updates and 0 double claims, with fencing verified.
- A SIGKILLed supervisor is reported as orphaned within ≤2× the lease TTL.
- The whole fleet, including delegation, verifies offline.
- A 0.34 client against the 0.43 server passes the compatibility suite.

### 0.44.0: Transparency, search and TS verifier GA (about 5 weeks)

**Scope:**

- **X33 transparency.** Reflog and remote audit publish over `opentine-log/1`:
  - Inclusion proofs on push and consistency checks on fetch.
  - Proofs embedded in bundles.
  - `tine witness` and `verify --offline --witnesses N-of-M`.
- **X34:** Rekor v2 tile proofs; TUF SigningConfig.
- **SCITT, experimental.** COSE_Sign1 statements and receipts, verified offline against a pinned key.
  - Caveat: the RFC 9943 number and SCRAPI status were *not verified* by the research.
  - The interop target is the open-source **scitt-community/scitt-api-emulator**. If no other implementation is usable, the feature stays behind `--experimental`.
- **X15 completion:** `QuotaAdmission` plus a token bucket returning 429. `TrustPolicyAdmission` emits a VSA.
- **Search:** a derived FTS5 BM25 index at `.tine/index/search.sqlite` and an MCP `recall` tool (read-only).
- **TS/WASM verifier GA:** TINEPACK5 and the 0.40 delta forms (zstd patch-from in WASM).
- **Cost:** OTLP metrics from cost aggregates and a signed cost statement.

**Acceptance:**

- A split-view fork is detected with 2-of-3 witnesses.
- Inclusion proofs verify from the bundle alone.
- Keyword search over 100k runs takes ≤200 ms p95 for a cold 3-term BM25 query on the pinned runner, with no 10k cap.
- The TS verifier passes 100% of the vectors.
- Over-quota requests get 429 with bounded memory, and a 0.34 client degrades cleanly.

---

## 9. Dependency order

```
0.35 sec+hold+X25 ─> 0.36 contract+log/1 ─> 0.37 packs ─> 0.40 deltas/v5-reader ─> 0.42 v5 default
        │                  │
        │                  ├─> 0.39 custody (log/1) ───────────────────────> 0.44 tlog/witness (log/1)
        │                  └─> 0.38 capture (hooks, tree, mcp-proxy) ─> 0.39 tiers T1/T2
        └─> 0.39 retention policy (extends the 0.35 hold)
0.39 signing-time ─> 0.41 key validity, PQ, FIPS
0.38 tree kind ─> 0.42 protocol capture/attribution ─> 0.43 fleets ─> 0.45+ merge
0.39 TS phase 1 ─> 0.40 v5 vectors ─> 0.44 TS GA
```

## 10. Releases 0.45 to 0.50, and the 1.0 track

*Planned 2026-11-07. Principle: close the visible gaps first (viewer, evals, sharing, CI), then go further on verifiable evidence end to end. Every hosted feature reads the same open formats the CLI writes. Items from the earlier "0.45+" list are marked **[0.45+]**. The rival facts behind this plan are in §3a.*

Rules for this stretch:

- **Format changes are flagged.** Each new object kind or `caps` flag ships with vectors in Python, TS and pyz in the release that adds it.
- **0.48 is the last release that may add a new object kind or wire format.** 0.49 and 0.50 only fix, test and document, so the 1.0 freeze review in 0.50 is not chasing new kinds. Kinds planned before the cutoff: `tine-eval-verdict/1`, the tombstone, the redacted derivative, `merge/v1`, memory annotations, Reviews, the in-toto `agent-run/v1` predicate, and the three project kinds (`opentine-project/1`, `opentine-mirror-state/1`, `opentine-forge-claim/1`, §11 "Projects and code mirror"), all targeted at or before 0.47.
- **Conformance is "the full pinned vector set"**, not a fixed count, because the set grows each release.
- **No git hosting.** OpenTine integrates with GitHub, GitLab, Forgejo and Entire instead. A project's code mirror (§11) is a read-only cache in opentine-web, not a git host.

### 0.45.0: See it, score it (about 6–8 weeks)

**Scope:**

- **`tine ui` [0.45+].** A read-only local viewer on 127.0.0.1: run timeline (prompts, tool calls, diffs, workspace trees), run DAG and fleet graph, verify and assurance badge, attribution view. It re-redacts at render time and makes no network calls.
  - It is built from a **shared viewer package** (`run-viewer`) and a **browser verifier package** (`verify-browser`) that live in this repo, so `tine ui` and opentine-web (§11) use the same code.
  - A spike at the start measures the browser bundle size and ML-DSA-65 / zstd WASM feasibility before the viewer timeline is committed.
- **`tine eval run|compare` [0.45+]** with signed `tine-eval-verdict/1` objects (new kind). Scorers: deterministic, regex, LLM-judge (the judge model and prompt are recorded as a run) and Python callables.
- **Datasets [0.45+]:** `tine dataset add --from-run`, JSONL and HF import and export.
- **Attribution in git:** `tine blame` (accepts git-blame flags), `tine why FILE:LINE` (opens the causal run slice), a `Tine-Run:` commit trailer, and `tine attach RUN COMMIT` for a session captured after the fact. Agent Trace import. The Entire importer is tested and fixed against the current `refs/entire/checkpoints/*` layout.
- **Witness HTTP protocol** (C2SP tlog-witness) and a **tiled log** (C2SP tlog-tiles) with O(log n) appends. **This is a format change:** tiles change `opentine-log/1` storage and proofs. The release decides, in writing, whether this is `opentine-log/2` or a compatible extension of `log/1`, and ships vectors for it before any hosted log exists.
- **JSON Schemas** for every object kind and every `--json` output, published as a versioned package. **`docs/SPEC.md` published** as a versioned, citable spec (the web's `/protocols` pages are generated from it).
- **Project prerequisites (§11 "Projects and code mirror"):** the trailer grammar `Tine-Run: <run-oid>[ <project_id>]` (repeatable) and `Tine-Project: <project_id>` (at most once), parsed identically by `tine git log` and the web; JSON Schemas `opentine-line-attribution/1`, `tine-blame/1` and `tine-ai-share/1`; `tine blame --json` emitting `tine-blame/1`; `tine git install-hook` setting `notes.rewriteRef refs/notes/tine` so rebase and amend keep attribution. No new object kind.
- **Pre-push redaction gate.** `tine push` re-scans against the current ruleset and refuses on hits (`--allow-unredacted` overrides). The ruleset is exported as data so the web can re-redact identically.

**Rationale:** the viewer and the eval runner are the two largest gaps in §3 and against Entire Trails and Langfuse. `tine blame`, `why` and `attach` answer Entire's `blame`/`why` and the `Entire-Checkpoint` trailer. Witness networking and the tiled log close the two gaps 0.44 left in the transparency work. Schemas, SPEC and the pre-push gate are prerequisites for any hosted service and cost little.

**Acceptance:**

- `tine ui` renders a 10k-step run in under 2 s. No unredacted secret from the fixture corpus appears in the DOM. A socket-audit test shows no outbound connections.
- `tine eval run` on a 1k-item dataset produces signed verdicts that `tine-verify.pyz` and the TS verifier both check. The full pinned vector set, including the new eval-verdict vectors, passes in Python, TS and pyz.
- `tine blame` output matches `git blame --porcelain` byte for byte on 20 fixture repos when no AI lines are present.
- The Entire current-layout import and export round-trips on a fixture from Entire CLI 0.10.x.
- Two independent witness processes cosign over HTTP. `verify --witnesses 2-of-3` passes and fails closed on a split view.
- A 1M-entry log benchmark shows O(log n) append with p95 under 10 ms on the pinned runner. The log/1-vs-log/2 decision is recorded and the 0.34 peer compatibility job stays green.
- Every `--json` output validates against its published schema in CI.
- The pre-push gate refuses every secret in the fixture corpus.
- Trailer vectors (one run; run + project; two `Tine-Project`, rejected; malformed oid) give the same link set in `tine git log` and the web parser. A rebase test keeps `refs/notes/tine`.

### 0.45.x: Parity and plumbing (point releases)

**Scope:**

- **Harness parity:** Copilot CLI, Antigravity, Factory Droid and Pi, each with fixtures and a named owner.
- **Git AI Standard v3 notes** reader and writer (imports their notes and signs them; OpenTine notes stay canonical). A post-commit AI-share line.
- **`tine doctor [--bundle]`:** environment, keys, hooks and harness checks, plus a redacted support bundle.
- **SSE events, `tine watch`, and webhooks with signed payloads [0.45+].**

**Rationale:** these are split out of 0.45 so it stays within 6–8 weeks. None of them changes a format except the signed webhook payload, which is a wire format negotiated by `caps`.

**Acceptance:**

- Each new harness passes the hook-protocol fixtures.
- Git AI v3 notes round-trip.
- `tine doctor --bundle` contains no secret from the fixture corpus.
- A webhook payload verifies with a documented 20-line verifier.

### 0.46.0: Share it, gate it (hosted beta starts) (about 6–8 weeks)

**Scope:**

- **Hosted beta (opentine-web M2/M3, §11)** against the CLI's `tine serve`. The CLI side adds the `caps` the web needs: `object_read_http`, `run_closure`, `list`, `search` (`tine repo-search --remote`), `share`, `log_http` read side, and `admin`. Remote-aware commands: `tine share create|revoke`, `tine open`, `tine remote login` (device-code OIDC).
- **Stable public API v1** (OpenAPI) for `tine serve`, plus a TS SDK. The hosted service implements the same spec and passes the same conformance suite.
- **Tombstone and purge** (new kind): a signed record that a blob was purged, the oid kept and the content gone. `verify` reports `content-unavailable`, not `failed`. `tine purge` uses the quarantine machinery.
- **Redacted public copy** (new kind): `tine bundle create --redacted-public` produces a pack holding only redacted blobs, with an attestation linking it to the original run oid.
- **CI:** a GitHub Action and a GitLab component for `tine verify`, `tine eval` and a VSA gate with a PR comment. The server-side named trust policy for the VSA. An Action that preserves attribution through squash and rebase merges.
- **`opentine-redaction/3`:** PII detectors and an optional classifier layer that runs locally (the model is named in the release notes), with a signed redaction report per run.
- **Hybrid search:** an optional local embedding index (`opentine[embed]`), computed only on redacted text.
- **Vendor I/O [0.45+]:** export and import for Langfuse, Phoenix, Braintrust and LangSmith. Whether each vendor displays `gen_ai.evaluation.result` is tested and documented per vendor, not assumed.
- **Steer and resume for Codex and Gemini.** `opentine-hook/1` published as a versioned spec with conformance vectors.
- **in-toto `agent-run/v1` predicate** draft, proposed upstream.
- **Projects, CLI side (§11 "Projects and code mirror"):**
  - `opentine-project/1` manifest (new kind): canonical JSON, tine-sig/3, a `prev` hash chain, every version logged, optional `forked_from`. Private projects must use `commitment` locators (a salted hash of the upstream URL), so the log never holds a private URL or repo name.
  - `opentine-mirror-state/1` (new kind, host statement): signed by the service identity, never a user key; written only when the ref set or result changes, plus a daily heartbeat. Verifiers report it as `signed by host service key`, never `pass`.
  - Ref namespace `project/` with the single ref `project/manifest`; fsck requires an `opentine-project/1` object there.
  - Git object check in `verify-browser`: recompute sha1 (SHA-1DC) or sha256 oids and check tree and commit links. A pass reads `matches its id (checked by you)`; it says nothing about whether the upstream holds that oid.
  - Ten new `tine-verify-report/2` reason codes, including `fail:manifest-signature`, `fail:git-object-mismatch`, `caveat:mirror-stale`, `caveat:history-truncated` and `unavailable:blob-not-mirrored`.
  - `tine serve`: `caps.project` (`GET /v1/tenants/<t>/project[/history]`, `PUT /v1/tenants/<t>/project` as a CAS on `project/manifest` that accepts only a client-signed manifest from the previous owner set) and `caps.social_export` (count-only stars and watches, for self-host parity). `tine serve` gets no code storage, no upload-pack or receive-pack for code, and no mirror cap.
  - CLI: `tine project init|show|verify|link|unlink|set-upstream|link-check|mirror-diff`, `tine remote add --project` (pins the `project_id`), `tine git attribute --project`.

**Rationale:** Entire, Traces and the harness vendors all give users a page they can link to. We match that, and the page shows a result the viewer's browser computed. Tombstones and the pre-push gate (0.45) must exist before any transcript is hosted.

**Acceptance:**

- A run pushed from the CLI appears in the web app in under 5 s through SSE.
- A share link verifies in the browser with the verifier script pinned by SRI. Changing one byte in storage turns the badge to `failed`.
- `tine serve` and the hosted service pass the same API conformance suite in CI.
- A purged blob verifies as `content-unavailable` in Python, TS and pyz.
- The redaction/3 recall benchmark is published with its corpus and numbers.
- The Action is used in at least two external repos before the release is tagged.
- Python, TS and pyz agree on accept/reject and canonical bytes for every manifest and mirror-state vector, including private + plaintext URL (must reject). 0.34–0.45 clients fetch, clone and push against a 0.46 server with `project/manifest` present. A one-byte change to a mirrored git object gives `fail:git-object-mismatch`. A private tenant's unauthenticated `GET /api/v1/project` is byte-identical to one on a nonexistent tenant.

### 0.47.0: Merge it, review it (about 6 weeks)

**Scope:**

- **Run merge, pick and merge queue (F2) [0.45+].** The queue runs on `coord/` leases. Gates combine signed VSAs, eval verdicts and human approvals. A merge emits a signed `merge/v1` attestation (new kind).
- **Reviews** (new kind, specified in this repo first): a unit of work across runs and commits, with findings, monitors (risk, intent drift, coverage, as eval scorers) and gates. Each gate decision is a signed object that exports and verifies offline. Multi-repo Reviews need a multi-repo object model; its spec lands here.
- **Push-triggered evals** (`.tine/evals.toml`), run locally, in CI or on a self-hosted runner.
- **Team memory:** signed, syncable memory annotations (new kind), exposed through MCP `recall`. **MCP 2025-11-25 tasks [0.45+].**
- **Prompt registry**, moved from the 1.0 track: `tine prompt push|label|get`, signed and linked to runs. *Justification: eval comparisons are not reproducible without versioned prompts, and the object kind must land before the 0.48 cutoff.*
- **Plugin API** for importers, signers, scorers and snapshot providers. `tine experts PATH`.
- **TS capture SDK.** SCITT statement emission without `--experimental`, if the interop target is usable.
- **Remote task backend** (`caps.coord`) and the 1,000 tasks × 50 workers scale test.
- **Witness service support** for the hosted trust network (opentine-web M4).
- **Projects, second half:** `opentine-forge-claim/1` (new kind, tiny): a `.opentine/project` file committed upstream, written by `tine project claim`. It arrives through the mirror, so it reads `claimed by upstream (as mirrored)` and never reaches ✓ on its own. Secondary code slots (`tine project link --role secondary`) and `tine project fork` (copies the run repository, never code). If 0.46 overruns, these are the items that move here; the manifest, mirror-state and ref namespace stay in 0.46.

**Rationale:** Trails is Entire's main forge feature. Reviews give the same unit of work, with every gate decision verifiable without our server.

**Acceptance:**

- Merging two forked runs is deterministic: the same inputs give the same merge oid in Python and TS (new vectors).
- The merge queue survives a chaos test (kill -9 workers) without a double merge; fencing tokens are verified.
- A Review exported as a bundle verifies with `tine-verify.pyz --offline` on an air-gapped machine, including every gate decision.
- 1,000 tasks × 50 workers produce zero lost or duplicated claims.
- Forge-claim vectors (match, wrong id, wrong fp, missing, non-default branch only) pass in three engines. `tine project verify` on a fork checks `forked_from` against the source's logged history.

### 0.48.0: Integrate everywhere (last new object kind) (about 6 weeks)

**Scope:**

- **Forge integration:** PR checks, comments and blame overlays for GitHub, GitLab and Forgejo, and an Entire forge integration that maps runs onto Entire-hosted repos. This replaces any plan to host git.
- **`tine review`:** multi-agent review through the fleet; each finding is a signed annotation. Optional `tine graph` code map, exposed to MCP.
- **IDE extensions** (VS Code, JetBrains): AI blame gutter and "verify this line's provenance".
- **`tine compliance check` profiles and the Provenance/Workflow Run Crate [0.45+]**, mapped against the primary texts (FRE 902(13)/(14), EU AI Act Art. 12/19/26, eIDAS) with a named legal reviewer.
- **OMS model-signature checks** as an assurance factor. OTLP gRPC ingest after its security review. OTLP protobuf logs.
- **TSA binding for Rekor v2 keyless verification**, so it no longer reports `unchecked`. Delegation × revocation registry semantics.
  - *Status:* done on `wip/048-trust-semantics`. A bundle's `rfc3161Timestamps` token over the DSSE signature bytes gives a Rekor v2 keyless receipt a verified signing time (SPEC §8.12.1, vectors `77-keyless-tsa`). A delegation chain is refused when any key on it is revoked at or before the verified signing time, or at all without one (SPEC §4.10.1, vectors `76-delegation-revocation`). Both families are answered by Python, TS and the pyz.
- **Projects:** PR checks and blame overlays resolve projects by `forge_repo_id`. Slack for the project kinds: any of the three that slipped from 0.47 lands here; one that misses 0.48 is dropped until after 1.0, with no cutoff exception.
- **Freeze cutoff:** after this release no new object kind or wire format is added before 1.0.
  - *Status (0.48 work, branch `wip/048-trust-semantics`):* the cutoff is documented in SPEC §5.5. `tests/test_048_freeze_cutoff.py` enumerates kinds from SPEC headings, `docs/schemas/` and the vector families against `tests/freeze_inventory.py`, and checks Python, the TS verifier and the built pyz answer each family. The audit added `78-fleet` vectors (the 0.43 fleet record had none) and pyz answers for the canonical-JSON, envelope, oid, agent, actions, delegation, tlog, eval-verdict and forge-claim families. The kinds 0.48.0 adds, `opentine.forge-check` (73), `opentine.review-finding` (74) and OMS model signatures (75), are inventoried and answered by Python, TS and the pyz. Still open, pinned and shrink-only: the pyz answers `.tine` artifacts and signatures as whole files rather than op by op (31, 35, 42, 47, 51); it never reads repository storage formats; and six pre-cutoff kinds have no vector family (`tine-verify-report/2`, `tine-custody/1`, `replay/v1`, `TINEAES6`, `opentine-line-attribution/1`, `tine-cost-statement/1`). 0.49 may add their vectors, because that adds tests, not kinds.

**Rationale:** OpenTine is the evidence layer under any forge, not a forge. Compliance claims ship only after primary-text review.

**Acceptance:**

- A PR check shows the AI share and verify status, with a link to an offline-verifiable bundle.
- Each compliance profile cites the article or rule number, and an external counsel sign-off is recorded in the repo.
- The gRPC ingest security review is published, and 72 h of fuzzing finds no crash.
- Every object kind in the tree has vectors in Python, TS and pyz.

### 0.49.0: Audit kit and public proof (about 5 weeks)

**Scope:**

- **Full air-gapped audit kit [0.45+]:** pyz and TS verifier, the crate, `replay/v1`, the witness set and a printed verification report. **Artifact-evaluation package [0.45+].** **`tine publish zenodo` [0.45+]** and `tine publish hf`.
- **S3 Object Lock and Azure immutable backends [0.45+].**
- **FastCDC lazy fetch for payloads ≥8 MiB and the S3 store**, moved from the 1.0 track. *Justification: the hosted service needs object storage with lazy fetch, and chunking is a stored form, not a new canonical kind, so it does not cross the 0.48 cutoff.*
- **Webhook and OTLP alerts [0.45+]. Jules importer [0.45+].** A2A importer, moved from the 1.0 track. *Justification: a thin importer that produces T0 runs; no format change.*
- **Public witness** operated by the project, and independent witnesses recruited.
  - *Status (branch `wip/049-witness-network`):* the operator kit is shipped: the runbook `docs/witness/OPERATING.md` (hardware, key ceremony, rotation, monitoring, incident response), a container definition in `deploy/witness/` (pinned base image, no secrets), the `opentine-witness-network/1` registry (`docs/witness/NETWORK.md`; a pinned config, not a kind) that `tine verify --offline --witnesses REGISTRY.json` checks against the majority-of-three policy, `tine witness doctor`, and `docs/witness/RECRUITING.md`. `tests/test_049_witness_network.py` requires 2-of-3 cosignatures from three local witness processes and fails closed on a split view. **Outstanding for humans:** operating the public witness, recruiting at least two independent operators, publishing the production registry and pinning the image by digest.

**Acceptance:**

- The audit kit verifies on Linux, macOS and Windows with networking disabled (1.0 criterion 4).
- At least three independent witness operators are live, and hosted logs require 2-of-3 cosignatures.
- The Object Lock backend refuses deletes within retention (integration test against MinIO and AWS).

### 0.50.0: Freeze candidate (about 5 weeks)

**Scope:**

- **Format freeze review.** Python, TS and pyz parity on the full pinned vector set (criterion 2). Deprecation policy published (criterion 7). Third-party security audit started, covering the CLI and the hosted service (criterion 1).
- **RFC 4998 evidence records** with PQ re-timestamping (`attest --renew`) and embedded CRL/OCSP, moved from the 1.0 track. *Justification: long-term evidence must be fixed before the freeze, or 1.0 freezes formats that cannot carry it.*
- **Per-kind dictionaries (P3).** Compression bench within 5% of 0.40 (criterion 6). *Status: dictionaries ship opt-in (`tine gc --dictionaries`, codec 3 in local v3 packs only; the TS verifier refuses it by name). The bench job gates stored bytes against 0.40.0 on the same runner; speed is reported, not gated. Numbers: `docs/bench/0.50-dictionaries.md`.*
- **Nightly stress** runs green for 30 days (criterion 5). The 0.34 peer compatibility job stays green (criterion 3).
- **"Leave the hosted service" test:** export, then `tine serve` import, then a byte-identical verify.

*Evidence-records status (0.50):* embedded CRL/OCSP is done inside the existing token format (SPEC §8.6, `timestamp.revoked`, `timestamp.revocation-invalid`; checked offline, can only fail a token). RFC 4998 evidence records and `attest --renew` are **deferred past the freeze, to a later additive format**: a renewal token must be bound to the previous archive timestamp, and `tine-timestamp-sidecar/1` has a closed `bound` set (`sha256:`, `run:sha256:`, `sig:sha256:`) that every 0.31–0.49 verifier reports as `timestamp.bound-mismatch` otherwise. Adding a bound form or an `EvidenceRecord` file is a new wire format, which the 0.48 cutoff forbids. Until then a run keeps up to 16 root-bound tokens, so a fresh token (SHA-384/512 imprint) can be added over time, but it is not a hash-tree renewal and does not survive a break of the SHA-256 content digest.

**Rationale:** 0.50 exists to meet the 1.0 criteria, not to add features.

**Progress (format freeze review):** Python, TS and the pyz agree on every case of the pinned suite each answers (61 families, 1163 cases; the pyz answers 990, the TS verifier 1149), checked case by case by `scripts/check_parity.py` and the CI `parity` job; the freeze-audit allow-lists in `tests/freeze_inventory.py` are empty and the six kinds 0.48 deferred have families 79-84. The pyz still excludes, by design, the repository storage families (it never opens a repository). The frozen list and the review result are [`docs/FREEZE.md`](FREEZE.md). Criterion 2 is not yet declared met: the storage-family exclusion needs the release owner's sign-off, and the `parity` job has not yet run green in CI. The other 0.50 items are open.

**Acceptance:** every 1.0 criterion except the completion of the audit is met. The leave-the-service test passes on every release from here on.

### 1.0 track

Still on the track: columnar pack v6, prolly-tree index, OpenZL spike, oid token table, eIDAS LOTL/JAdES, C2PA `tine media sign`, `rewind --with-side-effects` with compensation records, Bedrock CONNECT proxy, budgets, hash agility (activated).

Moved earlier, each justified above: the prompt registry (0.47), FastCDC lazy fetch and the S3 store (0.49), the A2A importer (0.49), RFC 4998 evidence records (0.50), per-kind dictionaries (0.50). Pluggable snapshot providers move to the 0.47 plugin API.

**1.0 criteria:**

1. All P0 and P1 items are closed, and a third-party audit has been done.
2. The formats are frozen, and the Python, TS and pyz implementations pass the same vectors.
3. The 0.34 peer compatibility job is green for every release.
4. The pyz is air-gap-tested on Linux, macOS and Windows.
5. Nightly stress tests have been green for 30 days.
6. The compression bench has regressed by no more than 5% since 0.40.
7. The deprecation policy in §2 is published.

---

## 11. Web platform (opentine-web)

*Planned 2026-11-07. Separate repo, `opentine-web`. The CLI repo stays the system of record for formats, verifiers and `tine serve`.*

**Surfaces.**

- `opentine.com`: site, docs and blog. Reference docs are generated from this repo (`docs/CLI.md`, `tine help --json`, `docs/SPEC.md`), so the site cannot drift. Today it still describes 0.34, including the old `.tine` default.
- `app.opentine.com`: the product (run viewer, projects, search, blame, transparency, orgs).
- `opentine.com/r/<oid>`: short content-addressed permalinks for public runs, resolved only within the public tenant so they cannot probe private tenants for an oid.

**Thesis: the server is not trusted.** Every page that shows a run also shows a verification result that the browser computed with the TS verifier, against signer keys, log checkpoints and witness cosignatures. The hosted service stores, indexes and displays; it is never the source of truth. Anything computed by the server (OG cards, README badges) is labelled as server-computed. The badge has an explicit `partial` state for blobs not downloaded, and a caveat state for checks that need the network (CRL fetch) or an encoding TS cannot read (xz).

**Shared code.** The viewer (`run-viewer`) and browser verifier (`verify-browser`) packages live in this CLI repo, so `tine ui`, the web app, embeds and a single-file offline viewer share one implementation. Web data types are generated from the 0.45 JSON Schemas.

**Milestones.**

| Milestone | CLI release | Web deliverable | CLI prerequisites |
|---|---|---|---|
| M0: site resync | now (0.44.x) | Site says 0.44 and every format statement matches the CLI; `/apps` replaced by a generated compatibility page; site copy states rule 6 as below | `tine help --json`; `docs/SPEC.md` |
| M1: offline viewer | 0.45 | `opentine.com/view` drag-and-drop viewer running fully client-side; `<opentine-run>` web component; offline single-file viewer. Attribution from a local bundle plus local git; no code mirror and nothing code-related on the web | `run-viewer` and `verify-browser` packages; TS verifier browser build passing the full pinned vector set in Chromium, Firefox and WebKit; JSON Schemas; `Tine-Run`/`Tine-Project` trailers, blame and AI-share schemas, `tine blame --json` |
| M2: hosted alpha | 0.46 | Login, orgs of one, run repositories backed by `tine serve`, run viewer with browser badge, compare, search, private by default, link shares, read-only transparency page. No code mirror yet: CLI 0.46 ships the project formats the web reads in M3 | `object_read_http`, `run_closure`, `list`, `search`, `share`, `log_http` (read); pre-push gate (0.45); tombstone/purge; `tine remote login`, `tine open`; `opentine-project/1`, `opentine-mirror-state/1`, `project/manifest` ref, git object check, project reason codes, `caps.project`, `tine project …`, `tine remote add --project` (all 0.46, read by the web in M3) |
| M3: teams | 0.46–0.47 | Roles, CI OIDC tokens, SSE updates, webhooks, run-level attribution (project code blame is M4), fleet view, keys and delegation, retention and holds, signed audit log, public publish with redacted copy, Reviews. Projects, on 0.47: project manifest panel; primary code slot as a read-only mirror (tree, README, blob, raw, history, commits, compare, branches, tags, tag-only releases, find file) with the mirror banner on every code route; stars and watches; migration of existing repos to projects with no code slot | SSE and webhooks (0.45.x); `--redacted-public`; VSA named policy; `caps.coord`; Reviews kind (0.47); project formats and `caps.project` (0.46); `opentine-forge-claim/1`, `tine project claim\|fork` (0.47, read by the web in M5) |
| M4: trust network | 0.47 | Hosted witness service, public log monitor (including manifest history and upstream changes), browser-cached consistency checks, viewer-supplied trust policies, signed web annotations, reproducible web build; optional browser check of ref tips against a public forge API. Code, reading the 0.45 schemas: blame with attribution lane, AI share, commit provenance, code search, opt-in PR-head list | Witness HTTP and tiled log (0.45); browser signing support in formats |
| M5: evals and compliance | 0.48–0.50 | Eval verdict and dataset views, compliance-profile reports, Auditor role, evidence and custody views, SAML/SCIM, data residency; code on 0.48, reading the 0.47 formats: forge claim display, secondary slots, project forks; PR checks resolve projects by `forge_repo_id` | `tine eval run` and datasets (0.45); compliance profiles (0.48); forge integration (0.48); Object Lock backend (0.49) |
| GA | 1.0 | Third-party audit of the web app and verifier, including the sync-worker sandbox, renderer and usercontent origin; Helm and air-gapped self-host kit | The 1.0 criteria |

**Projects and code mirror.**

A project is a run repository plus a read-only mirror of the code repository it is linked to. The run repository is served by `tine serve` as today. The mirror, its sync worker, the code-read API, the renderer and stars, watches and forks are opentine-web services; the self-host kit ships the same containers.

- **What is not built:** no git push or receive-pack, no CI, no hosted pull requests (reviews stay OpenTine Reviews over linked forge PRs), no clone or archive download from the mirror, no LFS, no public project over private code, and no cross-tenant object sharing.
- **Who sets the upstream:** the owner, through a signed, logged `opentine-project/1` manifest. The service never signs or creates a manifest, so changing the upstream is a visible version in the log. Private projects store a commitment, not the URL.
- **What the browser checks:** that each mirrored object matches its oid, and that the manifest and attribution notes are validly signed. It cannot check that an oid is what the upstream holds. Every code page therefore names the upstream and the last sync time, labelled as computed by the host, and `tine project mirror-diff` lets a user compare the host's mirror state with their own `git ls-remote`.
- **Access:** viewer rights on private code are project membership intersected with upstream read access, checked through the viewer's forge account where the forge allows it. For a plain git URL this cannot be checked; the project says so and the owner acknowledges it when linking. Anything a viewer cannot read returns the same 404 as something that does not exist.
- **Unlink and deletion:** unlinking or losing upstream access removes the mirrored code and its derived caches. The run repository and its log entries are untouched.
- **Limits:** published as numbers and identical for public and private projects (mirror size per slot, slots per project, active mirrors per account, blob size, egress). Exceeding a limit stops the mirror advancing; it deletes nothing. The cost of free private mirrors is measured and published before M3.
- **Formats** are in §10: trailers and schemas in 0.45; the manifest, mirror state, `project/` ref namespace, git object check and `caps.project` in 0.46; the forge claim, secondary slots and project forks in 0.47; 0.48 as slack under the cutoff.

**Non-negotiable rules.**

1. Every object the service shows can be exported and verified with no OpenTine server.
2. The service never signs as the user. User keys stay client-side or in the user's KMS. Service signatures use a separate, published, rotatable identity and are labelled.
3. Signed audit logs are available to everyone.
4. No cloud-only data types. Anything the service adds is specified in this repo first.
5. No token resale. No preferred model or harness.
6. No git hosting: a code mirror is a read-only cache of an upstream. It never accepts a push, never becomes the canonical source, and every code surface names the upstream and the last sync time.

**Free for everyone (amended 2026-11-13, decision D3 in §12).** The tools to track, audit, manage and hold agents accountable should be in the hands of everyone running AI. So:

- Every feature and all verification are free for everyone, for ever, for public and private projects. There are no per-seat prices and no per-feature paywalls, and no feature is held back for a paid plan.
- Self-host is the same software and is free.
- The only things the hosted service may ever charge for are hosted storage beyond the published fair-use limit, metered, and hosted runner compute, at cost. Runner model calls always use the user's own model credentials: there is no token resale (rule 5), and no margin on model usage.
- The service is otherwise sustained by sponsorship, grants and donations, and by optional paid support for organisations that want it. Paid support buys help, not features.
- Fair-use limits on storage and egress apply to everyone, so the service stays sustainable and hard to abuse. The limits are published as numbers before any metering starts (0.52), and exceeding them is answered by contact or by the metered option, never by silent deletion; self-host has no limits.
- Any pricing page (tineyard.com included) must match this section; a page that advertises paid feature tiers or per-member prices is out of line with it.

**Open questions.**

- **Unit economics and staffing.** Neither plan estimates the cost of free private storage, CDN egress, per-tenant indexes and witnesses, or the headcount to run a 24/7 service alongside the CLI. These figures are needed before M2, and scope is cut if funding does not cover them. Start in one region.
- **Security and privacy before M2:** CSRF and cookie model, SSE auth, per-tenant authz on CDN object reads, rate limits on share tokens, browser key storage, an npm supply-chain policy, `security.txt` and a disclosure process, a DPA and subprocessor list, retention defaults and a deletion SLA, what the server sees per mode in E2EE projects, and no third-party analytics.
- **Operations:** backup and disaster recovery, incident response, a status page, and an accessibility target (WCAG 2.2 AA).
- **Ownership:** trademark, domain and repo ownership moved to a legal entity, and a CLA/DCO policy, before M2.

---

## 12. Releases 0.51 to 0.60

*Planned 2026-11-13 against the released 0.50.0 tree (tag v0.50.0). Owner decisions D1–D8 below are final as of that date. **0.60.0 is a waypoint on the way to 1.0, not 1.0 and not a release candidate:** after 0.60 the owner reassesses, with more research and with tineyard's progress alongside OpenTine, before the 1.0 track is scheduled. Every release keeps the §2 invariants, the §11 rules and the format freeze in `docs/FREEZE.md`.*

**Where things stand at 0.50.** Two of the seven 1.0 criteria are met (pyz air-gapped on 3 OSes; the deprecation policy). Parity is green, but reason codes are not compared when an implementation names none. The nightly streak has just started, the compression gate has no green run on the pinned runner, and the audit is not engaged. tineyard.com (the hosted service of §11, a separate repo that consumes this repo's `ts/` packages and OpenAPI document) runs a browser verifier pinned to 0.45.1: `.tine` v4/v5 only, a 32 MiB cap, no bundles, no pinned signer, and backend APIs not yet specified here (rule 4).

**Thesis.** Fix the trust anchor first (tineyard's verifier at HEAD, its APIs specified here). Move the 1.0 criteria on a real schedule: green gates, reason-code parity, the audit started in 0.51 with two finding drops. Differentiate where others cannot quickly follow: hosted review as "just another reviewer" whose results verify offline, hardware **key** attestation phrased narrowly, and signed, reversible promotion for self-improving agent loops.

**Freeze rule for 0.5x.** Strict by default (FREEZE.md "Rulings after the freeze"): a new `predicateType` or claim schema counts as a new wire format unless granted by name under the adopted ruling, and no predicate is granted in 0.51. Each item below states its freeze impact: **none** (existing objects, envelopes, predicates, a derived index or local config), **NOT_KINDS** (an HTTP or CLI response shape or local config, classified like `tine-cli-*` outputs), or a **frozen-safe form** that ships by default, with an optional exception form. Every item has a frozen-safe fallback.

**Copy discipline.** Banned in docs and site copy: "verified execution", "genuine model output", "only line-level attribution", "unique line-level attribution", "proves the model". Hardware results read "valid at T against collateral C". `scripts/check_copy.py` enforces the list in CI from 0.51.

### 0.51.0: Trust anchor at HEAD, green gates, audit engaged (about 5 weeks)

**Theme:** close tineyard's biggest trust hole, turn the shipped 1.0 gates green on the pinned runner, and start the audit clock.

**Scope:**
- `verify-browser` and `run-viewer` tag-locked to each CLI release; a published version manifest, and opentine-web CI fails if tineyard pins more than one minor behind.
- Bundles verify in the browser with a streaming reader (no 32 MiB cap), covering Reviews, merge-queue decisions, eval verdicts, VSAs, prompts and memory.
- TS codec-3 dictionary decode (a deferred item; an existing stored form).
- A browser trust bundle: a cacheable, owner-signed config built from the existing `opentine-witness-network/1` and trust-policy formats, pinned locally by the viewer.
- The run-viewer esbuild advisory fixed.
- Gates: the compression bench on the pinned runner; the audit-kit job under `unshare --net`; a nightly streak file `docs/bench/nightly-streak.json` (local data, NOT_KINDS); signed, dated flake waivers with an owner.
- The overclaim docs lint (`scripts/check_copy.py`).
- The freeze ruling adopted (D1) and recorded in FREEZE.md with its unknown-predicate test; the pyz storage-family exclusion sign-off and the RFC 4998 deferral (D2) recorded there.

**Tineyard unlock:** `/verify` and `/view` reach the current version and accept bundles; the banner caveat shrinks to the checks the viewer chose not to pin.

**1.0 criteria moved:** 2 (exclusion signed off; TS codec-3), 5 (streak running and auditable), 6, and 1 (audit engagement letter; human-only).

**Acceptance:** the browser harness runs the full pinned set in Chromium, Firefox and WebKit with the same verdict as `ts/verifier`, against the case count `scripts/check_parity.py` prints at the tag (not a hard-coded number); a bundle of at least 200 MiB verifies in the browser with zero network requests; every codec-3 vector decodes in TS; the bench is within 5% of 0.40.0 on the pinned runner, or the regression is documented with a fix assigned to 0.53; parity, peer-compat, bench and audit-kit pass on 3 consecutive main-branch runs.

**Freeze impact:** none (new readers; the trust bundle reuses frozen configs).

### 0.52.0: Web contract and security debt (about 5 weeks)

**Theme:** rule 4. Everything tineyard runs is specified here and served by `tine serve`; security-shaped debt is cleared before auditors read it.

**Scope:**
- `openapi-v1.yaml` gains a tagged admin surface carrying no signed data: session; auth (passkey login as a server concern, provider sign-in as identity linking only); tenants (create, rename, archive, membership, roles, invitations, settings, retention, holds). All implemented in `tine serve`.
- `caps.authentication`: scoped, expiring, revocable tokens (per tenant, read or write, per ref namespace) and CI OIDC exchange for GitHub, GitLab and Forgejo, as optional `caps` fields where SPEC 5.2 allows, otherwise as unsigned `/v1/limits` and `/v1/auth-methods` documents.
- Quotas and limits (storage, egress, mirror size, runner minutes): 429 or 507, never deletion; published under D3.
- Security debt: OTLP alert DNS-rebinding pinned; S3 Object Lock delete/upload race fixed plus `tine gc --sweep-expired`; all-or-nothing `tenant import --remote`; TS keyless checks the RFC 3161 CMS signature and chain; `alert list` no longer creates a key.
- Merge approvals: queue id, nonce and expiry in an `attestation` over the approval (the approval schema is closed); `land` refuses a gated landing without a signing key.
- A uniform-404 oracle suite over every tenant route, and a token-scope fuzzer.

**Tineyard unlock:** gaps 2, 4 and 12 (sign-in, workspaces, settings, tokens, limits), with self-host parity.

**1.0 criteria moved:** 1 (P0/P1 security items).

**Acceptance:** 0 undocumented `/api/*` routes against a tineyard staging route list; the 404 oracle passes on 100% of routes; 24 h of token fuzzing finds no escalation; 200 fault-injected imports leave the target unchanged or fully imported; no chunk loss in the MinIO race test; the sweep removes every expired orphan chunk in the fixture.

**Freeze impact:** NOT_KINDS (HTTP admin shapes). The approval attestation is an existing `attestation` with a plain JSON claim and no new vectors; if that is read as a claim schema, nonce and expiry move to local queue state and become a 1.x item.

### 0.53.0: Reason-code parity, storage evidence, RFC 4998 recorded (about 4 weeks)

**Theme:** the three verifiers agree on *why* they refuse; the data behind criterion 6 becomes valid.

**Scope:**
- Every refusal in Python (150 unnamed today) and the pyz (124) names its pinned reason code; `check_parity.py --reasons` compares codes on every refusal.
- A 72 h fuzz run over OTLP, `.tine` v4/v5, pack readers and DSSE.
- The CDC bake-off re-run with a correct gear table (`docs/bench/0.53-cdc.md`, reproducible from a pinned script).
- The Windows gc/lock stress test stays in the nightly.
- RFC 4998 deferred to 1.1 (D2) with its caveat repeated in every compliance profile.

**Tineyard unlock:** the browser shows the same reason text as the CLI.

**1.0 criteria moved:** 2 (closed), 6 (valid data), 1 (fuzz).

**Acceptance:** 0 unnamed refusals and 0 reason mismatches across the pinned set in all three implementations; 0 untriaged crashes from the 72 h fuzz; the CDC report reproduces on the pinned runner.

**Freeze impact:** none.

### 0.54.0: Code mirror API and hosted review runner (about 6 weeks)

**Theme:** review on every push without becoming a forge. The runner is just another reviewer.

**Scope:**
- Mirror: the `caps.project.mirror` sync spec (polling, webhook sync, last-sync time, limits); a code-read API (tree, blob, raw, history, compare, refs) over the frozen `opentine-project/1` manifest and mirror state, every response labelled with its upstream, last-sync time and "computed by host"; per-tenant code search on the `repo-search --hybrid` index.
- The mirror refuses push, receive-pack, archive download, LFS and a public project over private code; unlinking deletes the mirror and its caches.
- Runner: `tine review run --fleet` as one container image for hosted and self-hosted use, triggered by a mirror sync or forge webhook. It emits existing Review findings, eval verdicts and the existing admission VSA under a published, rotatable "tineyard runner" key. It never signs as a user and is never trusted by default (D4). Users bring their own model credentials (no token resale); cost is shown per push; the sandbox has no egress except the user's configured model endpoints.
- `docs/REVIEW-RUNNERS.md` with a free local path; push-triggered evals (`.tine/evals.toml`) on the same runner; the runner sandbox added to the audit scope.

**Tineyard unlock:** gap 3, a real Code tab, and review on every push with every finding verifiable offline and clearly a third-party opinion.

**1.0 criteria moved:** 1 (the runner is in audit drop 2).

**Acceptance:** identical code-read responses from `tine serve` and tineyard on a fixture repo; every push to every endpoint refused; byte-identical hosted and self-hosted findings for a deterministic scorer set; exported runner decisions verify with `tine-verify.pyz --offline`; removing the runner key from trust policy flips the gate to "unmet" and nothing else; the sandbox egress test passes.

**Freeze impact:** none or NOT_KINDS (frozen kinds emitted; API shapes are NOT_KINDS).

### 0.55.0: Audit fixes I and one-command onboarding (about 5 weeks)

**Theme:** absorb audit drop 1 and close the onboarding gap.

**Scope:**
- Audit drop 1: every critical and high finding received by week 2 fixed or carrying a signed risk acceptance.
- `tine init --auto`: detects installed agents and wires hooks, OTLP and the MCP proxy; offers a default push of runs beside the code repository behind the existing pre-push preview gate, with redaction first.
- New hook dialects (OpenCode, Factory Droid, Pi, Antigravity), each a thin adapter with fixtures and a named owner; a dialect without fixtures by code freeze is dropped.
- `tine doctor --bundle` (a redacted diagnostics tarball); the Entire importer fixtures refreshed against CLI v0.13.3, including its metadata ref name.
- E2 and E3 decided at the end of this release (D8).

**Tineyard unlock:** new users get runs into tineyard in minutes.

**1.0 criteria moved:** 1.

**Acceptance:** 0 critical or high findings open more than 2 weeks; on clean Linux, macOS and Windows VMs `init --auto` produces a first signed run in under 5 commands for every agent with a fixture (live-agent runs human-logged); seeded secrets never leave the machine.

**Freeze impact:** none (adapters producing existing hook-protocol runs, and CLI behaviour).

### 0.56.0: Hardware-backed key attestation (about 5 weeks)

**Theme:** make "this witness, runner or release key is non-exportable" checkable, and say nothing more (D6: key attestation is the only hardware work before 1.0).

**Scope:**
- `tine keys attest-hw KEY --from {yubikey-piv, gcp-hsm, aws-cloudhsm, azure-mhsm, tpm2-certify}`; PIV accepts only on-device keys; TPM requires EK/AK activation.
- Evidence: raw vendor attestation, vendor chain and an RFC 3161 token over both, as evidence blobs; vendor roots pinned in the pyz and TS verifiers; chip and EK identifiers redacted in public copies and never written to public logs.
- A qualifier `T2+hw:<class>` computed by verify and never stored in a run; `--require-hw` and an admission-policy `require_hw` field (local config).
- Reason codes `fail:hw-attestation-signature`, `fail:hw-key-mismatch`, `caveat:hw-chain-expired-at-T`, `unchecked:hw-collateral-missing`, `unchecked:hw-unknown-class`.
- Copy: "signing key held in <class> hardware, attested at T". First users: the tineyard runner key and the public witness key.
- E1 decided here (D8), only because D1 is in force.

**Tineyard unlock:** a hardware badge, computed in the browser, on service and witness keys.

**1.0 criteria moved:** 1 (the parsers go into audit drop 2).

**Acceptance:** vectors for every vendor class pass in Python, TS and pyz (accept, wrong key, imported PIV key, expired chain, tampered signature, missing collateral); zero network calls during verification; 72 h fuzzing of the CBOR, COSE, X.509 and TPMS_ATTEST parsers finds no crash; a YubiKey 5 and a GCP Cloud HSM key attest end to end (human-run, logged).

**Freeze impact:** E1 if granted by name under the ruling. Otherwise the frozen-safe form ships: evidence blobs on a plain attestation, a local unsigned `T2+hw` report (NOT_KINDS), labelled experimental, no new vectors, not a tier factor until 1.1.

### 0.57.0: Signed promotion and memory provenance for self-improving loops (about 5 weeks; may move after 0.60, D7)

**Theme:** the highest-fit differentiator, built from frozen parts.

**Scope:**
- `tine promote CANDIDATE --baseline LABEL`: signed eval verdicts that beat the baseline under a stated test (paired bootstrap interval or permutation test, a minimum n, a holdout), an approver set and a budget cap; emits the existing admission VSA; `--revert` writes a signed decision; canary evals revert automatically on a signed regression.
- Lineage: E2, or the frozen-safe form (VSA evidence plus verdict references). The prompt schema is untouched.
- Holdouts sealed with TINEAES with keys held only by the eval role; contamination checks (exact oid and near-duplicate, threshold recorded); `eval` refuses a run whose closure touched holdout items.
- Reward-hacking monitors as scorer plugins (grader or test edits, deleted or skipped tests, held-out versus visible gap, judge versus ground truth, fabricated tool-use evidence); a firing monitor blocks promotion unless a human overrides.
- Key separation lint; `tine loop stop` writes a signed stop and lease fencing refuses further generations.
- Memory provenance: E3, or the frozen-safe form (signer plus tlog entry); served memory oids recorded at capture time in the consuming run's existing step evidence; `recall --min-assurance`; `tine memory quarantine NOTE` writes a signed supersede note and lists every run served the note.

**Tineyard unlock:** a promotion page and a memory "served to" view.

**1.0 criteria moved:** none.

**Acceptance:** in a red-team fixture with 20 seeded hacks at least 18 are detected and 0 promoted; a planted holdout leak is refused; n below minimum or an interval crossing 0 is refused with a named reason; promote, revert, promote verifies offline in all three implementations; after a stop the next generation is refused within one lease period, with a clock-skewed fleet too; an injected note is traced to every consuming run on a 100k-run repo in under 5 s.

**Freeze impact:** none in the frozen-safe forms; E2 and E3 optional.

### 0.58.0: Audit fixes II, deferred debt, product surfaces on frozen objects (about 5 weeks)

**Theme:** close the audit, then make existing features visible in tineyard with no new kinds.

**Scope:**
- Audit drop 2 (runner, hardware parsers, web contract): every finding through medium fixed or risk-accepted in writing.
- Deferred items: Reviews pull from a remote and exports include run bundles; team-key pinning for a prompt's first version (local trust config); `tine experts` counts only validly signed notes; a merge-queue lease poll limit and `merge-queue recover`; the forge commit-status fallback for fine-grained tokens; importer, signer and snapshot plugins wired into `import`, `sign` and `rewind`.
- Run-anchored comments and an annotation queue in `tine ui` on the existing v3 `annotation` (`target_id` the run, chained by `previous_id`; the `value` convention is documentation only).
- Score history per push, insights, explore, badges and OG cards as derived indexes and HTTP outputs labelled "server-computed"; the browser recomputes badges and warns on a mismatch; explore lists public tenants only.
- SSE event kinds documented for Reviews, merge queue and coord.

**Tineyard unlock:** gaps 6 to 11; changelog, docs and status pages generated from this repo.

**1.0 criteria moved:** 1 (all P0/P1 closed).

**Acceptance:** the audit firm confirms in writing that every critical and high finding is resolved; every chart point links to its signed objects; insights recomputed offline from an export equal the hosted numbers; a private oid queried through explore, a badge or `/r/<oid>` gets the same 404 as a random oid; the `freeze_inventory.py` lists are unchanged or shorter.

**Freeze impact:** none or NOT_KINDS.

### 0.59.0: Hardening (about 3 weeks)

**Theme:** no features. Prove stability and collect the human sign-offs.

**Scope:** FREEZE.md regenerated from the inventory, listing every grant made under the ruling (if any); SPEC, CLI.md, DEPRECATION.md and the OpenAPI document reviewed for 1.0 readiness; a leave-the-service test against tineyard production (export a tenant of at least 10k runs, import it with `tine serve`, verify byte-identically); a reproducible, attested web build and a tineyard trust page listing every service key and its hardware attestation; human sign-offs (counsel on the compliance profiles with eIDAS references re-checked; live S3, Azure and forge tests; one Zenodo and one HF publish; the witness registry).

**1.0 criteria moved:** evidence collected for all seven.

**Acceptance:** each criterion has a dated evidence link in the CHANGELOG; the nightly streak is at least 30 days and unbroken through the branch cut; 0 open P0 or P1 bugs.

**Freeze impact:** none.

### 0.60.0: Waypoint and reassessment (about 3 weeks, mostly soak)

**Theme:** 0.60.0 is a stabilisation waypoint on the way to 1.0 (D5 as modified). It is not 1.0.0-rc1 and is not re-tagged 1.0.0.

**Scope:**
- A 14-day soak in which nightly, parity, peer-compat, bench, audit-kit and fuzz stay green; regression fixes only, each as 0.60.x.
- The audit's final report published with the fix list, if it has arrived.
- **The reassessment:** after 0.60 the owner reviews the 1.0 criteria evidence, further research (competition, hardware, self-improving loops) and tineyard's progress alongside OpenTine, and only then schedules the 1.0 track (release candidate, the RFC 4998 1.1 work, and whatever moved, such as 0.57 under D7).

**Acceptance:** 14 days with zero red standing jobs; a written criteria status for all seven; the owner's reassessment recorded in this roadmap.

**Freeze impact:** none. The formats stay frozen as in FREEZE.md; nothing is added while the reassessment is pending.

### Timeline and dependencies

```
audit engagement (human, 0.51) ─> drop 1 ─> 0.55 ─> drop 2 ─> 0.58 ─> 0.59 ─> 0.60 waypoint ─> reassess ─> 1.0 track
0.51 browser verifier/trust bundle + green gates + D1 in force
  ├─> 0.52 web contract/auth/404/security debt ─> 0.54 mirror + hosted runner ─> 0.58 surfaces
  ├─> 0.53 reason-code parity + fuzz + CDC (closes criterion 2)
  ├─> 0.55 onboarding (needs 0.52 tokens); E2/E3 decided
  ├─> 0.56 hw key attestation (E1 decided here; runner key from 0.54)
  └─> 0.57 promote + memory provenance [may move after 0.60, D7]
nightly streak from 0.51 ─────────── unbroken ≥30 days at the 0.59 cut
```

Starting 2026-11-16 with one core team and the audit engaged by 2026-12-15: 0.51 about 2026-12-21, 0.52 2027-02-01 (holiday slack), 0.53 2027-03-01, 0.54 2027-04-12, 0.55 2027-05-17, 0.56 2027-06-21, 0.57 2027-07-26, 0.58 2027-08-30, 0.59 2027-09-20, 0.60 about 2027-10-11. Slip risk is about 6 weeks, dominated by the audit. No 1.0 date is set until the post-0.60 reassessment.

### 1.0 criteria tracker

| # | 0.51 | 0.52 | 0.53 | 0.54 | 0.55 | 0.56 | 0.57 | 0.58 | 0.59 | 0.60 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 Audit, P0/P1 | engaged | security debt | fuzz | runner in scope | drop 1 fixed | parsers in scope | — | drop 2; all P0/P1 closed | evidence | report, if arrived |
| 2 Parity | exclusion signed; TS codec-3 | — | reason codes: closed | hold | hold | hold | hold | hold | evidence | soak |
| 3 Peer-compat | green | green | green | green | green | green | green | green | evidence | soak |
| 4 pyz air-gap | re-run | … | … | … | … | … | … | … | evidence | soak |
| 5 30 nightly days | streak file starts | … | … | … | … | … | … | … | ≥30 unbroken | soak |
| 6 Compression | pinned run | — | valid CDC data | hold | … | … | … | … | evidence | soak |
| 7 Deprecation | met | … | … | … | … | … | … | … | evidence | soak |

The streak is only required to be unbroken at the 0.59 cut; a feature release may reset it without being blocked.

### Owner decisions, 2026-11-13

| # | Decision |
|---|---|
| D1 | The narrow freeze ruling is adopted as an explicit relaxation (text in FREEZE.md, conditions a–e): no new vector families, no new `docs/schemas` files, no new signature schemes, each predicate signed off by name. None is granted in 0.51. |
| D2 | RFC 4998 is deferred to 1.1, with the documented caveat: up to 16 root-bound tokens; not a hash-tree renewal; does not survive a SHA-256 break. |
| D3 | Every feature and all verification stay free for ever. At most, metered hosted storage beyond fair use and hosted runner compute at cost may be charged, always on the user's own model credentials; no token resale. §11 is amended accordingly. |
| D4 | The hosted runner key is an optional, labelled reviewer and is never trusted by default. |
| D5 | **Modified:** 0.60.0 is not 1.0-rc1. It is a waypoint on the way to 1.0; after 0.60 the owner reassesses with more research and tineyard's progress. |
| D6 | Hardware before 1.0 is key attestation only (0.56). Nitro/SNP witness, TDX, CCA, GPU confidential computing and per-run binding go to 1.x. |
| D7 | 0.57 may move after 0.60 if the audit slips. |
| D8 | E1 (hardware-key predicate) is granted only with D1 in force and is decided at 0.56; E2 (promotion lineage) and E3 (memory-provenance claim) are decided at the end of 0.55. The frozen-safe forms ship regardless. |

Also signed off on 2026-11-13: the pyz storage-family exclusion for criterion 2 (FREEZE.md).

### Human-only work

| Item | Suggested owner | Must start |
|---|---|---|
| Engage and fund the third-party audit (CLI, hosted service, browser verifier, runner, hardware parsers); schedule two finding drops | Release owner / funding lead | Now; signed by 0.51 week 2 |
| Watch the nightly streak; approve signed waivers | CI owner | 0.51 to 0.60 |
| 72 h fuzz runs and crash triage (0.53, 0.56) | Security engineer | 0.52 |
| Hardware lab: YubiKey 5, TPM box, GCP, AWS and Azure HSM accounts; live attest runs | Security engineer with cloud access | Purchase by 0.54 |
| Licensed agent installs for onboarding runs; one named owner per hook dialect | Integrations lead | 0.54 |
| GEPA reference loop and the 20-hack red-team suite | Self-improvement owner | 0.55 |
| Public witness operation; at least 2 independent operators; the registry | Witness operator lead | 0.54 |
| Live S3/MinIO/Azure Object Lock, forge, Zenodo and HF tests | Infra owner | 0.58 |
| Counsel: compliance profiles, eIDAS re-check, "hardware-held key" copy | Legal reviewer | Engage by 0.56; sign by 0.59 |
| Tineyard: implement the OpenAPI routes, bump the verifier pin, runner operations and unit economics, DPA and subprocessor list, `security.txt`, status page, incident response, a pricing page that matches §11 | Web / tineyard operator | 0.51 onward; runner economics before 0.54 |
| Legal entity, trademark, CLA/DCO | Project lead | Before 0.59 |
| The post-0.60 reassessment (D5) | Project owner | At the 0.60 soak |

### Cut ideas

- **Code hosting, push to the mirror, an own forge:** breaks rule 6; we stay the evidence layer beside the forge.
- **New fields on `opentine.memory`, `opentine.prompt` or `opentine.merge-approval`:** all three schemas are closed; attestations or capture-time evidence are used instead.
- **A new signed "issue" kind:** the v3 `annotation` covers it.
- **A profiles escape list in `freeze_inventory.py`:** a self-granted escape class beside lists that may only stay empty or shrink.
- **WebAuthn signatures verified inside a claim:** a new signature scheme, so 1.x. Passkeys may gate access to an existing `tine-sig` key.
- **RFC 4998 `attest --renew` before 1.0:** a new bound form (D2).
- **TEE witness, TDX DCAP, Arm CCA, NVIDIA NRAS, per-run TEE binding before 1.0:** weaker evidence, collateral rot and parser surface during the audit (D6).
- **"Verifiable inference", a TEE agent runtime, zkML, on-chain anchoring:** hardware cannot vouch for a remote model; the tlog and witnesses already anchor.
- **TLSNotary/zkTLS transcripts and EAT/Veraison/ITA token ingest:** late parser surface; 1.x spikes.
- **FIDO device attestation for approvals:** synced passkeys mostly give "none" attestation.
- **`tine ask` cross-repo search and live SSE share sessions:** move no 1.0 criterion; 1.1, on existing indexes.
- **Columnar pack v6, prolly-tree, OpenZL, hash-agility activation:** format work, so 1.x.
- **Marketing claims of only or unique signed line-level attribution, or that no one else ships this offline:** refuted or unverified.
