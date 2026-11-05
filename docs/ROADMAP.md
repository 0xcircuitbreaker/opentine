# OpenTine roadmap: 0.35 to 0.44

*Baseline: v0.34.0, November 2026. Horizon: about **7–9 months**. Each release below is 3–5 weeks of work, not the 1–3 weeks the earlier draft claimed. Work that does not fit has moved to "0.45+" or the 1.0 track and is not hidden inside a release. Every claim that OpenTine "lacks" something was grep-checked in `opentine/`. Claims about competitors come from a survey of a subset of tools and are stated with that caveat.*

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

## 10. After 0.44 (0.45+) and the 1.0 track

**0.45+ (named, not hidden):**

- Run merge, pick and merge queue (F2).
- SSE events, webhooks, `tine watch`.
- `tine eval run` and compare, with signed verdicts.
- Datasets: `add --from-run`, JSONL/HF/Langfuse I/O.
- Direct export and import for Langfuse, Phoenix, Braintrust and LangSmith. Whether those vendors display `gen_ai.evaluation.result` is *unconfirmed* and will be tested, not assumed.
- Read-only `tine ui`.
- `tine compliance check` profiles and the Provenance/Workflow Run Crate.
- `tine publish zenodo`.
- An **artifact-evaluation package**: crate, `replay/v1` attestation and the pyz verifier.
- Full air-gapped audit kit.
- Webhook and OTLP alerts.
- MCP 2025-11-25 tasks.
- S3 Object Lock / Azure immutable retention backends.
- Jules importer.

**1.0 track:**

- Per-kind dictionaries (P3).
- FastCDC lazy fetch for payloads ≥8 MiB, plus an S3 store and promisor fetch.
- Oid token table; columnar pack v6; prolly-tree index; OpenZL spike.
- RFC 4998 evidence records with PQ re-timestamping (`attest --renew`) and embedded CRL/OCSP.
- eIDAS LOTL/JAdES.
- C2PA `tine media sign`.
- Pluggable snapshot providers and `rewind --with-side-effects`, with compensation records.
- Bedrock CONNECT proxy.
- A2A importer.
- Budgets and the prompt registry.
- Hash agility, activated.

**1.0 criteria:**

1. All P0 and P1 items are closed, and a third-party audit has been done.
2. The formats are frozen, and the Python, TS and pyz implementations pass the same vectors.
3. The 0.34 peer compatibility job is green for every release.
4. The pyz is air-gap-tested on Linux, macOS and Windows.
5. Nightly stress tests have been green for 30 days.
6. The compression bench has regressed by no more than 5% since 0.40.
7. The deprecation policy in §2 is published.

The FRE 902, AI Act and eIDAS mappings still need to be checked against the primary texts before any compliance profile ships.