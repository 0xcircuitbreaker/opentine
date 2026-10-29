# Changelog

## 0.14.0 — unreleased

### Security

- **MCP output is re-scrubbed.** `show_run` and the `run://` resource now pass
  a run back through the writer's redaction before rendering it, as `tine
  export` does, so a legacy (pre-0.9.1) or hand-written unredacted `.tine` no
  longer hands its secrets to the client's model.
- **`tine run --model` failures are display-safe.** URLs in the error text
  lose their userinfo, query and fragment (`--base-url` / `OLLAMA_HOST`
  credentials echoed by httpx), and the rest is redacted (provider error
  bodies that quote part of a key).
- **An invalid `OLLAMA_HOST` names only its scheme**, never the value, which
  may carry `user:password@`.
- **Base64-wrapped credentials are redacted.** A standalone, padded base64
  run (24-8192 characters, at most 64 per value) that decodes to printable
  UTF-8 is scanned like plain text and replaced whole on a hit. Binary
  payloads and ordinary text are kept; URL-safe and unpadded base64 are not
  unwrapped (a documented limit).
- **`tine run --parallel` members start with `python -P`**, so an `opentine/`
  package in the project directory no longer shadows the installed one.
- **Fan-out member logs are private.** Logs are created 0600 without
  following symlinks, and `--log-dir` is created 0700: they hold raw member
  output, keys passed by `--env` included.
- **Repository refs, reflogs and directories are private.** New refs, ref
  staging and journal files and reflogs are written 0600, directories inside
  `.tine` are created 0700, and the `.tine-worktree` marker is 0600.
- **`tine plugin export` writes 0600 files and 0700 directories**, and its
  help and the README now say the bundle is machine-local: it embeds the
  interpreter's and the repository's absolute paths.
- **Allowlisted adapters must be installed.** An entry point whose
  distribution was found in the working directory (`python -m` puts it on
  `sys.path`), or whose provenance is unknown, is skipped and not loaded.

## 0.13.1 — 2026-10-28

### Fixed

- **Windows: a file mid-replace no longer reads as a path escape.** The
  repository containment check resolved paths without the sharing-violation
  retry the rest of 0.13 uses, so a reader that raced another process's
  `os.replace` could get a transient `PermissionError` and report
  "repository path escapes its root". `tine prune` then refused to run
  (failing closed, nothing deleted). Python 3.11 also resolves such a file to
  its extended-length `\\?\C:\...` spelling, which the check compared against
  the plain root. The resolve is now retried, the extended prefix is dropped
  before comparing (`\\?\UNC\` paths still fail closed), and a denial that
  persists is reported as "repository path cannot be inspected".
- **A pack being renamed in is no longer hidden from a running process.** If a
  pack index could not be opened while another process's gc was still
  renaming it into place, the pack was skipped and that listing cached, so the
  process treated the pack's objects as missing until the directory changed
  again (a live recorder then failed with "missing linked object"). Index
  loads now retry sharing violations on Windows, and a listing with an
  unreadable index is not cached, so the next lookup rescans. A corrupt index
  is still skipped and reported by `tine fsck`.

### Compatibility

- Golden compat fixtures for 0.13.0, generated from the published wheel, join
  the release gate: 0.13.1 reads every artifact and repository 0.13.0 writes.

## 0.13.0 — 2026-10-26

### Footprint I (no format change)

No on-disk format change: 0.12 reads every repository 0.13 writes, and 0.13
still reads every format back to 0.3.0.

- **Auto-pack.** `Recorder.finalize()` packs cold loose objects once 256 (by
  default) have piled up. It only runs on repositories already at storage
  descriptor version 2; a version-1 repository is never upgraded. Loose
  objects younger than 60 s are never packed. It takes the gc lock without
  waiting and is skipped if a gc is running. It never fails a recording. Small
  packs are merged so pack sizes stay a geometric progression. Turn it off
  with `OPENTINE_AUTO_PACK=0`, or set a threshold with `OPENTINE_AUTO_PACK=N`
  or `"auto_pack": false | {"objects": N}` in `config.json` (0.12 ignores the
  key).
- **gc removes the empty fan-out directories it leaves** (`objects/<kind>/<xx>`),
  and the empty directories older releases left behind. A writer that races
  the removal retries.
- **`tine du`**: footprint by kind, run or ref (`--by`). It shows canonical
  and stored bytes, loose and packed objects, fan-out directories, refs, logs
  and indexes. `--json` is supported.
- **`tine prune`**: a dry run by default; `--delete` removes. Only objects
  that are unreachable and older than `--older-than` (default 14 days, never
  under 60 s) are candidates. Roots include:
  - every ref (including tags) and every reflog row
  - annotations and attestations
  - the shallow boundary and `worktrees/`
  - any other repository file outside the object store
  - runs named by the git checkout's `Tine-Run` trailers and `refs/notes/tine`

  If a root source can't be read, prune deletes nothing.
- **Pruning is safe against a live writer.** Re-storing an object that already
  exists now refreshes it: a loose file's mtime, or a pack's at most hourly.
  An object a writer is about to reference again is therefore never old
  enough to prune. The delete takes the gc lock, plans again, checks each age
  again, and rewrites packs (writing and reading back first) instead of
  editing them.
- **Reflog expiry** runs with `tine prune`. It is conservative by default:
  rows older than 90 days *and* beyond the newest 100 per ref go. The row for
  the ref's current target always stays, and tag reflogs never expire. Set it
  with `--reflog-expire DAYS` or `"reflog": {"expire_days": N, "keep": N}`.
  Each log is rewritten under its ref's own lock, and a ref that is locked is
  skipped.

### Footprint II: storage version 3 (opt-in)

The one format change in 0.13, and only when asked for: `tine gc --upgrade`.
Object ids, digests and signatures do not change. opentine 0.12 and older
refuse a version-3 repository at open (`repository config is incompatible`);
`tine gc --downgrade` returns it to version 2. 0.13 still reads every format
back to 0.3.0, and v2 and v3 packs side by side.

- **v3 packs**: blocks of up to 16 MiB, one object kind per block, blobs and
  events in recording order. A block of several objects is capped at 16 MiB
  inflated, checked against the index before inflating. Readers keep a small
  cache of inflated blocks (64 MiB).
- **Run snapshots as deltas**: a snapshot is stored as the previous snapshot
  in its block plus the newly appended events (and any changed fields), with
  a full snapshot at least every 32. Chains are walked iteratively and capped
  at 64; a delta never starts a block, so a chain cannot loop.
- **Slim events**: fields holding their empty default are left out in the
  pack and restored on read.
- **Binary pack index** with a trailing SHA-256, exact-length and tiling checks
  before any field is trusted.
- Every read rebuilds the canonical bytes and checks them (and every delta
  base) against the object id, failing closed. `fsck` reads every object of
  every pack and reports a v3 pack in a repository below version 3.
- On the recorded-session benchmark (20 runs × 30 events, 13.5 MB of
  canonical objects) `tine gc --upgrade` takes the repository from about
  89 KB to about 38 KB per run on disk; the packs alone go from 74 KB to
  23 KB per run (reflogs and the index are most of the rest).
- Conformance: new `localpack.read` op and `29-localpack.json` vectors
  (binary index, blocks, stored forms, delta and bomb bounds); the adapter
  contract grows by one op.

### Branch engine: crash-safe refs, fan-out and worktrees

- **`Repo.update_refs`**: move several refs at once, all or none. Every row is
  compare-and-swap. Locks are taken in sorted order, then a journal
  (`txn/<id>.json`, `opentine-ref-txn/1`) is written durably as the commit
  point, then the refs and their reflog rows. A writer killed before the
  journal changed nothing; one killed after it is rolled forward by the next
  ref write anywhere in the repository (`Repo.recover_refs()` does it on
  demand). Roll-forward is itself compare-and-swap and never clobbers a ref
  moved since. A malformed or tampered journal (illegal ref, missing object,
  wrong type, extra fields) is never applied: it is renamed `<id>.rejected`.
- **Ref deletes take a stamped lock.** `tine branch -d` and the other delete
  paths wrote an empty `.lock`, which a crash left behind for good; they now
  record pid/host/time like every other ref lock, so a dead one is broken.
- **`tine fan-out RUN [--from-step N] --vary model=a,b [--repeat K] -- CMD`**:
  one fork per member from a single fork point. The run is walked once for all
  N forks, every `experiments/fanout/<id>/<n>` ref is written in one
  transaction, and the fan-out is recorded as an annotation on RUN
  (`opentine.fanout.<id>`, no new object type). CMD runs per member as an argv
  list (never a shell) with `{model}`, `{run}`, `{ref}`, `{index}` and every
  `--vary` name substituted in one non-recursive pass. A value that would
  stand alone as an argument and starts with `-` is refused. Without CMD the
  forks are only prepared.
- **`tine run --parallel N`** runs the same `tine run` invocation N times
  (times every `--vary` combination), each member saving its own run;
  `--save` and the autosave flags are refused with it.
- Both take `--jobs` (never exceeded), `--timeout` per member, `--budget USD`,
  `--env NAME`, `--log-dir`, `--json` (NDJSON status, one object per event,
  never argv, env or variation values) and `--resume ID`. Members start in a
  fresh process group (Linux subreaper) or a kill-on-close Job Object
  (Windows) and are killed with their whole process tree on timeout, budget,
  stop or Ctrl-C, and after a normal exit too.
- **Shared budget ledger** (`budget.SharedLedger`): members report their
  cumulative cost in `$OPENTINE_FANOUT_COST_FILE` (`tine run` writes it);
  reports are taken under one lock and can never double-count. Once the total
  reaches `--budget`, running members are killed and nothing else starts. With
  a budget set, a member that ends without a readable cost closes the budget
  too (fail closed).
- **Member environment is an allowlist**: `PATH`, `HOME`, locale, temp and the
  Windows system variables, plus the `OPENTINE_FANOUT_*`/`OPENTINE_VARY_*`
  variables. API keys and signing keys reach a member only when named with
  `--env`.
- **`--resume ID`** reruns only the members that did not finish (`ok` or
  `failed`). The state file (`.tine/fanouts/<id>.json`, or
  `.tine_runs/parallel/` for `run --parallel`) is validated field by field and
  holds no command: resume takes the command again and refuses one whose
  digest differs, so a planted state file cannot choose what runs. The spend
  already recorded counts against the budget.
- **`tine worktree add PATH REF [--git [COMMIT]]`, `list`, `remove [--force]`,
  `prune`**: an isolated directory per branch, registered at
  `.tine/worktrees/<name>.json` (a prune root) and marked with a
  `.tine-worktree` file. `--git` also makes it a detached `git worktree`.
  Names are one safe component; a symlinked target, one inside the repository,
  or a non-empty directory is refused. `remove` deletes a directory only when
  its own marker names this repository and worktree, so an edited registry
  cannot point it at another directory; `prune` only drops registrations.
  `tine fan-out --worktree-dir DIR` gives every member its own worktree.
- **`tine rebase`/`tine cherry-pick --ref NAME`** refuse to move an existing ref
  unless `--force` is given (0.12.1 review).

### Agent identity and signed actions

Additive: old runs, repositories and indexes keep working, and 0.12 ignores
the new metadata key and manifest files.

- **`opentine-agent/1` identities.** A harness run now records
  `metadata.agent_identity`: harness, model, provider, a digest of the agent's
  definition files (`CLAUDE.md`, `.claude/agents/*.md`, `AGENTS.md`, ... --
  hashed, never stored), an optional signing-key fingerprint, a per-run
  instance nonce, and a claimed parent link for subagents. Its stable ref is
  `agt_` + 128 bits. A run without one is `legacy:<harness>`, shown as unsigned.
- **`tine agent id | show | trust | keys`.** `id` computes the ref an agent
  would record; `show RUN|agt_...` prints identity, trust state and whether a
  lineage link is verified; `trust` trusts `.tine/agents.toml`.
- **`tine keygen --agent NAME`** writes an Ed25519 key to
  `$XDG_CONFIG_HOME/opentine/agent-keys/` (0600), outside every repository.
- **`.tine/agents.toml`** pins agent key fingerprints. Like `porcelain.json` it
  is inert in a clone until `tine agent trust`; any edit revokes the trust.
- **`tine-actions/1` signed action manifests.** `tine actions RUN --sign`
  (`--agent NAME`, `--ed25519-key-file`, `--key-file`/`--key-env`) writes a
  hash-chained manifest of the run's actions, bound to the run id and a digest
  of its step graph, and signed with the existing `sign_block`. `--verify`
  (`--pubkey`, `--pin`, HMAC key flags) recomputes it from the run.
- **Every output shows a trust state**: `unsigned`, `verified`, `mismatch` or
  `unknown-key` -- in `who`, `touched`, `actions`, `audit` and `agent show`.
- **`tine audit --require-signed`** fails unless every run's manifest
  verifies; `--pin` adds trusted keys.
- **`tine who` / `touched`** gain `--agent-ref` (full refs only; prefixes are
  refused), `--lineage REF` (an iterative walk over claimed parent links) and
  `--verified-only`; `--by agent_ref` groups by ref.
- The action index is now `ACTIONS_SCHEMA` 4 (agent refs). It is a cache, so
  an older index is rebuilt on first use.
- Security: a manifest moved onto another run is `mismatch`; a key other than
  the identity's `key_fpr` is `mismatch`; a lineage link counts only when both
  runs verify and the parent's signed manifest lists the child's spawn step;
  look-alike names are NFKC-normalised before hashing and flagged when shown;
  a planted `verified` column or `agent_ref` row in the sqlite index is
  ignored, because every trust state is recomputed from the run and manifest;
  agent strings reach the terminal escaped.
- Conformance: `48-actions.json` and `49-agent.json` vectors, ops `agent.ref`
  and `actions.chain`, and SPEC §4.8 and §4.9. The suite is now
  **550 conformance vectors**; 209 of the 550 refuse input, and the adapter
  contract still has one entry point: 36 ops.

### Harness integrations and fleets (no format change)

Additive run metadata only (`agent_identity`, `opentine.fleet`); older readers
see ordinary runs and forks.

- **`tine import --fleet`** (Claude Code, needs `--repo`): the session's own
  events become the root run and each subagent a child run forked at the tool
  step that spawned it (a nested subagent forks from its parent subagent).
  Every member records an `opentine-agent/1` identity with `parent`,
  `parent_run` and `spawn_step`; the root carries the `opentine.fleet`
  manifest. A subagent with no spawning step (a stop without a start) becomes a
  standalone child. Agent ids are clamped before naming
  `heads/fleet/<root>/a-<agent>`. The fleet's cost counts shared steps once and
  equals the single-run import's cost. Nested subagent links are now followed
  in plain imports too.
- **Transcript imports record an agent identity** (Claude Code, Codex, Gemini
  CLI, Qwen Code, OpenCode, ATIF, Hermes) instead of reading as `legacy:`.
- **`hermes-trajectory` importer** for Hermes Agent's ShareGPT-style JSONL
  trajectories (`<tool_call>`/`<tool_response>`/`<think>` blocks; the last
  record, or `FILE::N`). Detected by `--format auto`. Trajectories carry no
  token counts, so their model steps stay unpriced. Tool blocks are bounded in
  count and size and parsed with the stdlib JSON decoder only.
- **`tine plugin export DIR --repo PATH`** writes a Claude Code plugin:
  exec-form hooks running `python -I -m opentine.cli` (SessionEnd import,
  SubagentStart/SubagentStop journal), read-only skills, and a `.mcp.json`
  starting the MCP server with `--read-only`. It refuses to write inside
  `~/.claude` or `$CLAUDE_CONFIG_DIR`, refuses symlinks and non-empty
  directories without `--force`, and warns when the old-style hook would
  import each session twice.
- **`tine hook event`** journals subagent hook payloads read from stdin only
  (clamped ids, `<repo>/journal/subagents.jsonl`, capped at 8 MiB, always exits
  0). **`tine hook status`** no longer needs `--global` and lists the events
  each CLI has installed. `--agent hermes` prints a `config.yaml` snippet and
  never edits YAML.
- **`python -m opentine.mcp_server --read-only`** registers an allowlist of
  read tools only; write tools, and any tool added later, are left out.
- **`AdapterSpec` SDK** (`opentine.adapters`): a harness importer in one file.
  Third-party adapters are `opentine.adapters` entry points and are never
  loaded unless allowlisted in `$XDG_CONFIG_HOME/opentine/adapters.json`; one
  cannot shadow a built-in. The core enforces the source byte cap, the event
  cap and the result type. `tine import --adapter NAME` and
  `tine harnesses --check [NAME]`.
- **ATIF export emits `subagent_trajectories`** instead of flattening: each
  subagent's steps become an embedded trajectory referenced from the spawning
  tool step's result, and import back as a typed subagent edge.
- **`tine fleet up|status|stop|cost`** runs a declared `fleet.toml` (fan-out
  or supervisor/workers) on the parallel executor. The manifest is refused
  until `--trust` records the SHA-256 of its exact bytes; any edit revokes
  trust. Commands are argument lists only, members see only allowlisted
  environment variables, `cwd` stays inside the manifest's directory, workers
  get the supervisor's parent link, and `stop` kills every member's process
  tree. `fleet cost --repo PATH RUN` totals an imported fleet.

### Security

- **Ref transactions stay atomic on Windows.** A reader holding a ref or lock
  file open made a post-commit rename fail, leaving a paired update half applied
  and locks behind. Ref, journal, lock and prune reads/writes now retry Windows
  sharing violations (bounded, then fail closed), and lock release never strands
  the remaining locks.

- **`tine prune` refuses (deletes nothing) when a stored object it must walk
  cannot be read** -- corrupt bytes, or a pack whose codec (zstd) is not
  installed. Only a truly absent object is skipped; before, everything reachable
  only through an unreadable object could be deleted.
- **Prune's age floor is now 70 minutes** (was 60 s), above the hourly
  pack-freshen throttle, so a packed object a live recorder just reused can no
  longer be pruned from under it.
- **Ref transaction recovery tolerates a journal that vanishes after listing**
  (finished by its owner or another recoverer) instead of failing the write
  with `FileNotFoundError`.
- **`--lineage --verified-only` follows only edges recomputed from the runs and
  signed manifests**; an index row only nominates a run, so a forged row can no
  longer graft an unrelated verified agent onto a lineage. Residual: the
  parent's manifest lists spawn steps, not which child each spawned, so another
  trusted-key run naming a real spawn step is still accepted.
- **`tine fleet status`/`cost` escape member agent names, statuses and costs**,
  and a member's reported cost is stored only if it is a number.

## 0.12.1 — 2026-10-23 — Patch: crash-safe locks, rev:path containment

Fixes from the round-0 audit of the shipped 0.12 surface. Each fix has a
regression test in `tests/test_patch_0_12_1.py`. No format
change: every file and repository written since 0.3.0 still reads, and 0.12.0
reads everything 0.12.1 writes.

### Fixed

- **A ref lock left by a crashed writer no longer blocks the ref forever.** Ref
  locks (`refs/**/<ref>.lock`) and `gc.lock` now record pid, host and start
  time. A lock whose process is provably gone on this host is broken
  automatically (moved aside and re-checked, so a racing writer's fresh lock is
  never deleted); a live, foreign-host, empty or unreadable lock is left alone
  and the error names the lock file and says how to remove it.
- **gc lock recovery is the same on every platform.** Windows no longer breaks a
  gc lock by age alone; liveness is checked through the process handle, and a
  long-running gc on POSIX is no longer taken over after a day.
- **Git allowlist: `rev:path` is contained the way git resolves it.** Git reads
  the path of `rev:path` from the repository top, not the working directory,
  so with a shell root that is a subdirectory of a larger repository
  `git show HEAD:<file>` (or `HEAD:` for the whole top tree) could read
  committed content above the root. Such paths are now checked from the
  repository top; `rev:./path` stays cwd-relative.

### Tests

- Backwards-compat fixtures for 0.12.0 (`tests/fixtures/compat/v0_12_0`),
  generated by the released 0.12.0, join the cross-version gate.

## 0.12.0 — 2026-10-22 — Git for agent runs: blame, bisect, git integration, porcelain, interop

opentine now works the way git users expect. A commit can name the agent runs
that produced it, `tine blame` says which run, step, model and tool call wrote a
line, and `tine bisect` finds the run or step where things went wrong. Remotes,
branches, tags, the reflog, `pull`, `reset`, aliases and hooks behave like their
git namesakes, and the plain verbs (`log`, `show`, `diff`, `tag`) act on a
repository first. Agent sessions can be captured with no setup, ATIF and
OpenCode sessions import, media endpoints are called and priced directly, and
transfers and server storage are compressed.

### Upgrade notes

- **Pricing catalogs are signed with a domain-separated scheme**
  (`ed25519/opentine.pricing-catalog.v2`): the signature covers
  `opentine.pricing-catalog.v2:` followed by the canonical body, so it cannot be
  confused with an artifact or attestation signature. Older (v1) signatures still
  verify for catalogs generated before 2026-11-01 by the existing release key;
  anything newer must be v2. **opentine 0.11 and older cannot read a v2-signed
  catalog file**, so a user or workspace catalog signed by 0.12 needs 0.12.
- **The remote stores new objects compressed, then sealed (TINEAES4)**, with the
  codec and the uncompressed size bound into the authenticated data. A 0.11
  server cannot read TINEAES4. Before rolling a server back, run
  `tine serve --root R --tenant T reseal --to aes3` for each tenant and set
  `TINE_REMOTE_STORAGE_CODEC=off`. `TINE_REMOTE_STORAGE_CODEC=off|zlib|zstd` and
  `tine serve --uncompressed-tenant T` turn compression off server-wide or per
  tenant. TINEAES1–3 objects keep opening.
- **Transfers negotiate TINEPACK4**, a binary compressed pack. A 0.12 client only
  offers it to a server that advertises it, and a 0.12 server only answers with it
  when asked, so 0.11 clients and servers keep exchanging TINEPACK3 in both
  directions.
- **The plain verbs act on a repository first.** `tine show`, `diff`, `tag` and
  `log` read the v3 repository when one is found (`fork` with `--ref`, `search`
  with `--repo`). An existing file path or a legacy run id still selects the old
  file behaviour, and `--legacy` forces it; the `repo-*` names keep working.
- **Aliases, hooks and remote token files only take effect in a repository this
  machine has trusted.** `tine config --trust` records the exact bytes of
  `.tine/porcelain.json` outside the repository; any edit not made through `tine`
  makes them inert again, so a cloned repository cannot run anything. Hooks are
  also off until `hooks.enabled` is set.
- **`tine export --output` writes owner-only (0600) files**, also when `--force`
  replaces an existing file, and refuses a destination that exists and is a
  directory, FIFO or device.
- **OIDC discovery fetches through a bounded HTTPS client by default**
  (`opentine.remote._jwks.https_fetch`): no redirects, no proxy environment, a
  1 MiB cap and a total deadline. Pass `fetch=` to use your own.
- **The remote can enforce fast-forward-only `heads/*`**: `tine serve
  --fast-forward-heads`. It is off by default, because an ordinary `put_run`
  repoints `heads/main` at an unrelated new run. With it on, a non-fast-forward
  move is refused unless an admin pushes with `tine push --force`; both outcomes
  are audited.
- New verbs (README count 64): `git`, `blame`, `bisect`, `remote`, `pull`,
  `branch`, `verify-tag`, `reflog`, `reset`, `config`, `rebase`, `cherry-pick`,
  `hook`, `media` (and the porcelain `log`).

### Added

- **Runs linked to git commits.**
  - `tine git install-hook [--global]` adds a `prepare-commit-msg` hook that
    appends a `Tine-Run: <run>` trailer for every recorded run that wrote one of
    the staged files since the last commit. It never blocks a commit and never
    replaces a hook you already have: an existing hook is kept as
    `prepare-commit-msg.tine-chained` and runs first. `--global` uses your global
    `core.hooksPath`, or opentine's own hooks directory with pass-through shims
    so each repository's own hooks keep running.
  - `tine git note COMMIT [RUN...]` records runs, model and cost under
    `refs/notes/tine`, for example after a rebase rewrote the message.
  - `tine git log --commit SHA | --pr N` (also `tine log --commit/--pr`) lists the
    runs behind a commit or a GitHub pull request (`--pr` uses `gh`).
- **`tine blame PATH[:LINE] [--git]`** names the run, step, model, agent and tool
  call that wrote a file or a line, by matching the line against each recorded
  write (Write content, Edit/MultiEdit text, `apply_patch` hunks). `--git` starts
  from `git blame`: commit, then its trailers and notes, then the step.
- **`tine bisect`** finds the first bad run along a fork lineage, in an explicit
  run list (`--runs`, e.g. one task across models), or the first bad step of one
  run (`--steps RUN`). `bisect run --eval CMD` uses an evaluator's exit code like
  `git bisect run`; `bisect run --score NAME>=X` uses recorded evaluation scores.
  In a repository each verdict is recorded on the run as an annotation.
- **Git-style porcelain.**
  - `tine remote add/ls/rm/rename` (a remote stores a path to a token file, never
    the token, and refuses URLs with credentials, a query or a fragment); `fetch`
    and `push` accept remote names and `--all`; `tine pull` fetches and only
    fast-forwards.
  - `tine branch`, `tine tag NAME [RUN] [-s|-d|-f]` (signed tags) and
    `tine verify-tag`, `tine reflog`, `tine reset REF RUN [--expect]`. Every
    change is compare-and-swap, and a deleted branch or tag can be brought back
    with `reflog` and `reset`.
  - `tine config get/set/--list/--unset/--trust` and `alias.*` (an alias never
    shadows a built-in verb).
  - `tine log --graph --all --oneline` draws the fork tree with model, status,
    steps and cost.
  - Client hooks `pre-record`, `post-run`, `pre-push`, `post-fetch`: opt-in,
    trust-gated, regular files only, a scrubbed environment (no API keys) and a
    timeout; a failing `pre-*` hook aborts.
  - `.tineignore` drops paths from the captured diff, or replaces their content
    (`redact:`).
  - `tine rebase RUN --onto-model M [--from-step N]` prepares a fork of a run on
    another model, and `tine cherry-pick RUN:STEP --onto RUN2` copies one step
    onto another run; both write `experiments/...` refs and leave the sources
    untouched.
- **Zero-config capture: `tine hook install --global --repo PATH`** adds a
  session-end hook to Claude Code (`settings.json`), Codex (`hooks.json`) and
  Gemini CLI (`settings.json`) that imports every finished session. `--agent`
  narrows it, `--dry-run` previews, `tine hook uninstall --global` removes only
  opentine's entry, and `tine hook status --global` reports. Other hooks are never
  edited, the original file is backed up to `<file>.tine-backup`, and invalid or
  symlinked config files are refused untouched.
- **ATIF import and export.** `tine import` reads Harbor's Agent Trajectory
  Interchange Format (v1.0–v1.8, auto-detected), including embedded subagent
  trajectories, and `tine export --format atif` writes an ATIF-v1.8 trajectory.
  Usage converts both ways without loss; the file's `cost_usd` is kept as an
  attribute and never used as the price.
- **OpenCode import.** `tine import ~/.local/share/opencode/opencode.db[::<id>]`
  (or `tine import latest --from-default-location --format opencode-session`)
  imports an OpenCode session and its child sessions. The database is opened
  read-only, only the session, message and part tables are read, an unrecognised
  schema is refused by name, and rows, sessions, depth and bytes are bounded.
- **Media endpoints.** `tine media image|speech|transcribe` and
  `opentine.models.media` call OpenAI image generation (gpt-image), text-to-speech
  and transcription, and xAI Grok Imagine images. Each call is a model step that
  `tine price` re-prices exactly; outputs are stored as size and SHA-256, never
  inline. The usual transport rules apply: no redirects, a 64 MiB body cap,
  identity encoding, keys only over TLS or loopback, and a custom `--base-url`
  needs `--api-key-env`.
- **xAI media cards** (231 cards): grok-imagine-image ($0.02), -2.0 ($0.04),
  -quality ($0.05) per image; grok-imagine-video-1.5-lite ($0.020/s), -1.5
  ($0.080/s), grok-imagine-video ($0.050/s); grok-voice-3.0 ($0.08/min).
- **TINEPACK4 and TINEAES4** (see Upgrade notes). A v4 pack is about 8–12%
  smaller than v3 on text runs, and zstd is used when both ends have it.
- **Conformance:** a TINEPACK4 reader vector joins the suite, which now ships
  **524 conformance vectors**; 195 of the 524 refuse input, and the adapter
  contract still has one entry point: 33 ops.

### Changed

- Imported Claude Code subagent transcripts, OpenCode child sessions and ATIF
  subagent trajectories are linked through a typed `subagent` step under the tool
  call that delegated them, so the delegation survives import, storage and export.
- Gemini image and video prompt tokens are recorded separately (`input_image`,
  `input_video`). A Google card that prices them like text and states no rate of
  its own folds them back into `input`, so existing cards, overlays and recorded
  runs price exactly as before.

### Security

- **Commit trailers carry only well-formed run ids.** A run id containing a
  newline can no longer add a forged trailer (such as `Signed-off-by`) to a
  commit message; ids must fully match the run-id grammar.
- **`.tineignore` applies from any subdirectory.** Capture loads the rules from
  the git worktree root (where git reports paths from), and drops the patches if
  the root cannot be determined.

- **Hooks never import code from the project directory.** The installed
  `prepare-commit-msg` hook and the `tine hook` agent commands run Python in
  isolated mode (`-I`), so a cloned repository shipping its own `opentine/`
  package is not executed on commit or session end.
- **A harmless config write never trusts a cloned `porcelain.json`.**
  `tine remote add`/`rm`/`rename` and `tine config set`/`--unset` keep trust
  only if the file was already trusted; planted `hooks.*`, `alias.*` and
  token-file entries stay inert until `tine config --trust`.
- **Trust covers the hook programs too.** The recorded digest hashes
  `porcelain.json` and every file under `.tine/hooks/`; a hook edited, added or
  removed after trust (a project update, a re-clone) revokes it until reviewed.
- **A cloned project's remote never receives your token.** A named remote
  resolves only from a trusted `porcelain.json`, so `tine pull`, `tine fetch
  origin` and `tine push origin` in an untrusted project refuse instead of
  sending `TINE_REMOTE_TOKEN` or `--token` to a URL the project chose; a literal
  URL still works.
- **The commit hook credits only runs you pointed it at.** It reads the runs
  directory or repository recorded by `tine git install-hook` (`git config
  tine.runsDir` / `tine.repo`, or `--runs-dir`/`--repo`), never a cloned work
  tree's own `.tine/` or `.tine_runs/`, and ignores writes stamped in the
  future. Installed globally, it still runs each repository's own
  `prepare-commit-msg`, and every client hook gets a pass-through shim.
- Pricing catalog signatures are domain-separated (see Upgrade notes). Key
  rotation stays a documented procedure; the release key is unchanged.
- Every git call the link commands make uses the shell tool's hardening: the
  binary bound with `shutil.which`, no fsmonitor, hooks, pager, external diff or
  transports, and an environment without `GIT_*`, pager or editor variables.
  Revisions that could be read as options are refused, and anything read back
  from git (trailers, notes) is used only if it matches the run-id grammar.
- The installed commit hook only reads the (redacted) action index and swallows
  every failure, so it can never block or alter a commit beyond adding trailers.
- Repository hooks, aliases and remote token files are trust-gated per machine
  and per byte of configuration, so cloning a repository never runs its hooks.
- `tine hook install` never edits another tool's hooks and refuses symlinked or
  invalid config files; ATIF subagent references to other files or URLs are never
  followed; the OpenCode database is opened read-only and its credential tables
  are never read.
- The TINEPACK4 reader checks the checksum, the header size, the object count and
  the total declared size before inflating, and inflates with exactly that size
  as the limit. TINEAES4 caps the declared size before decrypting.
- Exports of run content no longer inherit a world-readable mode, and OIDC
  discovery no longer depends on the caller supplying a bounded fetch.
- `tine bisect run --score` now applies search's evaluation trust rules: a
  signed evaluation outranks unsigned ones, unsigned scores outside ±1e6 count
  for nothing, and the new `--signed-only` ignores unsigned evaluations. Before,
  any MCP client could write an unsigned evaluation that decided the bisect.
- `.tineignore` now matches paths git C-quotes in diff headers (non-ASCII,
  quotes, backslashes); captures run git with `core.quotePath=false`, quoted
  headers are unquoted, both sides of a rename are checked, and a header that
  cannot be parsed drops its section instead of capturing it.
- `tine blame --git` and the git-link hook never run a repository's own
  `filter.*.clean` or `diff.*.textconv` programs: blame reads the committed
  `HEAD` with `--no-textconv`, and git-link calls set `core.attributesFile`
  to the null device.
- The first `tine config`/`tine remote` write no longer trusts `.tine/hooks/`
  files a clone shipped without a porcelain file; it leaves them untrusted and
  points to `tine config --trust`.
- A TINEPACK4 header whose `shallow` field is not a list of strings is refused
  as an invalid pack rather than raising `TypeError`.
- Transcription usage without an input-token breakdown bills its input tokens
  as audio instead of dropping them; non-finite or negative durations are
  treated as unreported.

### Still open

- `tine rebase` prepares the fork on the new model; it does not re-execute the
  steps (resume it yourself). `post-run`/`pre-record` hooks fire from rebase and
  cherry-pick, not yet from the recorder.
- `tine pull` only fast-forwards; there is no merge of diverged run histories.
- OS sandbox backends for the python tool (Landlock, bubblewrap) are deferred:
  the 0.12 prototypes left host IPC (UNIX sockets) reachable, so they were not
  shipped. The python tool remains resource containment, not an OS sandbox.
- Windows on-disk path cases (junctions, UNC, 8.3 names) are covered by
  normaliser tests, not yet by a Windows-only CI slice.
- Veo and Imagen have no published prices and no adapter; xAI text-to-speech and
  speech-to-text, xAI video/voice adapters and the OpenAI realtime adapter are not
  built.
- ATIF export flattens subagents into one trajectory instead of emitting
  `subagent_trajectories`. Qwen Code and other CLIs get no global hook (no
  documented session-end hook).
- Blame matches a line by its text, so identical lines are attributed to the
  newest write, and shell-made writes are blamed at file level only.

## 0.11.0 — 2026-10-20 — Agent actions, multimodal pricing, storage compression

You can now ask which agents did what. `tine who` finds every agent, model or
session that ran a command, touched a path, called a host or used an MCP tool,
and `tine audit --policy` turns those questions into a CI gate. Image, video,
voice and omni-modal models are priced by their own units: per image, per
second, per minute, per character. `.tine` files and repositories are stored
compressed by default, and `tine gc` packs a repository about 18× smaller on
disk. The shell tool's git guard, the one area the 0.10 audit did not cover,
is rebuilt as an allowlist.

### Upgrade notes

- **Files written by 0.11 need 0.11 to read.**
  - A compressed `.tine` starts with `TINEZ1`, and a compressed or packed
    repository has a version-2 descriptor. Releases before 0.11 refuse both;
    for repositories the refusal is clean.
  - To share with an older release, write plain files: `tine --no-compress …`
    or `OPENTINE_COMPRESS=0`. `tine compress --decompress` converts existing
    `.tine` files.
  - Existing version-1 repositories are never written compressed until
    `tine gc` upgrades them.
- **Compressed `.tine` files are binary.** `cat` and `jq` show compressed
  bytes; use `tine show`, `tine export` or `tine compress --decompress`.
- **Codecs.** `OPENTINE_COMPRESS=zlib|zstd` picks one. On Python 3.11–3.13,
  install `opentine[zstd]` (`backports.zstd`) to read zstd data; without it,
  writes use zlib.
- **Network transfer is unchanged.** Push, fetch, clone and transfer packs carry
  canonical bytes, so compressed and plain repositories exchange objects
  freely.
- **The bundled catalog is `opentine-pricing/3`.**
  - 0.10 and earlier refuse a /3 catalog (`unsupported pricing catalog
    schema`). Installing a 0.11 catalog on 0.10 therefore fails closed rather
    than reading a per-image price as a per-million price.
  - A /1 or /2 catalog that carries `units` or `same_rate_as` is refused.
  - Recorded Gemini image/audio/video output and OpenAI audio/image tokens now
    land in media dimensions, so a workspace pricing overlay for those models
    needs the media rates or the price comes out `partial`.
- **git in the shell tool is opt-in beyond read-mostly work.**
  - `ShellPolicy` gains `git_network` and `git_write_out`, both off by default.
  - `fetch`, `pull`, `push` and `ls-remote` need `git_network`.
  - `init`, `clone`, `archive` and `format-patch` need `git_write_out`; `clone`
    needs both.
  - Abbreviated git options, `-p`/`--paginate`, `diff --output`, `--no-index`,
    and subcommands outside the list below are refused.
  - `git-*` helpers and `scalar` can no longer be allowlisted directly.
  - Bare allowlist entries are resolved with `shutil.which` when the command
    runs.
- **New index files.**
  - The run index (`index.json`) moves to version 2 and rebuilds once, on the
    first `ls` or `search`.
  - The new action index lives in `.tine_runs/actions.sqlite` and
    `.tine/indexes/actions.sqlite`. Both are caches and safe to delete.

### Added

- **`tine who`: which agents did an action.**
  - Filter by tool, command text (`--cmd`), program (`--program rm`), path,
    host, MCP server/tool (`--mcp github/create_*`), verb, agent, model,
    provider, session, run and time (`--since 7d`).
  - Verbs are `exec`, `file.read`, `file.write`, `file.delete`, `net`, `mcp`,
    `git` and `spawn_subagent`.
  - Group results with `--by agent,model` (or provider, session, subagent, run,
    tool, program), or list them with `--list`. `--json` is available.
  - It covers the legacy runs directory by default, or a v3 repository's refs
    with `--repo PATH`.
  - Commands are parsed through `sudo`, `env`, `bash -c`, and `&&`, `;` and `|`
    chains.
- **More action commands.**
  - `tine actions RUN` lists one run's tool calls in order.
  - `tine touched --path X` shows which agents wrote or deleted a path.
  - `tine audit --policy FILE` checks recorded actions against deny/warn rules
    (TOML or JSON). It exits 1 on a deny rule, or on any rule with `--strict`,
    so CI can gate on what agents did. It also exits 1 when a run could not be
    read or hit the per-run action cap, unless `--allow-partial` is given.
- **MCP `find_actions`.** The same query for a model client, with bounded
  arguments and the usual result sanitizing.
- **The action index.** A rebuildable SQLite cache (stdlib `sqlite3`). Updates
  are incremental, and an incremental sync gives the same result as a fresh
  build.
- **Image, video, voice and omni models are priced.**
  - Usage has per-modality token dimensions: `input_image`, `input_audio`,
    `input_video`, `output_image`, `output_audio`, `output_video`.
  - It also has per-unit dimensions: `images[:variant]`,
    `video_seconds[:variant]`, `audio_input_seconds`, `audio_output_seconds`,
    `audio_minutes`, `tts_characters`, `realtime_minutes` and `requests`.
  - A rate card can price a dimension per unit (`units`), and can declare that a
    dimension bills like another (`same_rate_as`).
  - A used dimension with no rate makes the price `partial` with a warning, so
    media is never billed at the text rate.
  - `opentine.billing._media.media_usage()` builds usage for a media call.
- **Adapters and OTel capture media usage.**
  - Gemini output is split by modality.
  - OpenAI audio and image tokens are split from text.
  - OTel `gen_ai.usage.<image|audio|video>.<input|output>_tokens` import into
    the media dimensions and export from them.
    The modality counters are read as a breakdown of the inclusive input and
    output totals, like the cache counters: they never bill more than the span
    reported. Counters larger than what is left after cache (cached media, or
    several modalities against a small total) are clamped, with an import warning.
- **Pricing catalog: 190 → 224 signed cards (`opentine-pricing/3`, verified
  2026-10-20).**
  - Mistral Large 4's launch sale is over. Runs from 2026-10-20 price at the
    list rate: $1.36 input, $0.14 cached, $4.18 output.
  - New text models: MiniMax M3.1 Flash, and Gemini Omni Flash with its
    preview. Omni video output is priced at $17.50/M.
  - New Gemini media models: Nano Banana 2.1, 3.1 Flash Image and Flash-Lite
    Image; 3.8 Flash TTS and Flash-Lite TTS; 3.8 Live; Lyria 3.5.
  - New OpenAI media models: the gpt-realtime and gpt-audio families,
    gpt-4o-mini-tts, tts-1 and tts-1-hd (per character), the gpt-image family,
    and whisper-1 and gpt-transcribe (per minute).
  - DeepSeek's `deepseek-flash` records model version V4.1-Flash-1017.
- **Compressed storage, on by default.**
  - New `.tine` files and new repositories are stored compressed: zstd on
    Python 3.14 or with `opentine[zstd]`, zlib otherwise. On real Claude Code
    sessions a `.tine` is about 21% of its plain size.
  - Object ids, run digests and signatures are computed over the uncompressed
    canonical bytes, so a compressed copy and a plain copy are the same
    artifact and every existing signature still verifies.
- **`tine gc` and `tine repack`.**
  - They move loose objects into compressed packs (`.tine/packs/*.tpk` +
    `.tidx`). On four real sessions, a store went from 5.3 MB on disk to
    300 KB.
  - A pack is written and read back before anything loose is deleted.
  - `repack` merges all packs into one.
- **`tine archive create FILE` / `tine archive restore FILE DEST`.** A whole
  repository as one compressed file. Restore verifies every object id and goes
  into a new repository only. Refs (including `remotes/*/annotations`), shallow
  boundaries and the unadopted-annotation record travel with the archive, so a
  restored repository labels runs exactly as the original did.
- **`tine compress PATH...` / `--decompress`.** Rewrites existing `.tine` files
  without reserializing them, so the digest and signature are untouched.
- **`tine export --compress gzip|zstd`.** Writes a `.gz` or `.zst` document that
  other tools open directly.

### Fixed

- **`tine search` finds tool arguments.**
  - The index used to take only a step's `text`, `name` and `result`, so a run
    that ran `rm -rf /tmp/build` could not be found by that command.
  - A run past the 8,000-character index text is marked `truncated` and
    searched in full from its file.
  - New `harness:` and `provider:` predicates.
- **`tine gc` / `tine repack` take a repository lock.**
  - Two packers can't race.
  - A lock left by a crashed gc is taken over once its process is gone (POSIX)
    or after a day; `OPENTINE_GC_BREAK_LOCK=1` forces it.
  - An interrupted gc loses nothing and can be re-run.
  - gc no longer removes emptied object directories, which raced concurrent
    writers.
- **Shell-side writes count as writes.**
  - Recognised forms: redirects (`>`, `>>`, `&>`), `tee`, `cp`/`mv`/`install`/
    `ln` destinations (including `-t DIR`), `sed -i`, `dd of=`, `truncate`,
    `touch`, and `chmod`/`chown`/`chgrp` targets.
  - `tine touched` and `writes=true` policy rules now see them.
  - The action index rebuilds once.
- **`tine who --program X --by program`** groups under the program that
  matched, not the command's first program.

### Security — git in the shell tool

- **`rev:path` stays inside the shell root.** A `rev:path` token is also
  contained as a filesystem path, and its path part must stay inside the root:
  `git diff` silently switches to `--no-index` for a path outside the work tree,
  so `ab:c/../../../x` could print a host file. Drive-letter, backslash and
  absolute forms are refused.
- **git in the shell tool is an allowlist, not a denylist.**
  - git accepts any unambiguous abbreviation of a long option, so an
    abbreviation of `--upload-pack` got past the old option denylist.
  - Its subcommand set is open-ended: `maintenance`, `credential-store`, and
    any `git-*` program.
  - The shell tool now runs only these read-mostly subcommands: status, log,
    show, diff, shortlog, describe, add, rm, mv, commit, branch, checkout,
    switch, restore, rev-parse, ls-files, ls-tree, cat-file, grep, blame,
    stash, tag, merge, reset, reflog, version.
  - Each subcommand accepts only its own listed long options and short letters,
    and an abbreviation is never accepted.
  - Each option is classed as taking a required value, an attached-only
    optional value (`--pretty[=fmt]`, `-U5`, `-uno`), or none, per subcommand,
    so the token after a flag is always checked. A test asks the installed git
    whether every option the guard reads a value for really takes one.
  - Merge strategies are limited to git's own.
- **Network and write-out git need an explicit opt-in.** Remotes must be
  https/ssh URLs or remote names. Local paths, `file://` and `transport::`
  helpers are refused, including as clone sources.
- **Every path git is told to use stays inside the shell root.**
  - Covered: `-C` (including through `..` or a symlink), path-valued options,
    init and clone directories, and every positional of a local subcommand
    (`rm`, `mv`, `checkout`, `restore`, `add`, `reset`, `stash`, `diff`, …).
  - Pathspec magic (`:(top)`, `:/`, any leading `:`) is refused.
  - `rev:path` is accepted only by the read-only `show`, `diff`, `log`, `grep`
    and `blame`.
  - Paths resolve from the directory git actually runs in, so a symlink below
    the working directory cannot lead outside the root.
- **git runs with a clean environment and hardened configuration.**
  - `GIT_*`, `PAGER`, `EDITOR`, `VISUAL` and `LESS*` are dropped.
  - Five variables are pinned: `GIT_CONFIG_NOSYSTEM=1`,
    `GIT_TERMINAL_PROMPT=0`, `GIT_PAGER=cat`, `GIT_EDITOR=true` and
    `GIT_PROTOCOL_FROM_USER=0`.
  - Hooks, the pager, external diff and every transport are disabled; https
    and ssh are re-enabled only with the network opt-in.
  - This applies to the shell tool and to `code_manifest`.
- **git helpers are refused, and allowlist entries resolve to absolute
  programs,** so PATH order cannot swap the program that runs.
- **`.git` aliases.** The fs tool also refuses `.git.`, `GIT~1`, NTFS stream
  names and HFS+-ignorable spellings.

### Security — storage and indexes

- **An action index is trusted only if this machine wrote it.** Its stamp is
  keyed with a per-user secret (`$XDG_CONFIG_HOME/opentine/actions-index.key`),
  so an `actions.sqlite` shipped with a clone or archive is rebuilt from the runs
  instead of steering `who`, `touched` or `find_actions`. A symlinked, junctioned
  or non-regular index (or runs directory) is refused, SQLite opens it with
  `nofollow`, and a file that is not opentine's own index is replaced, never
  emptied in place.
- **A process survives another process's repack.** A packed read whose pack
  disappeared refreshes the pack list and retries once.
- **Cached audio no longer moves text into the audio bucket.** OpenAI's input
  `audio_tokens`/`image_tokens` include cached media; only the uncached share
  (after `cached_tokens_details`) is split out of fresh text, so text no longer
  bills at the audio rate.
- **Every compressed read is bounded before it allocates.**
  - The declared length must fit the reader's limit and a 1000:1 ratio, and the
    data must inflate to exactly that length.
  - Trailing data, multiple frames, nested compression and unknown codecs are
    refused.
  - Packed objects are checked against their id on every read and by fsck.
- **A crafted pack index or archive can't force repeated inflation.**
  - Reads, fsck and `tine archive restore` could be made to re-inflate a large
    block for every object.
  - Each block's entries must now tile it exactly.
  - A block of several objects stays within 1 MiB.
  - A block must inflate to exactly the size its entries describe.
  - fsck and gc read packs block by block.
- **Per-unit media dimensions are priced only in their stated unit.**
  - Covered: images, video and audio seconds, minutes, TTS characters,
    requests, and their `:variant` forms.
  - A card that gives no unit makes the price `partial` with a missing-rate
    warning, instead of a "complete" price per million units.
  - Such cards are refused at load, and /1 or /2 catalogs carrying per-unit rate
    names are refused.
- **Hosts behind userinfo stay visible.** A URL with a password no longer loses
  its host in the action index once redacted, so `host=` rules and
  `tine who --host` match it.
- **The action index holds only redacted content.** It is built through the
  same redaction a saved run gets, and every query filter is a bound SQL
  parameter.
- **Redacted coverage is reported, not hidden.** A `--cmd` query says how many
  actions it could not match because their text was redacted.
- **`tine audit` re-derives every verdict.** It builds the action index in
  memory from the runs on each call, so an index file that arrived with a
  cloned tree or archive cannot hide an action from it. A run that could not be
  read, or that hit the per-run action cap, fails the audit unless
  `--allow-partial` is given. So does a command whose text redaction cut short
  (`export TOKEN=x; rm -rf /` is stored as `export TOKEN=[REDACTED]`): the
  audit reports it as unchecked coverage instead of a pass. Program names are
  also read from the command before redaction -- only bare executable names
  that redaction leaves untouched, never an argument -- so `rm` still reaches
  a `program="rm"` rule.
- **Only written paths count as written.** A shell command records the files
  it reads and the files it writes separately: `cat /a > /b` and `cp /a /b`
  list `/a` as read and `/b` as written, so `tine touched` and `writes=true`
  rules no longer report a file an agent only read. `sed -i`'s script is not
  taken for a file.
- **Whole-tree git forms stay inside the root.** When the shell root is a
  subdirectory of a larger repository, `reset --hard` (or any `reset`/`checkout`
  without a `--` pathspec), `commit -a`, `add -A`/`-u` without a pathspec,
  `stash` (except `list`/`show`), `merge`, `pull` and `switch` are refused:
  they act on files outside the root. `--pathspec-from-file` is no longer
  accepted by `add`, `reset` or `commit`, because the pathspecs inside the file
  were never checked.
- **Per-unit media never aliases a per-million rate.** `same_rate_as` compares
  units by dimension family (`images:hd` is per image through `images`), so a
  card cannot join a per-image variant to a per-million token rate.
- **Deleting a bare filename is recorded on that path.** `rm notes.txt`,
  `unlink`, `rmdir` and `shred` operands now appear in `tine touched` and
  `writes=true` rules, not only paths with a slash.

### Still open

- **Remote transfer.** Network packs (TINEPACK4) and compress-then-seal on the
  remote server are planned for 0.12. Network transfer is uncompressed today.
- **Gemini image and video input** are not split from `input`, so Gemini Live
  image and video input prices at the text rate.
- **Media endpoints.** opentine cannot call the OpenAI Images, TTS and
  Transcription endpoints or Gemini Veo, Lyria and Live itself. Such calls are
  priced when recorded through the library, a harness or an import.
- **Not carded:** Veo, Imagen, gpt-4o-transcribe, xAI media and ElevenLabs.
- **OpenAI media cards start 2026-10-20,** because OpenAI publishes no launch
  dates.
- **Archives.** `tine archive` covers a whole repository.
- **Action records.**
  - Writers outside the list (`python -c`, `perl -i`, editors) aren't
    recognised.
- **git `rev:path`.** In read-only commands, `rev:path` names committed content
  anywhere in the repository, which can lie outside a shell root that is a
  subdirectory.
- **Inflate budget.** Inflate work is bounded by block structure (at most 1 MiB
  per small-object read), not by a total byte budget per operation.
- **Stale gc locks on Windows** are detected by age only.
- **Not yet built:** saved queries, `tine diff --actions`, signed action
  manifests and action stats.
- **Still open from 0.10.0.**

## 0.10.0 — 2026-10-15 — Universal harnesses & round-3 security

Every major agent CLI is now a harness whose runs record the real model, token
usage, tools and cost, and the session logs those CLIs keep for themselves
import directly — so `tine price` works on Gemini CLI, Qwen Code, Codex, Pi,
OpenCode, Goose and a dozen others, not only Claude Code. Local servers gain
`--base-url`/`--api-key-env` and eleven new presets, hosted vendors fifteen,
and the signed catalog grows from 122 to 190 cards. This release also fixes
every finding of a third security audit of 0.9.2 (25 confirmed issues across
the remote, the repository, signing, redaction, the tool sandbox and the CLI),
the Anthropic SDK 1.x crash, and `tine price` reporting $0 for most runs. Each
fix has a regression test in `tests/test_security_0_10_*.py` that fails on
0.9.2. No format change: every file and repository written since 0.3.0 still
reads and prices.

### Upgrade notes

*Pricing and models*

- **`tine price` totals rise for runs recorded before 0.10.** It now also prices
  the `done`, `think` and `error` steps the capture billed (a `tine run --model`
  run's only step is a `done` step), and applies the recorded service tier
  (fast, priority, flex, US-geo). Totals captured at run time are unchanged.
- **Default models changed:** `groq` and `openrouter` default to
  `openai/gpt-oss-120b`, `together` to `meta-models/Muse-Glimmer-30B` (the old
  defaults were removed or made Enterprise-only upstream).
- A signed `.tine/pricing.json` older than the bundled or installed catalog is
  ignored (stderr notice); re-sign or remove it. `tine pricing install` refuses a
  different catalog signed at the same `generated_at` as the installed one.
- `gemini-3.5-flash` calls after 2026-10-07 re-price `unknown` (Google retired
  the model and routes its calls to 3.6 Flash at half the price); May–July 2026
  calls now price.
- A later GPT generation (`gpt-7`) behind any OpenAI-compatible endpoint is
  treated as a reasoning model and sent no `temperature`.
- `--base-url` with a hosted preset (Groq, DeepSeek, …) needs `--api-key-env`:
  the vendor's own key never follows the URL to another host.
  `Anthropic(base_url=<non-Anthropic host>)` and `--model anthropic --base-url`
  read `ANTHROPIC_COMPAT_API_KEY` (or an explicit key), never
  `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN`. `ANTHROPIC_BASE_URL` set in the
  environment keeps the SDK's own behaviour — the operator's pairing of
  endpoint and key (Bedrock/Vertex/Foundry-style gateways).
- The SDKs' environment headers (`ANTHROPIC_CUSTOM_HEADERS`,
  `OPENAI_CUSTOM_HEADERS`, `OPENAI_ORG_ID`, `OPENAI_PROJECT_ID`) are no longer
  sent to an explicit `--base-url`, a compatible server, a hosted-vendor preset
  or a local preset. Where they are still sent (the first-party API or the
  operator's `*_BASE_URL` gateway) their values count as credentials for the
  cleartext rule: a plain-`http://` non-loopback gateway needs
  `OPENTINE_ALLOW_INSECURE_ENDPOINTS=1`.
- `tine price` books a call `unmetered` only when its provider is a local
  server, its model has no `:cloud` / `-cloud` tag and the capture recorded no
  other verdict; runs captured as unmetered (0.9.x included) re-price the same.
  Imported traces and session logs are never booked `unmetered` from a provider
  label: a model call imported without `--price` now carries an explicit
  `unknown` billing record, and every billing block a source file carries is
  dropped whatever its status says (missing, empty and odd statuses included), so an imported local run (a Codex session on Ollama, say) prices
  `unknown`, and a cloud-tagged model through a local daemon or a loopback
  Anthropic-compatible endpoint prices `unknown`. A model call with no billing
  re-prices `unmetered` only inside a run the harness wrapper captured; anywhere
  else (a library `Recorder.import_events` import, a run imported by 0.9.x) it
  prices `unknown`, as 0.9.2 did. `Recorder.import_events` now drops a source's
  billing and cost by default; pass `trusted_billing=True` for events you priced
  yourself.
- An imported trace no longer sets its own cost: the source's `cost` figure moves
  to the `opentine.source_reported_cost` attribute (shown, never summed), so
  `tine show`, `tine cost`, MCP and `tine export` report the catalog's price or
  nothing — never what the file claimed. `tine import --price` prices from the
  catalog; a model it cannot price keeps no cost.
- On Linux, bounded tool commands (shell, python, `code_manifest`'s git) run
  under a supervisor process; a timed-out command reports exit status 137
  rather than -9.
- `tine run --harness --autosave` without `--autosave-interval` or
  `--autosave-seconds` now checkpoints at most every 2 seconds and only after
  the run has grown by a quarter (it saved after every output line). An
  explicit throttle is honoured as before.
- An imported run's cost always comes from the catalog (`--price` or
  `tine price`), never from billing the source file carries.
- A pricing catalog whose `signature` holds any field other than `algorithm`,
  `key_id` and `value`, or a field that is not a string of at most 256
  characters, is refused.
- A malformed `cost`/`price`/`duration` in an agent CLI's JSON event is ignored
  with a `meter_warning` on the step instead of failing the run.

*Harnesses and import*

- **Default harness commands now ask each CLI for its JSON mode:**
  `codex exec --json --skip-git-repo-check`, `gemini --output-format stream-json -p`,
  `opencode run --format json`, `kimi --print --output-format stream-json -p`,
  `openclaw agent exec --json`, `hermes chat --oneshot --format stream-json -q`,
  `grok --no-auto-update --output-format streaming-json -p` (was `grok exec`,
  which does not exist), `agent --print --output-format stream-json` for
  `cursor` (was `cursor-agent run`), and `pi --mode json`. Pass
  `--harness-command` to keep an old invocation.
- **Structured stdout is decided by the last output-format option.** A harness
  command whose only JSON hint was a bare `json` word or a non-format `--x=json`
  option now records text; name the output-format option explicitly.
  `claude-code` follows the same rule, so a plain `claude -p` command records
  text.
- `pi` no longer needs `--harness-command`, and free-text "cost: $N" lines are
  now booked only for an operator-written `generic` command.
- Harness results carry `"stderr"` when the CLI wrote any; stderr is never
  parsed as events.
- `tine import`'s `--format` is optional (default `auto`); passing it behaves as
  before. OTel-imported events whose provider used a registry spelling now
  record the catalog id (`google`, not `gcp.gemini`).
- `tine` has 41 subcommands (`harnesses` is new).

*Repository and remote*

- `fetch` no longer moves a local `annotations/*` ref for a run you already
  held: the remote's head is kept under `remotes/<name>/annotations/`; adopt it
  with `tine fetch --adopt-annotations`.
- A remote URL with `user:pass@`, a query or a fragment is refused in every form
  (including one with the tenant embedded in its path); pass the token with
  `--token-file` or `TINE_REMOTE_TOKEN`. A remote tenant, from the flag or the
  URL, must match `[a-z0-9][a-z0-9._-]*` (the server already required this).
- `put_run`, `migrate-v3` and `fork` raise `ValueError` for a value nested
  deeper than 512 levels (it was silently truncated at 100 with a marker).
- `tine clone` refuses a target that already holds refs or objects.
- `tine serve purge --grace-seconds N` with N below 60 needs `--force` (or
  `--dry-run`).

*Signing and MCP*

- Ed25519 signature blocks without an embedded `public_key`, and any block with
  a `null` field, verify as `error` (OpenTine never wrote either).
- `--ed25519-key-file` refuses `*.pub` files and copies of the adjacent `.pub`.
- `repo-verify --claim approved=true` no longer selects a claim of `1`.
- MCP `attest_run` refuses evaluation scores outside ±1e6, `fork_run_v3` /
  `resume_run_v3` refuse a prompt or policy over 1 MiB, and the `mcp` extra now
  allows MCP SDK 2.x (`mcp>=1.28.1,<3`).

### Added

- **Every major agent CLI is a harness, and most runs are now priceable.**
  `tine run --harness NAME` drives 25 agent CLIs: `claude-code`, `codex`,
  `gemini`, `qwen-code`, `cursor`, `opencode`, `pi`, `hermes`, `openclaw`,
  `kimi-code`, `grok`, `goose`, `amp`, `droid`, `copilot`, `auggie`, `cline`,
  `qoder`, `continue`, `openhands`, `vibe`, `aider`, `crush`, `kiro`, and
  `generic` for anything else (new: `qwen-code`, `goose`, `amp`, `droid`,
  `copilot`, `auggie`, `cline`, `qoder`, `continue`, `openhands`, `vibe`,
  `aider`, `crush`, `kiro`). Each catalogued CLI runs in its documented
  headless JSON mode, and an event *dialect* built from that CLI's own source or
  reference docs reads it into `model` steps (model, provider, token usage in
  OpenTine's exclusive buckets), `tool` steps paired with their results, errors,
  and the CLI's own dollar figure where it reports one. `tine price` re-prices
  Claude Code, Codex, Gemini CLI, Qwen Code, Pi, Hermes, OpenClaw, OpenCode,
  Goose, Amp, Copilot and Cline runs from the signed catalog. Token conventions
  are per CLI and converted explicitly: Gemini CLI and Qwen Code count cached
  tokens inside `input_tokens` and keep thinking outside `output_tokens`; Goose
  and Copilot count cache inside input; Pi keeps reasoning inside output.
  Copilot's `cost` is a premium-request multiplier, recorded as
  `premium_multiplier` and never booked.
- **`tine harnesses`** lists every harness, the command it runs, whether the CLI
  is on `PATH`, and what a recorded run holds (model / usage / cost / tools:
  `yes`, `no`, `flag` = model only when `--model` is passed, `unverified` = JSON
  mode documented but its schema not). `--installed`, `--json`.
- **Codex runs record their model and exact usage.** The `codex` harness reads
  Codex's documented `exec --json` event stream: a tool step per command,
  patch, MCP call (`server.tool`), web search and collab call, and one model
  step per turn. Codex reports the thread's *running* total on every
  `turn.completed` and counts cached input and reasoning inside its totals, so
  each turn records its own difference in exclusive buckets. The model comes
  from `-m` / `--model` / `-c model=…` or `~/.codex/config.toml` (profiles
  included), a `model rerouted` notice updates it, and `--oss` /
  `--local-provider` record the local provider.
- **Claude Code harness runs carry a W3C `TRACEPARENT`**, so Claude Code's own
  OTel trace (when its telemetry is on) shares the run's trace id, recorded as
  `run.metadata["otel_trace_id"]`; an operator-supplied one is kept.
- **Agent CLI session logs import directly.** `tine import` reads the session
  logs Claude Code (`~/.claude/projects/*/*.jsonl`), Codex
  (`~/.codex/sessions/**/rollout-*.jsonl`), Gemini CLI
  (`~/.gemini/tmp/*/chats/session-*.jsonl`, and the legacy `.json`) and Qwen
  Code (`~/.qwen/projects/*/chats/*.jsonl`) keep for themselves
  (`--format claude-code-transcript | codex-session | gemini-session |
  qwen-session`). Each API call becomes a model step with its model, provider
  and exact usage, each tool call a tool step, each prompt a human step.
  `tine import --from-default-location` lists the newest sessions across all
  four CLIs, and `tine import latest --from-default-location --save run.tine`
  (or a session-id prefix) imports one. A transcript-imported run records
  `metadata.capture = {"method": "transcript-import", "source_format": …,
  "agent_writable": true}`: the agent wrote that log and could have edited it.
  Claude Code subagent transcripts (`<session>/subagents/agent-*.jsonl`) are
  imported with their session (with `--format auto` and
  `tine import latest --from-default-location` too), each hung under the tool
  step that spawned it
  (bounded: each file on disk is read once, so hard links or a second path to
  it are skipped, and the session's byte budget is charged before a file is
  parsed, whether it then imports or not; any left out are counted in
  `opentine.import_warnings`), and the
  listing shows how many each session has. Fast-mode and US-only calls in
  Claude Code transcripts and OTel logs keep their `fast` / `fast_us` / `us`
  tier, so they price at the carded modifier.
  A Claude Code response that a mid-stream tool result splits across lines is
  still one model step with its usage counted once, a session id that is not
  short and id-shaped is stored as `session-<sha256 prefix>`, and reused span
  ids and Gemini `$patch` merges cost linear work.
- **`--format auto`** (the new default) recognizes OTLP spans or logs, OpenTine
  JSONL, OTel span lists and the session logs above by shape.
- **OTLP logs import (`--format otel-logs`).** Claude Code `api_request` /
  `user_prompt` / `tool_result` / `tool_decision` / `api_error`, Codex
  `codex.sse_event` / `user_prompt` / `tool_result` / `tool_decision`, Gemini CLI
  `gemini_cli.api_response` / `user_prompt` / `tool_call` / `api_error` and
  `gen_ai.client.inference.operation.details` each become a priced event,
  chained per session in time order; Gemini's semconv details event is used only
  when no `api_response` reports the same call. `otel-json` also accepts the
  collector file exporter's one document per line.
- **Claude Code traces import priced.** Its spans carry bare `input_tokens` /
  `output_tokens` / `cache_read_tokens` / `cache_creation_tokens` and set no
  `gen_ai.usage.*`; each `claude_code.llm_request` is now a priced model step,
  `claude_code.interaction` a human step, `claude_code.tool` a tool step and
  `tool.blocked_on_user` an approval.
- **Provider spellings are mapped onto catalog ids at import:** `gcp.gemini` /
  `gcp.vertex_ai` / `gcp.gen_ai` → `google`, `x_ai` → `xai`, `mistral_ai` →
  `mistral`, `aws.bedrock` → `bedrock`, `azure.ai.openai` / `azure.ai.inference`
  → `foundry`, LangChain's `google_genai` / `mistralai` / `azure_openai` / …
  likewise. The original attribute stays on the span.
- **`tine run --model … --base-url URL --api-key-env NAME`** points any adapter
  at a server on another port or machine, or one that needs a key, without
  Python. Every local preset also reads `<PRESET>_BASE_URL` /
  `<PRESET>_API_KEY` (for example `LLAMACPP_BASE_URL=http://127.0.0.1:9931/v1`
  for llama.cpp's newer default port, `JAN_API_KEY`, `TABBYAPI_API_KEY`). A real
  key from the environment is still held to the cleartext rule.
- **Local runtimes:** `docker-model-runner` (12434, `/engines/v1`), `lemonade`
  (13305, `/api/v1`), `mistralrs`, `tabbyapi` (5000), `xinference` (9997),
  `lmdeploy` (23333), `llamafile` (8080), `dynamo` (8000), `aphrodite` (2242),
  `foundry-local` and `ovms` (`/v3`) — the last two have no conventional port
  and need `--base-url`. TGI is marked deprecated (archived upstream).
- **Hosted vendors:** `meta` (Muse; no temperature), `minimax`
  (`reasoning_split`), `deepinfra` (priced from its reported
  `usage.estimated_cost`), `fireworks` (the US host bills the 1.5x `us` tier),
  `cerebras`, `sambanova`, `stepfun`, `xiaomi`, `upstage`, `inception`,
  `nvidia`, `huggingface`, `vercel`, `cohere`, and `bedrock` (Bedrock's
  OpenAI-compatible endpoint with `AWS_BEARER_TOKEN_BEDROCK`; a `global.` model
  id prices at list, a geographic `us.` / `eu.` / … id at the 1.1x `regional`
  tier, which a reported `default` / `standard` tier never erases and a real
  tier composes with, e.g. `batch_regional`). Vendors without a card record
  `unknown`, never a guessed price.
- **Compatible endpoints:** `Anthropic(base_url=…, provider=…, unmetered=…,
  cache_inclusive=…)` targets the Anthropic-compatible `/v1/messages` that
  Ollama, LM Studio, llama.cpp, vLLM and gateways serve, under their own
  provider, and never receives the first-party `ANTHROPIC_API_KEY` /
  `ANTHROPIC_AUTH_TOKEN` (only an explicit key or `ANTHROPIC_COMPAT_API_KEY`);
  `tine run --model anthropic --base-url` records such a run as
  `local-anthropic-compatible` (loopback, unmetered) or `anthropic-compatible`.
  `OpenAI(base_url=…, provider=…, responses=True)` targets a
  compatible `/v1/responses`. OpenAI's data-residency hosts
  (`eu.api.openai.com`, …) stay native OpenAI and bill the carded `regional`
  uplift on Responses and Chat Completions alike; a Priority or Flex call there
  bills `priority_regional` / `flex_regional`, priced only where carded and
  otherwise `unknown`, never the global rate.
- **Pricing catalog refreshed (122 → 190 signed cards, verified 2026-10-15).**
  New: Gemini 4 Argon (introductory $2 / $10 through 2026-11-30 and the
  already-published $4 / $20 from 2026-12-01), Gemini 3.1 Flash-Lite, Mistral
  Large 4 (launch sale), Mistral-hosted GLM 5.3, GPT-Rosalind Research, the
  older OpenAI families still served for Codex and imported traces (gpt-5.5
  with its 2.5x Fast multiplier, gpt-5.4 / mini / nano, gpt-5.3-codex,
  gpt-5.2, gpt-5.1, gpt-5-mini with 1.8x Fast, gpt-5-nano), Groq gpt-oss-120b /
  20b / safeguard-20b, Together MiniMax-M3 / Muse Glimmer 30B / gpt-oss-120b /
  Qwen3.7-Plus; new first-party vendors Meta (Muse Wonder 1.0, Muse Spark
  1.1–1.3 and the Contributor-mode variants), MiniMax (M3, M2.7,
  M2.7-highspeed), StepFun, Xiaomi MiMo v2.6 and Fireworks; and cloud
  namespaces `bedrock` (Claude 5.x and GPT-6 Astra: global at first-party list,
  regional 1.1x), `vertex` (Claude 5.x) and `foundry` (Claude at Anthropic's
  rates with the US Data Zone 1.1x; Azure OpenAI GPT-6 with Data Zone US 1.1x
  and EU 1.2x). OpenAI's 10% regional-processing uplift is carded as a
  `regional` tier on models released on or after 2026-03-05. Every GPT-6,
  GPT-6.1 Sol, Claude Opus / Sonnet / Haiku 5.5 and Fable 5 / 5.1 card was
  re-verified against the vendor's page; unannounced successors
  (`claude-fable-5-5`, `gpt-6.2-*`, `gpt-7`) get fail-safe wire rules and stay
  visibly unpriced until a card exists.
- **MCP SDK 2.x.** The `mcp` extra allows `mcp>=1.28.1,<3`; the server runs on
  SDK 2's `MCPServer` or 1.x's `FastMCP`, and under 2.x a tool's (sanitized)
  error message reaches the client.
- `StdoutTrust.json_options` / `json_values`: a harness names the option and
  values that switch its CLI to JSON output.

### Security — repository and remote

- **Fetched associations made every local push and pack quadratic.** The pack
  walk listed every annotation and attestation file once per run in the
  history, so objects arriving with ordinary fetches cost runs × objects on
  each later push. The association target indexes are now listed once per walk.
- **A writer could still make someone else's run unfetchable.** 0.9.2 promised
  associations could no longer make a pack fail, but only the object *count*
  was budgeted. An attestation whose `evidence_ids` named large blobs broke the
  pack-body or semantic-source limit, and one naming ten thousand tiny ones
  overflowed the traversal queue (raised before the walk's own budget check) —
  `fetch`, `clone` and `negotiate` of the victim's run then failed for every
  reader, promoted runs included. The association phase now budgets objects,
  encoded pack-body bytes, the source budget and the shallow-boundary list a
  depth-limited pack carries (at depth 0 one attestation citing ten thousand
  events added ten thousand boundaries), treats any failure of an association
  subset as "does not fit", rolls back what it charged, and reports the run as
  `associations_omitted`. A pack also leaves out what the receiver already
  holds (and, on a typed fetch, what the type filter drops), so links into
  those objects could still overflow the shallow list after the budget was
  checked: a fetch, typed fetch or push whose pack cannot be built with
  associations is now rebuilt from the object graph alone, its runs reported
  as omitted (`Opentine-Associations-Omitted`). A graph that does not fit by
  itself still fails as before.
- **One fetch can no longer re-read the same oversized evidence once per run.**
  A rolled-back association set used to leave the next run a fresh budget, so a
  writer attaching one body-sized evidence set to thousands of runs made a
  single fetch, negotiate or push read it thousands of times while holding one
  of the server's pack slots. Everything the association phase reads is now
  charged, before it is read, to a total of twice the pack body budget that is
  never rolled back; once it is spent, the remaining runs keep their graph and
  their associations are reported omitted.
- **An annotation planted ahead of its run was adopted when the run arrived.**
  A pack could carry an annotation for a run it did not include (the run as a
  shallow boundary); nothing was recorded, and when the real run arrived later
  without an annotation ref the fallback adopted the planted tags. An
  annotation is now the pack's own only when its run arrives in the same pack
  and was not already held; every other one is recorded as unadopted. A
  remote's advertised `annotations/<digest>` ref is likewise adopted only for a
  run that fetch delivered, and never when any annotation in its chain was
  recorded as foreign at install.
- **A co-writer on a shared remote could still relabel a run you held.** Pushing
  an annotation *and* its `annotations/<digest>` ref made the next `fetch` adopt
  it (an absent local ref counted as a fast-forward). `fetch` now adopts
  advertised annotation refs only for runs it delivered; for runs held before
  the fetch the remote's head is kept as `remotes/<name>/annotations/<digest>`,
  and `tine fetch --adopt-annotations` adopts them deliberately.
- **Advertised annotation refs could make a fetch quadratic.** A remote could
  point thousands of `annotations/*` refs at one long annotation chain, and the
  client re-walked the whole chain for every ref after the transfer (hours of
  object reads for a ~1 MB pack). A ref whose annotation names a different run is
  now skipped before any walk, and chain reads and verdicts are memoized per
  fetch, so adoption costs one read per object.
- **Remote errors printed credentials.** An HTTP error from a remote verb
  carried the full URL, userinfo and query-string tokens included. Errors now
  name only the status and path, a remote URL carrying credentials, a query or
  a fragment is refused — checked on the URL as given, before an embedded
  tenant (`…/v1/tenants/acme`) is split off, so a token cannot ride into every
  request path as part of the tenant — the tenant must match the server's
  tenant grammar, and the client no longer appends `/v1/...` after a query
  string.
- **A non-string `azp` crashed authentication** (a 500 with no audit row); it is
  now an `OIDCError` (401, audited).
- **One IPv6 client could hold every worker slot.** The per-peer share was per
  address, and an IPv6 host routinely has a whole /64; peers are now grouped by
  /64 (IPv4-mapped addresses as their IPv4 address).
- **`--token-file` warns** when the file is readable by group or others, as key
  files already do.
- **Annotations from a remote can no longer break a repository.** The record of
  annotations no ref vouches for could grow past what its own reader accepted,
  after which every fetch, `load_run` of an untagged run and `put_run` failed.
  It is now kept within its limit (entries the fallback can no longer read are
  pruned); a foreign annotation that still does not fit is not installed, with
  a warning; and a damaged record makes the fallback adopt nothing instead of
  failing. `tine fsck` still reports a damaged record.
- **Unheaded-annotation lookups read only the run's own annotations.**
  `load_run`, `put_run`, pack walks and unadopted pruning decoded every
  annotation and attestation in the repository — minutes at 100,000, and a hard
  failure past that which a remote could reach over a few fetches. A cache in
  `.tine/indexes/` maps each annotation and attestation to its target; past the
  scan bounds the fallback adopts nothing rather than failing.
- **Two unheaded annotations can no longer brick a run.** A writer on a shared
  remote could push two independent unheaded annotations for someone else's
  untagged run; every fresh fetch then failed `load_run` and tagging with
  "ambiguous unheaded legacy annotations". The fallback now adopts nothing (with
  a warning), and tagging starts a fresh, ref-backed head.
- **A remote can no longer un-adopt an annotation you already have.** An
  unheaded annotation the fallback had adopted (after an import, a clone with no
  annotation ref, or from an older repository) was recorded as foreign when a
  remote sent it again, and the run lost its tags and metadata for good. Only
  annotations new in a pack are judged now.

### Security — signing, keys, pricing trust and redaction

- **Private keys are redacted whole, in every common armor.** A PEM block is
  replaced from its `BEGIN` marker to its `END` before any other pattern runs, so
  no value pattern can eat the marker and leave the body behind
  (`MYSQL_PWD=x\n-----BEGIN …`, in text or inside a JSON string). A truncated
  block keeps no body behind OpenPGP armor headers (`Version:`, `Hash:`,
  `Charset:`) or numbered, quoted or indented body lines, while a diagnostic
  such as `error: …` after a lone marker is kept, and the line after a truncated
  block keeps its line start so its own credential is still redacted. A
  base64-wrapped key (`base64` / `openssl base64` output at 64 or 76 columns, on
  real lines or as `\n` / `\r\n` escapes inside a JSON string) is removed
  whole, including after a credential name (`SSH_PRIVATE_KEY=LS0t…`,
  `client-key-data: LS0t…`); a block whose marker will not decode is redacted,
  and a wrapped certificate is left alone. PuTTY `.ppk` files (header through
  `Private-MAC`, whatever decorates each line — the Read tool's `N→` numbers,
  `cat -n`, a diff's `+`, a `> ` quote, an indent, and a quote inside the
  `Comment:` line of a file with real line breaks) and RFC 4716
  `---- BEGIN SSH2 … PRIVATE KEY ----` blocks carry no PEM marker and were saved
  whole by 0.9.2; both now become `[REDACTED PRIVATE KEY]`.
- **About twenty more credential formats are redacted**, in both writers and on
  export: xAI (`xai-`), Groq (`gsk_`), Replicate (`r8_`), Perplexity (`pplx-`),
  Google OAuth access tokens (`ya29.`) and client secrets (`GOCSPX-`), Slack app
  and refresh tokens (`xapp-`, `xoxe`), Stripe webhook secrets (`whsec_`), every
  GitLab token prefix (`glrt-`, `gldt-`, `glptt-`, …); an `Authorization`,
  `Cookie` or `Set-Cookie` header in the middle of a log line or a repr'd
  request; a docker `"auth"` blob; URL passwords containing `/`; `<password>` in
  XML; and `key=`, `auth=` and `code=` query parameters.
- **More credential names, in every spelling.** `*_PWD` / `*_PW` names,
  `REDISCLI_AUTH`, `AZURE_STORAGE_KEY`, `*_storage_key` and `client-key-data`
  are redacted as field names, in command text (`export LDAP_BIND_PW=…`),
  quoted or bare with the quotes kept (`MYSQL_PWD='…'`, `mysql_pwd: "…"`) and as
  flags (`--db-pwd=…`, `--db-pwd …`), whatever the value looks like
  (`MYSQL_PWD=2024/Summer!`); only a dotted host glued to a port
  (`example.pw:8443/api`) is left alone. A quoted field is secret by exactly the
  names the record walk uses, so `"MYSQL_PWD": "…"` in text or nested JSON is
  redacted as the same dict would be (a digit-only value under a plural
  `*tokens` name is a usage count and is kept), whatever the length of the name,
  and `"a": "password": "v"` redacts `v`. JSON-escaped fields in other text
  (`curl -d "{\"password\":\"…\"}"`, `echo`, logged payloads) are redacted too.
  A second assignment on the same line is redacted on its own
  (`-e AZURE_STORAGE_KEY=x -e DB_PASSWORD="y"`): an unquoted value stops only
  before the next credential-name head, so base64 padding
  (`credentials: Basic dXNl…=`) or a `user:pass` word stays inside the value.
- **CLI and `.netrc` credentials.** `curl -u user:PW`, `mysql -pPW`,
  `redis-cli -a PW` and `docker login -p PW` are redacted, quoted or bare (quotes
  kept), also right after a literal `\n` or `\t` escape in a repr or logged
  command; `mysql -P3307` is a port. A credential flag's value
  (`--password`, `--token`, `--api-key`, `--client-secret`, `--access-token`,
  …) is redacted space-separated or with `=` (`--token=x`, Go-style `-token=x`),
  quoted or bare, in text and in JSON at any nesting depth, and a long token is
  removed whole rather than cut at 512 bytes; bare `token=`/`pass=` counters
  are kept. `.netrc` passwords are redacted whole, unquoted through `,` `;` `]`
  `}` or quoted to their own closing quote; on a `password` line of its own a
  quoted value must end the line, so prose such as
  `Password "must be 8 chars" is the rule` is kept.
- **Redacting a JSON document never makes it invalid, and never keeps what the
  scan removes.** The byte scan stays authoritative — it still redacts
  credentials split across strings (`{"name": "X-Api-Key", "value": …}`,
  `["Cookie", …]`) — and its output is kept whenever it keeps the document's
  structure. Where it would not (an escaped quote eaten, two member names made
  alike), the blob is rebuilt from its original bytes: any string, number or
  literal a scan step would remove anything from is replaced whole (by its own
  decoded-text redaction only when no removed word survives in that, else by
  `"[REDACTED]"`), every other byte (numbers, escapes, lone surrogates, layout)
  is kept, and names that redact alike stay distinct. Strings that hold escapes
  are also redacted as decoded text at every nesting level, so a multi-line
  `.netrc`, a `jq -Rs` / `json.dumps`'d log or MCP text held inside a JSON
  string is seen; a clean blob stays byte-identical. JSON with a byte-order mark,
  `NaN`/`Infinity`, or JSON Lines whose first record is a scalar take the same
  path. Vendor tokens, URL userinfo and query secrets are redacted before the
  bounded form values, a form value longer than its bound is removed whole, and
  a bounded value never ends inside a multi-byte character.
- **Redaction stays linear in its input.** Survivor checks look for every
  removed word in one pass, repeated capped forms extend only to the next match,
  colliding names are renamed in linear time, a run of byte-order marks is
  ordinary text, and nested JSON grows linearly with depth. `PWD=/home/...`,
  ports and usage counters are left alone.
- **An old signed release catalog in a project re-priced runs.** Every release
  catalog OpenTine has shipped still verifies under the release key, and the
  rollback check covered only the user's installed catalog: a cloned project's
  `.tine/pricing.json` holding the 2026-07-20 release catalog outranked both the
  bundled and the installed one, with no notice, and priced seven models at old
  rates (DeepSeek V4 Pro output 56% under). A signed workspace catalog older
  than the newest signed catalog already in use is now skipped with a notice,
  and two different catalogs signed at the same `generated_at` cannot replace
  each other, at load or at install.
- **One signature still verified under several attestation ids.** A header field
  stored as an explicit `null` rebuilt the same signed header, and an Ed25519
  block with its `public_key` dropped verified when the key came from
  `--pubkey`: 4 (HMAC) and 12 (Ed25519) distinct verified oids from one
  signature. Both spellings are now `error`; no writer ever produced either.
- **A public key was accepted as an Ed25519 signing key.**
  `tine sign` / `tine attest --ed25519-key-file key.pub` used the 64-hex public
  key as a seed, so anyone holding the `.pub` could derive the signing key — and
  a pin on its fingerprint passed. A `*.pub` file, a PEM or OpenSSH public key,
  or a file identical to the `.pub` beside it is now refused as signing
  material, as it already was as an HMAC key.
- **`tine verify` read the artifact twice.** The verdict and the fingerprint
  checked against `--pin` came from two reads, so a file swapped in between
  paired one file's verdict with another's key. `migrate-v3 --pin` likewise
  checked the pin and then re-verified with "whatever key is embedded"; it now
  hands the import the key that passed the pin.
- **Search counted junk as signed, and unsigned scores without bound.** Any dict
  under `signature` ranked an evaluation as signed; only a well-formed block
  counts now. MCP `attest_run` wrote `{"kind": "evaluation"}` claims without the
  ±1e6 bound `evaluate_run` enforces (a 1.7e308 score ranked first); both tools
  refuse it now, and search ignores an unsigned score outside ±1e6 whatever
  wrote it.
- **`tine repo-verify --claim` compared with Python equality**, so
  `{"approved": true}` selected a signed `{"approved": 1}`. JSON types now
  compare strictly (an integral float still equals its integer, as canonical
  JSON stores it).
- **`tine export` sent secrets an older `.tine` kept under field names.** A file
  written before 0.9.1 holds `github_token`, `connection_string` or `pwd` values
  its writer did not know to redact; export scrubbed free text only, so the
  `gen_ai.prompt` kvlist — where each name and value are separate strings —
  carried them to the file or collector. Export now applies the writer's full
  redaction (field names and the run's own `extra_secret_keys`) before it builds
  spans, no longer prints a collector's query string (`?token=…`), and drops
  reserved `opentine.*` attributes that rode in from a foreign trace and would
  have changed the run's kind, cost or billing on the next import.
- **`migrate-v3` ignored the run's `RedactionPolicy.extra_secret_keys`.** It now
  redacts exactly as `put_run` does, so both produce the same object ids.
- **`RedactionPolicy(extra_secret_keys=("output",))` broke every save.** The walk
  matches a name one `s` longer, so the singular of a reserved field blanked it;
  such names are now refused like the reserved names themselves. A policy
  recorded in an older run that names one keeps its other secret fields: only
  the unusable entry is dropped, with a warning.
- **A catalog's signature block can no longer carry unsigned content into every
  run.** The `signature` object sits outside the signed bytes and was copied
  into each billed step's provenance, so a validly signed catalog padded there
  (a cloned `.tine/pricing.json`, or a mirror for `tine pricing update`) grew
  every model call's record. A signature with any field other than
  `algorithm`, `key_id` and `value`, or a field that is not a short string, is
  now refused, and provenance copies only those three fields.
- **A catalog file that is not a regular file is never read.** A cloned
  repository could symlink `.tine/pricing.json` to `/dev/stdin`, `/dev/tty` or a
  FIFO, and every pricing load in that directory blocked. Catalog files are now
  opened non-blocking and refused unless they are regular files; a skipped
  workspace overlay is reported like an untrusted one.

### Security — CLI, MCP, export and import

- **A Unicode-digit token count no longer aborts a session import.** Counts
  are read from ASCII digits only; any other record value is skipped.
- **`tine migrate` printed an artifact's digest raw**, so a crafted legacy file
  could write a terminal escape (a title change, a screen clear) in the default
  preview. It is escaped like all run text now.
- **Rich emoji shortcodes still expanded** in run trees and step labels
  (`tine show`, `replay --inspect`, `diff`): `:white_check_mark:` in run text
  rendered as a check mark. They stay literal everywhere now.
- **Hidden and control characters no longer reach MCP clients.**
  `search_runs`, `inspect_object`, `context_slice`, `semantic_diff` and the
  legacy `fork_run` returned bidi, zero-width and Unicode tag characters from
  run content verbatim — text a client's model reads and a human reviewing the
  transcript cannot see. The server now sanitizes every tool and resource
  result as it returns it, dropping every format character and
  Default_Ignorable_Code_Point (variation selectors U+FE00–FE0F and
  U+E0100–E01EF, fillers such as U+3164, the soft hyphen) plus C0 controls
  other than newline and tab, ESC, DEL and C1 controls, from every string and
  key in text and structured content; terminal output strips the same set.
  `list_runs` leaves out a run file whose name hides such characters (counted
  as `hidden-name`), since a cleaned name would not resolve.
- **MCP forks are bounded.** `fork_run_v3` refuses a prompt or policy over 1 MiB
  or a model name over 256 characters, and the legacy `fork_run` stops once the
  runs directory holds 1 GiB.
- **A message array serialized into one OTel attribute bypassed the import
  bounds.** `tine import` scans a document's structure before parsing it, but
  not text inside a string, so `"[{},{},…]"` held in `gen_ai.input.messages`
  reached `json.loads` unbudgeted (about 24x its size in memory; a 60 MB file
  peaked at 1.6 GB). Such a string is now decoded only within the JSONL line
  bound and the structural-token budget; otherwise it stays in the attributes
  as text and the span carries an import warning.
- **One span with an invalid `opentine.trace.kind` failed the whole import.** It
  is now read by its operation name and the span records a warning.
- **Session-log import cannot multiply one oversized value across events.**
  Per-record ids Claude Code stamps on each tool result (`requestId`,
  `promptId`, `agentId`), span ids and the session id are kept only when short
  and id-shaped (otherwise a digest); tool names repeated on results are
  clipped to 256 characters; a Codex call's arguments are recorded with its
  first output only; a Gemini tool result attaches to one call even when ids
  repeat; a timestamp string longer than 64 characters is not parsed. Gemini
  session `$patch` merging and span-id numbering are linear.
- **OTLP span import checks a span's message turns against its classic prompt
  in one bounded pass.** Each turn used to be searched for separately in the
  `gen_ai.prompt` / `gen_ai.completion` text, so one crafted 2.9 MB span cost
  about 155 s of CPU; the turns are now found together in linear time (0.6 s),
  with the search index capped at 64K characters — past that the turns count
  as not covered and the conversation is kept in the attributes with a warning,
  never dropped.
- **`tine import --format otel-logs` refuses an oversized file while reading
  it.** The event cap is enforced as records are mapped, before any session
  chain is built (a 65 MB file of one-record sessions took 2.7 GB and 64 s
  before the refusal); at most 400,000 raw log records are read. A record
  whose `timeUnixNano` is out of range or not a number (a 400-digit integer
  aborted the whole import with `OverflowError`) falls back to
  `event.timestamp` with an import warning, and a record that still raises an
  arithmetic or shape error is skipped and counted.
- **One record with an unexpected field type no longer fails a whole import.**
  A session-log or OTLP-logs record whose `content`, `usage`, `toolCalls`,
  `parts` or `logRecords` has the wrong type is skipped like an unparsable
  line, and the run's first event counts the skipped records
  (`opentine.import_warnings`).
- **Codex OTel imports no longer guess the provider from the model id.** A `:`
  in the model (OpenAI fine-tunes are `ft:…:org::id`) recorded the call as a
  free local Ollama call; the provider is now what the event states,
  `ollama-cloud` for a cloud tag, else `openai`.
- **Claude Code session import bills each API response once.** A subagent
  transcript that repeats the response which spawned it (or a sibling's), or a
  repeated request id, is not recorded a second time; on a real session this
  had overcounted output by about 31%. Subagent transcripts are also read by
  `--format auto` and `tine import latest --from-default-location`.
- **Importing a long OTel span chain is linear.** The pass that decides which
  agent spans to bill climbed every span's full ancestor chain; a 2.5 MB chain
  of 16k spans took about a minute of CPU. Each ancestor is now climbed once.

### Security — tool sandbox and model adapters

- **`--base-url` on a hosted preset priced at the default endpoint's rates.**
  The adapter was built for its default host and the URL swapped in afterwards,
  so host-derived billing stayed stale: a Fireworks `us.` host was billed at the
  list rate instead of its 1.5x `us` tier, and a GLM China (`bigmodel.cn`)
  endpoint was booked complete at the international USD card. The preset is now
  constructed against the given URL, and a `bigmodel.cn` endpoint always records
  `glm-cn`.
- **A `GEMINI_API_KEY` could be sent in cleartext.** The Google adapter checked
  only `GOOGLE_API_KEY` before refusing an `http://` non-loopback
  `GOOGLE_GEMINI_BASE_URL`, while google-genai fell back to `GEMINI_API_KEY` on
  its own and sent it. The key is now resolved the way the SDK resolves it,
  checked, and passed explicitly. The Anthropic adapter likewise checks
  `ANTHROPIC_AUTH_TOKEN` and passes both credentials explicitly — so a user with
  only `ANTHROPIC_AUTH_TOKEN` can use the adapter at all.
- **One model response could run any number of tool calls past the budget.**
  `max_steps` / `max_duration` / `max_cost` / `max_usage` were checked before
  and after a model call and after the whole tool batch, and the model chooses
  how many calls a response holds (200 calls ran against `max_steps=3`). The
  budget is now checked before every call; once spent, the remaining calls are
  answered "not executed: run budget exhausted" without running, so the batch
  stays complete for a resume.
- **The tool environment scrub covers far more credentials.** `inherit_env=True`
  handed tools `*PASSPHRASE*` (`BORG_PASSPHRASE`, `GPG_PASSPHRASE`), `*_PW`,
  Bitwarden's `BW_SESSION`, 1Password's `OP_SESSION_<account>` and
  `*MNEMONIC*` / `*SEED_PHRASE*` — unlock tokens that usually exist only in the
  environment — and any `*HEADERS*` variable (`OPENAI_CUSTOM_HEADERS`,
  `ANTHROPIC_CUSTOM_HEADERS`, `OTEL_EXPORTER_OTLP_*HEADERS`), which carry
  gateway credentials. Those are scrubbed now, and so is any variable, whatever
  its name, whose value is a credential header (`Authorization:`,
  `X-Api-Key=`, `Cookie:`, `Bearer …` / `Basic …`), a connection string
  (ASP.NET `ConnectionStrings__*`, `*CONNECTIONSTRING*`, or a `password=`,
  `pwd=`, `token=` or `api_key=` pair as in ADO.NET, ODBC and JDBC URLs) or a
  signed URL (Azure SAS `sig=`, S3 `X-Amz-Signature` / `X-Amz-Credential`, GCS
  `X-Goog-Signature` / `X-Goog-Credential`).
- **Web tool: a server-chosen charset could stall the event loop.**
  `charset=punycode` (quadratic to decode; 512 KB took about 10 s, a test fetch
  ran 53 s past its 5 s timeout) and other non-text codecs (`idna`, `utf-7`,
  `unicode_escape`, `rot13`) were decoded outside the request timeout. Only text
  encodings are honoured now; anything else is read as UTF-8.
- **Web tool: multicast and reserved IPv6 passed the private-address block**
  (`224.0.0.1`, `ff02::1`, `ff0e::1`, the SIIT form `::ffff:0:a9fe:a9fe` of the
  metadata address). Refused now, as SECURITY_MODEL always said.
- **Tool descendants that left the process group survived (Linux).** A python-
  or shell-tool snippet whose child called `setsid()` kept running after the
  timeout kill (and after a normal exit). On Linux every bounded tool command
  now runs under a child-subreaper supervisor that kills everything left
  beneath it, whatever group or session it moved to, and OpenTine sweeps
  every process still carrying the run's `OPENTINE_TOOL_SCOPE` marker after
  each command, whatever the supervisor reports. This cleans up runaway and
  leftover processes; it cannot contain an adversarial process running as the
  same user, which can read OpenTine's own `/proc` entries, kill the supervisor
  and drop the marker.
  Real isolation needs a container or cgroups: this is resource containment,
  not an OS sandbox. macOS and the BSDs have no subreaper; there the group
  kill remains the boundary.
- **A custom `--base-url` never receives first-party credentials.** An explicit
  non-Anthropic base URL gets only an explicit key or
  `ANTHROPIC_COMPAT_API_KEY` (a placeholder otherwise), and the SDK is handed
  both auth headers explicitly so it cannot read `ANTHROPIC_API_KEY` /
  `ANTHROPIC_AUTH_TOKEN` from the environment either (verified on anthropic
  0.87 and 1.13). A hosted preset's `--base-url` needs `--api-key-env`, so a
  vendor key such as `GROQ_API_KEY` is never sent to another host.
- **Nor the SDKs' environment headers.** Anthropic's and OpenAI's SDKs add
  `ANTHROPIC_CUSTOM_HEADERS` / `OPENAI_CUSTOM_HEADERS` (often a gateway
  credential) and `OPENAI_ORG_ID` / `OPENAI_PROJECT_ID` to every request on
  their own. A client built for an explicit `--base-url`, a compatible server, a
  hosted-vendor preset or a local preset now cancels every one of them; they
  still reach Anthropic's or OpenAI's own API and the operator's
  `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` gateway, and there they obey the
  cleartext rule a key does.
- **A cloud-tagged model is never captured as free.** Every adapter applies one
  rule at capture: a `:cloud` / `-cloud` model served through a local daemon —
  a loopback `--model anthropic --base-url`, an OpenAI-compatible endpoint or a
  local preset — is recorded with a warning and priced `unknown`, not
  `unmetered` $0, so `tine cost` and `--max-cost` see it.
- **A provider name alone no longer books a call as free.** `tine price`
  re-prices a recorded call as `unmetered` only when its provider is a local
  server, its model carries no `:cloud` / `-cloud` tag (Ollama proxies those to
  a per-token API) and the record carries positive evidence: the capture's own
  `unmetered` verdict, or no billing inside a run the harness wrapper captured.
  An imported trace or session log — through `tine import` or the library's
  `Recorder.import_events` — is never booked `unmetered` from its provider
  label, and keeps no cost from its source file.
- **Inline-reasoning splitting is bounded on a compatible server's stream.** It
  searches only new text, holds at most 64 KiB waiting for Harmony's final
  channel (the rest is then the answer, as for a whole message), and caps
  leading whitespace — linear in the stream however it is chunked.
- **Inline reasoning is kept beside structured reasoning.** A non-streamed
  chat response that carried both `reasoning_content` and a different inline
  `<think>` block recorded only the first; both are now kept (the same text in
  both places is kept once).

### Security — harnesses

- **A plain-text Claude Code run could forge its own record.** `claude -p`
  prints the model's answer, yet the claude-code harness parsed every
  JSON-shaped line as a Claude Code event, so an answer could book $250, six
  million tokens and a `deploy_prod` tool call (and trip a cost budget). Like
  every other harness, claude-code now decides from the command line: only the
  *last* output-format option asking for JSON makes stdout events, and a bare
  `json` word or `--something=json` argument no longer counts. Every catalogued
  dialect is tested in text mode against a forged JSON line, and
  `codex exec --json -o last.txt` stays in JSON mode (Codex's `-o` names a
  file).
- **stderr is no longer parsed as the CLI's events.** It was merged into stdout,
  so a JSON line written by anything the CLI let reach stderr (an MCP server, a
  hook) was trusted in structured mode. stderr now has its own pipe and is
  recorded as text (`"stream": "stderr"`), never as events or cost.
- **A private key the agent printed no longer survives in harness runs.** Each
  output line was redacted on its own, but the key scrubber needs the `BEGIN`
  marker and the body in one string, so every body line was stored verbatim
  (0.9.2 too). Harness output is now masked across lines and events:
  - PEM blocks from `BEGIN` to `END`, base64-wrapped keys (`base64 id_rsa`, a
    line that decodes to a `BEGIN … PRIVATE KEY` marker and the base64 lines
    after it), PuTTY `.ppk` files (through `Private-MAC`) and RFC 4716 SSH2
    blocks;
  - in text lines and stderr, with per-line decoration stripped first (line
    numbers from `cat -n`/`nl`/`grep -n`, `> ` quotes, bullets, indents, diff
    `+`/`-`, `cat -A`'s `$`, comment leaders, terminal colour codes, table
    borders);
  - inside JSON events, where a key's whole span becomes
    `[REDACTED PRIVATE KEY]` in string values and object keys and the event is
    re-serialized, so the event is never truncated and its usage, cost and tool
    calls survive; pretty-printed `--json` envelopes (openclaw, droid, auggie)
    are masked member by member and still parse;
  - across streamed delta events (gemini, hermes, qwen-code, claude
    `--include-partial-messages`): a block follows the delta's string path into
    the next deltas of the same message and content block, only while they are
    still key-shaped and for at most 64 KiB, and a PEM marker split between
    deltas is joined through a short carry.

  Masking reaches only key material and stops at the first prose, so later
  commands, tool results and messages are never touched; it is linear in the
  input; the masked form is never less redacted than the record's scrubber
  would leave the raw text, and the joined output kept for the done step and
  the error tail retains each raw `BEGIN`/`END` marker so that scrubber still
  removes the whole block on save. A failing run's 4000-character tail is
  redacted before it is cut.
- **Malformed or hostile CLI output no longer ends or loses a run.** An odd
  `type`, a non-list `tool_calls`, a non-numeric, negative, non-finite
  (`NaN`/`Infinity`, read as `null`) or huge cost, duration or token count
  (meters above 1e15, counts above 2^53) is ignored with a `meter_warning`, and
  any other parse error records the line as text (`parse_error`). An event
  nested past 256 levels is recorded as compact JSON text with a
  `truncated_depth` marker, and an unpaired surrogate escape (Node CLIs slicing
  mid-emoji, an MCP result) as its six-character escape text with
  `surrogates_escaped: true`, so the run always saves; a step the record still
  refuses is kept as text and never kills the agent.
- **Harness output stays bounded.** The output cap charges the longer of the
  raw marker line kept for the scrubber and its masked form, and `--autosave`
  without a throttle checkpoints at most every 2 seconds and only after the run
  has grown by a quarter, so checkpoint work stays linear in output an
  untrusted CLI controls.

### Fixed

- **Anthropic SDK 1.x broke every pre-4.6 Claude model.** Anthropic's Python SDK
  1.0 (2026-08-20) removed `temperature` / `top_p` / `top_k` from
  `messages.create`, and `anthropic>=0.87` resolves to 1.13 on a fresh install,
  so `claude-haiku-4-5`, `claude-sonnet-4-5`, `claude-opus-4-5` and older raised
  `TypeError` before any request. On SDK ≥ 1 the temperature now travels in
  `extra_body` (the API still accepts it for those models); verified against
  anthropic 1.13.0. The adapter still works on the 0.x SDK.
- **`tine price` priced most runs at $0.** It priced only steps of kind
  `model`, but the runtime records a call by what it answered: the final answer
  is a `done` step, text beside tool calls a `think` step, a refusal an `error`
  step. A `tine run --model … --prompt` run (one `done` step) re-priced at
  `$0.0000, priced=0`, and every agent run lost its final call. A call-shaped
  step the capture itself billed is priced now; a harness's closing step (no
  usage) still is not, so nothing is counted twice.
- **Local runs re-priced as `unknown`.** A call captured from Ollama, LM Studio,
  vLLM or any local preset is recorded `unmetered`; `tine price` re-billed it
  against the catalog and reported an unknown model. Post-hoc pricing now
  treats the same set of local providers as unmetered (one registry, tested
  against the preset list).
- **`tine price` ignored the recorded service tier**, so a Claude fast-mode call
  (2x), a Priority or Flex call, or a US-geo call re-priced at the standard
  rate. The tier recorded at capture is used now, and both the native Anthropic
  adapter and the claude-code harness record `usage.speed == "fast"` and
  `inference_geo: "us"` as the `fast` / `fast_us` / `us` tier (nothing read
  them before).
- **Claude Code's estimate is no longer booked as cost when it is not a list
  price.** Its `total_cost_usd` is booked only when every model's `costBasis`
  is `list`; otherwise it is kept as `reported_estimate_usd`.
- **Claude Code against a local or third-party `ANTHROPIC_BASE_URL` was recorded
  as `anthropic`.** A loopback base URL records `local-anthropic-compatible`
  (unmetered); another non-Anthropic host records `anthropic-compatible`
  (priced unknown). Bedrock/Vertex/Foundry flags still win.
- **Dead default models.** OpenRouter's default `nousresearch/hermes-4-70b` was
  removed from OpenRouter, Groq's `llama-3.3-70b-versatile` is Enterprise-only,
  and Together removes `Llama-3.3-70B-Instruct-Turbo` on 2026-10-22.
- **LangChain runs were billed up to ~4.7x.** LangChain's normalized
  `usage_metadata` reports *inclusive* totals, and OpenAI's raw `token_usage`
  nests `cached_tokens` / `reasoning_tokens` inside its totals. The callback
  handler stored those totals as exclusive buckets and added the breakdowns on
  top, so a 10k-fresh + 90k-cached Anthropic call recorded
  `input: 100000, cache_read: 90000` ($0.458 instead of $0.098) and
  `tine export` sent `gen_ai.usage.input_tokens = 190000`. Breakdowns are now
  subtracted, langchain-anthropic's `ephemeral_{5m,1h}_input_tokens` split is
  honoured (also when it sits nested under `cache_creation` in the raw usage
  `llm_output` carries, so a 1-hour write is not priced as a 5-minute one), and
  the handler records the serving provider from `ls_provider`, so
  a LangChain run prices instead of reading `unknown`. Runs recorded before keep
  their stored usage.
- **gemini-3.5-flash billed at its retired rate after being rerouted.** Google
  deprecated it on 2026-10-08 and routes calls to gemini-3.6-flash (half the
  price); the card was open-ended, so a response that still names 3.5 billed 2x.
  The card now closes on 2026-10-07 and starts at GA (2026-05-19) instead of
  2026-07-15, so May–July runs price too.
- **Together cards past their models' lives.** Llama-3.3-70B-Instruct-Turbo and
  DeepSeek-V4-Flash-0731 end 2026-10-21; GLM-5.1 is now 2026-04-08 to 2026-06-08
  at $1.40 / $4.40 and 2026-06-09 to 2026-07-09 with the $0.26 cached rate;
  GLM-5.3 starts 2026-08-28 and GLM-5.3-Flash 2026-08-26. OpenRouter's
  `hermes-4-70b` card closes, Groq `qwen/qwen3.8-27b` is backdated to
  2026-09-05, and `qwen-max` gets its implicit-cache rate ($0.32).
- **`OLLAMA_HOST` in the forms Ollama documents failed** (`0.0.0.0`,
  `127.0.0.1:11434`, `gpu-box`): "Request URL is missing an 'http://' or
  'https://' protocol". It is read the way Ollama's own client reads it.
- **Ollama Cloud calls were recorded as free.** `:cloud` / `-cloud` tags proxied
  through the local daemon, or `https://ollama.com` itself, are recorded under
  `ollama-cloud`, never `unmetered`; `OLLAMA_API_KEY` is sent only to
  ollama.com. Ollama's `prompt_eval_cached_count` is recorded as cache reads.
- **Reasoning left inline was recorded as the answer.** `<think>…</think>`,
  `[THINK]…[/THINK]` and raw Harmony channels at the start of a message — what
  TGI, llama-cpp-python, llama.cpp `--reasoning-format none`, MLX-LM and others
  return — are split into reasoning, identically for a whole message and a
  stream; a server that sends both (llama.cpp `deepseek-legacy`) is no longer
  recorded twice.
- **Streams from cumulative-usage servers emitted a usage event per chunk**
  (vLLM `--enable-force-include-usage`, `continuous_usage_stats`); a Chat
  Completions stream now emits one usage event, the last. LocalAI and KoboldCpp
  streams request usage. Mistral's applied tier is read from
  `usage.service_tier`, Inception's top-level `cached_input_tokens` count as
  cache reads, and Gemini's `ON_DEMAND_OFFPEAK` traffic type maps to an
  `offpeak` tier (priced only where carded).
- **Harness fixes.** `grok` ran `grok exec`, which does not exist; `cursor` ran
  `cursor-agent run`, which current Cursor CLIs do not accept; `--harness-arg`
  landed between a prompt flag and its value for harnesses whose prompt is
  passed with `-p` / `-q` / `--message`, so `--harness-arg --model
  --harness-arg X` became the prompt. All three are fixed.
- **`put_run` and `migrate-v3` silently truncated deep JSON.** A step value
  nested more than 100 levels was stored as `"[MAX_DEPTH]"` with fsck green,
  while the v2 file held it intact. The repository writers now keep it (up to
  the format's 512-level limit) and refuse a deeper or circular value; only the
  trace and live recorders still truncate.
- **An interrupted shallow fetch left unreadable objects.** The shallow-boundary
  file was written after the objects, so Ctrl-C or a full disk during the pack
  copy left runs whose cut links were neither present nor recorded — and a retry
  sent nothing, so it never healed. The boundaries are now recorded before any
  object is written.
- **A full unadopted-annotation record refused every later pack** carrying a
  foreign annotation; it now first forgets entries the fallback can no longer
  read.
- **`tine clone` into an existing repository** silently re-pointed its
  `heads/main`; it now refuses (use `fetch`).
- **fsck** reports a ref file whose name is not a legal ref (dot-files such as
  `.DS_Store` are still ignored) and a corrupt `unadopted` record.
- **`tine serve purge --grace-seconds` below 60 needs `--force`**: with no grace,
  a purge can delete orphaned objects a push in progress is about to reference.

### Still open

- **Not part of this audit round:** the shell tool's executable allowlist and
  the git option/subcommand guard (`tools/_git_guard.py`) were not re-audited.
- **Harnesses:** Kilo Code and iFlow CLI are not catalogued (no documented
  headless invocation could be confirmed; use `generic`). Grok Build and Qoder
  JSON schemas are undocumented and read as Claude-compatible events
  (`unverified`); `droid`, `auggie` and `continue` record only their final
  result; `aider`, `crush` and `kiro` are text only. Dialect fixtures are built
  from each CLI's documented schema, not live account captures. Model
  ids are recorded as each CLI spells them (Copilot's `claude-haiku-4.5`,
  Cursor's display name), so those price `unknown`. A generic ACP client
  harness would cover several CLIs at once.
- **Import:** OpenCode session import (its SQLite schema is still changing).
  Claude Code's `cost_usd` in OTel logs is kept as an attribute, not booked.
- **Models and pricing:** Kimi's 1-hour cache-write header and LiteLLM's
  `x-litellm-response-cost` header; sending reasoning back to Ollama; token
  refresh for Bedrock short-term keys, Vertex OAuth and Entra; Vertex and
  Foundry adapters; `baseten`, `novita` and `nebius` presets; per-call fees for
  server-side tools (web search, grounding); region-scoped Qwen identity;
  compute/energy rates for non-Ollama presets. Mistral Large 4's list price is
  not carded (the sale's end date is unconfirmed), nor DeepInfra, Cerebras,
  Upstage, Inception or Nebius (pages not verifiable from raw text), Vertex
  Gemini, or Bedrock models other than Claude and GPT-6 Astra. Claude Fable 5.5
  has no published price and no card.
- **Unchanged from 0.9.2:** the pricing catalog's signature has no
  domain-separation prefix (added at the next release-key rotation); a bare
  64-hex public key under a name other than `*.pub` cannot be told from an HMAC
  secret; a custom `KMSKeyProvider` gets slot-bound encryption only by
  implementing `seal`/`unseal`; `heads/*` has no fast-forward rule on the
  remote; an HMAC key file is read byte-exact (a CRLF-written key is a different
  key — deliberate, so existing signatures keep verifying); an unsigned `.tine`
  or run record can claim anything about itself (harness markers, billing,
  costs) — verify signatures (`--require-signature`) where that matters.
- **Process containment:** on Linux the supervisor cleans up runaway and
  leftover tool processes but cannot contain an adversarial process running as
  the same user; real isolation needs a container or cgroups. On macOS and the
  BSDs a tool descendant that calls `setsid()` can outlive the tool.
- **Redaction residuals:** redaction is pattern-based and best-effort. On the
  rare JSON rebuild path a whole string can be replaced where the scan would
  have cut part of it; JSON holding nested JSON strings full of secrets costs
  about 7–14x the 0.9.2 scan (flat JSON at most about 4x; always linear); a blob
  over 32 MiB, or one that is not a JSON document or JSON Lines, keeps the byte
  scan's output, which can still break JSON in rare shapes; the survivor checks
  ignore removed text with no word of four or more letters or digits (the
  scan's own removal still stands); a single-quoted `.netrc`/`*_PWD` value
  containing `"` is cut at that quote, and a raw-quoted one with no closing
  quote on its line is not redacted by those patterns; an unquoted multi-word
  value stops before a following credential-name head (`pw: a api_key=c`
  redacts `a` and `c` separately but keeps the name `api_key`); a bare `token`
  name is not a credential name (it is too often a counter).
- **Harness masking residuals:** a body line with a decoration the masker does
  not strip can reach its own per-line step, and a PuTTY header or SSH2 marker
  split across two streamed deltas is not re-joined (PEM markers are); in both
  cases the done step keeps the raw text for the record scrubber. Streamed
  chat responses keep only structured reasoning when one delta carries both it
  and inline `<think>` text.
- **Local endpoints:** a loopback `ANTHROPIC_BASE_URL` (or `--base-url`) is
  recorded as a local, unmetered endpoint; a local proxy in front of a paid API
  should not be labelled that way.
- Conformance vectors for `config.json`, reflog rotation and `unadopted`.

## 0.9.2 — 2026-10-09 — Hardening

The follow-ups 0.9.1 left open, `tine --version`, and every hardening item the
0.9.0 audit listed beyond its confirmed findings — the remote server, signing
and keys, pricing trust, the CLI/MCP/export surface, and the tool sandbox. Each
fix has a regression test in `tests/test_security_0_9_2*.py` that fails on
0.9.1. No format change: every file and repository written since 0.3.0 still
reads, and 0.9.1 reads the files and repositories 0.9.2 writes. The one
exception is the remote server's encrypted object store: objects a 0.9.2 server
stores (`TINEAES3`) cannot be read by a server downgraded to 0.9.1.

### Upgrade notes

*Remote server*

- **`promotions/*` and moving an existing `tags/*` ref need the `admin` role.**
  `tine serve --writer-promotes` / `RoleAuthorizationPolicy(writer_promotes=True)`
  restores writer promotion. A custom `AuthorizationPolicy` is now also asked
  about the actions `promote` and `retag`.
- New object files are `TINEAES3`; a server downgraded to 0.9.1 cannot read
  objects written by 0.9.2 (0.9.2 reads everything older).
- **`tine serve --insecure-dev` binds loopback only**; add
  `--insecure-dev-any-host` to serve plaintext on another interface.
- **OIDC tenant claims must be valid tenant names** (`[a-z0-9][a-z0-9._-]*`);
  other identities are refused at authentication.
- **OIDC: a token whose `typ` is not `JWT` / `at+jwt` is refused**, and
  discovered JWKS keys expire after `max_key_age` (default 3600 s) without a
  successful refetch — keep the issuer's `jwks_uri` reachable from the server.
- **Busy servers answer `503`** (worker slots full, a peer over its share, or no
  walk/install slot within 30 s); clients should retry.
- **`GET /audit/verify` no longer returns `head`.**
- **`POST /search` answers with at most 1,000 objects and a `truncated` flag**
  instead of `400`.
- **`tine fetch` / `tine push` JSON gains `associations_omitted`**, and a tenant
  holds up to 4,096 refs (was 1,000) within an 896 KiB listing.
- **`tine serve` takes an optional maintenance `ACTION`**; without one it serves
  exactly as before.
- New `tine serve` flags: `--header-timeout` (10), `--max-connections-per-peer`
  (half of `--max-connections`), `--insecure-dev-any-host`, `--writer-promotes`.

*Signing, keys and pricing*

- **An unsigned `./.tine/pricing.json` no longer prices anything** unless
  `OPENTINE_TRUST_WORKSPACE_PRICING=1` (or `true`/`yes`/`on`) is set.
- **`tine keygen` needs `--out PATH`** (or `--stdout` to print the private key).
- **`tine pricing update` refuses a catalog older than the bundled or installed
  one**, and an older signed user catalog is ignored.
- **`--key-file` refuses a `*.pub` file or a PEM/OpenSSH public key.**
- `tine verify --json` adds `signature_present`, `signature_checked` and
  `signature.key_fingerprint`; `repo-verify` rows add `key_fingerprint`.
- A small-order Ed25519 key is `error` (it verified forgeries before).

*Model providers and tools*

- **An API key is no longer sent over `http://` to a non-loopback host.** Use
  `https://`, or opt in with `allow_insecure=True` (OpenAI-compatible adapters)
  or `OPENTINE_ALLOW_INSECURE_ENDPOINTS=1` (all adapters) on a network you
  trust. Local presets with their default placeholder key are unaffected.
- **A redirect from the Anthropic or Google endpoint is an error.** Point
  `ANTHROPIC_BASE_URL` / `GOOGLE_GEMINI_BASE_URL` at the final URL.
- **The python tool ignores `PYTHON*` variables and user site-packages** (`-I`),
  even with `inherit_env=True`: install what snippets import into the
  interpreter's environment.
- **On Windows, a `.cmd`/`.bat` harness or shell-tool program is refused an
  argument holding `" % ! ^ & | < >` or a line break.** Point
  `--harness-command` at the real executable (`node path\to\cli.js`).
- **`RedactionPolicy(redact_secrets=False)` and a policy naming a format field
  raise `ValueError`;** `extra_secret_keys` is now enforced on every save of a
  run that records it.

*CLI, MCP and export*

- **Exported OTLP span ids changed shape** for natively recorded runs: `traceId`
  is now 32 hex and `spanId` 16 hex, derived from the run and step ids, which
  ride along as `opentine.run_id` / `opentine.step_id` attributes. Dashboards or
  queries keyed on the old raw ids should key on those attributes. Imported
  spans keep their ids.
- **`tine export` scrubs credential-shaped text** from the document it writes or
  pushes.
- **MCP:** `fork_run_v3`/`resume_run_v3` refuse an existing ref (pick a new
  `experiments/` name); `list_runs`/`fork_run` paths are relative to the runs
  directory; `attest_run` claims are capped at 64 KiB.
- **Remote URLs** other than `http://`/`https://` are refused even with
  `--allow-insecure`.

*Runs and repositories*

- **`repo.load_run(...).metadata` no longer repeats `system_prompt`,
  `user_prompt` and `model_info`** for runs stored from 0.9.2 on; read
  `run.system_prompt`, `run.user_prompt` and `run.model_info`. `.tine` files
  are unchanged.
- **`config.json` with a duplicated key or a boolean for a number is refused.**

### Added

- **`tine --version`** (`-V`) prints the installed version.
- **`tine keygen --hmac`**, **`--pin FINGERPRINT`** on `verify`/`repo-verify`/`migrate-v3`, key flags on `migrate-v3`, **`--token-file`** on `fetch`/`push`/`clone`, and **`tine serve`** maintenance actions and connection limits (all below).

### Security — remote server

- **The OIDC verifier accepted any JWT type the issuer signs.** A DPoP proof,
  logout token or security-event token from the same issuer, with the right
  audience, passed as a bearer credential. A token whose header `typ` is present
  must now be `JWT` or `at+jwt` (`application/` prefix and case ignored).
- **Issuer key rotation needed a restart, and a revoked key never expired.**
  `JWTVerifier.from_discovery` fetched the JWKS once at startup: a key the
  issuer rotated in was refused until a restart, and one it rotated out — say
  because it leaked — kept verifying for as long as the server ran. A
  discovered JWKS is now refetched when a token names an unknown `kid` (at most
  once a minute, so made-up `kid`s cannot turn the server into a request
  amplifier against the issuer) and once it is an hour old. A failed refetch
  keeps the current keys until that hour is up; after it every token is refused
  rather than checked against keys the issuer may have revoked. A static JWKS
  passed to `JWTVerifier` directly is the operator's pin and never expires.
  `refresh_interval`, `max_key_age` and `clock` are configurable.
- **Attestations could still make a history unfetchable.** 0.9.1 capped a run at
  1,000 annotations and attestations, but a fetch carries every run's
  associations under one 10,000-object budget, so ten runs at the cap — or one
  run with 9,000 events and a thousand attestations — still failed every fetch,
  clone and push that included them. A pack now walks the object graph first and
  adds each run's associations only while they fit; a run whose associations do
  not all fit keeps its annotations (its metadata) when those fit. Associations
  can no longer make a pack fail. The server reports the runs left short in the
  fetch audit record and an `Opentine-Associations-Omitted` response header, and
  `tine fetch` / `push` print them as `associations_omitted` (0 from older
  servers, which never send the header).
- **Two concurrent installs could overshoot the association cap by a pack.**
  The budget check and the writes it admits are now serialized for packs that
  carry annotations or attestations (packs without them never wait).
- **A tenant stopped accepting pushes after about a thousand annotated runs.**
  Each pushed run adds an `annotations/` ref and a tenant was capped at 1,000
  refs, so the thousand-and-first push moved `heads/main` and then failed at its
  annotation ref. The bound is now what keeps `GET /refs` readable by every
  client: up to 4,096 refs and 896 KiB of names and ids, under the 1 MiB
  control response clients accept (a run's annotation ref is about 160 bytes).
- **Operators can delete refs and objects.** There was no way to remove a ref
  or object from the remote short of editing SQLite. `tine serve ACTION` now
  runs offline maintenance on the server's storage — `refs`, `delete-ref NAME
  [--expect OID]` (compare-and-swap), `associations OID`, `delete-objects OID…
  [--from FILE|-] [--dry-run]` (only objects no ref reaches except as
  associations, e.g. an attestation flood) and `purge [--grace-seconds N]
  [--dry-run]` (objects no ref reaches, keeping anything written within the
  grace window, default an hour). It opens `--root` with `TINE_KMS_KEY` as the
  server does and adds no HTTP endpoint, so no token reaches it over the
  network. It is safe beside a running server — a pack install re-checks what
  it wrote or links to under the lock each purge batch takes, so a run pushed
  again mid-purge is never left with objects missing — and every action, dry
  runs included, is recorded in the tenant's audit chain.
- **A handful of idle connections could take the whole server.** Every
  connection held one of 16 worker slots for up to a minute, a request that
  trickled a byte every few seconds never hit the per-read timeout, and when the
  slots were full the accept loop itself blocked. A connection must now finish
  its TLS handshake, request line and headers within `--header-timeout`
  (10 s), one peer address holds at most `--max-connections-per-peer` slots
  (half of `--max-connections` by default), and a connection that finds no free
  slot is answered `503` (closed, over TLS) at once instead of queueing behind
  the accept loop. Negotiation, which walks up to a pack's worth of objects like
  a fetch, is now behind a bounded slot too, and a fetch, negotiate or install
  that waits more than 30 s for one is answered `503`.
- **Refusals were not audited.** A bad or missing token got `401` with no
  record; an OIDC identity whose tenant claim was not a valid tenant name
  (`"Acme Corp"`) got `400` because its denial could not even be written; and
  failures after authorization — an invalid pack or ref, an admission refusal —
  left nothing. An OIDC tenant claim must now be a valid tenant name (refused at
  authentication otherwise); a denial is written under the identity's tenant or,
  failing that, the one it asked for; authenticated failures are audited like
  successes; and unauthenticated refusals are counted and written at most once a
  minute per tenant named in the URL (under `_server` when it names none), so
  anonymous traffic cannot flood the log. No token, header or body is recorded.
- **Any writer could move a promotion or a tag.** `promotions/*` — what a
  release pipeline deploys from — and existing `tags/*` refs could be re-pointed
  by any writer. A promotion now needs the `admin` role (`promote`), and moving
  or replacing an existing tag does too (`retag`); creating a tag is still a
  writer's. `tine serve --writer-promotes` (or
  `RoleAuthorizationPolicy(writer_promotes=True)`) restores the old behaviour.
  Both refusals are audited.
- **`--insecure-dev` served plaintext bearer tokens on any interface.** It now
  binds a loopback `--host` only, unless `--insecure-dev-any-host` is also given.
- **A resumable upload belonged to whoever knew its id.** Any writer in the
  tenant who learned an upload id — the server's request log printed it — could
  append to it, read its progress, or complete it and have the install
  attributed to them. An upload now records the identity that declared it and
  refuses (`403`, audited) every other one, and request logs no longer print
  upload ids or query strings.
- **Audit verification leaked other tenants' activity and cost a full scan.**
  `GET /audit/verify` returned the server-wide chain head, which changes on every
  request any tenant makes, and walked every audit row on each call. It now
  returns only the status and warnings; the reference store walks the whole
  chain at most once every five minutes and, on every call, authenticates the
  rows appended since the last verified point up to the authenticated anchor.
- **Ciphertexts were bound to their tenant only.** An object file and an upload
  frame — or two objects, or frames of two uploads — encrypted for one tenant
  were interchangeable under the key (integrity still held, by content hash and
  pack checksum). New writes are `TINEAES3`, which authenticates purpose, tenant
  and slot (the oid; the upload id and offset), so a ciphertext opens only where
  it was written. `TINEAES1`/`TINEAES2` files and in-flight uploads still read; a
  KMS adapter opts in by implementing `seal`/`unseal`.
- **Search could be disabled by any writer.** `POST /search` returned `400` once
  a tenant held more than 1,000 objects of the requested type. It now returns
  the newest 1,000 (a total order, so pages are stable) with `"truncated": true`.
- **Purge stopped at 100,000 objects**, the request-path listing bound — the
  tenants most in need of one. Operator maintenance now streams the tenant's
  objects with no count bound.
- **The association cap could be overshot by two server processes.** The lock
  serializing installs that add annotations or attestations was per process; it
  now also takes a file lock beside the SQLite database, so processes (or WSGI
  workers) sharing a store serialize too.
- **Common access tokens were refused.** `azp` had to equal the audience, which
  rejects the ordinary access token an IdP issues to a client for this API
  (`aud` = the API, `azp` = the client). `JWTVerifier(..., authorized_parties=(
  "client-id",))` (also through `OIDCIdentityProvider.from_jwks`/`from_discovery`)
  lists accepted clients; with several audiences `azp` is still required.

### Security — signing, keys and pricing

- **A small-order Ed25519 key verified anything.** OpenSSL loads any 32 bytes as
  a public key and verifies without a cofactor check, so a block whose embedded
  key was the identity point — with the signature `R` = identity, `S` = 0 —
  verified as `verified-tofu` over *every* message. The eight small-order keys,
  in any spelling OpenSSL accepts (non-canonical `y ≥ p`, or `x = 0` with the
  sign bit set), are now refused as `error` wherever a key is trusted: the
  embedded key under `--trust-embedded-key`, `--pubkey`, and the library's
  `public_key=`. No generated key has small order, so nothing honest changes.
- **Trust-on-first-use named no key.** `tine verify` and `tine repo-verify`
  printed the same output for an artifact re-signed by someone else under the
  victim's `signer`/`key_id` labels. Every Ed25519 verdict now names its key by
  fingerprint (`sha256:` + the SHA-256 of the raw key; JSON
  `signature.key_fingerprint` / each row's `key_fingerprint`), and
  `--pin FINGERPRINT` (repeatable; on `verify`, `repo-verify` and `migrate-v3`)
  makes a trust-on-first-use check pass only for a pinned key — reported
  `verified` — and fail as `mismatch` for any other. A pin must be the full
  digest; a 16-hex prefix is 64 bits, which a key grinder can match.
- **A public key could be used as an HMAC secret.** Passing an Ed25519 public
  key to `--key-file` — an easy slip next to `--pubkey` — made the public key the
  shared secret, so anyone could mint HMAC blocks that verified. A file named
  `*.pub`, or holding a PEM or OpenSSH public key, is now refused as HMAC key
  material on every verb that reads one.
- **The workspace pricing overlay is opt-in.** `./.tine/pricing.json` comes from
  whatever directory the process runs in (a cloned project can ship one), and it
  outranks the user overlay and the bundled catalog; unsigned, it could price any
  model at $0 and so disarm every `max_cost` budget computed from the catalog —
  live model billing included. 0.9.1 announced it; it is now **ignored** unless
  validly signed by a trusted key or the operator sets
  `OPENTINE_TRUST_WORKSPACE_PRICING=1` (only `1`/`true`/`yes`/`on` count — `0`
  no longer silences anything). The CLI says on stderr which overlay it ignored.
- **A signed catalog could roll prices back.** `tine pricing update` installed
  any validly signed catalog, and the user slot outranks the bundled one, so an
  older signed catalog — installed by mistake, or replayed by anyone able to
  write the file — masked newer bundled cards even across upgrades. A signed
  catalog older (`generated_at`) than the bundled snapshot or than the catalog
  it would replace is now refused at install, and a signed user catalog older
  than the bundled one is skipped at load with a stderr note.
- **`tine migrate-v3` never checked signatures.** It took no key flags, so a
  signed source always imported as `no-key`, although `--allow-unverified`
  promised a signature check. It now takes `--key-env`/`--key-file`/`--pubkey`/
  `--trust-embedded-key`/`--pin`, and with one of them a source whose signature
  does not verify is refused (unless `--allow-unverified`).
- **`tine keygen` printed private keys.** Without `--out` it wrote the seed to
  stdout, where CI logs keep it. A private key now goes to `--out` (mode 0600)
  unless `--stdout` asks for it. A private or HMAC key file readable by group or
  others is announced on stderr, the way ssh does (POSIX).
- **Nothing made a good HMAC key.** The 16-byte floor is length-only —
  `passwordpassword` signed — and every signed object is an offline oracle for
  guessing the key. `tine keygen --hmac --out FILE` writes 32 random bytes as
  hex, and a key that looks guessable (under about 128 bits by a simple
  alphabet × length estimate) is announced on stderr.
- **`tine verify` without a key said "OK" about a signed artifact.** It checked
  the digest only and said nothing about the signature beside it. It now says
  *signature present but NOT checked* and how to check it; `--json` gains
  `signature_present` and `signature_checked`.

### Security — CLI, MCP and export

- **`tine export` scrubbed nothing on the way out, and its push had no bounds.**
  A `.tine` written before 0.9.1 still holds the prose secrets its writer kept
  (a `ghp_…` token, a PEM key, a URL password), and export sent them to the
  collector verbatim. The document is now scrubbed with the same free-text pass
  the repository applies. The push itself re-implemented its HTTP read without
  the repository client's controls: it advertised gzip/deflate/zstd and read a
  rejecting collector's reply decompressed (a 60 KB zstd reply drove the CLI to
  2.1 GB), and its 30 s timeout applied per read, so a collector trickling a
  byte every few seconds held it forever. The push now asks for `identity`,
  reads the reply raw (an encoded reply is not read at all), and runs under a
  120 s wall deadline. A malformed `--endpoint` (`http://[::1]:4318evil/`) is a
  refusal instead of a traceback, and `/v1/traces` joins the endpoint's path
  instead of landing after its query string or fragment.
- **Exported span ids now have the OTLP shape.** `traceId` was the run id and
  `spanId` the 64-hex step digest; OTLP requires 16- and 8-byte ids (32 and 16
  hex), and a spec-strict collector rejects the whole batch otherwise. Export now
  derives conforming ids deterministically (a domain-separated SHA-256 prefix),
  so every span of a run lands in one trace and parent and link references
  still meet, and carries the originals in `opentine.run_id`, `opentine.step_id`,
  `opentine.parent_step_id` and `opentine.causal_step_ids`. Ids that already
  have the OTLP shape — anything an import brought in — are kept as they are,
  and the importer reads the originals back and drops those attributes, so
  export → import still returns every id the run had.
- **MCP tools are bounded.** `fork_run` refuses a source run over 32 MiB and
  refuses once the runs directory holds 5,000 runs (each call wrote a new
  artifact the size of its source). `fork_run_v3` and `resume_run_v3` only
  *create* `experiments/*` refs: they used to compare-and-swap against the value
  they had just read, i.e. overwrite an operator's experiment. `attest_run` and
  `evaluate_run` cap a claim at 64 KiB of JSON and a signer at 256 characters.
  `list_runs` and `fork_run` report paths relative to the runs directory instead
  of absolute host paths.
- **`tine replay --harness` says what it is about to send.** Without `--prompt`,
  a harness replay hands a live agent CLI the `user_prompt` recorded in the
  artifact — text whoever wrote the file chose — and `--verify` sends it twice.
  It still does (that is what a replay is), but first prints the source, the
  length and a sanitized 200-character preview on stderr.
- **`--token` warns.** A bearer token on the command line is visible to `ps`,
  `/proc` and shell history; `tine fetch`/`push`/`clone` now say so on stderr and
  point to `TINE_REMOTE_TOKEN` or the new `--token-file PATH` (one token, at most
  8 KiB, and refused alongside `--token`).
- **Remote URLs must be http or https.** The loopback exemption accepted any
  scheme on `127.0.0.1` (`ftp://`, `file:` …); only the two the transport speaks
  pass now.
- **Terminal output hardening.** A diff value is clipped *before* it is escaped
  (clipping escaped markup could strand the backslash that escapes a `[`, so
  artifact text swallowed the closing style tag); a manifest's budget values
  (`Budget` accepts numeric strings padded with NEL and other separators) are
  sanitized; Rich emoji shortcodes are off, so `:warning:` in run text stays
  literal; and step-ref errors quote the artifact's ids (`'\x1b[2J…'`) instead of
  interpolating them raw.
- **`tine resume` says when it strips a signature.** It rewrites the artifact in
  place, and a plain save drops any signature; it now says so, as `tine tag`
  does.

### Security — tool sandbox and providers

- **The Anthropic and Google adapters no longer follow redirects.** httpx
  strips only `Authorization` when a redirect changes origin, so both SDKs
  carried `x-api-key` / `x-goog-api-key` to wherever a redirect pointed — a
  gateway named by `ANTHROPIC_BASE_URL` or `GOOGLE_GEMINI_BASE_URL`, or anything
  able to answer with a 307. A redirect is now an error, as it already was for
  OpenAI-compatible endpoints. The Google client also stays on httpx when
  aiohttp is installed, where the setting would not apply.
- **The fs tool opens the path it checked.** It resolved a path inside the root
  and then opened it by name, so a directory swapped for a symlink in between —
  by any other process writing in the workspace — sent the read or write
  outside the root, or into `.git`. On POSIX the path is now reached from the
  root one component at a time without following a symlink; on Windows the
  opened file must still be the one the path names, and a write truncates only
  after that check. A FIFO swapped in for a file fails instead of hanging the
  agent, and a file that grows past `max_file_bytes` after the size check is
  refused.
- **The python tool runs in isolated mode.** With `inherit_env=True` the host's
  `PYTHONPATH`, `PYTHONINSPECT`, `PYTHONWARNINGS` and user site-packages shaped
  every snippet. Snippets now run with `-I -X utf8`, which also makes their
  output UTF-8 on Windows.
- **Windows directory listings go through a handle.** `ls` listed a directory
  by path after checking it, and any Windows user can create a junction, so a
  junction swapped in between was listed. The directory is now opened once,
  its handle's final path must be the checked path, and its entries are read
  from that handle.
- **`RedactionPolicy` was recorded and read by nothing.** `extra_secret_keys`
  named fields the host considered secret, yet they reached `.tine` files and
  repositories verbatim, and `redact_secrets=False` disabled nothing. A run now
  carries the policy it ran under (`Agent(policies=PolicySet(...))` records
  `PolicySet.to_dict()` in `run.policies`), and every writer of that run —
  `Run.save`, autosave and `Repo.put_run` — redacts the named fields as it does
  `api_key` (camel/kebab/plural forms included, and `name: value` strings). A
  policy naming a field the run format itself uses (`steps`, `parent_ids`, …)
  is refused, and `redact_secrets=False` is refused rather than silently
  ignored. The policy's own list of names is no longer redacted out of the
  saved file (its key matched `*_secret_keys`), so it survives a reload.
- **Batch-file argument injection on Windows (BatBadBut, CVE-2024-24576
  class).** Windows runs a `.bat`/`.cmd` program through `cmd.exe`, which
  re-parses the command line; Python quotes for the C runtime, so a harness
  task or a shell-tool argument holding `"` and `&` could run a command of its
  own. npm installs most agent CLIs as `.cmd` shims. When the program is a
  batch file, an argument holding `" % ! ^ & | < >` or a line break is now
  refused before anything starts (harness launches and every `run_bounded`
  command: shell tool, python tool, git capture). Launch the real executable
  (`node <entry>.js`, an `.exe`) to pass such text.
- **API keys no longer cross the network in cleartext.** Every
  OpenAI-compatible adapter (local presets, hosted providers' `*_BASE_URL`
  overrides, `OpenAI(base_url=…)`) and the Anthropic/Google adapters'
  `ANTHROPIC_BASE_URL` / `GOOGLE_GEMINI_BASE_URL` accepted `http://` for any
  host, sending the key in the clear. A key now goes over plain HTTP only to a
  loopback address (`localhost`, `127.0.0.0/8`, `::1`); elsewhere use
  `https://`, or opt in with `allow_insecure=True` or
  `OPENTINE_ALLOW_INSECURE_ENDPOINTS=1`. A local server's own placeholder key
  (`vllm`, `lm-studio`, …) is no secret and is unaffected.
- **Flag values in a recorded command.** `--password=…` was redacted, but a
  recorded command is a list, and `["cli", "--password", "hunter2"]` left the
  value as an element of its own. The element after a credential flag
  (`--password`, `--token`, `--api-key`, `--client-secret`, `--auth`, `--pass`,
  …) is now redacted; token counters (`--max-tokens 4096`) and `-p` (the prompt
  flag of most agent CLIs) are kept.

### Security — repository

- **The reflog had no bound.** `logs/<ref>` grew by a row per ref update
  forever (`experiments/*` churn over MCP, CI loops). Each ref's log is now
  capped at 1 MiB: when an append would pass it, the log is atomically
  rewritten keeping its newest half. An oversized log from an earlier version
  is cut on its next append. The reflog stays history, not authority.
- **One repository descriptor, one reading.** `config.json` given a key twice
  (which value wins is parser-specific) or `true` for `1` (which Python's `==`
  accepted) is refused, and it must be strict UTF-8 (a BOM is tolerated).
  Unknown keys and any formatting stay accepted, as SPEC §2.2 and its
  conformance vectors require.

### Fixed

- **Run annotations no longer copy the prompts.** `put_run` stored the run's
  whole `metadata` in its annotation, and a run made by the runtime or loaded
  from a `.tine` file carries `system_prompt`, `user_prompt` and `model_info`
  there — fields the run already stores itself. A 40 KiB system prompt made a
  44 KiB annotation, pushed with every run and counted against the remote's
  1 MiB-per-annotation listing budget; it is now about 200 bytes. Annotations
  written earlier are unchanged and still read.

### Still open

- The pricing catalog's signature has no domain-separation prefix (no other
  signed message can collide today); one is added with the next release-key
  rotation, since it needs the bundled catalog re-signed.
- A public key saved as bare 64-hex under a name other than `*.pub` cannot be
  told from a 64-hex HMAC secret, so it is not refused as HMAC key material.
- A custom `KMSKeyProvider` gets slot-bound encryption only by implementing
  `seal`/`unseal`; `heads/*` has no fast-forward rule on the remote.

## 0.9.1 — 2026-10-09 — Security

A security and hardening release from a five-slice audit of 0.9.0 (kernel and
packs, repository and signing, the remote server, the tool sandbox and
harnesses, and the CLI/MCP/import surface). Every finding below was reproduced
with a proof of concept before it was fixed, and each has a regression test in
`tests/test_security_0_9_1*.py` that fails on 0.9.0. No format change: every
file and repository written since 0.3.0 still reads, and nothing new is written
that 0.9.0 cannot read.

### Upgrade notes

Some fixes change behaviour a workflow may rely on:

- **Text-mode agent CLIs record their stdout as text.** For structured capture,
  ask the CLI for JSON on its command line — `codex`: `--harness-arg --json`;
  `cursor`: `--harness-arg --output-format --harness-arg json`.
- **A `.tine` repository in a parent directory owned by another user is
  refused** (POSIX). Pass `--repo` or set `OPENTINE_SAFE_DIRECTORIES`.
- **The shell tool refuses some git invocations** (`git config`, `-c`,
  `submodule`, `rebase -x`, …), and the fs tool refuses writes inside `.git`.
- **`PythonPolicy(isolation_backend=…)` other than `subprocess` is refused** by
  the built-in python tool instead of running unisolated.
- **A rate card's `currency` must be an ISO code** (`USD`), and an unsigned
  workspace `.tine/pricing.json` is announced on stderr.
- **`repo-search` ranks signed evaluations first** and reports `score_signed`.
- **`verify_attestation`/`verify_artifact` take exactly one key**, and a
  signature block must be in the exact form OpenTine writes.

### Security — remote server

- **A ref listing can no longer be bricked by one annotation.** `GET /refs`
  decoded every annotation under a 1 MiB / 8 MiB budget that no write enforced,
  so one run with a large prompt — or about 185 ordinary annotated runs — made
  the listing return 400 for good, and with it every fetch, clone and push in
  the tenant. The listing now binds each annotation ref by the run the index
  recorded when the annotation was installed and verified, and `update_ref`
  runs the same listing check before committing, so no write can leave a tenant
  unlistable.
- **Uploads can no longer make someone else's run unfetchable.** Any writer
  could upload ~10,000 attestations naming an existing run, without touching a
  ref, and that run could never be fetched, negotiated or cloned again. A pack
  that would give any object more than 1,000 annotations and attestations is now
  refused at install, before anything is written.
- **A slow upload no longer stalls every tenant.** The direct pack upload read
  its request body while holding the server-wide install slots every fetch also
  needs, so two trickling connections from any writer blocked fetch, clone and
  push for all tenants. The body is now read before a slot is taken.

### Security — CLI, MCP and import

- **An untrusted `.tine` can no longer write terminal escape sequences.** A
  loader error quoting artifact content (a step-usage key) reached Python's
  traceback printer raw, so eleven verbs — `show`, `cost`, `price`, `diff`,
  `fork`, `replay`, `resume`, `tag`, … — could put an OSC 52 clipboard write, a
  title change or a screen clear on the operator's terminal, and MCP `show_run`
  errors carried the same bytes. Loader messages now quote such names; every
  `tine` invocation turns an uncaught exception into one sanitized
  `tine: <message>` line with exit 1 (`OPENTINE_DEBUG=1` restores the
  traceback); MCP tool errors are sanitized the same way.
- **Terminal and MCP text drop invisible characters.** Zero-width, word-joiner,
  BOM, line/paragraph-separator and Unicode tag characters are removed along
  with C0/C1 controls and bidi overrides; MCP text output previously escaped
  only line breaks.
- **Workspace pricing overlays.** A rate card's `currency` reached `tine
  pricing show` raw; it must now be a three-letter ISO 4217 code, so an overlay
  with free text (or `usd`) there is refused. The unsigned `./.tine/pricing.json`,
  which outranks the user overlay, is announced on stderr whenever the CLI loads
  it (`OPENTINE_TRUST_WORKSPACE_PRICING=1` silences this).
- **`tine import` is bounded before parsing.** Whole documents and each JSONL
  line pass the `.tine` structural-token budget before `json.loads` — a 256 MiB
  `[{},{},…]` file needed ~6.6 GB of memory before — and the 256 MiB cap is
  enforced by reading, so pipes, FIFOs, devices and JSONL on stdin are bounded.
- **`tine export --output` never writes through a symlink.** A dangling link at
  the destination is refused like an existing file, `--force` replaces the link
  instead of following it, and endpoint URLs are printed without their
  `user:password@`.
- **Search ranks by signed evaluations.** An unsigned evaluation, which any MCP
  client can write, decided a run's rank through `max`; one injected score of
  1.7e308 put a run first. A signed evaluation now decides a run's score
  whenever one exists, and runs scored by signed evaluations rank above runs
  scored only by unsigned ones. Results carry `score_signed`; `--signed-only`
  (CLI), `signed_only=` (library) and `search_runs(signed_only=…)` (MCP) ignore
  unsigned evaluations; MCP `evaluate_run` refuses non-finite or |score| > 1e6.
  Signed is not verified — use `tine repo-verify` with a trusted key.
- **Redaction of imported traces.** Beyond the shapes below, a field named
  `pass`, `pwd`, `auth`, `connection_string`, `dsn`, `webhook_url` or
  `private_key_id` (and `*_dsn`, `*_webhook_url`, `*_connection_string`), a
  `--password X` argument, and Slack or Discord webhook URLs are now redacted.
  A boolean `pass`, an auth *mode* such as `oauth2`, and `session_id` (a
  structural identifier) are kept.

### Security — tool sandbox and harnesses

- **A model could run commands on the host through git.** The fs tool could
  write `.git/config` (`core.fsmonitor`, a `filter.*.clean` driver) and the shell
  tool's allowlist checked only `argv[0]`, so with `git` allowlisted a model
  could pass `-c alias.x=!cmd` — and the next git invocation, its own or
  `code_manifest` capturing the workspace after the run, executed the command.
  The fs tool now refuses any write inside a `.git` directory (any case, or a
  `.git` file) or through a hard-linked file; the shell tool refuses git options
  and subcommands that run a command, inject configuration or point git at
  another repository (`-c`, `--config-env`, `--git-dir`, `config`, `submodule`,
  `--upload-pack`, `rebase -x`, `grep -O`, `clone -c`/`--template`, …), with
  global options checked against an allowlist; and every git OpenTine starts runs
  with fsmonitor off and `safe.bareRepository=explicit`, so a bare repository
  assembled from ordinary file writes is never discovered. An allowlisted
  interpreter or test runner remains arbitrary code execution by design; this is
  now stated in SECURITY_MODEL.
- **The SSRF guard let NAT64 addresses reach the metadata service.**
  `64:ff9b::a9fe:a9fe` (NAT64 for 169.254.169.254), IPv4-compatible `::/96` and
  site-local `fec0::/10` passed the private-host check because Python calls
  them global. An IPv6 address that embeds an IPv4 address is now public only if
  the embedded address is.
- **The subprocess environment scrub missed common credential names.**
  `DATABASE_URL`, `MYSQL_PWD`, `PGPASS`, `GH_PAT`, `SENTRY_DSN`,
  `*_WEBHOOK_URL`, `*_CONNECTION_STRING` and `*_PRIVATE` reached tool
  subprocesses — and through their output, the model. Inherited variables are
  now scrubbed by more names and **by value**: a vendor token shape, a URL with
  a password (including `redis://:pw@`), or a private key is dropped whatever the
  variable is called.
- **`PythonPolicy.isolation_backend` failed open.** The built-in python tool
  never read it, so a policy asking for `external` or `gvisor` isolation ran the
  snippet as the host user with network. Any backend other than `subprocess` is
  now refused.
- **Agent prose could forge steps and charges.** Text-mode harnesses (`gemini`,
  `grok`, `hermes`, `opencode`, `codex`, `cursor`) read any JSON-shaped stdout
  line as a structured event and any "cost: $250" as a charge, so a model's
  answer could record a `deploy_prod` tool call, an error, or money — and trip a
  cost budget. A JSON line is now an event only when the command asks the CLI
  for JSON output (`--json`, `--output-format stream-json`, …; `claude-code`,
  `kimi-code` and `openclaw` do), and free-text cost is booked only for an
  operator-written `generic`/`pi` command. For structured `codex` capture, pass
  `--harness-arg --json`.

### Security — repository, signing and redaction

- **A repository planted in a parent directory was adopted.** `Repo.open` and
  every verb's default `--repo .` walked to the nearest ancestor `.tine` with no
  ownership check, so one planted in `/tmp` or a shared project root would have
  your key sign the planter's runs and `migrate-v3` copy your runs into their
  store (git's CVE-2022-24765 class). On POSIX a repository found in a *parent*
  directory that another user owns is now refused; the directory you name, or
  the current one, is trusted as before, and `OPENTINE_SAFE_DIRECTORIES` lists
  others (`*` for all). A bare repository (`tine init --bare DIR`) now opens at
  its own path.
- **A pack could relabel a run you already had.** An annotation with no ref is
  still read — clones rely on it — but one delivered by a pack for a run the
  repository already held was adopted too, so anyone handing over a pack or
  writing to a shared remote could tag an untagged local run `approved` with a
  "reviewed by" note, and `fsck` stayed green. Those annotations are now recorded
  in `.tine/unadopted` at install and never adopted by object presence; `fetch`
  fast-forwards every annotation ref the remote advertises (not only the tip's),
  so real updates to older runs arrive through the remote's refs.
- **`tine repo-verify` could not express a release gate.** It required every
  attestation on the run to verify and never looked at what was signed: a
  verified *rejection* passed exactly as an approval, and any writer could block
  a release with one unsigned note. `--signer NAME` (repeatable) and `--claim
  JSON` now select the attestations a gate is about; it passes when at least one
  selected attestation verifies, and others neither pass nor block it. Every
  JSON row carries its `claim` and `selected`. Unscoped behaviour is unchanged.
- **One signature verified under several attestation ids.** A signature block
  with re-cased hex, an extra key, or another embedded public key still
  verified. Blocks are now accepted only in the exact form `tine attest` writes,
  with an embedded Ed25519 key that must be the key that verified.
- **The block chose which of the caller's keys was trusted.**
  `verify_attestation` (and artifact `verify`) accepted `hmac_key`,
  `public_key` and `trust_embedded` together and let the block's `alg` pick one.
  Exactly one is now required (`error` otherwise). The CLI already refused two
  key flags.
- **A UTF-16 JSON body evaded the structural budget.** The kernel's token scan
  reads UTF-8, and a UTF-16 body whose code units looked like quotes
  desynchronised it (U+0122 is `22 01`), letting an over-budget document reach
  `json.loads`. A NUL-bearing body — every UTF-16/32 document — is now refused
  before scanning.
- **The v2 writer saved secrets in prose.** `Run.save` redacted credential
  *field names* only, so a PEM private key, a `Bearer` token in a curl line, an
  inline `sk-proj-…`, a URL password or a `ghp_…` token in free text reached the
  `.tine` file. It now applies the same free-text scrub the v3 store does.
- **Credential shapes leaked through both scrubbers.** 13 of 16 common shapes
  survived: GitHub fine-grained PATs, Google API keys, Stripe, GitLab, Hugging
  Face, npm, PyPI, SendGrid and Vault tokens, JWTs, AWS STS keys, URL userinfo
  passwords, signed-URL signatures and token query parameters, PGP private-key
  blocks, and names such as `github_token`, `slack_bot_token`,
  `subscription_key`, `x_amz_security_token`. They are now redacted; token
  *counters* (`input_tokens: 120`, `max_tokens`, a list of token ids) are not.

### Fixed

- **A signed score of `1.0` verified as `mismatch`.** `tine-attest/1` signed
  the in-memory payload, but the v3 store writes an integral float as an integer,
  so every genuine signature over `--score x=1` (or any `-0.0`) failed. The
  signature now covers the payload as stored. A `--key-id` that redaction would
  rewrite (`api_key=prod`) is refused at signing instead of producing an
  attestation that can never verify.

## 0.9.0 — 2026-10-09

### Added

- **Signed v3 attestations (`tine-attest/1`).** An attestation's `signer` was a
  self-asserted label — anyone who could write to a repository could write
  `signer: security-team`. `tine attest` / `tine evaluate` now take `tine sign`'s
  key flags (`--key-env` / `--key-file` / `--ed25519-key-file`, `--key-id`) and
  bind that label to a key with HMAC-SHA256 or Ed25519, over a canonical signed
  view covering the `target_id`, `claim`, `signer`, `evidence_ids` and the
  signature header. `Repo.attest(..., key=...)` and
  `opentine.attest_signing.sign_attestation` are the API halves.
- **`tine repo-verify`.** Checks one `attestation:sha256:…` oid, or every
  attestation targeting a run ref/oid, and reports `tine verify`'s own verdicts
  (`verified`, `verified-tofu`, `unsigned`, `no-key`, `mismatch`, `error`). Same
  key flags, same fail-closed rule: any key, `--trust-embedded-key`, or
  `--require-signature` arms the check and exits non-zero unless everything
  verified. `Repo.verify_attestation` is the API half. MCP has no equivalent —
  signing and key material stay operator-only.
- **`docs/SPEC.md` — the format, published as a specification.** The v3 wire
  format was previously code-only: envelope framing, oid derivation, the
  `TINEPACK3` pack layout, the ref/reflog byte formats and `config.json` existed
  nowhere an outside implementer could build against, and v2 canonicalization
  was not reproducible from docs. All of it is now normative and citable —
  written for someone implementing a reader, writer or verifier in another
  language — including both canonical JSON forms rule by rule, the complete
  rejection table of every bound that can refuse an object, all three signature
  schemes with their domain prefixes and signed views, and executable test
  vectors for oid derivation, the v2 integrity digest and a `tine-attest/1`
  signature. Two documented **⚠ Hazards** an implementer would otherwise get
  wrong: v2 orders object keys by code point while v3 orders them by UTF-16
  code unit (they disagree on non-BMP keys, and unifying them would invalidate
  every stored digest and signature), and `tine-attest/1` signs a *v3* object
  using the *v2* canonicalizer.
- **`docs/conformance/` — the specification, as runnable evidence.** A prose
  spec lets nobody *prove* an implementation correct: before this, `SPEC.md`
  carried four inline worked vectors and an implementer's only recourse was to
  read Python. The format now ships **523 conformance vectors** across 25 families,
  language-neutral (SHA-256, HMAC-SHA256, base64 and a JSON parser; zlib inflate
  and Ed25519 flagged skippable), with a stdlib-only runner
  (`docs/conformance/run_conformance.py`, which imports no opentine) that speaks
  line-delimited JSON to an ~80-line adapter. `scripts/conformance_adapter.py`
  is the worked example. `MANIFEST.json` is the single machine-parsed entry
  point: 33 ops with their input/output shapes, per-file digests, alias groups,
  and which row of §1.6 each vector covers.
- **Negative vectors are the point.** 195 of the 523 refuse input, because
  "reject" is normative here — an implementation that silently repairs a
  document changes a digest claiming fidelity to recorded model output.
  `99-repair.json` goes further: each of its fourteen cases carries the exact
  answer a *repairing* reader returns, so producing it is scored `REPAIRED`
  rather than as a plain failure. Scoring has three columns and the second is
  the load-bearing one — `pairs` (both halves of every twinned case), on which a
  blanket rejecter scores near zero. `04-divergence.json` makes §0.4's
  canonicalization hazard checkable: each half of a pair carries the *other*
  canonicalizer's bytes as `forbidden`, and `sig.attest.hazard.nonbmp-1e20`
  exists because §4.5's own worked vector is all-ASCII, so both canonicalizers
  coincide on it and a JCS-using implementer passes §4.5 and fails only there.
- **`scripts/gen_conformance_vectors.py`, and why the vectors can be trusted.**
  Every expected byte string, oid, digest and verdict is generated from the
  reference implementation, never transcribed; each case's *disposition* is
  declared by hand in `tests/conformance/cases_*.py` and the generator **exits
  without writing** when observation disagrees with the declaration. Making
  opentine accept what it used to reject therefore costs one hand-edited line
  that reads exactly that. Regeneration is byte-identical, and the suite is
  gated four ways: through the low-level functions, through the public
  `Repo`/`Run` API, through the neutral runner and reference adapter, and by 28
  drift gates (no suite file is git-ignored, every §1.6 row is vectored or has
  written prose saying why it cannot be, every reason code is used and
  registered with its bound's *live* value, every twin resolves and flips, every
  `spec_note` has a mandatory resolution).
- **`docs/conformance/compat/index.json`.** The eight golden fixture sets are
  exposed as spec artifacts rather than duplicated: the index points at
  `tests/fixtures/compat/` by path and SHA-256 and copies zero bytes, because
  those bytes ARE the evidence for §5.1's read guarantee and a second copy could
  drift from them. Reflog rows are deliberately excluded — they embed a
  wall-clock timestamp and are the one non-reproducible part of a fixture.
- **`tests/test_format_spec_drift.py`.** The spec is pinned to the code it
  specifies: object types, the oid and ref-name regexes, every bound in the
  rejection table, the three domain prefixes, the frozen `tine-sig/1` metadata
  allowlist, the verdict vocabulary (read out of `_signing_verify`'s AST rather
  than restated), and the crypto test vectors, which are recomputed rather than
  quoted. Change a constant without updating the spec and the suite fails.

- **`docs/SPEC.md` prose amendments found by building the vectors.** §0.2 rule
  10 said nesting is rejected "at or beyond 512 levels"; the encoder accepts 512
  nested containers and rejects 513, and the rule now says so. §0.1 said both
  formats reject a lone surrogate "at write and at read" without naming where —
  `_canon._canonical_bytes` alone accepts one and emits the escape, so the
  section now names `parse_artifact_json`, `assert_loadable` and
  `guarded_redaction` as the enforcement points. §2.7 described the shallow file
  as "Sorted" with "the last line terminated"; the reader enforces neither, so
  both are now stated as **writer** properties. Every such finding is recorded
  in `docs/conformance/SPEC_NOTES.md` with a mandatory resolution.

### Compatibility

- Signing is **opt-in and additive**. An attestation written without a key is
  byte-identical to what 0.3.0–0.8.1 wrote (`"signature": null`), keeps its
  object id, loads out of every released repository, `fsck`s clean, and verifies
  as `unsigned` — never as `verified`.

## 0.8.3 — 2026-10-09

A hardening release: one security fix, and the capture and model-rule debts the
0.8.2 assessment found.

### Security

- **Windows process containment no longer has an escape window.** `run_bounded`
  (the shell and python tools) and every process harness started the child
  *running* and attached the kill-on-close Job Object afterwards, so a
  grandchild spawned in that gap was born outside the job and survived the
  kill — a tool command's descendants could outlive containment. The child now
  starts suspended (`CREATE_SUSPENDED`), joins the job, and only then resumes.
  It is resumed even when no job can be attached (the taskkill fallback
  remains), and a child that cannot be resumed is terminated rather than left
  half-started.

### Fixed

- **Claude Code harness runs are priceable.** The `claude-code` harness ran
  plain `claude -p` and guessed steps from text, recording the CLI's name
  instead of a model and no usage at all, so `tine price` could not price a
  harness run. It now reads `--output-format stream-json`: a `model` step per
  API call with model, provider and exact input-side usage, a `tool` step per
  call with its result, per-model output totals from the final `result` event
  (an assistant event's `output_tokens` is a message-start placeholder — 16
  and 4 against a true 120 in the live capture this was built from), and
  Claude Code's own cost on the closing step. On that capture the catalog
  re-prices the run to exactly the $0.100061 Claude Code reported. The provider
  comes from the environment Claude Code actually receives (Bedrock, Vertex and
  Foundry keep theirs), and the closing per-model totals always use the provider
  Claude Code itself reports — flagging a mismatch when Claude Code was switched
  to another provider through its own settings. The launch and task steps of a harness that reports real model
  calls are no longer recorded as phantom `model` steps.
- **A new model no longer breaks on day one.** Sampling rules lived in
  per-adapter name lists, and each new family missed one (0.8.2 fixed
  `claude-opus-5` and `gpt-6-*` being sent a `temperature` their APIs reject).
  They now live in one table with fail-safe defaults: an unlisted `claude-*`
  model, or an unlisted model on OpenAI's native API, is sent no sampling
  parameters — omitting one never fails a request, sending one a model rejects
  fails every request. Every listed model keeps its exact behaviour (pinned for
  all 56 catalogued Anthropic and OpenAI names); models behind a custom
  `base_url` are only treated as reasoning models when their name says so.

### Tests

- The Windows duration-budget test used a 10 ms budget against a ~15.6 ms timer
  tick, so a loaded runner could spend it before the tool step started.

## 0.8.2 — 2026-10-08

New models, and the adapter rules they broke. Every price was confirmed against
the vendor's own pricing page on 2026-10-08; nothing is converted, derived or
guessed, and anything a vendor does not publish stays `unknown`.

### Fixed

- **Native Claude Opus 5 calls were rejected.** Anthropic returns HTTP 400 for
  any non-default `temperature`, `top_p` or `top_k` on Fable 5/5.1, Mythos
  5/5.1, Opus 4.7/4.8/5/5.5, Sonnet 5/5.5 and Haiku 5.5, and the adapter sent
  `temperature` to `claude-opus-5` because no restriction rule matched it. The
  rule now covers the whole documented list, including the new Opus 5.5 and
  Haiku 5.5; Haiku 5.5 is also recognized as a thinking model (Haiku 4.5 is not).
- **Native GPT-6 calls sent `temperature`.** The Responses path omitted it only
  for `gpt-5*` and the o-series, and "GPT-6 Astra does not support custom
  temperature or top_p values". `gpt-6*` is now treated as the reasoning family
  it is, on the Responses path and on the Chat Completions path a custom
  `base_url` selects.
- **Early-refusal billing follows Anthropic's published rule.** A refusal that
  arrives before any output was non-billable only for exactly `claude-fable-5`.
  Since 2026-09-24 the rule is model-independent: such a refusal is billed when
  `stop_details.category` is `bio`, `frontier_llm` or `reasoning_extraction`,
  and free in any other category or with a null category. The category is now
  recorded in the step's billing calculation; a malformed category is not
  treated as evidence of a free refusal.
- **A missing OpenAI cache-write count is caught for every model that bills
  one.** The check was keyed on a `gpt-5.6` name prefix, so a `gpt-6-astra`
  usage block that omitted its cache-write count was priced as `complete` with
  zero writes. It is now keyed on the card: the count is required exactly when
  the resolved card prices cache writes.
- **Grok long-context pricing starts at 200,000 tokens, not after it.** xAI
  bills "requests whose prompt reaches the listed token threshold" at the higher
  rate; every xAI card fired only above 200,000, under-billing a prompt of
  exactly 200,000 tokens. The rule is now `at-least-200k`.
- **Imported OpenTelemetry traces bill cached tokens at the cache rate.** The
  current GenAI conventions report `gen_ai.usage.input_tokens` *including* its
  `cache_read.input_tokens` / `cache_creation.input_tokens` (now
  `cache_write.input_tokens`) sub-counts, and `output_tokens` including
  `reasoning.output_tokens`. The importer read none of those keys and treated
  the inclusive total as fresh input, so a 100k-token call with 90k cached
  priced at $0.525 instead of $0.12 on Claude Opus 5. The sub-counts are now
  read and subtracted; the older exclusive spellings (`cache_read_input_tokens`
  and friends, which every OpenTine export through 0.8.1 wrote) keep their
  reading, so existing documents import exactly as before. A total smaller than
  its own sub-counts is kept as reported and flagged on the span.
- **Imported agent spans no longer double-bill their model calls.** An
  `invoke_agent` span reports the aggregate usage of the calls beneath it, and
  was imported as a `model` step, so an agent with two $0.075 calls cost $0.30.
  Agent operations (`invoke_agent`, `create_agent`, `invoke_workflow`) now import
  as `subagent` steps that record their usage without being billed, unless no
  span beneath them reports usage of its own (a remote agent), in which case
  the agent span is the only record of that spend and is billed. `tine cost`
  token totals skip the roll-up for the same reason.
- **A v3 step kind the legacy enum lacks survives a `.tine` save.** `subagent`,
  `human`, `policy` and `approval` steps loaded as `model` and were written that
  way, so `tine price` on a saved run would have billed a roll-up a second time.
  The real kind is now carried as an additive `v3_kind` field (absent for every
  other step, so existing artifacts re-serialize byte for byte) and is what
  pricing reads.
- **DeepSeek peak pricing excludes Chinese public holidays.** "Peak hours are
  01:00 - 04:00 and 06:00 - 10:00 UTC, Monday through Friday, excluding Chinese
  public holidays." The 2026 weekday holidays (09-25 and 10-01 through 10-07)
  are carved out as flat off-peak cards; every peak hour falls on the same
  Beijing calendar day, so the split is exact.

### Added

- **Catalog refresh, 85 -> 122 cards.** Anthropic: `claude-opus-5-5` (cache
  read $0.20, fast mode 2x), `claude-sonnet-5-5` (cache read cut from $0.20 to
  $0.10 on 2026-10-07, carded as two date-scoped cards), `claude-haiku-5-5`
  (5x on every dimension for prompts over 100,000 tokens, counting cache reads
  and writes), `claude-mythos-5-1`, `claude-mythos-5`, and the previously
  uncarded `claude-sonnet-4-6`. OpenAI: `gpt-6.1-sol` (the whole GPT-6.1 series;
  cached input 5% of input, Ultrafast 6x), `gpt-6-sol` and `gpt-6-luna`.
  Google: `gemini-3.8-flash` (introductory price through 2026-12-31). xAI:
  `grok-4.7`. DeepSeek: `deepseek-flash` (V4.1-Flash, from 04:00 UTC on
  2026-09-10), which also prices the retired `deepseek-v4-flash` and
  `deepseek-v4-flash-vision-exp` names ("billed at the Flash price"). Qwen:
  `qwen3.8-2.4t-a95b`, `qwen3.8-max-0902` (alias `qwen3.8-max-2026-09-02`) and
  `qwen3.8-omni-flash`. GLM: `glm-5.3`, `glm-5.3-flash` (with its 50% launch
  promotion through 2026-09-09) and `glm-5.3-flashx`. Together: DeepSeek
  V4.1-Flash, V4-Pro-0813 and V4-Flash-0731, GLM-5.3 and 5.3-Flash, Kimi-K3,
  and the 2026-09-22 Qwen3.7-Max price cut. Groq: `qwen/qwen3.8-27b`.
- **Kimi K3 cache writes.** Kimi now bills cache writes separately (5-minute
  TTL $3.00, 1-hour $6.00) and reports them as
  `prompt_tokens_details.cache_write_tokens`; the card had no rate for them, so
  every K3 call that wrote cache priced as `partial`.
- **Corrections to existing cards.** Opus 4.8 gains its published fast-mode
  modifier; GPT-6 Astra gains Ultrafast (6x) and `priority`, which OpenAI
  renamed to Fast mode and serves as Fast; Grok 4.6 gains its 2x priority
  modifier; `gemini-3.1-pro-preview-customtools` aliases Gemini 3.1 Pro.
- **`deepseek-flash` is recognized as a thinking model**, and DeepSeek and Kimi
  join the providers that request streamed usage; both document
  `stream_options.include_usage`. The provider-level default set is exactly
  `deepseek`, `glm`, `glm-cn`, `kimi`, `openai`, `openai-compatible`, `qwen`,
  and `xai`; membership still requires positive evidence that the endpoint
  accepts the field.

### Changed

- **OpenTelemetry export speaks the current GenAI conventions.** Spans carry
  `input_tokens` / `output_tokens` totals that include the
  `cache_read.input_tokens`, `cache_creation.input_tokens` and
  `reasoning.output_tokens` sub-counts written beside them, so Langfuse, Phoenix
  and any other reader see every token a step consumed (the exclusive totals
  exported through 0.8.1 under-reported a cached call's input), and
  `gen_ai.provider.name` beside `gen_ai.system`. What no convention spells -- the
  1-hour cache-write TTL, a dimension like `input_audio` -- rides exactly in an
  `opentine.usage` attribute, written only when the standard counters cannot
  carry the usage back. Re-importing an export reproduces its usage exactly, and
  a span imported from elsewhere still re-exports with the attributes it came
  with. OpenTine 0.8.1 and earlier read these newer exports' inclusive totals as
  fresh input.
- **Adapter defaults move to each vendor's current model**: `OpenAI()` ->
  `gpt-6.1-sol`, `Anthropic()` -> `claude-sonnet-5-5`, `Google()` ->
  `gemini-3.8-flash`, `Grok()` -> `grok-4.7`, `GLM()` -> `glm-5.3`, `Qwen()` ->
  `qwen3.8-max`, `DeepSeek()` -> `deepseek-flash`. Passing a model name
  explicitly is unaffected.

### Removed

- **Aliases and modifiers a vendor no longer publishes.** `grok-latest` no
  longer aliases `grok-4.3` (no xAI page maps it there any more, and a run
  recorded under it now reports `unknown` instead of grok-4.3's rates).
  `gpt-5.6-cyber` loses its batch, flex, fast and priority modifiers: OpenAI
  publishes no tier price for it, so a tiered call stays visibly `unknown`.
  Cards for retired models are closed: `deepseek-v4-flash` and its vision
  variant (2026-09-09), `kimi-k2.5` (2026-08-31), and the Together listings
  removed from serverless.

### Held

- **Not carded, deliberately.** `mistral-large-4` (a launch sale with no
  published end date, and conflicting cache prices), Together's Kimi-K3
  promotion (undocumented start, conflicting cached rate; that window prices
  `unknown`), `glm-cn` (bigmodel.cn publishes CNY only), the historical
  Together Qwen3.7-Max rate, and `gpt-rosalind-research` (trusted access, no
  published long-context or tier rules).

## 0.8.1 — 2026-09-04

### Added

- **Catalog refresh (source-confirmed), 79 -> 85 cards.** `claude-fable-5-1`
  (input $10, cache read **$0.25**, 5m write $12.50, 1h write $20, output $50;
  batch 0.5x, US inference 1.1x, no fast mode), `gpt-6-astra` (input $10, cached
  input $1, cache writes $12.50, output $50; >272K input reprices the whole
  request at 2x input/cache and 1.5x output; batch/flex 0.5x, fast 2x),
  `qwen3.8-27b` and `qwen3.8-flash` on the Model Studio international endpoint
  (both with implicit and explicit cache tiers), and two `deepseek-v4-flash-vision-exp`
  cards carrying the V4-Flash rates and the platform peak/off-peak schedule
  across the 2026-08-23 weekend-rule change. `qwen3.8-max` re-verified unchanged.
- **`glm-cn` misses say why they are unpriced.** A billing miss on the GLM China
  endpoint now warns that the public catalog cards only the international z.ai
  provider and points at a local overlay. Status stays `unknown` and no amount is
  invented, so completeness gates behave exactly as before.

### Held

- **`qwen3.8-flash-next` is not carded and not aliased.** Its QwenCloud model page
  returns HTTP 404 and the model is open-weight only; the hosted, priced model is
  the distinct `qwen3.8-flash`. Runs against it report cost `unknown` until a
  local overlay supplies a price.

## 0.8.0 — 2026-08-22

The Model-Agnostic Core. OpenTine records `(provider, model, usage)` as opaque
data, and cost is now a **post-hoc function of that record** — a signed catalog
turns it into dollars, after the fact, for any run, native or imported. The model
layer is an optional capture convenience; the OpenTelemetry importer is the
universal, model-agnostic on-ramp that needs no adapter and no rate card. Stored
data stays readable: every artifact and repository written by 0.3.0 through 0.7.2
still loads.

### Added

- **`provider` is a recorded field.** Every step records its provider alongside
  model and usage; imported OTel runs read it from `gen_ai.system` /
  `gen_ai.provider.name`, so a run's identity survives independent of how it was
  captured. It is opaque recorded content — verify, fork, diff, and replay never
  branch on it — and additive: pre-0.8.0 artifacts load with an empty provider and
  re-serialize byte-identically.
- **`tine price` — cost after the fact.** Recompute a run's cost from the catalog
  (optionally as of a past date with `--at`), distinct from `tine cost`, which
  sums the cost recorded at capture. It prices imported and uncosted runs that
  `tine cost` shows as `$0`, carrying the catalog's status through verbatim — an
  uncarded step, a step with no provider, and a step that recorded no usage each
  report `unknown`, never a fabricated `$0`. `tine import --price` bakes catalog
  prices into an OTel import before anything is written.
- **Time-of-day pricing (`opentine-pricing/2`).** Rate cards can carry a
  peak/off-peak schedule (UTC hour windows + a weekday/weekend scope); DeepSeek V4
  is priced correctly again after it moved to peak/off-peak billing. Additive —
  every other card prices identically, and `/1` catalogs and overlays still load.
- **Local model servers are one command away.** vLLM, LM Studio, SGLang, TGI,
  LiteLLM, MLX-LM, NVIDIA NIM, TensorRT-LLM, KoboldCpp, Jan, LocalAI, Unsloth, and
  llama.cpp are now `tine run --model <name>`-nameable (16 → 30 providers), each
  at its conventional localhost URL, recorded unmetered like Ollama.

### Changed

- `provider` is surfaced in `--json` step views and `tine diff`. The README and
  concepts docs state the model-agnostic core outright and document `models/` as
  the optional capture convenience beside OTel as the universal on-ramp.

## 0.7.2 — 2026-08-17

The catalog &amp; trace patch. Source-confirmed pricing refresh, and the last OTel
round-trip data-loss path closed.

### Fixed

- **OTel round-trip preserves cost and billing.** A natively-priced run exported
  to OpenTelemetry and re-imported reported `$0.00` — the importer dropped the
  typed cost/billing the exporter had written (a writer/reader asymmetry). Both
  now round-trip exactly, the amount as its exact decimal string; a foreign span
  without them imports unpriced (never a fabricated amount), and unusable values
  stay visible in attributes. Guarded by the round-trip parity gate.

### Changed

- **Pricing catalog refreshed (61 → 75 cards), every rate confirmed from the
  vendor's official page.** Added `claude-opus-5` (the current flagship, before
  now uncarded), `claude-haiku-4.5`, `qwen3.8-max`, `gemini-3.7`/`3.6-flash`
  (promo-scoped), `gemini-3.5-flash-lite`, `ministral-3b`/`8b`, `codestral`,
  `gpt-5.6-cyber`, and `grok-build-0.1`. Repriced (date-scoped) the three
  `gpt-5.6-*` models. Removed the future-dated `claude-sonnet-5` card after
  Anthropic cancelled the scheduled September 1 increase — `$2/$10` is now
  permanent. Closed the DeepSeek V4 cards, which moved to a time-of-day peak/
  off-peak schedule the `opentine-pricing/1` schema cannot represent; those runs
  report `unknown` until a future release adds the dimension. No guessed prices;
  `qwen3.8-27b` and `glm-5.3` are held for lack of a published per-token price.

## 0.7.1 — 2026-08-17

The Hardening Release. A codebase health audit — every finding verified against
the working tree — surfaced two credential leaks, two false-attestation paths,
and three silent data-loss paths: the exact failure classes a provenance tool
cannot ship. All are fixed, and a new round-trip parity gate guards the recurring
writer/reader-asymmetry shape they shared. Stored data stays readable: every
artifact and repository written by 0.3.0 through 0.7.0 still loads, and every
genuine `tine-sig/1` signature still verifies byte-identically.

### Fixed

- **Redaction no longer leaks a quoted credential.** A quoted secret
  (`api_key: "…"`, `password = '…'`) walked out from under the `[REDACTED]`
  marker into the content-addressed store, remotes, and MCP responses. Quoted
  values are now redacted inside their quotes (a JSON body stays parseable), and
  the scan stays linear.
- **`inspect` / MCP no longer serves the unredacted legacy blob.** The one body
  stored `redact=False` — the v2 migration blob, which may still hold
  credentials — was rendered verbatim to any model that named its object id,
  directly or aliased under another `*_blob` key. Every served body is scrubbed
  now; `Repo.raw`, which no MCP tool exposes, still yields byte-exact bytes for
  deliberate review.
- **A re-saved migrated run drops its stale legacy attestation.** `_put_run`
  carried the five v2-migration fields forward from a run's stored payload, so a
  loaded-then-modified run kept claiming `legacy_verification.signature` over
  bytes it no longer matched. Both writers now share one field list and drop it
  unless the save re-attaches the legacy bytes.
- **Signatures now cover metadata tags (`tine-sig/2`).** Under `tine-sig/1` a
  signed artifact's `metadata.tags` (and any metadata key outside the allowlist)
  could be rewritten and the signature still verified. New signatures are written
  at `tine-sig/2`, which signs every metadata key except `integrity`.
  `tine-sig/1` is verified unchanged, so every 0.3.0–0.7.0 signature keeps
  verifying. Narrowing the integrity digest's metadata exclusion is deferred to a
  future format-version bump (the digest is a consistency check, not an
  authenticity claim — authenticity now comes from the signature).
- **`tine export` refuses rather than truncating deep content.** Export reused
  the import-path depth coercion, silently replacing content past a depth bound
  with `[MAX_DEPTH]`/`[CIRCULAR]` and exiting 0. It now serializes faithfully up
  to the format's legal depth and exits non-zero — writing no file — beyond it.
  The lenient truncation stays on the untrusted-import path only.
- **OTel import keeps the structured conversation.** A span carrying both classic
  `gen_ai.prompt`/`completion` scalars and 1.36 structured `*.messages` dropped
  the conversation (system prompt and full turn list) when the scalar won. The
  modern content is now preserved and an import warning is recorded when the two
  shapes disagree; this package's own export stays a round-trip fixed point.
- **`causal_ids` survive a `.tine` round trip.** A v3 repository run exported to
  `.tine` and reloaded dropped its causal edges, silently shrinking every later
  fork slice. `causal_ids` now round-trips (additive — emitted only when
  present, so pre-existing artifacts are byte-identical and older files load with
  none).
- **The shell tool stops leaking credentials to a subprocess.** With
  `inherit_env`, the shell tool handed the whole environment — API keys included
  — to the subprocess and its output back into model context. It now scrubs
  `KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH` names from the same shared helper
  the python tool has always used.
- **`tine run --save` no longer silently overwrites.** `tine run` gains
  `--force` and refuses an existing `--save` destination without it, like every
  other artifact-writing verb. The run-id-keyed default location stays unguarded.

### Added

- **Round-trip parity gate.** A permanent release test asserting full-fidelity
  `repo → .tine → repo` and `export → import` round trips on a run exercising
  every step kind, a fork, distinct causal edges, usage/billing, and
  tags/metadata — the standing catcher for the writer/reader-asymmetry bug class.

## 0.7.0 — 2026-08-16

The Interop & Adoption Release. OpenTine stops being a silo: a recorded run now
ships to any OpenTelemetry backend in one command, a first capture no longer
requires writing Python, and the v3 repository — the headline of 0.6.0 — finally
has a runnable on-ramp and real getting-started docs. Stored data stays readable:
every artifact and repository written by 0.3.0 through 0.6.0 still loads.

### Added

- **`tine export` — ship a run to the OpenTelemetry ecosystem.** `tine export
  <run>` renders a recorded run as an OTLP/JSON GenAI document to stdout or
  `--output PATH`, or POSTs it to an OTLP/HTTP collector (`--endpoint`, or
  `$OTEL_EXPORTER_OTLP_ENDPOINT` under `--format otlp`). It reuses the exact
  exporter the `otel-json` importer inverts, so a run exported and re-imported is
  the run that was exported. A cleartext push is refused unless the endpoint is a
  loopback IP or `--allow-insecure`; a connection failure or non-2xx exits 1,
  never a silent drop.
- **Complete, modern OTel export.** The exporter now emits semconv 1.36 structured
  `gen_ai.input/output.messages` beside the 1.27 attributes (so Arize Phoenix and
  Langfuse render rich content), every usage dimension (cache, reasoning, total —
  not just input/output), a scope `schemaUrl`, and per-event span kinds. The
  event-level round-trip still holds exactly, and usage now survives it verbatim.
- **No-code first run: `tine run --model <provider>[:model] --prompt`.** Capture a
  run against any bundled adapter without writing a Python script — sixteen
  providers (the native four plus the hosted-compatible set, read off the adapters
  so a new one is nameable for free). `provider:model` splits on the first colon;
  no provider SDK is imported until one is named.
- **One `--json` contract.** `tine pricing` gains `--json` on `list`, `check`, and
  `update` (all four subverbs scriptable through one writer); `tine export`, the
  run receipt, and every JSON path share a single serializer, so a collector and a
  file cannot receive different bytes. The five v3 plumbing verbs (`fsck`,
  `object`, `migrate-v3`, `fetch`, `push`) stay bare-JSON by design, now documented
  as such, and the README's subcommand count is pinned to the router by a meta-test.
- **Adoption docs and runnable v3 examples.** `docs/GETTING_STARTED.md`,
  `docs/CAPTURE.md`, `docs/CONCEPTS.md`, `docs/API.md`, and `CONTRIBUTING.md`, plus
  `examples/v3_repository.py` and `examples/otel_interop.py` — executed in-process
  by a smoke test so they cannot rot. Every documented command is parse-verified
  against the real CLI.
- **New-model pricing.** A verified rate card for xAI `grok-4.6` (with its
  ≥200k-prompt 2× tier), and `Grok` now defaults to it. Kimi K3 re-verified
  unchanged. GLM 5.3 is intentionally left unpriced — it is announced but its
  per-token API is not yet published — so it runs and reports `unknown` cost until
  a real rate exists.

## 0.6.0 — 2026-08-01

The Surface Release. The v3 provenance engines that shipped only as MCP tools —
semantic diff, search, attestation, evaluation, promotion, fork and resume — are
now human CLI verbs, so an operator at a terminal, and CI, can drive what only an
agent could before. Deterministic replay becomes a checkable gate and cross-run
statistics land. Stored data stays readable: every artifact and repository
written by 0.3.0, 0.4.0, and 0.5.0 still loads, gated by golden fixtures for all
three.

### Added

- **The v3 repository engines are now CLI verbs.** `repo-show`, `repo-log --json`,
  and `context` read a run, its object log, and a minimal causal slice;
  `repo-diff` (with `--exit-code`) and `repo-search` expose the semantic-diff and
  search engines; `attest`, `evaluate`, and `promote` append an attestation, an
  evaluation, or a promotion; `repo-fork` and `repo-resume` branch and continue a
  v3 run. Each mirrors the MCP tool it shares an engine with, and a parity
  meta-test keeps the two in lockstep — pinning the deliberate divergences
  (`promote` is an unconditional operator verb on the CLI though MCP gates it
  behind `allow_promotion`; the CLI is not confined to `experiments/*`, whose
  threat model is model-controlled input rather than an operator). The read verbs
  are read-only; the mutating verbs append objects exactly as the MCP path does,
  preserve the expect-absent CAS on a promotion (moving one needs
  `--expected-old`; there is no `--force`), and never emit a `--json` object on a
  failed write. Every verb has a stable `--json` object through one writer, and
  attacker-controlled recorded content is terminal-escaped on the human path.
- **`tine diff` gains `--json` and `--exit-code`.** The legacy diff verb becomes
  scriptable, with git-diff exit semantics (0 identical / 1 differs / never 2)
  and a drift object literally the same shape `replay --verify` reports. The
  default invocation is byte-identical.
- **`tine stats`.** Cross-run aggregation over the local `.tine_runs` index — run
  and step counts, cost total/mean/max, distinct models, tag and format-version
  histograms — grouped (`--group-by model|status|tag|day|format-version`) and
  filtered exactly like `tine ls`. Token and duration figures are *absent* unless
  `--deep` loads each run; "not collected" is never a silent zero that would sum
  with real costs.
- **Top-level re-exports and more `--json`.** Thirteen diff/query/signing names
  (`RunDiff`, `Graph`, `Query`, `parse_query`, `sign_artifact`, `verify_artifact`,
  …) are now importable straight from `opentine`, and `tine import` and `tine tag`
  gain `--json`.
- **`tine replay <run> --verify`.** Deterministic replay was an asserted
  property; it is now a check with an exit status, so CI can gate on it. The
  check is deliberately not an in-memory one — `Run.fork` deep-copies, so
  diffing a fork against its source always passes and proves nothing. Instead
  the replay is saved to a *temporary* path and loaded back, the replay is
  derived a second time from the source file, and the two must agree on the
  64-hex run id, on the retained slice, on the canonical digest of the
  round-tripped artifact (`Run.verify_integrity`), and on every structural
  field. Exit status is binary: **0** reproduced, **1** drift or a source that
  will not load (argparse keeps 2). `--ignore-cost-drift` downgrades an
  accounting-only difference — the cost/usage/billing bucket `tine diff`
  already reports separately — to a pass; structural drift always fails.
  `--json` emits one documented object (`command: "replay-verify"`) through the
  same single writer as the other `--json` commands. A source that does not
  load produces no verdict, so it is a human message and never JSON.
- **`--verify` with `--harness`** re-executes the run **twice** over one
  context and compares the two saved artifacts: the real nondeterminism gate
  for an external agent. Cache-mode verification, which spawns nothing, is the
  default CI gate.

### Fixed

- **`tine replay --inspect` / `--dry-run` previewed the wrong steps.**
  Inspection listed the *descendant* closure of `--from-step` while a replay
  retains the *ancestor* closure, so on any branched run the preview was the
  complement of what the replay reuses; on a linear run the two agreed by
  accident. Preview, verification verdict, and `Run.fork` now read one helper
  (`retained_closure`), and inspection prints the matching `would reuse N
  recorded steps` count.
- **`tine fork` / `replay --harness` recorded the wrong causal context.** The
  same descendant-vs-ancestor slip, in a second place: `_run_context` fed a
  fork/rerun the *descendant* closure of the fork point (the discarded future)
  instead of the *ancestor* closure it keeps, so a forked run's recorded context
  cited steps its own graph does not contain — a silent provenance defect. It now
  shares the one `retained_closure` helper `fork` and `replay --verify` use, and
  `replay --verify --harness` gained the slice check that catches a regression.

### Changed

- `tine replay --verify` writes nothing under `.tine_runs/` unless `--save`
  names a destination — the always-write paths of a plain replay are
  conditional under `--verify`. With `--save` the verified bytes are copied out
  and the existing refusal to overwrite without `--force` still applies. The
  temporary workspace is removed on every path, failures included.
- `--json` and `--ignore-cost-drift` are refused, not ignored, when the chosen
  replay mode cannot honour them (`--json` without `--verify`, either of them
  with `--inspect`/`--dry-run`), matching the refusal rule the other commands
  already follow.

### Known divergence

- A cached replay from the CLI carries the *source's* status, while
  `Agent.replay(mode="cache")` (`HistoryMixin.replay`) marks its result
  `completed`. `--verify` checks the CLI's artifact and therefore pins the CLI
  behaviour. This is documented, not changed, in 0.6.0; reconciling the two is
  a 0.7.0 change.

### Compatibility

- No format change. `--verify` runs over the committed v0.3.0 / v0.4.0 / v0.5.0
  golden artifacts in cache mode as part of the backwards-compatibility gate.

## 0.5.0 — 2026-07-31

The Ecosystem Release. OpenTine is now a *source* of OpenTelemetry GenAI
provenance as well as a sink, its interop is usable from the shell and in CI, and
it can record a LangChain/LangGraph run as it happens instead of only after the
fact. Stored data stays readable: every artifact and repository written by 0.3.0
and 0.4.0 still loads, now proven by a golden-fixture gate covering both.

### Added

- **OpenTelemetry GenAI export.** `opentine.to_otel_genai` /
  `to_otel_genai_document` render any run — a v2 `Run`, a loaded `.tine` file, a
  v3 repository run, or `TraceEvent`s — as GenAI spans in the exact shape the
  importer consumes, and as a complete OTLP/JSON document, so a verified run can
  be shipped to whatever observability backend runs beside it. Import and export
  are inverses; both spell their `gen_ai.*` keys through one module so the two
  halves cannot drift.
- **`tine import` and `--json`.** `tine import` brings the existing importers to
  the shell — OTel GenAI (spans / OTLP-JSON), OpenTine JSONL, and LangChain /
  LlamaIndex / AutoGen / CrewAI / OpenAI-Agents logs — writing a portable `.tine`
  artifact (`--save`) and/or a v3 repository ref (`--repo`). `--json` on `show`,
  `verify`, `ls`, `search`, and `cost` emits one stable, documented
  machine-readable object; the rich human rendering stays the default.
- **Modern OpenTelemetry content on import.** The OTel importer now reads content
  from the shapes current instrumentations emit — span events / log records
  (`gen_ai.*.message`, `gen_ai.choice`), structured `gen_ai.input`/`output.messages`
  (including the JSON-string form real SDKs serialize into an attribute), and the
  flattened OpenLLMetry and OpenInference conventions — so those runs no longer
  import with empty inputs and outputs. The classic `gen_ai.prompt`/`completion`
  path is unchanged and still wins.
- **Live LangChain / LangGraph capture.**
  `opentine.integrations.langchain.OpenTineCallbackHandler` records a run as it
  happens through langchain-core's callback protocol, which LangChain and
  LangGraph both drive, materializing the same `TraceEvent` / `Recorder` path the
  importers use. Optional (`opentine[langchain]`) and import-safe: `import
  opentine` never pulls in langchain. CrewAI is deliberately deferred rather than
  guessed at; its logs still import post hoc.
- **`py.typed`.** OpenTine ships the PEP 561 marker, so type checkers see the
  public API's annotations.

### Compatibility

- Backwards compatibility of stored data is now gated for both prior releases:
  the cross-version suite loads golden `.tine` artifacts and a v3 repository
  generated by the published 0.3.0 **and** 0.4.0 and asserts the current build
  still reads and verifies them. A reusable, deterministic generator produces
  each release's golden set from its published wheel.
- Everything above is additive. Nothing changes what OpenTine writes; export and
  the importers are read-only over provenance and introduce no new artifact or
  repository format version. The `langchain` dependency is an optional extra only.

## 0.4.0 — 2026-07-31

Fork-act identity for portable `*.tine` files, so divergent forks no longer
collide. Stored data stays readable: every artifact written by 0.3.0 still
loads under 0.4.0, and its fork IDs are unchanged.

### Changed — BREAKING (v2 fork identity)

A v2 fork ID now identifies the *fork act*, not just its `(parent, fork point)`
coordinate. `Run.fork` derives the ID from the source lineage, the retained
slice, the branch, the caller's declared intent, and a recorded 128-bit random
nonce, and records that basis in `metadata.fork` so any fork can prove its own
ID with `verify_fork_id`. Because `metadata` sits outside the integrity digest
— which does cover the top-level `run_id` — the ID itself, not the stored
record, is the commitment to the basis.

- Forking the same run at the same point twice now yields two **distinct** runs.
  Previously both derived one ID and one filename: through the CLI the second
  fork was refused, through MCP it raised `FileExistsError`, and through the
  plain library `Run.save` the second write **silently destroyed the first**.
  Runs lost that way before 0.4.0 cannot be recovered.
- `branch=` and the MCP fork `reason` now affect identity. Previously neither
  did — `branch` never entered the ID, and `reason` was attached only after the
  ID was formed.
- `Agent.replay`, `Agent.resume`, and rerun no longer splice the parent run ID
  into the new ID (the former `<parent id>-replay` / `-resume` / `-rerun`
  names), which concatenated untrusted artifact text into a run ID.
- Cached replay stays deterministic: it reuses recorded steps and produces
  nothing new, so it forks with `nonce=""` — replaying twice yields one ID and
  the existing overwrite refusal still applies. `Run.fork(..., nonce="")` opts
  any fork into the same reproducibility.
- v3 repository IDs are unchanged and remain content-addressed hashes; identical
  v3 forks still dedupe.

This is breaking for fork ID **values** only, and only for callers that hardcode
a fork's ID or filename. It does not affect data readability: there is no
`format_version` bump, 0.3.0 artifacts load unchanged and keep their IDs, and
`verify_fork_id` returns `None` (never `False`) for any pre-0.4.0 fork, so the
new check never accuses old provenance of tampering.

Migration: use the returned `Run.id`, the MCP `new_run_id`, or `--save` rather
than recomputing a fork's filename. `Run.fork(new_run_id=...)` still reproduces
any legacy ID exactly.

### Fixed

- The MCP `fork_run` tool could not fork the same point twice — a dead end in
  the headline feature, because it always writes the default `<id>.tine` path
  and the second fork's colliding ID raised `FileExistsError`. It now succeeds,
  without adding any force escape and without weakening the overwrite refusal on
  explicitly named destinations.
- `metadata.fork`, the fork-identity record, is now covered by artifact
  signatures, so tampering with a fork's recorded basis breaks its signature.
  `metadata.fork_reason` is deliberately left unsigned: 0.3.0 emits it but did
  not sign it, so signing it now would flip a genuine 0.3.0 signature to a
  false mismatch.
- A v3 repository committed to version control or archived — which drops its
  empty directories (`packs/`, `indexes/`, `logs/`, the empty `refs/*`
  namespaces) — now opens intact. `Repo.open` recreates the layout, best-effort
  so read-only media still opens for reading, and `fsck` treats a missing
  `packs/` as empty rather than reporting a healthy repository as corrupt.

### Compatibility

Backwards compatibility of stored data is now a tested release gate. A
cross-version suite loads golden `*.tine` artifacts and a v3 repository
generated by each supported prior release — starting with the published
0.3.0 — and asserts the current build still loads, reads, and verifies every
one. From 0.3.0 on, a newer opentine is committed to reading what an older one
wrote; each release adds its own golden fixtures so the guarantee is proven,
not assumed.

## 0.3.0 — 2026-07-30

Git-shaped repository foundation for agent runs. Portable `*.tine` files remain
v2; repository objects use the new verified v3 format.

### Added

- Dependency-free trusted semantic kernel (≤250 physical lines) with RFC 8785
  canonical JSON, raw blobs, typed SHA-256 IDs, immutable envelopes, typed
  parent/causal links, verification, and a minimal repository protocol.
- `.tine/` object storage, refs/reflogs, CAS ref updates, semantic log/diff,
  fork, causal context slices, deep `fsck`, deterministic packs, shallow
  boundaries, missing-object negotiation, fetch/push, and clone.
- `blob`, `event`, `run`, `attestation`, and separately versioned `annotation`
  objects. Redaction occurs before canonicalization and hashing.
- V2 migration that retains the exact legacy bytes and original verification
  result, recomputes v3 identities, stores a deterministic ID map, and scopes
  the legacy signature to the legacy blob only.
- Normalized native/JSONL/OpenTelemetry/framework trace importers and a live
  `Recorder` workflow for record, resume, fork, evaluate, approve, and promote.
- Python and MCP search, inspect, minimal context, semantic diff, fork/resume,
  evaluation, attestation, and promotion operations.
- Minimal self-hosted HTTP remote with discovery, filtered/shallow fetch,
  bounded pack download, resumable pack upload, tenant-scoped RBAC, static-token/OIDC seams,
  encrypted filesystem objects, SQLite metadata, hash-chained audit records, and
  pluggable storage/index/identity/authz/key/audit/retention/admission policies.
- CLI commands: `init`, `fsck`, `repo-log`, `object`, `pack`, `migrate-v3`,
  `fetch`, `push`, `clone`, and `serve`.

### Added (provider and harness coverage)

- GLM (both the international and China endpoints) now requests usage
  accounting on streams. It previously sent no `stream_options.include_usage`,
  so a streamed call returned no token counts and priced as `unknown` —
  reporting $0.00 for real spend. The provider-level default set is exactly
  `glm`, `glm-cn`, `openai`, `openai-compatible`, `qwen`, and `xai`;
  membership requires positive evidence that the endpoint accepts the field,
  because Mistral rejects it with HTTP 422 and a wrong entry breaks streaming
  outright. Groq, Kimi, DeepSeek and OpenRouter opt in at the adapter level.
  Together, Mistral, Ministral and Hermes do not send the field: their
  streamed calls still price as `unknown` unless the provider reports usage
  anyway or the deployment passes `include_usage=True`.
- `tine pricing update` installs to the path the loader actually reads. It
  hard-coded `~/.config` while `load_catalogs` honours `XDG_CONFIG_HOME`, so
  under a non-default config home the update reported success and changed no
  prices.
- Harness presets are table-driven (`opentine/harnesses/_presets.py`), so
  supporting another terminal agent costs one row rather than a subclass. Adds
  `grok` (xAI Grok Build, `grok exec`) and `gemini` (Gemini CLI, `gemini -p`).
- `docs/pricing-overlay-claude-5.json` prices `claude-opus-5`,
  `claude-mythos-5`, and `claude-haiku-4-5` ahead of the next signed catalog
  release; see PRICING.md.

### Fixed (first release audit)

- An OIDC token carrying no roles claim now grants no roles instead of silently
  defaulting to `reader`. A misconfigured issuer, or one that stops emitting the
  claim, previously conferred read access to every run in the tenant. Operators
  who relied on the old behaviour can pass `default_roles=("reader",)`.
- The remote's SQLite metadata database and its WAL/shm siblings are created
  `0600`. sqlite3 applied the process umask — typically world-readable — while
  every other file the server writes was already hardened.
- `tine keygen --out` refuses to overwrite an existing key file without
  `--force`, and `tine sign --save` refuses to overwrite its destination
  without `--overwrite` (`sign` keeps `--force` for "sign despite a failed
  integrity check"). Clobbering a private key destroys the only copy of a
  signing identity and makes every artifact it signed unverifiable.
- `tine ls`, `tine search`, and `tine reindex` report an over-cap runs directory
  as an error naming the limit and the directory, rather than an interpreter
  traceback.
- An effective-date string honours its UTC offset. Truncating to the first ten
  characters dropped it, so a timestamp already into the next day in UTC resolved
  to the previous day's rate card.
- Free-text cost scraping requires a currency marker, so an agent writing
  "cost: 500" about an approach it was weighing no longer books $500 to the run.
- Credential redaction no longer leaks on two common shapes. A v2 assignment
  whose value contains a colon (`api_key=sk-proj:abc`) was split on the colon,
  which buried the credential name in the label and stored the secret in
  cleartext; the separator is now chosen by position. In v3 blobs, a credential
  preceded by a dash — a `git diff` removal line for a `.env` file, or a captured
  `--api-key=…` argv — was never matched. Name matching stays linear.
- A run long enough to save is again long enough to load. The reader enforced a
  fixed structural-token cap that the writer did not, so runs of roughly 20k
  steps were persisted and then permanently unreadable. The bound now scales with
  artifact size, keeping the container-amplification guard intact.
- Updating a ref no longer stages through a filename that is another ref's guard
  lock (`x` staged as `x.new.lock`, which is ref `x.new`'s lock). The old name
  made a sibling update fail, then deleted the lock a live writer still held,
  defeating the compare-and-swap.
- `tine migrate-v3` reports its fail-closed refusal on a tampered artifact as an
  error instead of an unhandled traceback.
- `inspect(resolve_blobs=True)` no longer auto-resolves `legacy_blob`, the one
  deliberately unredacted blob, which the MCP `inspect_object` tool returned to a
  model by default. It remains reachable by its own object id.
- MCP `fork_run_v3`/`resume_run_v3` may only write `experiments/*`. Their ref
  update is an unconditional overwrite, so mainline, promotion, tag and
  remote-tracking refs are no longer reachable from untrusted run content.
- Harness-reported `duration_ms` is converted to seconds rather than stored
  verbatim, which inflated durations 1000x and could trip a duration budget.
- `tine tag` warns when re-saving removes a signature; `SECURITY_MODEL.md` no
  longer implies the signature survives an ordinary edit.
- The OpenRouter adapter requests usage accounting; because it is priced from
  provider-reported cost with no rate-card fallback, streamed calls previously
  always reported `unknown` and $0.00.
- Adapter billing tests derive the expected charge from the effective rate card
  instead of freezing a promotional rate that expired on 2026-07-23.

### Fixed (post-audit hardening)

- Billing arithmetic now runs in a fixed Decimal context, independent of caller
  precision, rounding, or traps. Compatibility totals accumulate exact pinned
  subtotals, terminal model calls cannot escape budget enforcement, and tool
  latency contributes to wall-duration budgets.
- Provider accounting now handles xAI's exclusive reasoning tokens, cumulative
  stream usage, exact charged-cost ticks, and observed Priority tier; OpenRouter
  reported account/upstream costs; Groq final stream usage; Anthropic thinking
  tokens; OpenAI cache writes and observed Priority tier; canonical model aliases;
  and top-level/nullable cache counters without silently claiming completeness.
- The first public catalog trust anchor is the retained `r3` key; unpublished
  pre-release `r1`/`r2` keys with no durable custody were retired. The snapshot
  ends stale DeepSeek alias pricing when V4 launched and prices Mistral reasoning
  at its documented output rate.
- Deep graphs use iterative ancestry and fixed-size structural diff keys. CLI
  rendering strips terminal control sequences, cached replay cannot derive paths
  from artifact IDs, filesystem tools reject special files, trace payload types
  fail before storage, and DuckDuckGo HTML parsing is linear and bounded.

- Canonical JSON now rejects integers beyond the exactly representable range
  (±(2**53−1)) instead of silently coercing them to a float, which could collide
  two distinct values onto one object id and corrupt stored values.
- Pack transfer and decompression are bounded (maximum 256 MiB), reject trailing
  compressed data, and stream client downloads under the same cap, so a zlib bomb
  from an untrusted remote or authenticated writer cannot grow memory without
  bound. The reference server limits individual requests to 16 MiB, caps resumed
  packs separately, bounds worker concurrency, and applies inactivity plus absolute
  request timeouts.
- Repository JSON CLI commands (`fsck`, `object`, `migrate-v3`, `fetch`, `push`)
  emit plain JSON; the shared console no longer forces ANSI color, so piped or
  redirected output is machine-readable and honors `NO_COLOR`.
- Local CAS ref updates take an exclusive lock, making the compare-and-swap
  atomic (no lost updates) and directory writes are fsynced for durability.
- V2 migration is fail-closed: a source that fails integrity (or a requested
  signature) is refused unless `--allow-unverified` / `strict=False` is passed.
- Object envelope headers are bound to exactly `{encoding, schema, type}`, and
  `Run.save` to a repository target rejects `.tine` signing/draft options rather
  than silently ignoring them.
- Audit rows use a serialized HMAC chain and authenticated external head;
  startup and `verify_audit_chain` detect modification, reordering, and
  truncation. Legacy rows require explicit trust-on-migration and remain marked
  unverified. Repository read operations are audited; verification itself is read-only.
- OIDC ships a real `JWTVerifier` with RS256/ES256 algorithm/key binding, JWKS,
  issuer/audience/authorized-party/time validation, critical-header rejection,
  and bounded discovery documents.
- Credential redaction catches vendor-prefixed and header-style key names
  (`OPENAI_API_KEY`, `x-api-key`, …) while preserving numeric usage counters.
- The OTel importer parses extracted spans or complete OTLP/JSON exports
  (camelCase/snake_case keys and typed `AnyValue` attributes); JSONL/framework
  importers accept ISO-8601 timestamps and
  list-shaped messages without crashing or corrupting data.
- Billing: tiered context multipliers apply only the highest matching tier
  (no compounding); OpenAI-compatible top-level cache tokens
  (`prompt_cache_hit_tokens`) are billed at the cache rate, not as fresh input.
- All client control-plane JSON is streamed under a 1 MiB raw-byte cap and
  non-identity content encodings are rejected, with a wall-clock deadline that
  includes response headers. Resumable upload offsets must advance, loops are
  bounded, upload IDs are validated, staging uses encrypted tenant-bound frames
  plus private POSIX modes, per-upload locks are released, and stale partial
  uploads are reaped. Agent web fetches pin validated DNS answers, ignore implicit
  proxies, and enforce whole-response time and body limits.
- Raw and structured redaction covers Basic/Cookie credentials in header lines,
  arrays, pairs, and HAR-style `{name, value}` records. Large trace integers are
  string-preserved, malformed JSONL records are skipped per line, and imported
  parents/causal links are ordered before recording.
- Trace bulk import now writes one final run snapshot in linear graph work and
  preflights a 3,000-event run ceiling before writing blobs. Repository search
  and object inspection verify data under explicit object, source-byte, and
  rendered-output caps so deduplicated references cannot amplify memory use.
- Kernel errors now wrap oversized integer literals; v2 migration parses the
  verified bytes only; OIDC rejects unsupported critical headers; pack manifests
  require an integer version; repository descriptors are bounded and versioned.
- The signed catalog was reverified and rotated to a retained release key. It
  adds Kimi K3, Gemini 3.5 Flash, and GLM-5.2, maps current DeepSeek compatibility aliases
  to V4 Flash, distinguishes Gemini audio/cache dimensions and exact service
  rates, applies xAI's >200K Grok 4.5/4.3 prices, removes an unsafe `qwen-plus`
  cross-model alias, corrects Together's Llama 3.3 effective date, removes its
  deprecated Llama 3.1 cross-model alias, uses Mistral's canonical API IDs,
  splits GPT-4o's historical price transitions, and applies Anthropic's reported
  US inference geography multiplier. Qwen3.7-Max records its limited promotion,
  automatic-cache rate, and explicit cache creation/hit rates separately. Kimi
  K3 is the current default with its reasoning continuation and official
  $3/$0.30/$15 rates; Kimi Batch and Groq service tiers use exact rates, invalid provider aliases are
  removed, and tier-scoped Groq shutdown dates are recorded without suppressing
  enterprise committed-spend billing.
- Live traces retain cost and latency, causal forks retain causal ancestors, and
  semantic diff includes artifacts and evaluation scores.
- Production KMS adapters can provide external audit-key derivation and the
  reference app fails closed when neither that nor an explicit key exists.
  Audit rows commit before their authenticated anchor, one-step interrupted
  anchors heal safely, arbitrary recovery requires an exact dedicated re-anchor
  value, legacy migrations report `legacy-unverified`, and verification is
  read-only. Existing local audit-key sidecars are tightened to mode 0600.
- Scalar service-tier modifiers reject negative and non-finite values. Partial
  uploads survive transient short reads while terminal checksum/size failures
  are removed, pending-upload limits run before admission accounting, and push
  rejects malformed completion metadata. Credential assignment redaction is
  linear on delimiter-heavy input, truncated private-key captures cannot trigger
  quadratic scans, and benign credential-label prose is preserved while
  authentication header labels always fail closed.
- Search-provider responses are streamed under a fixed body cap with compressed
  payloads and redirects refused. Release metadata checks invoke Twine through
  the interpreter consistently in CI and tag-publish workflows.
- Enabled shell and Python tools drain child pipes continuously while retaining
  only a bounded prefix, clean up descendant processes after every execution,
  and use Windows Job Objects when available.
- Audit append authenticates the current chain tail before a one-step checkpoint
  heal. A cross-process file lock spans the SQLite commit and external anchor
  update. Verification uses stable optimistic snapshots and retries under that
  lock only across concurrent writes, preventing forged-row laundering and
  commit/checkpoint races without starving writers.
- Timed-out shell and Python tools terminate the spawned process tree, retain
  bounded partial diagnostics, and reserve output space for stderr. Run-moving
  refs (`heads`, `experiments`, `promotions`) and attestation targets are
  type-checked as runs; `fsck`, local operations, and the remote enforce the same
  rule while tags may still identify any immutable object.
- Repository CLI object-read failures now produce concise stderr messages rather
  than tracebacks, search rejects non-string queries explicitly, header redaction
  has no prose-shaped bypass, and a truncated PEM capture preserves later text
  only after a clear paragraph boundary.
- Stable audit verification uses an optimistic database/anchor snapshot and
  takes the exclusive cross-process lock only when a concurrent append requires
  a consistent retry, preventing hot admin verification from starving writers.
- Source distributions use an explicit allowlist, and CI/publish gates require
  both source and wheel archives to match their tracked-file inventories exactly,
  preventing globally ignored local agent/editor state from entering a release.
- Release automation now tracks and enforces the hashed dependency lock, pins
  the build backend, uv, and GitHub Actions by immutable versions/commits, builds
  the wheel from the validated sdist, and reuses that one artifact pair for an
  attested GitHub release and OIDC PyPI Trusted Publishing. The identity-token
  permission is held only by the attestation and publish jobs, never by the job
  that builds and tests, and only the publish job declares the protected `pypi`
  environment that PyPI's trusted-publisher binding requires.
- External process harnesses now fail closed under configurable time, output,
  line-size, and parsed-event ceilings and clean up their owned process group or
  Job Object on every exit path. Git code capture streams under a 16 MiB ceiling;
  untracked paths mark the worktree dirty and make capture incompleteness explicit.
- Dependency floors exclude vulnerable cryptography wheels (`>=48.0.1`),
  Anthropic SDK releases (`>=0.87`), and MCP SDK releases. The OpenAI-compatible
  extra starts at `openai>=1.75.0`, the first SDK release that supports both the
  Responses API and its service-tier field. The MCP extra stays
  on the supported v1 line (`>=1.28.1,<2`) until OpenTine adopts its breaking v2 API.
  The development floor also excludes pytest's vulnerable tmpdir handling
  (`pytest>=9.0.3`).
- Authenticated repository clients ignore implicit environment proxies so a
  loopback development bearer token cannot be forwarded through `HTTP_PROXY`.
  Web-result text extraction is linear on malformed markup, and structured
  redaction recognizes camel/acronym/plural/scoped credential names plus bare
  token header pairs while retaining numeric token counters.
- Qwen streams explicitly request final usage and retain explicit-cache billing
  tiers. Trace import accounting counts repeated/empty containers incrementally,
  rejects expansion-prone non-JSON values, and charges skipped oversized JSONL
  records. Harnesses observe direct-parent exit independently of inherited pipe
  handles and close an escaped descendant's retained pipe after a short drain.
- Custom `OpenAI` base URLs now default to the provider identity
  `openai-compatible`, so a proxy or compatible service cannot silently inherit
  an OpenAI rate card merely by reusing an OpenAI model name. Explicit provider
  and rate overrides remain authoritative.
- Shallow-boundary state is validated, cached, and capped across the repository;
  bounded object enumeration and negotiation no longer sort or parse an
  unbounded local tree. Pack creation and installation enforce the same global
  object and shallow-link ceilings before writing.
- Trace parent and causal resolution is qualified by `(trace_id, span_id)`.
  Duplicate spans and dependency cycles are rejected before recording, while
  unresolved partial-trace boundaries are retained explicitly instead of being
  silently rewritten. Ollama response/NDJSON parsing and OTLP `AnyValue`
  traversal now have body, line, depth, and cycle limits.
- OpenAI now defaults to GPT-5.6, Kimi accepts the official Moonshot credential
  names, and DeepSeek-compatible streams request final usage. Together's
  `reasoning` field and Mistral's list-shaped thinking/text blocks are retained,
  bounded, and replayed without duplicating private reasoning representations.
- `OpenAICompatible` accepts an exact hosted-gateway base with unknown billing
  by default; `LocalOpenAICompatible` accepts exact or conventional `/v1`
  local endpoints with unmetered billing by default. Named LM Studio, vLLM,
  Unsloth, llama.cpp/llama-cpp-python, LocalAI, Jan, SGLang, TGI, MLX-LM,
  NVIDIA NIM, TensorRT-LLM, and KoboldCpp presets remain compatible. Explicit
  local auth, tool suppression, final stream usage, and provider-specific
  request bodies are configurable without forwarding ambient OpenAI keys,
  proxies, or redirects.
- Provider SDK retries are disabled so one recorded invocation represents one
  attempted provider request, and short-lived SDK clients close deterministically
  after complete and streamed responses. Missing provider tool-call IDs are
  normalized once and stored consistently in steps, transcripts, and tool results.
- The README now uses the official website mark, documents generic local runtime
  endpoints and their trust boundary, and no longer ships obsolete unreferenced
  animation assets in the source distribution.
- Compatibility imports no longer treat event-shaped legacy step IDs as trusted
  v3 identities; only provenance recovered from a verified v3 wrapper can reuse
  an event map. Repository association/evaluation/annotation scans, semantic
  source reads, and reflog-ordered ref updates now have explicit hard bounds and
  stable write guards.
- Remote ref discovery bounds annotation decoding, filesystem object reads reject
  linked or oversized leaves before decryption, resumable-upload reaping cannot
  race an active transfer, and push clients bind completion receipts to the exact
  pack ID and object count submitted. The signed catalog also corrects Grok 4.5
  cached input to the official $0.30/MTok rate.

### Fixed (second release audit)

Security fixes:

- Credential redaction covers quoted JSON field names. The v2 string path
  compared labels with their quotes attached, so `"api_key": "sk-…"` inside
  captured tool output was stored in cleartext. Quotes are stripped before
  matching; a quoted `"token"` value is treated as a credential (matching the
  mapping path) while numeric counters such as `input_tokens` still survive.
- An unterminated private-key marker no longer leaks the key bytes that follow
  it. Redaction required the entire remainder to be PEM data, so one trailing
  byte — the closing quote of a JSON string — made it emit the key verbatim
  directly after `[REDACTED PRIVATE KEY]`, output that reads as redacted. The
  scanner now consumes the base64 key material itself while keeping trailing
  prose, and a prefix rewrite removes a scan quadratic in indentation depth.
- Overwriting `tine sign --save`'s destination is its own flag, `--overwrite`.
  It shared `--force`, which also means "sign despite a failed integrity
  check", so replacing a file silently waived tamper detection. Neither flag
  implies the other.
- The remote's metadata database is created with private permissions before
  sqlite3 opens it. It was created under the process umask and tightened
  afterwards — a window in which a local process could open the file and keep
  a descriptor the later chmod does not revoke.
- MCP promotion is opt-in (`register_repository_tools(allow_promotion=False)`).
  A promotion ref is a release gate and run content read over MCP is
  untrusted, so text recorded inside a run could ask the model to promote an
  attacker-chosen run.
- The MCP experiments-only ref guard decides on the canonical ref name, so the
  guard and the filesystem layer can never disagree, and the legitimate
  fully-qualified `refs/experiments/…` form is accepted.
- `tine keygen` refuses `--out` and `--pub` naming the same file, which wrote
  the public key over the just-written seed and exited 0 with the private key
  destroyed.

Reliability fixes:

- Five false corruption reports on healthy repositories are gone: a ref inode
  observed during a concurrent update or mid-rename no longer trips the
  hard-link guard (only a link count above one is refused); a stray file such
  as `.DS_Store` in the refs directory no longer blanks the whole listing and
  masks every real error behind it; cache-eviction drift past ten thousand
  events no longer reports resolvable events as missing; and a few hundred
  annotations on one run no longer kill `fsck`, pack, and push with
  `RecursionError`.
- Search filters candidates to run objects, so one tag pointing at a large
  blob no longer permanently breaks search for the whole repository, and a run
  load memoises blob decoding, so events sharing a blob no longer decode
  hundreds of MiB from an 800 KiB repository.
- Search results are deterministic — equally ranked runs tiebreak on run id
  and candidates iterate in sorted order — and packed objects install in
  dependency order, so an interrupted install can no longer leave objects
  whose link targets were never written.
- A step subtotal such as `Decimal("1e999999999")` is rejected when recorded
  instead of crashing `ls`, `search`, `show`, and `cost` for every
  neighbouring run at aggregation time, and a harness duration arriving as a
  string (`"duration_ms": "1500"`) is coerced instead of keeping the
  thousandfold inflation the conversion exists to remove.
- Redacting a credential mention inside a JSON string no longer runs past the
  closing quote and breaks parsing for every downstream reader; an unvalidated
  `*_blob` field no longer makes `inspect` fail permanently for its object;
  and event metrics are validated at write exactly as strictly as at read, so
  a run can no longer be hashed into the store and then refused on every later
  read.
- Saving refuses an artifact this build could never load: the reader's
  integer-width and nesting-depth bounds now apply at write, leaving the run
  in memory instead of persisting it unreadably. HTML text extraction budgets
  collapsed text rather than raw markup, so a page's article is no longer
  silently replaced by its navigation links.
- Streamed usage accounting requires positive evidence that a provider
  supports `stream_options.include_usage`; Mistral rejects the field with HTTP
  422, so the blanket opt-in broke its streaming outright. GLM keeps the
  opt-in; Mistral, Ministral, Together, and Hermes opt in per deployment with
  `include_usage=True`.
- The per-user pricing overlay path honours an empty `XDG_CONFIG_HOME` instead
  of silently becoming CWD-relative, and PRICING.md's overlay recipe now
  produces a `catalog_id` the loader accepts (a `sha256:`-prefixed digest).
- The file-editing tool reads and writes with line endings preserved, so
  editing one line no longer rewrites every line ending in the file;
  `tine pricing show` escapes rate-card content instead of losing
  context-threshold surcharge lines to markup parsing; and an over-limit run
  index names the limit that actually fired (artifact count, source bytes, or
  serialized size) instead of always blaming the count cap.

### Fixed (third release audit)

- Depth-limited (shallow) clones no longer crash every graph read API at the
  fetch boundary: `repo-log`, semantic diff, and context slices stop at the
  boundary the way `git log` does, diff summaries aggregate only the events
  actually present, and loading a run whose events lie beyond the boundary is
  refused with an error that says to deepen the fetch.
- Two more writer/reader asymmetries that bricked runs while `fsck` stayed
  green: annotation writes reject the metadata/tags shapes the reader refuses
  (and a poisoned annotation head can be superseded through the API instead of
  blocking repair), and v3 compatibility blobs are written under the same
  structural guard the reader enforces, so a run that saves is a run that
  loads.
- One stray file under `objects/` no longer takes down `fsck`, object
  enumeration, search, pack, and fetch — the policy the refs directory already
  had — and object enumeration is sorted, so identical repositories enumerate,
  and therefore diff and pack, identically everywhere instead of in
  per-filesystem readdir order.
- The remote server also installs pack objects in dependency order, so an
  interrupted server-side install cannot leave durable objects whose link
  targets were never written.
- `tine tag` on a repository run applies the tag instead of crashing on the
  signature check meant for artifact files; `tine ls --since`/`--until` with
  an invalid date prints an error instead of a traceback; and the save-time
  loadability check bounds integer literals with the reader's own parser, so a
  long digit run inside a JSON string no longer makes a valid run unsavable
  (which aborted live runs through autosave).
- `run.fork()` tolerates non-dict transcript items and a malformed
  `manifest.pricing.catalogs` shape — both of which `load` already accepted —
  instead of raising `AttributeError`; the same paths are reached through
  cached replay and MCP `fork_run`.
- OpenAI usage parsing reads each cache and reasoning detail from whichever
  details spelling carries it — the same either-object rule the missing-usage
  probe applies — instead of only the first truthy details object.
- `TraceEvent` validation runs the event store's own metric gate on the stored
  form of timestamps, durations, costs, and usage, so an event that constructs
  can always be appended instead of crashing recorder appends and trace
  imports from inside the store.
- The filesystem `read()` tool returns raw line endings to match `edit()`, so
  a multi-line `old` string copied from read output matches CRLF files instead
  of always failing.
- Importing a legacy run keeps the extra parents of a merge step as causal
  edges instead of silently dropping all but one parent edge.

### Fixed (fourth release audit)

- Python 3.11, the declared support floor, ran a different build. Recursive
  walks over caller data cost two interpreter frames per nesting level before
  3.12 inlined comprehensions, so input that raised a clean error on 3.12+
  escaped as `RecursionError` on 3.11. Every such walk — canonical conversion,
  redaction, harness serialization, and pricing-catalog freezing — now uses
  statement loops and an explicit depth bound, so the same input is refused at
  the same depth with the same error on every supported interpreter.
- Canonical encoding is no longer interpreter-dependent, which was a data
  portability break: the encoder bounded nesting by catching `RecursionError`,
  so it accepted depth 496 on 3.12 but only 330 on 3.11 while the validator
  accepted 511 — and an object written on 3.12 could be unreadable on 3.11,
  because reading re-encodes to verify canonical form. Writer and reader now
  share one depth limit.
- Two more cases where a run saved and then never loaded: compatibility blobs
  are re-parsed with the same bounds the kernel uses, so a large float no
  longer becomes an unreadable integer literal, and the blob budget scales the
  way the artifact reader's does, so `migrate-v3` accepts healthy archives it
  had begun refusing. Saving refuses artifacts above the reader's size bound
  rather than writing one nothing can open.
- Text that the canonical form cannot encode — an unpaired surrogate, which
  any JavaScript producer emits for a truncated emoji — is refused when the
  artifact is written, with the offending field named, instead of surfacing as
  a raw codec error deep inside a repository write.
- Redaction of a private key embedded in JSON, and of a truncated
  passphrase-encrypted key, no longer leaks key bytes, and the private-key
  scan is linear rather than quadratic in the number of unterminated markers.
- Malformed values in `manifest.pricing` no longer crash `fork`, cached
  replay, `resume`, or `tine migrate-v3` with a raw traceback; nor does a
  `null` model entry, which the validator has always permitted, crash the
  loader and with it every command that reads a run.
- `agent.resume()` and `agent.replay()` no longer raise raw `AttributeError`
  or `TypeError` on runs the validator accepts and this build writes:
  malformed resume history, transcript entries, and tool-call records are
  handled explicitly, and cache-replaying a run with no recorded steps says so
  instead of raising `IndexError`.
- Flags are honored or refused, never silently ignored: `tine run --save`
  writes where it was told, and `tine sign --overwrite` without `--save` and
  `tine migrate --dry-run` with `--save`/`--in-place` are rejected instead of
  exiting successfully having done nothing.
- The test suite shipped in the source distribution passes without a git
  checkout or a `git` binary, and the release inventory check explains a
  line-ending mismatch instead of reporting every file as changed.

### Architecture and compatibility

- Every production Python module is capped at 250 physical lines; CI also caps
  the complete trusted kernel and rejects dependency-layer violations.
- `Run.save/load` can wrap repositories while legacy file behavior stays v2.
- The enterprise claim applies to the repository and extension seams. The
  bundled bounded WSGI server targets development and small self-hosted use,
  not turnkey HA, hosted SaaS, or billing/payment services.

## 0.2.1 — Unpublished; folded into 0.3.0

The provider-neutral billing work was developed under version 0.2.1, but no
`v0.2.1` tag or PyPI distribution was published. The first public release to
contain these changes, including the subsequent audit hardening, is 0.3.0.

Provider-neutral usage and cost accounting without changing `.tine` v2.

### Added

- Public `Usage`, `BillingResult`, `RateCard`, and `PricingCatalog` records with
  Decimal arithmetic, effective dates, cache/reasoning dimensions, context
  thresholds, service modifiers, currencies, and explicit complete/partial/
  unknown/unmetered states.
- Signed bundled pricing snapshot plus explicit `tine pricing list`, `show`,
  `check`, and `update`; local discount/infrastructure overlays remain separate
  from the signed upstream snapshot. No inference-time network lookup.
- Provider-scoped cards for OpenAI, Anthropic, Kimi, DeepSeek, Gemini,
  Grok/xAI, GLM/Z.AI, Qwen, Groq, Together, Mistral/Ministral, and Hermes. An
  unknown exact price is visible and never inherits another provider's rate.
- Digest-covered catalog signature/hash provenance, rate-card selection, and
  calculation inputs; the existing `cost` field is the known subtotal.
- Strict cost-completeness budgets through `Budget(strict_cost=True)`.

### Changed

- Native OpenAI models use Responses API semantics; compatible services retain
  a separate Chat Completions transport.
- Anthropic retains cache buckets and distinguishes early non-billable from
  midstream billable refusals. Kimi uses its current endpoint/default and
  preserves reasoning continuation. Google and Ollama retain usage/timing.
- Every invocation is recorded even for tool-only output, refusal, or a raised
  error carrying billable partial output.
- Credential redaction is typed/path-aware so numeric usage counters survive.

## 0.2.0 — 2026-06-29

Format `.tine` v2 plus six coordinated features. Reading v1 stays fully
supported; the public Python API only grows.

### Added

- **Format migration** — `FORMAT_VERSION` 2 with a pure migration registry.
  `Run.load` auto-migrates v1 in memory (never rewriting the file); re-saving
  upgrades to v2. New `tine migrate` (dry-run by default; verifies the source
  first). Also best-effort imports the legacy **0.1.0 linear format** (recomputes
  step ids). New `golden_v2.tine` / `golden_signed_v2.tine` / `golden_v0_linear.tine`
  fixtures.
- **Run tags + search** — `Run.tags` (+ `add_tag`/`remove_tag`/`has_tag`),
  persisted at `metadata.tags` outside the digest so re-tagging never changes a
  digest/signature. New `tine tag` / `tine search` (query DSL) / `tine reindex`
  and tag/model/status/cost/date/text filters on `tine ls`, backed by a
  rebuildable `.tine_runs/index.json` sidecar.
- **Cost + budget** — per-step `usage` tokens, `Run.total_tokens`,
  `Run.cost_breakdown()`, and `Run.set_budget(...)` enforced in the agent loop
  (`stop`/`raise`). New `tine cost`. (Serialized keys avoid "token" to dodge
  redaction; budgets live in `manifest.budget`, inside the digest.)
- **Streaming autosave** — atomic, crash-safe draft checkpoints with AND-throttle
  for long runs; native `Agent` and harnesses both flush a clean final artifact.
  Drafts carry a top-level `draft` flag inside the digest. `tine run --autosave`.
- **Signing (`tine-sig/1`)** — HMAC-SHA256 (stdlib) and optional Ed25519
  (`opentine[crypto]`). `Run.save(sign_key=...)`, `Run.verify_signature(...)`,
  `tine sign` / `tine keygen` / fail-closed `tine verify --key-*`/`--pubkey`.
  The signature commits to content (not the stored digest) and excludes mutable
  metadata so tags/budget/autosave edits don't break it.
- **Field-level diff** — `Run.diff` now populates `changed` via lineage-position
  alignment with `StepChange`/`FieldDelta`; `tine diff` renders per-field
  before/after, including cost/usage drift between same-id steps.

### Changed

- `FORMAT_VERSION` 1 → 2. `RunDiff.changed` is now `list[StepChange]`.
  `IntegrityResult` gains a `draft` field. Saves are now atomic.

### Compatibility

- 0.2 reads and migrates v1. **0.1.x cannot read v2**, and re-saving a v1 file
  upgrades it to v2 (one-way). HMAC signing needs no extra; Ed25519 needs
  `pip install "opentine[crypto]"`.

## 0.1.1 — 2026-06-25

- Ollama adapter now detects tool-calling capability via `/api/show` (cached) so
  `Ollama(...).supports_tools` is accurate. Agents with tools on a model that
  does not support them (e.g. `gemma3`, `codellama`, `phi4`, `deepseek-r1`) now
  run without tools and record a note in `run.metadata["warnings"]` instead of
  failing with an opaque Ollama `400`.
- OpenAI adapter token pricing is now configurable
  (`input_cost_per_mtok` / `output_cost_per_mtok`). Local OpenAI-compatible
  wrappers (`LMStudio`, `VLLM`, `Unsloth`, `LlamaCpp`, `LocalAI`, `Jan`) report
  `$0` cost by default instead of inheriting gpt-4o pricing.
- Removed the unused `msgspec` runtime dependency.
- Added a `mcp` optional extra (`pip install opentine[mcp]`) for the MCP server.
- Fixed the broken README logo (now a committed `docs/assets/opentine-logo.svg`).
- CI now runs `twine check` and uploads the built wheel/sdist as a downloadable
  artifact on every run; tagged releases carry `SHA256SUMS` plus a verifiable
  build-provenance attestation (`gh attestation verify`).

## 0.1.0

Initial public beta for the current 0.1.x surface.

- Added explicit `.tine` integrity verification through `Run.verify_integrity(...)` and `tine verify`.
- Added golden v1 `.tine` fixture coverage for load, save, fork, and diff behavior.
- Added security regression coverage for redaction, digest failure, path escape, symlink escape, private-network blocking, shell/Python denial, environment isolation, and output caps.
- Added a CI-sized graph performance smoke test for save, load, fork, and diff.
- Added wheel smoke testing for installed-package import, `tine --help`, and `tine verify`.
- Replaced PyPI publishing automation with a GitHub release artifact workflow that builds sdist/wheel, checks metadata, generates `SHA256SUMS`, and attaches artifacts to tagged GitHub releases.
- Documented the security model, current `.tine` v1 format policy, troubleshooting notes, and support policy.

Known scope:

- Package metadata remains `Development Status :: 4 - Beta`.
- `.tine` compatibility is current v1 only; migrations are future work.
- Artifact checksums are provided, but HMAC/signing and PyPI trusted publishing are not part of this pass.
