# CLI spellings

Since 0.16 related verbs are reachable under a noun group. A group spelling is
rewritten to the old verb before parsing, so both take the same flags and give
the same output and exit code. The old spellings keep working unchanged.

| Old spelling | New spelling |
| --- | --- |
| `tine init` | `tine repo init` |
| `tine config` | `tine repo config` |
| `tine worktree` | `tine repo worktree` |
| `tine branch` | `tine repo branch` |
| `tine reset` | `tine repo reset` |
| `tine reflog` | `tine repo reflog` |
| `tine archive` | `tine repo archive` |
| `tine pack` | `tine repo pack` |
| `tine migrate` | `tine repo migrate` |
| `tine serve` | `tine repo serve` |
| `tine du` | `tine repo storage du` |
| `tine gc` | `tine repo storage gc` |
| `tine repack` | `tine repo storage repack` |
| `tine prune` | `tine repo storage prune` |
| `tine compress` | `tine repo storage compress` |
| `tine fsck` | `tine repo storage fsck` |
| `tine reindex` | `tine repo storage reindex` |
| `tine hook` | `tine repo integrate hook` |
| `tine enable` | `tine repo integrate enable` |
| `tine disable` | `tine repo integrate disable` |
| `tine plugin` | `tine repo integrate plugin` |
| `tine harnesses` | `tine repo integrate harnesses` |
| `tine git` | `tine repo integrate git` |
| `tine push` | `tine share push` |
| `tine fetch` | `tine share fetch` |
| `tine pull` | `tine share pull` |
| `tine clone` | `tine share clone` |
| `tine remote` | `tine share remote` |
| `tine bundle` | `tine share bundle` |
| `tine archive` | `tine share archive` |
| `tine sign` | `tine trust sign` |
| `tine keygen` | `tine trust keygen` |
| `tine attest` | `tine trust attest` |
| `tine evaluate` | `tine trust evaluate` |
| `tine promote` | `tine trust promote` |
| `tine verify-tag` | `tine trust verify-tag` |
| `tine who` | `tine agent who` |
| `tine actions` | `tine agent actions` |
| `tine touched` | `tine agent touched` |
| `tine blame` | `tine agent blame` |
| `tine audit` | `tine agent audit` |
| `tine migrate-v3` | `tine repo migrate --to-v3` |
| `tine bundle verify FILE` | `tine verify FILE` (FILE is a bundle, no other arguments) |

Since 0.17 `log` and `show` also front the read-only verbs. The folded flag is
rewritten to the old verb before parsing, so both spellings give the same output
and exit code; a flag the old verb does not take is a usage error (exit 2), as
are `--cost` with `--price`, `--at` without `--price`, and `log --search` with a
`log` option (`--graph`, `--all`, `--oneline`, `--limit`, `--commit`, `--pr`, REF).

| Old spelling | New spelling |
| --- | --- |
| `tine search QUERY` | `tine log --search QUERY` |
| `tine ls` | `tine log --legacy` |
| `tine ls --tag T --model M ...` | `tine log --tag T --model M ...` (an `ls` filter implies `--legacy`) |
| `tine cost RUN` | `tine show RUN --cost` |
| `tine price RUN [--at DATE]` | `tine show RUN --price [--at DATE]` |

`tine log` without these flags is unchanged: it reads the v3 repository, while
`--legacy` lists the legacy `.tine_runs` index that `tine ls` lists.

`tine stats --repo PATH` is new in 0.36: run inside a v3 repository (or with
`--repo`), `stats` counts the repository's store (runs, events, blobs, objects,
canonical bytes, cost; `--json` adds a `store` object and `scope:
"v3-repository"`) instead of the legacy `.tine_runs` index. `--group-by` takes
`model`, `status` or `day` there; the `ls` filters and `--deep` stay legacy-only.
Elsewhere `stats` reads the legacy index exactly as before.

`tine trust policy set|list|show|rm|default` is new in 0.16 (no older spelling):
named trust policies for `tine verify --policy NAME` (see below).

`tine agent id|show|trust|keys` are unchanged. `tine GROUP --help` lists a group;
`tine help --all` lists every command.

`tine hold add|list|release OID|REF` is new in 0.35 (no older spelling): it
keeps objects and everything they reach from `prune`, `gc --prune=now`,
`rewind --apply` and remote deletes. Also new in 0.35: `gc --prune=never|now`
(default `never` until 0.39, which adds `retention` and makes it the default:
see `tine retention show|check` and REPOSITORY.md), `verify --offline --hermetic` (exit 6 where no OS sandbox
exists, Windows included), `rewind --allow-control-dirs`,
`replay --trust-recorded-prompt` and `serve reseal --to aes4 --from aes2`.

New flags in 0.37 (no new subcommands):

- `gc --level N` / `repack --level N`: the pack compression level (zstd 1-22,
  default 19; zlib caps at 9). Auto-pack reads `"auto_pack": {"level": N}` from
  the repository's `config.json`.
- `archive create --archival`: writes the archive with xz (storage codec 4, zlib
  where Python lacks `lzma`), so a stock Python 3.11+ restores and verifies it
  with no optional package. opentine 0.36 and older cannot read codec 4, which
  is written only on this request.
- `fsck --budget SECONDS` / `fsck --max-objects N`: stop the object walk
  cleanly; the JSON report gains `checked` and `complete` (exit 0 when nothing
  checked failed), and stderr says how far it got.
- `gc` also removes staging files left by killed writers once they are an hour
  old (`reaped_temp` in `--json`); live writers' files are never touched.

New in 0.38: `tine rewind` restores a workspace snapshot (a tree blob, SPEC
§1.5.7) exactly. `tine rewind TREE_OID` takes the tree id directly;
`tine rewind RUN[@STEP] --tree` uses the tree linked from that step
(`outputs.tree`, or the nearest earlier step with one). `--repo DIR` names the
repository holding the snapshot (default: the one containing `--root`). Dry run
by default; `--apply` writes every file, link and executable bit back byte for
byte and removes tracked paths the snapshot did not have, so changes made
through a shell are undone too. Writes go through the 0.35 `O_NOFOLLOW`
directory-descriptor writer; control files are refused without
`--allow-control-dirs`; ignored, version-control and omitted paths (too large
or unreadable at capture) are left alone; a file stored redacted is refused.
`--json` reports `restore`, `remove`, `unchanged`, `refused` and `kept`.

## Errors, `--json` and exit codes (0.36)

Every leaf subcommand accepts `--json`. Commands with their own JSON payload
keep it unchanged; `fleet up` (with or without `--dry-run`) and
`replay --dry-run`/`--inspect` now emit one JSON object instead of ignoring the
flag. Any other command wraps its human output:

```
{"command": "fsck", "exit_code": 0, "output": "..."}
```

The v3 plumbing verbs (`fsck`, `object`, `migrate-v3`, `fetch`, `push`) always
print bare JSON; `--json` on them is a no-op. `output.format = json` turns on
only a command's own JSON, never the wrapper.

Errors go to stderr. Under `--json`, stdout carries only JSON: a failing command
that wrote no JSON of its own emits one error object (a usage error included)
and anything human it printed moves to stderr:

```
{"error": {"code": "not_found", "exit_code": 3, "message": "..."}}
```

| Exit | `code` | Meaning |
| --- | --- | --- |
| 0 | — | ok |
| 1 | `error` | any other failure |
| 2 | `usage` | bad flags or arguments, or a refused flag combination |
| 3 | `not_found` | a run, ref or object that does not exist |
| 4 | `verification_failed` | a signature, digest or verdict did not hold |
| 5 | `budget_exhausted` | a budget or limit stopped the work |
| 6 | `trust_required` | needs a trust decision, or is unsupported here (`verify --hermetic`) |

Existing exit statuses keep their meaning; commands move to the specific codes
as they are revised, so a script should treat any non-zero status as failure
and read `error.code` for the reason.

New in 0.36: `serve --oidc-issuer URL --oidc-audience AUD` verifies OIDC bearer
tokens instead of the static token (`--oidc-jwks-uri URL` pins the key set,
otherwise it comes from the issuer's discovery document; every URL must be
`https://` and none is ever taken from a token; `--oidc-tenant-claim` and
`--oidc-roles-claim` name the claims). The static token must now hold at least
32 bytes; `serve --allow-weak-tokens` starts with a shorter one while it is
rotated. After 5 consecutive failed authentications a client gets 429 with
`Retry-After` for a delay that doubles per failure (up to 5 minutes), and a 500
answers only `{"error":"internal","request_id":...}`, logging the exception.

## Default output format

```
tine config set output.format json    # every command with --json now emits JSON
tine config get output.format         # prints json; exit 1 when unset
tine config unset output.format
OPENTINE_OUTPUT=text tine show RUN    # the env var wins over the file
tine show RUN --text                  # human output for this call only
```

`output.format` is `text` or `json`, stored only in the user's
`$XDG_CONFIG_HOME/opentine/settings.json` (written 0600; a repository cannot set
it). Precedence: an explicit `--json` or `--text` on the command, then
`OPENTINE_OUTPUT`, then the file, then text. Every command that has `--json` also
has `--text`; giving both is an error. Commands whose `--json` is only the
0.36 wrapper ignore the setting and never read the file. A value other than `text`/`json` in the env var
or the file, or a malformed file, stops the command with a one-line error (exit
1) instead of guessing. `tine config set|get|unset` are the user settings;
`tine config KEY [VALUE]` still edits the repository's porcelain keys. With no
setting, every command's output is unchanged.

## Op log and undo (0.36)

Every `tine` command that moves a local ref (`branch`, `tag`, `reset`, `fork`,
`pull`, `rebase`, `cherry-pick`, ...) appends one entry to the op log: op id,
command, actor, time and each ref's `old -> new`. The log is `opentine-log/1`, a
hash-chained record log in the [C2SP tlog-tiles](https://c2sp.org/tlog-tiles)
layout under `.tine/log/op/` (`checkpoint`, `tile/<L>/<N>`, `tile/entries/<N>`),
with an Ed25519 [signed-note](https://c2sp.org/signed-note) checkpoint; the
verifier key is in `.tine/log/op/vkey`.

* `tine op log [-n N] [--json]` lists ops, newest first.
* `tine op verify [--vkey KEY] [--json]` recomputes every tile, the Merkle root,
  the hash chain and the checkpoint signature from local files only (it never
  touches the network). `--vkey` pins a key obtained out of band.
* `tine undo [OP] [--force] [--json]` puts back the refs `OP` (id, id prefix or
  index; default the latest) moved, as a new forward ref transaction that is
  itself logged (`undoes`), so `tine undo` twice redoes. It refuses (exit 1) when
  a ref was moved since by a later op (`superseded`) or by a writer that does
  not log, such as opentine 0.34 or a library caller (`gap`: the ref differs from
  the logged value, or its reflog has newer rows); `--force` undoes anyway.

## Offline verification (0.25)

```
tine verify RUN --offline                        # human report
tine verify RUN --offline --json --report r.json # tine-verify-report/1
tine verify RUN --offline --pubkey release.pub --strict
tine verify RUN --offline --attestation a.sigstore.json --trusted-root trusted_root.json \
    --cert-identity ci@example.com --cert-oidc-issuer https://token.actions.githubusercontent.com
tine verify RUN --offline --action-policy policy.toml
```

Every check runs from local files only; a socket connect or DNS lookup during
the run is a hard error. Each check names its **trust basis**.

What "offline verified" proves:

* the file's bytes match its own sha256 digest (internal consistency: anyone who
  edits a run can also recompute its digest, so on its own this proves nothing
  about who wrote it);
* with `--pubkey`, `--pin`, `--key-file` or `--key-env`, that the holder of that
  key signed these bytes -- the only case the report fills `authorship`;
* with `--attestation`, that the statement is signed and names this digest, and
  that a receipt it carries is signed by the Rekor key or trusted root you gave;
* for a keyless bundle, that the certificate chains to your Fulcio root /
  trusted root, matches `--cert-identity`/`--cert-oidc-issuer`, and (with CT
  keys) carries a valid SCT.

What it does not prove: that the log still contains the entry or was not
rolled back (no live inclusion or consistency check), that a key or certificate
was not revoked later, that your trusted root is current, or anything about a
check reported `unavailable-offline`. `--trust-embedded-key` verifies a key the
file itself carries, so it is reported as trust-on-first-use, never authorship.
Use `--strict` to make any missing required check fail the verdict.

`--locate` reports where a failed run broke, using only finer-grained hashes
that exist: step ids (each covers a step's kind, inputs, outputs, model_info,
tool_info, error and parent_ids, so it names the step, not the field), a stored
action manifest, or a key-verified attestation subject. When none of them
explains the break it says `locate.unlocalisable` rather than guess. Byte
offsets index the canonical JSON of the **redacted, stored** body with
`metadata` removed (what the digest covers), not the file on disk.

`tine verify --offline DIR|REPO` writes one `tine-verify-dataset/1` report with
a Merkle root over the sorted `(run_id, digest)` pairs (leaf
`sha256(0x00 || canonical_json([run_id, digest]))`, node
`sha256(0x01 || left || right)`, an odd node carried up unchanged). A
repository run's digest is its `tine-actions/1` `run_digest`.

```
tine timestamp data RUN
tine timestamp attach RUN TOKEN.tsr
tine verify RUN --offline --tsa-roots FILE.pem
```

0.31.0: offline RFC 3161 timestamp checks. `timestamp data` prints the exact
bytes a token must cover (the run's digest string, no newline); build the query
and fetch the response yourself, for example
`tine timestamp data run.tine > bound.txt`,
`openssl ts -query -data bound.txt -sha256 -cert -out q.tsq`, then POST `q.tsq`
to your TSA. opentine never contacts a TSA. `timestamp attach` checks the
response parses and covers the run's current digest, then stores it in
`RUN.timestamps.json`. `verify --offline` then reports one `timestamp` check per
token (imprint, TSA signature, timestamping EKU, genTime within the
certificate's validity, chain to a root in `--tsa-roots` or the
`--trusted-root` TSAs) and a `timestamps` section with genTime, TSA name,
policy OID and hash algorithm (SPEC §8.6).

```
tine evidence export RUN... --out DIR [--sign KEY] [--pubkey P] [--pin FPR]
                     [--action-policy FILE] [--attestation FILE]
                     [--trusted-root FILE] [--operator NAME]
```

Writes `MANIFEST.sha256`, `custody.jsonl`, `timeline.jsonl`, `timeline.csv`,
`verify-report.json`, `trust/` and `runs/`. `custody.jsonl` is outside the
manifest (it holds the only timestamp) and names the manifest's SHA-256; with
`--sign` it is signed with Ed25519 over `opentine.custody.v1:` + canonical JSON.
`--attestation` (one run only) and `--trusted-root` (only with a keyless
attestation) feed the attestation checks and are copied into `trust/`.
`docs/conformance/minimal_verifier.py evidence DIR` re-checks the folder
without opentine (SPEC Part 8).

```
tine evidence report RUN --format html|pdf -o PATH [--pubkey P] [--pin FPR]
                     [--action-policy FILE]
```

New in 0.39. Writes one run's offline verification, timeline and the
canonical evidence JSON (embedded as `<script type="application/json"
id="tine-evidence">`) as one self-contained page. **The HTML is canonical and
byte-identical across runs**: no wall-clock time (only the run's own), the
source reduced to its file name, sorted-key canonical JSON, inline CSS, the
`tine view` CSP (no scripts, nothing fetched), and every string re-redacted.
`--format pdf` needs `pip install 'opentine[pdf]'` (pikepdf; exit 6 without it)
and is a derivative: fixed `/CreationDate` from the run, content-derived `/ID`,
`evidence.json` attached with `/AFRelationship /Data`. It is deterministic for
a given pikepdf/qpdf version, but only the HTML is gated on byte identity; the
PDF uses the base-14 Courier font (no system font is read), so it is not yet
PDF/A-3 conformant.

`tine retention show|check [--repo DIR] [--json]` (0.39) prints the retention
policy, or dry-runs what default `gc` would prune.

## Trust policies

```
tine trust policy set prod --pubkey ~/keys/release.pub --rekor-key ~/keys/rekor.pem --require-receipt
tine trust policy set ci --cert-identity ci@example.com --cert-oidc-issuer https://token.actions.githubusercontent.com \
    --fulcio-root ~/keys/fulcio.pem --rekor-key ~/keys/rekor.pem --ct-key ~/keys/ctlog.pem --require-sct
tine trust policy set sigstore --cert-identity ci@example.com \
    --cert-oidc-issuer https://token.actions.githubusercontent.com --trusted-root ~/keys/trusted_root.json
tine trust policy list [--json]
tine trust policy show prod [--json]
tine trust policy default prod        # or: --clear; no argument prints it
tine trust policy rm ci
tine verify RUN --attestation a.intoto.jsonl --policy prod
tine verify RUN --no-policy           # ignore trust.default for this call
```

A policy holds `pubkey`, `pin`, `rekor_key`, `require_receipt`, `cert_identity`,
`cert_oidc_issuer`, `fulcio_root`, and (0.18) `ct_key` (a list of CT log key
files), `require_sct` and `trusted_root` (which replaces `rekor_key`,
`fulcio_root` and `ct_key`). Flags given on the command line win over the
policy; any key flag (`--pubkey`, `--pin`, `--key-env`, `--key-file`,
`--trust-embedded-key`) replaces the policy's key as a whole. Fields that do not
apply (keyless fields for a key-signed attestation, receipt fields for a plain run
verify) are unused rather than refused. The default policy applies only when no key,
receipt or keyless flag and no `--policy` is given. `--trust-embedded-key` cannot
be stored in a policy.

## Sigstore trusted root (0.18)

```
tine verify RUN --attestation a.sigstore.json --cert-identity ci@example.com \
    --cert-oidc-issuer https://token.actions.githubusercontent.com --trusted-root trusted_root.json
tine trust root update --root root.json [--repo-url https://tuf-repo-cdn.sigstore.dev] [--json]
tine trust root update                # later runs: stored root and repository
```

`--trusted-root FILE` takes the Rekor keys (`tlogs`), Fulcio chains
(`certificateAuthorities`) and CT log keys (`ctlogs`) from one Sigstore
`trusted_root.json`, honouring each entry's `validFor` window. It is a usage
error beside `--rekor-key`, `--fulcio-root` or `--ct-key`. When the root lists
CT logs, an embedded SCT is required.

`tine trust root update` is a minimal TUF client: it refreshes
`trusted_root.json` into `$XDG_CONFIG_HOME/opentine/sigstore/`, after which that
copy is the default for keyless `tine verify --attestation` calls that name no
key file. Nothing is ever fetched implicitly. No TUF root is embedded: the first
run needs `--root FILE`, an initial `root.json` you obtained and checked out of
band (for the Sigstore public-good instance, from
[sigstore/root-signing](https://github.com/sigstore/root-signing), e.g. its
`metadata/root_history/` or `https://tuf-repo-cdn.sigstore.dev/N.root.json`
compared against the signing ceremony). To start over, remove
`$XDG_CONFIG_HOME/opentine/sigstore/tuf/`.

## Agent Trace export (0.19)

```
tine export RUN --format agent-trace                    # record on stdout
tine export RUN --format agent-trace --output trace.json
```

Writes one [Agent Trace](https://agent-trace.dev/) record (RFC 0.1.0, validated
against `https://agent-trace.dev/schemas/v1/trace-record.json`). Each file the
run's successful tool calls wrote is a `files` entry with one conversation per
model, contributor `ai`, `model_id` spelled `provider/model` when the provider was
recorded. Line ranges are emitted only when they are known: a whole-file write
that is the run's last write to that path covers lines 1..N. Edits, patches and
shell redirects get file-level attribution (an empty `ranges` array). Absolute
paths are made relative to the enclosing repository (the nearest directory with
`.git`, else the current directory); paths outside it are left out and counted.
`vcs` and conversation `url` are omitted, since a run records neither; the run
id rides in `metadata["io.github.0xcircuitbreaker.opentine"]`. `version` is `"0.1"`, the spelling the
published schema accepts. `--endpoint` is refused.

## Citation export (0.25)

```
tine export RUN --format citation --output CITATION.cff
tine export RUN --format ro-crate --output ro-crate-metadata.json
```

`citation` writes a [Citation File Format](https://citation-file-format.github.io/)
1.2.0 document (`type: dataset`); `ro-crate` writes an
[RO-Crate 1.1](https://w3id.org/ro/crate/1.1) `ro-crate-metadata.json` with
the metadata descriptor, a root `Dataset`, the run file, and `opentine` plus
each model as `SoftwareApplication` entities. Both carry the run id, the
integrity digest (`sha256:…`, SPEC §3.5), every model the run recorded, the
run's own creation time and the opentine version. Nothing else varies (no
clock, host or path), so the same run and version always give the same bytes.
A run whose digest does not verify is refused, and `--endpoint` is refused.
Without `--output` the document goes to stdout.

## Entire checkpoint import (0.19)

```
tine import . --format entire --save run.tine        # newest checkpoint, last session
tine import .::a3b2c4d5e6f7/0 --format entire --repo runs
```

[Entire](https://entire.io) commits coding-agent sessions to the
`entire/checkpoints/v1` branch (`<id[:2]>/<id[2:]>/metadata.json`, one numbered
directory per session with `metadata.json`, `full.jsonl` and `prompt.txt`).
SOURCE is the git repository; `::ID` picks a checkpoint by id or unique prefix and
`/N` a session (0-based, in the summary's order). The branch is read with
`git cat-file`, never checked out; `origin/entire/checkpoints/v1` is used when
there is no local branch. `--format auto` recognizes a directory SOURCE. The
session transcript is imported by the Claude Code, Codex or Gemini CLI importer;
any other agent imports as one human step carrying its prompt, with an import
warning. `attributes["entire"]` on the first step keeps the checkpoint and session
ids, agent, model, strategy, branch, commit, files touched and Entire's token
usage. `full.jsonl` holds the session up to that checkpoint, so the run is the
session so far. Session metadata over 1 MiB and transcripts over 64 MiB are
refused before they are read.

# Writer format (0.26)

Since 0.26 every writer produces **format v4** (SPEC Part 9): `.tine` files are
`tine-artifact/4`, signatures `tine-sig/3`, Ed25519 attestations on a run
`tine-attest/2`, and `tine init` creates an object-format-4 repository (an
existing repository is marked object format 4 before the first object 0.26
writes into it). Reading never changes: every older file and repository stays
readable, and a read never rewrites it.

| Spelling | Writes |
| --- | --- |
| *(default)* | format v4; new repositories object format 4 |
| `tine --format 2 COMMAND ...` | the deprecated v2 file / object-format-3 repository writers, for this command only |
| `OPENTINE_FORMAT=2` (or `3`) | the same, for the whole environment |
| `OPENTINE_FORMAT=4` | strict v4: no deprecated block even where v4 cannot express it (an HMAC attestation, `sign_artifact` on a v2 dict) |
| `tine migrate FILE` | upgrades to v4 (`--to v4` is the default; `-o`/`--save` names the output, else `NAME.v4.tine`) |
| `tine migrate FILE --to 2` | the deprecated in-file v1 -> v2 migration |

The legacy writers print one deprecation warning per process on stderr. A file
or repository written by 0.26 needs opentine 0.26 or newer; share with older
releases with `tine --format 2`. An explicit write refuses an integer beyond
2**53-1 or a non-finite number, naming the field; recorders (`tine run`, `tine
record`, imports, hooks, `serve --otlp`) store such a value as its exact string
and list the field under `metadata.warnings` instead of losing the run.
`tine bundle` (and `bundle push/fetch`) carries the `tine-sig/3` blocks of
imported v4 runs in the bundle manifest.

## Fan-out status and MCP tools (0.36)

`tine fleet status [ID] --repo PATH` lists the repository's `tine fan-out`
records (`.tine/fanouts/`) instead of
the fleets in `--dir`; with `--json` it prints
`{"command": "fanout status", "fanouts": [...]}`.

The MCP server (`python -m opentine.mcp_server`) builds its tool list from one
registry (`opentine/_mcp_registry.py`), each tool annotated read or write. The
default exposes only read tools; `--allow-writes` or
`OPENTINE_MCP_ALLOW_WRITES=1` adds exactly the annotated write set (never
`promote_run`). The read tools generated from the registry return the same
payload as their command's `--json`:

| Tool | Command |
| --- | --- |
| `verify_run` | `tine verify RUN --offline --json` |
| `log` | `tine log [REF] --limit N --repo REPO --json` |
| `fleet_status` | `tine fleet status [ID] --json` |
| `fanout_status` | `tine fleet status [ID] --repo REPO --json` |
| `cost` | `tine cost RUN --json` |
| `agent_show` | `tine agent show TARGET --repo REPO --json` |
| `stats` | `tine stats [--group-by KEY] --limit N --json` |

## Per-turn capture (0.38)

| Command | What it does |
| --- | --- |
| `tine hook capture [--agent NAME] --repo PATH` | `opentine-hook/1`: one JSON event on stdin becomes one durable step of the session's run; prints a JSON response and always exits 0 |
| `tine enable [--agent NAME] [--dry-run] --repo PATH` | Adds the capture shims to the Claude Code, Codex and Gemini CLI hook files and sets `hooks.capture`; `--dry-run` prints the unified diff only |
| `tine disable [--agent NAME] [--dry-run]` | Restores each hook file byte for byte (or removes only the shims if it was edited since) |

Capture records nothing unless the repository's trusted config sets
`hooks.capture`. See [CAPTURE.md](CAPTURE.md#per-turn-capture-tine-hook-capture-opentine-hook1).

## MCP proxy capture (0.38)

```text
tine mcp-proxy [--save PATH] [--force] [--repo PATH [--ref REF]] -- CMD [ARGS...]
tine mcp-proxy --http-upstream URL [--listen HOST:PORT] [--allow-non-loopback] [--save PATH] [-- CMD...]
```

Relays an MCP session over stdio (spawning CMD) or Streamable HTTP and records
each JSON-RPC exchange as a redacted `tool` step, saved incrementally. In HTTP
mode an optional CMD is run alongside and the proxy stops when it exits;
otherwise it serves until Ctrl-C or SIGTERM. `--listen` defaults to
`127.0.0.1:0` (the chosen port is printed on stderr). See
[CAPTURE.md](CAPTURE.md#6b-live-capture-an-mcp-session-038).

## Assurance tiers (0.39)

| Command | What it does |
| --- | --- |
| `tine proxy keygen [--force] [--json]` | Creates the proxy witness key (Ed25519) under `$XDG_CONFIG_HOME/opentine/proxy-keys/`, apart from every agent key; `tine record` and `tine mcp-proxy` sign their finished runs with it (`tine-sig/3`) |
| `tine verify RUN --min-assurance T0..T3` | Exits 4 (`verification_failed`) when the *verified* tier is below the floor |
| `tine verify RUN --proxy-pubkey FILE` | Also trusts this proxy public key as a T2 witness (repeatable) |
| `tine verify RUN --min-assurance T3 --tsa-roots FILE.pem` | Lets an attached RFC 3161 token count toward T3 (outside `--offline`, `--tsa-roots` needs a floor) |
| `tine verify RUN --compare-capture OTHER [--json]` | Divergence report: the better-witnessed run against the other, step by step (MCP `tools/call` and prompts); exits 4 when they diverge |

Tiers: **T0** self-reported import, **T1** hook-captured, **T2** witnessed by
the record proxy or `tine mcp-proxy` and signed with a trusted proxy key,
**T3** T2 plus a verified timestamp. The tier a capture *claims* is recorded
(`metadata.capture.claimed_tier`); the tier reported is *computed* at verify
time, and a claim alone never rises above T1. Every report carries an
`assurance` object, `{"claimed", "verified", "witness", "reasons"}`: `tine
verify --json`, `tine verify --offline` (and so the MCP `verify_run` tool) and
`tine show --json`; the human output prints one `assurance` line.

## Push preview and manifest (0.36)

`tine push REMOTE --dry-run` (alias `--outgoing`) prints, as JSON, exactly what
the push would send, and opens no connection: each ref as `old -> new` (the old
side is the local `remotes/<name>/...` tracking ref from the last fetch, so the
list is an upper bound if the remote has moved), the objects by kind with their
stored bytes, and every run with the redaction ruleset it recorded (`null` for
a run that recorded none). It honours `--ref`, `--all` and `--remote-ref`.

`--manifest PATH` writes the same document as canonical JSON (JCS) -- on a dry
run, or beside a real push before it starts. `--key-file` (HMAC) or
`--ed25519-key-file` signs it with a `tine-sig/3` header block over
`opentine.push-manifest.v1:` + JCS of `{body, header}`; `--key-id` names the key.
A key flag without `--manifest` or `--dry-run` is refused.

`git config tine.transcriptRemote NAME` (a git remote name, URL or path) makes
the `tine git install-hook --push` pre-push hook send `refs/tine/bundle` --
the runs named by `Tine-Run:` trailers -- to that remote instead of the code
remote, keeping transcripts off the code host.
