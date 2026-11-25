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
`log` option (`--graph`, `--all`, `--oneline`, `--limit`, `--commit`, `--pr`, `-f`, REF).

| Old spelling | New spelling |
| --- | --- |
| `tine search QUERY` | `tine log --search QUERY` |
| `tine ls` | `tine log --legacy` |
| `tine ls --tag T --model M ...` | `tine log --tag T --model M ...` (an `ls` filter implies `--legacy`) |
| `tine cost RUN` | `tine show RUN --cost` |
| `tine price RUN [--at DATE]` | `tine show RUN --price [--at DATE]` |

`tine log -f [RUN|--all] [--json]` (0.77) follows new events as they become
durable, each marked with its verification status ([LIVE.md](LIVE.md)).

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
- `gc --sweep-expired [--state DIR] [--tenant T]...` (0.52) packs nothing: it
  removes the expired orphan chunks of the object store `tine serve --root DIR`
  opens (`TINE_REMOTE_OBJECT_STORE`). A chunk goes only when no object or
  in-flight upload names it, its retention has ended and it has no legal hold;
  the removal is fenced against concurrent uploads (docs/STORAGE.md).
  `--json` writes `tine-cli-gc-1`.

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

New in 0.52: `tine serve` implements the admin surface (SPEC 8.27; operations
tagged `admin` in `docs/api/openapi-v1.yaml`): `GET`/`DELETE /v1/session`,
tenants, members, invitations, settings, retention and holds. `serve
--passkey-rp-id ID --passkey-origin https://ORIGIN` turns on passkey (WebAuthn)
login, where the server keeps public keys only; `serve --insecure-dev
--dev-login` lets a local developer sign in as any subject with no proof;
`serve --open-signup` lets any signed-in subject create tenants (otherwise an
admin bearer token registers its own tenant and invites people). No new verb;
`scripts/check_api_contract.py ROUTES` lists a hosted deployment's `/api/*`
routes the spec does not document.

New in 0.44: `serve --quota-rate PER_SECOND [--quota-burst N]` gives every
(tenant, subject) a token bucket; an upload or ref update over quota gets 429
with `Retry-After`. At most `--quota-max-keys` buckets (10,000) are held, the
least recently used evicted first. Clients retry a 429 at most 3 times,
honouring `Retry-After` up to 30 seconds and within the request deadline; a
0.34 client reports `remote returned HTTP 429` and stops. `serve --vsa-dir DIR`
writes an in-toto SLSA Verification Summary Attestation
(`https://slsa.dev/verification_summary/v1`) for every admitted push to
`DIR/<tenant>/<sha256>.json`.

New in 0.46: `serve --trust-policy NAME=FILE` (repeatable) admits ref updates
only under a named server-side policy (`opentine.admission-policy` version 1,
schema `docs/schemas/opentine-admission-policy-1.schema.json`): `refs` globs
(required; fnmatch, so `*` also matches `/`: `heads/*` covers `heads/a/b`) and optional `tenants`, `roles`, `subjects`, `object_types` and the
`levels` the VSA records. Policies are tried in order and the first whose
tenants and refs cover the update decides; an update no policy covers, or one
the deciding policy refuses, gets 403, so naming any policy makes admission
fail-closed. Each VSA's `predicate.policy` is
`{"uri": "opentine:trust-policy/NAME", "digest": {"sha256": <file sha256>}}`.
`serve --vsa-signing-key FILE` (a 32-byte seed or 64-char hex) wraps each VSA
in a DSSE envelope signed by the server's own Ed25519 key, and
`GET /v1/capabilities` then lists `vsa.keys` (`{"kid", "alg", "public_key"}`,
as `webhooks.keys`) and the policy URIs under `vsa.policies` for a CI gate to
pin. The policy is operator configuration: nothing in a pushed repository
selects one, and the server signs VSAs only with its own key, never as a user. CI
integrations that gate on these VSAs are in [CI.md](CI.md).

New in 0.52 (SPEC 8.28): scoped, expiring, revocable API tokens.
`tine serve token mint --root R --tenant T --access read|write --ref NAMESPACE
[--ref ...] [--ttl 90d] [--label TEXT]` prints a `tine_pat_` token once (only
its SHA-256 is stored, in `R/auth.sqlite3`); a NAMESPACE is a ref
(`heads/main`), a prefix ending in `/` (`heads/ci/`) or `*` (the default).
`tine serve token list` shows the tenant's tokens without secrets and
`tine serve token revoke ID` revokes one; a running server sees both at its
next request. `--json` writes `tine-cli-serve-token-1`. A token limited to
namespaces lists, fetches and (with `write`) moves only refs inside them and
gets no other tenant route. `serve --ci-trust FILE` turns on the CI OIDC
exchange (`POST /v1/auth/oidc-exchange`) for GitHub Actions, GitLab and
Forgejo ID tokens: the JWT is checked against the JWKS FILE configures for its
issuer (`jwks`, `jwks_file` or an `https` `jwks_uri`), and the first rule whose
claims match, which must pin the repository, mints a `tine_ci_` token of at most
an hour, and never past the ID token's own expiry. Quotas are off by default
on a self-hosted server, so an upgrade never starts refusing it:
`serve --limits fair-use` applies the published fair-use limits the hosted
service uses (`GET /v1/limits` `fair_use`: 10 GiB stored, 20 GiB egress per
UTC day, 2 GiB mirror, 2000 runner minutes per month, per tenant), and
`serve --limits FILE` sets them (`{"base": "fair-use"|"unlimited",
"defaults": {...}, "tenants": {"T": {...}}}`, `null` for unlimited).
Over a limit a tenant's own caller gets `507` (storage) or `429` with
`Retry-After` (egress); nothing is ever deleted. `GET /v1/tenants/T/usage`
shows the tenant's use.

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

## Watching events (0.45.1)

* `tine watch [REMOTE|REPO] [--tenant T] [--token-file F] [--json]` tails a
  remote's event stream (`GET /v1/tenants/<t>/events`, Server-Sent Events) when
  given a URL or a configured remote name, reconnecting with `Last-Event-ID`;
  otherwise it polls the op log of the repository named (default `.`) every
  `--interval` seconds (2) and prints each new op as an `op.logged` event
  (`--from-start` prints the ops already logged too).
* `--once` stops after one stream or one poll; `--max-events N` after N events.
* `--json` is JSON Lines, not one object: each line is a `tine-watch/1` record
  holding a `tine-event/1` `event`, or `"reset": true` when the server says
  events were missed (re-list refs).

Event kinds, the SSE endpoint and signed webhooks: [EVENTS.md](EVENTS.md).

## Hosted remotes: share links, open, login (0.46)

These verbs take a remote by name (`tine remote add`) or URL, plus `--tenant`,
`--token-file` and `--allow-insecure` like `tine watch`. The token comes from
`--token-file`, the remote's `token_file` or `TINE_REMOTE_TOKEN` and is never
printed. The server side is `tine serve` (SPEC §8.14).

* `tine share create RUN [--ttl 7d] [--remote R] [--json]` asks the remote for
  a read-only link to one run that expires (`--ttl` seconds, or with an
  `s`/`m`/`h`/`d` suffix; at most 90 days). The token is shown once.
  `tine share list [--run RUN]` lists ids and states (`active`, `expired`,
  `revoked`), never tokens; `tine share revoke ID` revokes one. The verb is
  `tine share-link`; `--json` prints `tine-cli-share/1`.
* `tine open RUN [--remote R] [--web-url URL] [--print] [--json]` prints the
  run's page in the web app and opens it on a terminal. The base is
  `--web-url`, else `TINE_WEB_URL`, else the trusted `web.url` setting, else the
  remote's URL. `--json` prints `tine-cli-open/1`.
* `tine repo-search QUERY --remote R [--json]` searches the remote's runs
  (`caps.search`) instead of the local repository.
* `tine remote login NAME --issuer URL --client-id ID` signs in with the OAuth
  2.0 device-code flow (RFC 8628) against the issuer's OIDC discovery document:
  it prints the code and URL to enter on stderr, polls until approved, stores
  the `id_token` (or `--use-access-token`) owner-only under
  `$XDG_CONFIG_HOME/opentine/credentials/` and records that path as the
  remote's `token_file`.

## Offline verification (0.25)

```
tine verify RUN --offline                        # human report
tine verify RUN --offline --json --report r.json # tine-verify-report/2
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
tine timestamp data RUN --signature [N]
tine verify RUN --offline --report r.json --sign-key KEY [--timestamp]
tine verify-report data r.json
tine verify-report attach r.json TOKEN.tsr
tine verify-report check r.json [--pubkey P] [--tsa-roots FILE.pem] [--allow-unsigned] [--json]
```

0.39.0 (X20, X22). `timestamp data --signature` prints `sig:sha256:<hex>` of
the run's N-th signature block; a token over it verifies only while the run
carries that signature, and the report's `signing_time` is its genTime (the
verified signing time). Root-bound tokens keep verifying. `--sign-key` (an
Ed25519 key file from `tine keygen`, `--report` only) writes the
`tine-verify-report/2` as signed canonical JSON; `--timestamp` (needs
`--sign-key`) also writes `r.json.tsdata`, the bytes a TSA token over that
signature must cover. `verify-report check` verifies the report offline and
exits 0 when it is authentic (whatever verdict it records), 4 when its
signature or a token fails, and 4 for a `/1` or unsigned report unless
`--allow-unsigned` (SPEC §8.7).

```
tine replay RUN --verify --attest OUT.intoto.jsonl --attest-key KEY
```

Writes the verdict as an in-toto `replay/v1` DSSE envelope, predicate type
`https://opentine.dev/attestation/replay/v1` (SPEC §8.8). Both flags need
`--verify`; `--attest` needs `--attest-key`.

```
tine custody record ACTION SUBJECT --sign-key KEY [--actor A] [--note N] [--repo R]
tine custody record timestamp SIG_BOUND --token T.tsr --sign-key KEY
tine custody log [--json]
tine custody verify [--pubkey P] [--vkey V] [--tsa-roots FILE.pem] [--json]
```

Chain of custody on the repository's `opentine-log/1` (`.tine/log/custody`):
each record says who (`--actor`, default the login name) `received`,
`exported`, `verified`, `transferred` or `stored` what, when, and is signed by
that actor's Ed25519 key. A `timestamp` record stores a TSA token over an
earlier record's `sig_bound` (printed by `record` and `log`). `verify` checks
the checkpoint, tiles, hash chain, signatures and tokens offline and exits 4
on any break (SPEC §8.9).

```
tine witness vkey --key KEY --name NAME
tine witness cosign CHECKPOINT --log-vkey V --key KEY --name NAME
                    [--proof P.json | --tiles DIR] [--state DIR] [--out FILE] [--json]
tine witness serve --key KEY... --name NAME --log-vkey V... [--listen HOST:PORT] [--state DIR]
                   [--rate-limit N]
tine witness submit CHECKPOINT --url URL... [--tiles DIR] [--out FILE] [--json]
tine witness doctor --key KEY... --name NAME --log-vkey V... [--state DIR] [--registry FILE]
                    [--url URL] [--json]
tine verify TARGET --offline --witnesses N-of-M --witness-vkey V... [--log-vkey V...]
tine verify TARGET --offline --witnesses REGISTRY.json
tine bundle create FILE REF... --transparency
```

0.49, the witness network (SPEC 8.23; `docs/witness/`). `verify --offline
--witnesses REGISTRY.json` takes the quorum, the witness keys and the log key
from an `opentine-witness-network/1` registry (`docs/witness/NETWORK.md`) and
refuses one that is not a strict majority of three or more witnesses with
distinct operators, names and https URLs (e.g. 2-of-3); a cosignature by any
key a witness lists counts once, and `--witness-vkey`/`--log-vkey` are refused
alongside it. `--json` adds `"registry": {"log", "quorum"}`. `witness doctor`
is an operator's pre-flight check: keys load, key files are private (POSIX),
`--state` is writable, each log's stored checkpoint opens, the `--registry`
lists this witness with its keys and log, and `--url` answers `/health` and
serves exactly these keys at `/keys`. It prints each check (`--json`:
`tine-cli-witness-doctor/1`) and exits 4 when any fails. The runbook, the
container definition (`deploy/witness/`) and the recruitment notes are in
`docs/witness/`.

0.47, for witness operators (SPEC 8.23): `serve` takes `--key` more than once;
every key cosigns, the first is current, so a key is rotated by adding the next
one, waiting until verifiers pin both vkeys, then dropping the old one. `GET
/keys` lists the vkeys (current first) and `GET /health` answers `200
{"status": "ok", "witness", "keys", "logs": {origin: size}, "uptime_seconds",
"requests"}` (`503` `degraded` when `--state` cannot be written; no local path
is ever shown). `--rate-limit N` (default 60, 0 = off) is a per-client token
bucket on `POST /add-checkpoint`: an empty bucket is `429` with `Retry-After`.
The per-origin state is written before a cosignature is returned, so a
restarted witness still refuses a view inconsistent with one it signed.

0.44 (X33). `witness cosign` checks a signed-note checkpoint against the pinned
log key and against the last checkpoint this witness cosigned for that origin
(`--state`, default `$XDG_STATE_HOME/opentine/witness`): the same size must have
the same root, a smaller size is a rollback and a larger one needs an RFC 9162
consistency proof (`--proof`, or computed from a local tile mirror with
`--tiles`). Only then does it print the checkpoint with a C2SP
`cosignature/v1` line added; a fork or rollback exits 4. `witness vkey` prints
the key others pin with `--witness-vkey`. `verify --offline --witnesses N-of-M`
takes a bundle, an `opentine-tlog-receipt/1` file or a bare checkpoint (with
one `--log-vkey`) and exits 4 unless N of the M pinned witnesses cosigned every
checkpoint; `--log-vkey` pins a log key by origin (otherwise the receipt's key
is used, trust on first use). `bundle create --transparency` embeds op-log and
push receipts for the bundled refs so they verify from the bundle alone; such
bundles need opentine 0.44+ to read. `tine push` and `tine fetch` check the
remote's audit log automatically (SPEC §8.10).

0.45. `witness serve` runs the same checks behind the C2SP tlog-witness HTTP
endpoint `POST /add-checkpoint` (default `127.0.0.1`, a free port printed as
`listening on URL`): 200 returns the cosignature line, 409 the size the witness
holds, 404 an unknown log, 403 a bad log signature and 422 a fork or rollback.
`witness submit` sends a checkpoint to each `--url`, answers a 409 with a
consistency proof from `--tiles`, and prints the checkpoint with every
cosignature gathered; it exits 4 when no witness cosigned. Log appends are
O(log n) and the log format is unchanged (`docs/design/log-2.md`).

```
tine scitt verify STATEMENT --key PEM [--receipt R]... [--service-key PEM] --experimental
```

0.44, **experimental**: a COSE_Sign1 SCITT signed statement and its
RFC9162_SHA256 receipts, verified offline against pinned keys (SPEC §8.12).
Without `--experimental` it exits 2. Interop with scitt-api-emulator is not
claimed. 0.47 re-checked the roadmap's condition for dropping the flag and
for emitting statements (interop with scitt-api-emulator shown offline from
recorded fixtures) and it is not met: the repository holds no
emulator-produced statement or receipt, and the emulator's receipts follow
CCF and earlier draft layouts rather than the RFC9162_SHA256 leaf rule of
SPEC §8.12. Verification stays behind `--experimental` and no emitter ships.

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

## Browser trust bundles (0.51)

```
tine trust bundle create --key owner.key --name example.com/trust --serial 7 \
    [--policy NAME | --pin sha256:HEX...] [--witnesses network.json] [--log-vkey VKEY]... \
    [--admission NAME=policy.json]... [--expires 2027-06-01T00:00:00Z] [--out bundle.note] [--json]
tine trust bundle verify bundle.note --owner-vkey VKEY [--min-serial N] [--json]
```

A trust bundle is the trust configuration a browser viewer (`tine ui`,
opentine-web) pins, signed by its owner (SPEC 8.26). It holds only existing
documents: a trust policy's portable fields (`pin` fingerprints,
`require_receipt`, the keyless identity fields, `key_lifecycle`; a policy that
names local files is refused), an `opentine-witness-network/1` registry, pinned
signed-note log keys and `opentine.admission-policy` documents. `create` prints
the owner's verifier key (`owner_vkey`), which viewers pin out of band; `verify`
checks the signature against it, the expiry and, with `--min-serial`, that the
bundle is not older than one already accepted, and exits 4 otherwise. `--json`
writes `tine-cli-trust-bundle/1` (Part 12, `tine-cli-trust-bundle-1`).

A viewer page names the bundle with `<meta name="opentine-trust-bundle"
content="URL">` and the owner key with `<meta name="opentine-trust-owner"
content="VKEY">`. The browser verifier then reads a signature by a pinned key as
verified, and one by any other key as failed, exactly like `tine verify --pin`.
It remembers the highest serial it accepted. The TS command line takes the same
bundle: `opentine-verify FILE --trust-bundle bundle.note --owner-vkey VKEY`.

## Keyless run signing: `tine sign --keyless`, `tine keyless verify` (0.74)

```
tine sign RUN --keyless [--rekor URL] [--fulcio-url URL] [--output FILE] [--overwrite] [--json]
tine keyless verify BUNDLE --fulcio-root PEM --rekor-key PEM [--run RUN] [--trust-bundle FILE] [--json]
```

`sign --keyless` is for CI jobs and runners. It reads the OIDC token from
`SIGSTORE_ID_TOKEN` or the GitHub Actions ambient token, gets a short-lived
Fulcio certificate, signs the run's in-toto statement and logs the signature to
Rekor. It writes the existing Sigstore bundle (`RUN.sigstore.json`).
`keyless verify` checks the bundle offline: the receipt, the inclusion proof
against the signed tree head, the signature, the chain to `--fulcio-root`, and
the certificate window at the log's integrated time (outside it:
`caveat:keyless-outside-window`). It then reports the identity and its
assurance tier. An identity is trusted (`keyless.trusted`, exit 0) only when
the owner-pinned trust bundle's `trust_policy` names its exact
`cert_oidc_issuer` and `cert_identity`; otherwise the result is
`caveat:keyless-unpinned` (exit 1). `--json` writes `tine-cli-keyless/1`. See
[KEYLESS.md](KEYLESS.md).

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

### Vendor I/O (0.46)

```sh
tine export RUN --format langfuse --output langfuse.json      # POST /api/public/ingestion body
tine export RUN --format phoenix|braintrust|langsmith --output FILE
tine import FILE --format langfuse|phoenix|braintrust|langsmith --repo runs
```

Files only (an `--endpoint` is refused): the vendor's ingestion body, or its own
export, through the OTLP importer. Scores travel as `gen_ai.evaluation.result`
and each vendor's native score record. See [VENDOR_IO.md](VENDOR_IO.md).

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

`--format run-crate` (0.48) writes a Provenance Run Crate: RO-Crate 1.1 plus
the Workflow Run RO-Crate profiles 0.5 (process, workflow, provenance). Each
step is a `HowToStep` run by a `CreateAction` (the model or tool is its
`instrument`), linked by a `ControlAction` and orchestrated by opentine's
`OrganizeAction`; see SPEC §12.5. It is deterministic like `ro-crate`.

## Compliance profiles: `tine compliance` (0.48)

**Draft — not legal advice, pending counsel review.** No external counsel
sign-off is recorded yet.

```
tine compliance list [--json]
tine compliance check RUN --profile NAME|FILE [--repo DIR] [--pubkey FILE] [--pin FPR]
    [--tsa-roots FILE.pem] [--attestation FILE --rekor-key FILE] [--trusted-root FILE]
    [--proxy-pubkey FILE] [--strict] [--json]
```

Profiles are data in [`docs/compliance/`](compliance/): `fre-902` (US FRE
902(13)/(14)), `eu-ai-act` (EU AI Act Art. 12, 19, 26) and `eidas` (eIDAS as
amended by 2024/1183). Each requirement cites its article or rule and lists the
OpenTine evidence that shows it. `check` runs the offline verifier with the
given keys and roots, reads `--repo`'s `retention.toml` and custody log, and
reports every requirement as `evidenced`, `missing` (with the fact that is
missing and why) or `out-of-scope` (organisational duties, qualified trust
services). It exits 0 whatever the result; `--strict` exits 4 when anything in
scope is missing. `--json` writes `tine-cli-compliance-check-1` and `list
--json` `tine-cli-compliance-list-1`.

## Air-gapped audit kit: `tine audit-kit` (0.49)

```
tine audit-kit build RUN... | BUNDLE --out DIR [--zip] [--pubkey FILE] [--pin FPR]
    [--action-policy FILE] [--trusted-root FILE] [--sign KEY]
    [--attest-key KEY | --replay-attestation FILE [--replay-pubkey FILE]]
    [--witness VKEY]... [--witness-set FILE] [--log-key FILE]... [--quorum N-of-M]
    [--operator NAME] [--allow-unredacted] [--json]
tine audit-kit verify DIR|ZIP [--pyz] [--pubkey FILE] [--json]
```

`build` writes a self-contained directory (and with `--zip` a deterministic
`DIR.zip`): `tine-verify.pyz`, `verify.html` (the TS verifier as one offline
page with the runs embedded), the evidence folder (`tine evidence export
--with-verifier`), each run's Provenance Run Crate, a `replay/v1` attestation
(`--attest-key` replays the run now in cache mode and signs the verdict;
`--replay-attestation` copies one), the pinned witness set and log keys,
`REPORT.md`/`report.html` (the printed report; no PDF), the artifact-evaluation
package `ae/` (an ACM-badge README, `verify_kit.py` needing only the standard
library, `verify.sh`, `verify.ps1`, `reproduce.sh`) and `SHA256SUMS`. A bundle
input is verified and its runs are written out; the bundle is kept in
`source/`. `verify` re-checks everything with the network refused (SPEC
§8.4.1); `--pyz` also runs the kit's own pyz in a separate process. Without
opentine: `python3 -I ae/verify_kit.py`, then open `verify.html`. Both exit 1
when a check fails; `--json` writes `tine-cli-audit-kit-build-1` (also the kit's
`kit.json`) and `tine-cli-audit-kit-verify-1`.

A kit is made to be handed out, so `build` refuses (exit 2, nothing written) a
run that the redaction ruleset would still change; build from `tine bundle
create --redacted-public` instead, or pass `--allow-unredacted`. Whoever alters
a kit can also regenerate `SHA256SUMS` and its `pubkey.pub`, so without an
outside key `verify` proves integrity only (its `anchor` check is `skip`);
`verify --pubkey FILE` pins the run signatures to a key obtained separately and
fails `anchor` when the kit carries another. `verify` refuses links and special
files in a kit directory, and unsafe, linked, duplicate or oversized zip entries.

## Leaving a hosted service: `tine tenant` (0.50)

```
tine tenant export [--remote REMOTE] [--tenant T] [--token-file F] --out DIR [--json]
tine tenant import DIR [--repo PATH | --remote REMOTE [--tenant T] [--token-file F]] [--json]
```

`export` refuses a non-empty DIR, then writes everything a `tine serve` tenant holds that leaves in a format
frozen at 0.48: `tenant.tbundle` (a bundle of every tenant ref whose closure the
server holds, with tombstones and `tine-sig/3` sidecars), `reviews/ID.json`
(each Review as its `opentine-review-bundle-1`), `log/checkpoint.json` and
`log/entries.json` (the server's signed checkpoint and this tenant's log
entries, as the API returned them) and `shares.json` (share-link ids, runs and
expiry; never a token). `import` installs the bundle and the Reviews into a
local repository under the same ref names, refusing to move a ref that already
points elsewhere, or with `--remote` imports them into another `tine serve`
tenant all or nothing (0.52): the objects are uploaded first, then one `POST
import` (`caps.tenant_import`) creates every ref, Review and project version
together, and an interrupted or refused import leaves the tenant unchanged (run
it again to finish). A server without `caps.tenant_import` is refused.
`tine verify . --offline --json` then prints the same bytes in either place.
`--json` writes `tine-cli-tenant-1`. The walkthrough, and what cannot move, is
[LEAVING.md](LEAVING.md).

## Alerts: `tine alert` (0.49)

```
tine alert add NAME --on verify.failed|policy.denied|cost.threshold|witness.disagreement
    [--threshold USD] [--webhook URL] [--otlp ENDPOINT] [--allow-private] [--replace]
tine alert list | remove NAME
tine alert test [NAME] [--event FILE] [--always] [--dry-run]
tine watch [REPO|REMOTE] --alerts
```

Rules live in `.tine/alerts/rules.json`. Alerts are evaluated on `tine-event/1`
events: `op.logged` and `run.created` announce runs, which are loaded from the
repository and checked (an attestation whose signature does not verify, a
`policy` step with a deny decision, a total cost above `--threshold` USD);
`log.checkpoint` events are compared with the last checkpoint of the same
origin (a rollback or fork is a `witness.disagreement`). A webhook delivery is
a `tine-webhook/1` body (SPEC 8.13) whose `event` is the triggering event, with
an `alert` member added, signed with `.tine/alerts/webhook-ed25519.key`
(created by the first webhook delivery); `list` prints its `kid` and
`public_key` for the receiver to pin once it exists, and never creates it. Targets must be
`https://` global addresses unless `--allow-private`; 408/429/5xx are retried
(3 attempts). An OTLP delivery POSTs one OTLP/JSON log record per alert to
`ENDPOINT/v1/logs` (severity `ERROR` for verify and witness alerts, else
`WARN`; `opentine.alert.*` attributes); it may be `http://` but, like a webhook,
must not carry credentials or name (or resolve to) a private, loopback or
reserved address unless `--allow-private`. Both sinks resolve the host once,
check every address and connect to the checked one, so a rebinding DNS answer
cannot redirect the request (0.52). Stored rules are re-checked when
read, so a hand-edited `rules.json` cannot bypass these checks. `test` evaluates the newest op-log entry
(or `--event FILE`: an event or a `tine watch --json` line) and delivers what
trips; `--always` also sends a `test: true` alert for each other rule. `--json`
writes `tine-cli-alert-1`; `test` exits 1 when a delivery failed. `tine watch
--alerts` evaluates the rules on every event it reports.

## Jules and A2A import (0.49)

```
tine import session.json --format jules --save run.tine
tine import task.jsonl --format a2a --repo .
```

`jules` reads a Jules session as its REST API returns it (`{"session",
"activities"}`, a list-activities response, a bare activity list, or JSONL
pages): the prompt and user messages become human steps, agent messages, plans
and progress model steps (`jules`/`google`, no token usage is reported),
`planApproved` an approval and `sessionFailed` an error; `bashOutput`,
`changeSet` (patch, base commit, suggested message) and `media` (MIME type and
size only) artifacts become tool steps. `a2a` reads Agent2Agent tasks,
messages and `status-update`/`artifact-update` stream events, bare or in
JSON-RPC envelopes, one JSON document or JSONL; messages are de-duplicated by
`messageId`, `failed`/`rejected` states become errors and
`input-required`/`auth-required` approvals; file parts keep name, MIME type and
URI, never inline bytes. Neither is auto-detected; pass `--format`. Sources:
`tests/fixtures/jules/SOURCE.txt`, `tests/fixtures/a2a/SOURCE.txt`.

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

### Per-checkpoint refs, `--all` and export (0.42)

```
tine import . --format entire --save run.tine          # refs first, v1 branch as fallback
tine import . --format entire --all --repo runs        # every checkpoint session, one run each
tine export run.tine --format entire --output ~/proj   # write the run as a checkpoint ref
```

Current entireio/cli keeps one ref per checkpoint,
`refs/entire/checkpoints/<id[-2:]>/<id>`, whose commit tree *is* the checkpoint
(`metadata.json`, `0/`, `1/` ...; sessions listed as `/<N>/metadata.json`).
Those refs are read first, newest commit first; any checkpoint id found only on
the `entire/checkpoints/v1` branch is read from there. `attributes["entire"]
["layout"]` says which (`refs` or `branch`). `--all` records each session of
each checkpoint on `heads/entire/<id, lowercased>/<N>` and needs `--repo`
(`--save`, `--ref` and `--fleet` are refused with it); with `--json` it prints
`{"command": "import", "format": "entire", "all": true, "runs": [...]}`.

`export --format entire` writes the run, redacted, as one checkpoint in the
`--output` git repository: a 12-hex id derived from the run id, a Claude Code
`full.jsonl`, `prompt.txt`, `content_hash.txt` and both metadata files, committed
with Entire's `Checkpoint: <id>` message and `Entire-Session`/`-Strategy`/`-Agent`
trailers. Only git objects and that one ref are written. Exporting the same run
again is a no-op; a changed run becomes a child commit on the same ref.

## Cline and Roo Code task import (0.42)

```
tine import ~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/tasks/1730985600000 --save run.tine
tine import --from-default-location --format roo-task          # list Roo Code tasks
```

SOURCE is a task directory (or its `api_conversation_history.json`);
`ui_messages.json` and Cline's `task_metadata.json` beside it are read when
present. Each assistant message is a model step, tool results (native
`tool_result` blocks or the `[tool for 'x'] Result:` text convention) are tool
steps, and other user turns human steps, with `<environment_details>` blocks
dropped. Token usage comes from the matching `api_req_started` record (Roo's
`apiProtocol: "openai"` counts cache reads inside `tokensIn`), else from the
message's `metrics`. `auto` tells Roo from Cline by the
`rooveterinaryinc.roo-cline` folder in the path. Windsurf is not supported: it
has no documented local session format.

# Writer format (0.26, 0.42)

Since 0.42 `.tine` files are written as **format v5** (SPEC Part 10): the v4
document with UTF-8 text blobs spelled as text, carrying the same oids, root
and `tine-sig/3` signatures; opentine 0.40 or newer reads it. `--for-legacy`
writes v4 for older readers, and `tine evidence export` always copies its runs
as v4. Since 0.26 every writer produces **format v4** objects (SPEC Part 9):
`.tine` files were `tine-artifact/4` until 0.42, signatures `tine-sig/3`, Ed25519 attestations on a run
`tine-attest/2`, and `tine init` creates an object-format-4 repository (an
existing repository is marked object format 4 before the first object 0.26
writes into it). Reading never changes: every older file and repository stays
readable, and a read never rewrites it.

| Spelling | Writes |
| --- | --- |
| *(default)* | format v5 `.tine` files (SPEC Part 10; opentine >= 0.40 reads); new repositories object format 4 |
| `tine --for-legacy COMMAND ...` (or `--format 4`) | format v4 `.tine` files, for readers before 0.40, for this command only |
| `tine --format 2 COMMAND ...` | the deprecated v2 file / object-format-3 repository writers, for this command only |
| `OPENTINE_FORMAT=2` (or `3`) | the same, for the whole environment |
| `OPENTINE_FORMAT=4` | v4 files for the whole environment, strict: no deprecated block even where v4 cannot express it (an HMAC attestation, `sign_artifact` on a v2 dict) |
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

## FIPS mode (0.41)

```
tine --fips COMMAND ...          # or OPENTINE_FIPS=1
```

`--fips` is global, like `--format`. Without an active OpenSSL FIPS provider
in `cryptography` every command fails before it runs with exit 6
(`trust_required`) and, under `--json`, `{"error": {"code": "trust_required",
...}}`. A non-approved primitive met later (ChaCha20-Poly1305, writing the
archival xz form) fails the same way. `tine verify --offline --json` adds
`crypto: {mode, provider_fips, openssl}` to the report.

`tine serve --root R --tenant T reseal --to aes6` rewrites a tenant's objects
as `TINEAES6` (key id, epoch, XAES-256-GCM); it needs `TINE_KMS_KEY_ID` set.

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
| `code_graph` (0.48) | `tine code-graph [PATH] [--symbol NAME] --repo REPO --json` |

New in 0.44, `recall(query, limit=10)` is a hand-written read tool over the
derived search index (`tine repo-search --rebuild-index`, see
[REPOSITORY.md](REPOSITORY.md)): runs whose stored text mentions every word of
the query, best BM25 match first, at most 50 rows of run id, status, models and
a snippet of at most 240 characters. It never scans the store or builds the
index; without one it answers `{"indexed": false, ...}`.

New in 0.46, `tine repo-search QUERY --hybrid [--embedder hash|MODULE:ATTR]`
fuses the BM25 ranking with a local embedding index of redacted text
(`.tine/index/embed.sqlite`) by reciprocal rank fusion; `--json` adds
`hybrid` and `embedder`. `--hybrid` with `--no-index`, and `--embedder` without
`--hybrid`, are usage errors. The `embed` extra (`opentine[embed]`) adds numpy
for the similarity scan. See [PII.md](PII.md#hybrid-search).

## Cost export (0.44)

```text
tine cost RUN --otlp PATH|-                     # OTLP/JSON metrics from the cost aggregate
tine cost RUN --statement PATH --sign-key KEY [--signer NAME]
tine cost RUN --verify-statement PATH [--pubkey KEY.pub]
```

`--otlp` writes an `ExportMetricsServiceRequest` (a `/v1/metrics` body):
`gen_ai.client.token.usage` by `gen_ai.token.type` and `opentine.cost.usd` in
total, by `gen_ai.request.model` and by `opentine.step.kind`, as cumulative
sums on a resource carrying `opentine.run.id`. `--statement` writes a
`tine-cost-statement/1`: the aggregate (totals, tokens, by model, by kind) with
an Ed25519 `tine-sig/3` block under `opentine.cost-statement.v1:`.
`--verify-statement` recomputes the aggregate from RUN and prints
`{"ok", "matches_run", "signature", "basis"}`, exiting 4 unless both the numbers
and the signature check (without `--pubkey` the embedded key is trusted on first
use, and `basis` says so). The statement covers the cost the run *recorded*;
`tine price` re-prices from the catalog.

## Per-turn capture (0.38)

| Command | What it does |
| --- | --- |
| `tine hook capture [--agent NAME] [--event NAME] --repo PATH` | `opentine-hook/1`: one JSON event on stdin becomes one durable step of the session's run; prints a JSON response and always exits 0 |
| `tine enable [--agent NAME] [--dry-run] --repo PATH` | Adds the capture shims to the Claude Code, Codex, Gemini CLI, Copilot CLI, Factory Droid and Antigravity hook files and sets `hooks.capture`; `--dry-run` prints the unified diff only |
| `tine disable [--agent NAME] [--dry-run]` | Restores each hook file byte for byte (or removes only the shims if it was edited since) |
| `tine hook resume --agent codex\|gemini\|claude-code --session ID --message TEXT [--repo PATH] [--dry-run]` | 0.46: continues an ended session with the CLI's own resume command (`codex exec resume`, `gemini --resume`, `claude --resume`), run without a shell (resolved on PATH; a Windows `.cmd` shim refuses messages with cmd.exe metacharacters); `--repo` first records the message as a `steer` step on the session's capture run; `--dry-run` prints the plan (`tine-cli-hook-resume-1`) |

Capture records nothing unless the repository's trusted config sets
`hooks.capture`. See [CAPTURE.md](CAPTURE.md#per-turn-capture-tine-hook-capture-opentine-hook1).

Since 0.46 a `tine fleet send` message steers Codex (its `Stop` hook answers
`{"decision": "block", "reason": ...}`) and Gemini CLI (`AfterAgent`,
`{"decision": "deny", "reason": ...}`) as well as Claude Code. The protocol
is published as [`docs/spec/hook-1.md`](spec/hook-1.md) (SPEC 8.16, vectors
`67-hook.json`).

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

## OTLP ingest: protobuf logs and gRPC (0.48)

| Command | What it does |
| --- | --- |
| `tine serve --otlp [--otlp-port 4318]` | OTLP/HTTP: `/v1/traces` and `/v1/logs` take OTLP/JSON or `application/x-protobuf` (logs protobuf is new in 0.48); loopback only unless `--insecure-dev-any-host` |
| `tine serve --otlp --otlp-protocol grpc\|both [--otlp-grpc-port 4317]` | OTLP/gRPC (`TraceService/Export`, `LogsService/Export`) into the same collector; needs `opentine[grpc]` |
| `... --otlp-token-file FILE` | Every gRPC call must send `authorization: Bearer <token>` (16..4096 bytes, compared in constant time) |
| `... --cert PEM --key PEM` | Serves gRPC over TLS; off loopback both TLS and a token are required, with no override |
| `tine import FILE --format otlp-proto-logs` | Imports an OTLP protobuf `ExportLogsServiceRequest` |

`--max-body-mb` bounds a gRPC message both on the wire and after
decompression. The controls and what is left open are in
[security/otlp-grpc-review.md](security/otlp-grpc-review.md);
`scripts/fuzz_otlp.py` is the fuzzer (CI runs it scaled; the 72-hour run is
`--hours 72`). Since 0.53 `scripts/fuzz.py` also fuzzes the `.tine` v4/v5, pack,
local pack and DSSE readers; see the 72-hour fuzz run in [RELEASING.md](RELEASING.md).

## Assurance tiers (0.39)

| Command | What it does |
| --- | --- |
| `tine proxy keygen [--force] [--json]` | Creates the proxy witness key (Ed25519) under `$XDG_CONFIG_HOME/opentine/proxy-keys/`, apart from every agent key; `tine record` and `tine mcp-proxy` sign their finished runs with it (`tine-sig/3`) |
| `tine verify RUN --min-assurance T0..T3` | Exits 4 (`verification_failed`) when the *verified* tier is below the floor |
| `tine verify RUN --proxy-pubkey FILE` | Also trusts this proxy public key as a T2 witness (repeatable) |
| `tine verify RUN --min-assurance T3 --tsa-roots FILE.pem` | Lets an attached RFC 3161 token count toward T3 (outside `--offline`, `--tsa-roots` needs a floor) |
| `tine verify RUN --model-signature BUNDLE [--model PATH] [--model-pubkey PEM]` | 0.48: checks an OpenSSF Model Signing (OMS v1.0) bundle under a pinned P-256 key, and the model's files when `--model` is given, as the `oms-model-signature` factor in `assurance.factors`; a failed factor exits 4. Keyless bundles are refused as `oms.unsupported` (SPEC 4.24) |
| `tine verify RUN --compare-capture OTHER [--json]` | Divergence report: the better-witnessed run against the other, step by step (MCP `tools/call` and prompts); exits 4 when they diverge |

Tiers: **T0** self-reported import, **T1** hook-captured, **T2** witnessed by
the record proxy or `tine mcp-proxy` and signed with a trusted proxy key,
**T3** T2 plus a verified timestamp. The tier a capture *claims* is recorded
(`metadata.capture.claimed_tier`); the tier reported is *computed* at verify
time, and a claim alone never rises above T1. Every report carries an
`assurance` object, `{"claimed", "verified", "witness", "reasons"}`: `tine
verify --json`, `tine verify --offline` (and so the MCP `verify_run` tool) and
`tine show --json`; the human output prints one `assurance` line.

## Key storage and signers (0.41)

| Command | What it does |
| --- | --- |
| `tine keygen --out PATH` / `--agent NAME` | Writes the private key as encrypted PKCS#8 (PEM, PBES2/AES-256); `--unencrypted` writes the deprecated plaintext-hex form |
| `tine key encrypt PATH [--json]` | Rewrites a plaintext-hex private key as encrypted PKCS#8 in place; an encrypted key is left alone (`"changed": false`) |
| `tine key show SIGNER [--json]` | Opens a signer and prints its `signer`, `algorithm`, `key_id` (`sha256:<hex>`) and `public_key` |
| `tine proxy keygen --signer URI [--force]` | Makes the key an agent, HSM or KMS holds the proxy witness key; only the URI and the public half are stored |
| `tine proxy migrate --to URI [--json]` | Moves the proxy key into a signer; the old pair goes to `proxy-keys/retired/` and stays trusted for runs it signed |

The passphrase for an encrypted key comes from `OPENTINE_KEY_PASSPHRASE`, the
OS keyring (`OPENTINE_KEY_KEYRING=1` with `pip install 'opentine[keyring]'`),
or a prompt when stdin is a terminal; with none, `keygen` refuses (exit 1) and
loading the key fails. A plaintext-hex key still loads, with a
`PlaintextKeyWarning` on stderr.

Every flag that takes an Ed25519 signing key file (`sign --ed25519-key-file`,
`custody record --sign-key`, `verify --offline --report --sign-key`, `evidence
export --sign`, `replay --attest-key`, `push --ed25519-key-file`, `export
--format intoto --ed25519-key-file`, `actions sign`) also takes a signer URI:

| Signer | Backend |
| --- | --- |
| `file:PATH` or `PATH` | A key file (encrypted PKCS#8, or legacy hex) |
| `ssh-agent:FINGERPRINT` | An Ed25519 key in `ssh-agent` (`SSH_AUTH_SOCK`); `SHA256:...` as `ssh-add -l` prints it, `sha256:<hex>`, or `*` for the only one |
| `pkcs11:token=T;object=O?module-path=LIB` | An HSM via `opentine[pkcs11]` (`CKM_EDDSA`); PIN from `pin-source=env:VAR`, `pin-value=` or `OPENTINE_PKCS11_PIN` |
| `kms:aws:ARN` | AWS KMS `ECC_NIST_EDWARDS25519`, `ED25519_SHA_512` over the raw message (at most 4096 bytes), via `opentine[kms-aws]` |
| `kms:gcp:RESOURCE` | GCP Cloud KMS `EC_SIGN_ED25519` (`.../cryptoKeyVersions/N`), via `opentine[kms-gcp]` |

The flag is not spelled `--signer` there because `tine sign --signer` already
names the signer recorded in the block. Every backend's signature is checked
against its public key before it is used.

## Key lifecycle and verifier hardening (0.41)

| Command | What it does |
| --- | --- |
| `tine key rotate KEY [--out NEW] [--json]` | A new Ed25519 key, written as encrypted PKCS#8, replaces the private key file KEY (and `KEY.pub`); the old pair is kept as `KEY-retired-<fp12>`. The old key gets `not_after = now`, the new one `not_before = now`, and the old key signs an endorsement of the new one (`tine-key-rotation/1`). `--out NEW` writes the new key elsewhere and leaves KEY in place |
| `tine key rotate --agent NAME` / `--proxy` | The same for an agent key (`keygen --agent`) or the proxy witness key (`proxy keygen`); the retired proxy key goes to `proxy-keys/retired/`, as with `proxy migrate`, and stays trusted for T2. A proxy key held by a signer is refused (use `proxy migrate`) |
| `tine key revoke KEY [--at TIME] [--json]` | Records `revoked_at` (RFC 3339, default now) for `sha256:<hex>`, a `.pub` file or a private key file. An earlier revocation already recorded stands; a malformed `--at` is a usage error (exit 2) |
| `tine verify RUN --offline --tsa-policy OID` | Accept only RFC 3161 tokens issued under this TSA policy (repeatable) |
| `tine verify RUN ... --allow-stale-root` | Use the TUF-installed trusted root even though its metadata has expired (a warning on stderr) |

Both `tine key` verbs write only `$XDG_CONFIG_HOME/opentine/key-lifecycle.json`.

## Fleet records and delegation (0.43)

| Command | What it does |
| --- | --- |
| `tine key delegate KEY --to PUB --agent NAME --action NAME [--max-depth N] [--not-before T] [--not-after T \| --days N] [--parent CHAIN] --out CHAIN [--json]` | KEY signs an `opentine-delegation/1` certificate (SPEC 4.10) giving PUB the named agents and tools (`*` is any) for the window (default now to now + 30 days); `--out` gets the chain, root first, with `--parent`'s certificates before the new one. `--agent` and `--action` repeat |
| `tine key delegation show CHAIN [--json]` | Each certificate's digest, issuer, subject, window, parent and scope |
| `tine key delegation verify CHAIN --signer PUB\|FPR [--at T] [--agent NAME] [--action NAME] [--root FPR] [--json]` | Verifies the chain offline for that signer at T (default now); exit 4 and the `delegation.*` code (`expired`, `scope-violation`, `broken-chain`, `wrong-signer`, `bad-signature`, `too-deep`, `malformed`) when it fails |
| `tine fleet record RUN.tine [--json]` | The run's `opentine-fleet/1` record (SPEC 4.11), captured from `OPENTINE_FLEET_ID`/`_MEMBER`/`_ROLE`/`_PARENT`, and the length of its delegation chain |
| `tine fleet record RUN.tine --sign-key KEY --out FILE` | Writes an `opentine-fleet-record/1` document: the record bound to the run's id and digest under a `tine-sig/3` block |
| `tine fleet record RUN.tine --attest OUT --attest-key KEY` | Writes an in-toto `https://opentine.dev/attestation/fleet/v1` DSSE envelope whose subject is the run's digest |
| `tine fleet record FILE [--pubkey PUB]` | On a signed fleet record: verifies it offline (exit 4 on failure); without `--pubkey` the embedded key is trusted on first use |

A capture with `OPENTINE_DELEGATION=CHAIN` stores the chain in the run;
`tine verify RUN --offline` then adds a required `delegation` check: the chain
must verify for the run's signer at its signing time, its agent (agt_ ref,
harness, fleet member or role) and every tool it used. The check's detail lists
the chain root first; its trust basis says whether the root is one of `--pin`.
A trusted `.tine/agents.toml` may also carry windows
(`[agents.NAME.lifecycle."sha256:<hex>"] not_after = "..."`), as may a trust
policy's `key_lifecycle` table; the strictest window wins.

`tine verify RUN --offline` adds a `key-lifecycle` check whenever a window
names the signer key, judged against the report's verified `signing_time` (a
signature-bound RFC 3161 token): `lifecycle.valid`, `lifecycle.expired`,
`lifecycle.not-yet-valid` or `lifecycle.revoked`. With no verified time it is
`unavailable-offline` / `lifecycle.unverified-time`, except that a revoked key
fails (`lifecycle.revoked-unverified-time`) and a claimed `signed_at` outside
the window fails. Plain `tine verify RUN --pubkey/--pin` has no verified time:
it exits 4 (`verification_failed`) on those failures and otherwise notes that
the window was checked against an unverified time.

Timestamp tokens now fail with `timestamp.signing-cert-mismatch` (no single
ESS signingCertificate/V2 attribute binding the TSA certificate),
`timestamp.critical-extension`, `timestamp.policy-not-allowed`, or
`timestamp.missing-eku` when the timeStamping EKU is not critical or not alone;
genTime plus or minus the token's accuracy must lie inside the TSA validity.
An attestation's `tine-attest/2` record must be signed by the DSSE envelope's
key; the detail says `record bound` (0.41 records name `signer_key`) or
`record unbound` (older records, still accepted). Keyless verification refuses
(exit 6) a TUF-installed trusted root whose stored metadata has expired.

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

## Local run viewer: `tine ui` (0.45)

`tine ui [RUN] [--port N] [--open]` serves a read-only viewer on 127.0.0.1
(never another interface; `--port 0`, the default, picks a free port). Without
RUN it lists every run in the runs directory (up to the CLI scan limit). Tabs:
timeline (prompt, model, tool, human and steer steps; each step's input parts,
tool arguments and results load when expanded), workspace (files rebuilt from
recorded writes at step N, and a unified diff between two steps), run DAG
(`parents[]`, `forked_from`, children, merge steps), fleet groups, verify and
attribution (the step and model that last wrote each file).

- **Redaction:** every string, keys included, is re-redacted at serve time;
  text the redactor cannot read is withheld.
- **No network:** the server answers GET and HEAD only, and its
  Content-Security-Policy allows nothing but its own origin (`connect-src
  'self'`). The page fetches no external resource. A request whose `Host` is
  not `127.0.0.1:PORT` or `localhost:PORT` gets 403, so a DNS-rebinding page
  cannot read runs; `--port` must be 0..65535.
- **Verification states** are `verified`, `failed`, `partial`, `unchecked` and
  `unpinned`, each labelled with who computed it. Integrity and assurance are
  checked by the local `tine`; a signature is `unpinned` because `tine ui` pins
  no key (use `tine verify --pubkey`). Since 0.45.1 the browser re-checks the
  run itself: a Web Worker runs the TS verifier's browser bundle
  (`tine-verifier.js`) over the artifact bytes and shows its own integrity and
  signature states beside local `tine`'s. With no key pinned, a signature that
  holds under the key the file embeds reads `unpinned`, an HMAC one `unchecked`,
  and one that does not hold `failed` (which fails the badge). The bytes are
  served only when the current redaction ruleset finds nothing in the decoded
  artifact; otherwise the request gets 403 and the browser column reads
  `unchecked`, saying why.
- **Assets** are built from `ts/run-viewer` (`npm ci` in `ts/verifier` and
  `ts/run-viewer`, then `npm run build`: `tsc` for the viewer, pinned esbuild
  for `tine-verifier.js`) into `opentine/data/ui` and committed; tests rebuild
  them and compare bytes.

JSON API (same origin, all redacted): `/api/runs`, `/api/run/RUN`,
`/api/run/RUN/step/N`, `/api/run/RUN/verify`, `/api/run/RUN/attribution`,
`/api/run/RUN/tree?step=N`, `/api/run/RUN/diff?a=N&b=M`, and (0.45.1)
`/api/run/RUN/artifact`, the raw artifact bytes for the browser re-check (403
when withheld). It is not a stable interface yet.

## Pre-push redaction gate, `tine redact check` and `tine doctor` (0.45)

```
tine push REMOTE [--allow-unredacted REASON] ...
tine bundle push REMOTE [REF]... [--allow-unredacted REASON]
tine redact check [--run RUN]... [--key-file K | --ed25519-key-file K] [--key-id ID]
                  [--out PATH] [--json] [--repo R]
                  [--pii [--classifier rules|none|MODULE:ATTR]]     # 0.46
tine redact verify REPORT [--key-file K | --pubkey K.pub] [--json]   # 0.45.1
tine redact rules [--json]                                           # 0.45.1
tine doctor [--bundle PATH] [--json] [--repo R]
```

Before a real push sends anything, every outgoing object is re-scanned with
the current redaction ruleset (`opentine-redaction/2`): first, offline, the set
`--dry-run` counts from the tracking refs, then again the exact pack negotiated
with the server (it can hold more, e.g. after the remote was reset). `tine
bundle push` and the git pre-push run sync are gated the same way over every
object the bundle carries. An object the redactor would still change, or one
that cannot be decoded, is a finding, and the push is refused (exit 1) naming
the object ids -- never the matched bytes. `--allow-unredacted REASON` pushes
anyway; before anything is sent it writes an op-log entry (`tine op log`,
command `push`, no ref moves) whose `note` is `allow-unredacted: REASON (N
object(s))`, with REASON itself redacted, and a failed write refuses the push.
`tine undo` with no selector skips such note-only entries. `--dry-run` is not
gated; it warns on stderr when the real push would be refused.

`tine redact check` prints one redaction report per run reachable from
`heads/*` (or each `--run`): `{kind: "opentine.redaction-report",
report_version: 1, ruleset, run, objects, findings: [{oid, kind}], clean}`. A
key flag signs each report with a `tine-sig/3` header block over
`opentine.redaction-report.v1:` + JCS of `{body, header}`; pinned HMAC and
Ed25519 vectors are in `tests/fixtures/redaction_report/vectors.json`, and the
`60-redaction-report.json` conformance family (SPEC 4.13) pins how Python, the
TS verifier and `tine-verify.pyz` check them. It exits 4 (verification failed)
when any report has findings and 3 (not found) when a `--run` does not resolve
(0.45.1; 0.45.0 exited 1 for both). `--json` prints `{command: "redact-check",
clean, reports}` (`tine-cli-redact-check-1`; each report follows
`opentine-redaction-report-1`).

`--pii` (0.46) re-scans under `opentine-redaction/3` (credentials plus the
PII detectors and local classifier layer of [PII.md](PII.md)) and writes
version 2 reports (SPEC 4.13.1, `opentine-redaction-report-2`): each finding is
`{oid, kind, detectors}` and the report carries `classifier`; they are signed
over `opentine.redaction-report.v2:` and checked by `62-redaction-report-v2.json`.
`--classifier` without `--pii` is a usage error.

`tine redact verify REPORT` checks every report in REPORT (one report, the list
`--out` writes, or `--json` output): the field rules, the `tine-sig/3` block
under `--key-file` (HMAC) or `--pubkey` (Ed25519; without one, the embedded key,
reported as `verified-tofu`), and that `clean` means no findings. It exits 4
when any report fails, naming its `redaction-report.*` reason; `--json` follows
`tine-cli-redact-verify-1`. `python tine-verify.pyz REPORT.json [--pubkey K |
--key-file K]` performs the same check offline (mode `redaction-report`).

`tine redact rules --json` prints the ruleset as data (`tine-redaction-rules/1`):
the ruleset name a report records, one row per scan step in the order the
redactor runs them (`order`, `id`, `family`, `description`), the vendor token
prefixes, and a `digest` over the ruleset name and rows.

`tine doctor` runs offline checks (opentine and Python versions, platform, git,
the names of `OPENTINE_*`/`TINE_*` variables, agent keys by name, tine git
hooks, installed harnesses, the repository and its configured remotes; remote
capabilities are not probed). It exits 1 only on a `fail` row. `--json` follows
`tine-cli-doctor-1` (0.45.1 adds `command: "doctor"`). `--bundle PATH`
writes the report as canonical JSON after `redact_value`, and refuses to write
it if any credential shape survives.

## Purge, tombstones and redacted public copies (0.46)

```
tine purge OID --reason TEXT (--key-file K | --ed25519-key-file K) [--key-id ID]
           [--actor NAME] [--json] [--repo R]
tine purge --list [--key-file K | --pubkey K.pub] [--json] [--repo R]
tine bundle create FILE REF --redacted-public (--key-file K | --ed25519-key-file K)
                  [--key-id ID] [--pack-format TINEPACK3|TINEPACK5] [--repo R]
tine bundle verify FILE [--key-file K | --pubkey K.pub]
```

`tine purge OID --reason TEXT` removes one blob's bytes and keeps its oid, so
every event and run that links it still hashes the same. It writes a signed
`opentine.tombstone` (SPEC 4.14): `{kind, tombstone_version: 1, oid, reason,
actor, purged_at}` plus a `tine-sig/3` block over `opentine.tombstone.v1:` +
JCS of `{body, header}`. The reason is redacted before it is signed; the actor
is `--actor`, else `--key-id`, else `local`. A purge needs a signing key and is
refused for a blob reachable from a hold (`tine hold`). The bytes leave through
the prune quarantine under the gc lock: a loose file is moved out, a packed
copy is dropped by rewriting its pack, every kept transfer pack carrying it is
deleted, and the derived search index is deleted (rebuild it with `tine
repo-search --rebuild-index`). The oid joins the shallow boundary list, so
`tine fsck` stays ok and lists it under `content_unavailable`. `--json` follows
`tine-cli-purge-1`; an unknown blob exits 3.

A `--redacted-public` bundle is TINEPACK3 or TINEPACK5 only: its signed
record names the pack's bytes, and `--pack-format TINEPACK6` is refused.

`tine purge --list` prints every tombstone with `content: unavailable` (or
`present`, for one imported beside a copy still held) and its trust:
`verified` under `--key-file`/`--pubkey`, `verified-tofu` for an Ed25519
record with neither, `unchecked` for an HMAC record without its key, or
`failed` with its `tombstone.*` reason, which exits 4. `--json` follows
`tine-cli-purge-list-1`.

Tombstones travel with the packs that leave the purged blob out: a bundle
manifest carries them under `tombstones`, and `tine push` sends them (`PUT
tombstones/<oid>`) before the pack to a remote that lists `caps.tombstones`;
`tine fetch` asks for the tombstone of each blob boundary it received. The
remote stores the record exactly as signed and never signs one; a `PUT` for a
blob the tenant still holds is a purge there and needs the admin-only `purge`
permission, and `GET` answers the same `404` for an oid that was never purged,
never existed or is another tenant's. A received tombstone is stored only for a
blob the receiver does not hold: it never deletes local bytes.

`tine bundle create FILE REF --redacted-public` bundles a redacted public copy
of the one run REF names: each blob it reaches (never its annotations or
attestations) is re-redacted with the current ruleset, every payload is
redacted again, and each event and the run are rewritten to link the new oids,
so the copy has its own run oid, under REF. The manifest key `redacted_public`
holds a signed `opentine.redacted-copy` (SPEC 4.15): `{source_run, public_run,
ruleset, objects, redacted, pack}`, where `pack` is the digest of the bundled
pack, so the web can publish the copy and show which private run it came from
without exposing that run. `tine bundle verify` reports a bundle's
`content_unavailable` oids and, for a public copy, `redacted_public` with the
record's state (as for `purge --list`); a `failed` record exits 4. `python
tine-verify.pyz RECORD.json [--pubkey K | --key-file K]` checks a tombstone or
redacted-copy record offline (modes `tombstone`, `redacted-copy`); the
`63-tombstone.json` and `64-redacted-copy.json` conformance families pin
Python, the TS verifier and the pyz.

## Projects: `tine project` (0.46)

```
tine project init ID --tenant T --forge github --url URL --ed25519-key-file K
                  [--forge-repo-id X] [--default-branch B] [--visibility public|private]
                  [--upstream-visibility public|private] [--owner HEX]... [--forked-from ID]
                  [--key-id ID] [--json] [--repo R]
tine project link [--role primary|secondary] --forge git --url URL --ed25519-key-file K [...]
tine project show|history [--remote R [--tenant T] [--token-file P]] [--json] [--repo R]
tine project verify [--remote R] [--owner-key HEX] [--json] [--repo R]
tine project push [--remote R] [--json] [--repo R]
tine project claim [--code DIR] [--json] [--repo R]
tine project claim --check FILE [--branch B] | --missing [--json] [--repo R]
tine project fork DEST --project-id ID [--tenant T] --ed25519-key-file K [--json] [--repo R]
tine project verify --source PATH [--json] [--repo R]
tine remote add NAME URL [--tenant T] [--token-file P] [--project ID]
```

A project binds this run repository to the code repositories it is linked to,
through a signed, hash-chained `opentine.project` manifest (SPEC 4.16) kept
under the `project/manifest` ref. `init` writes the first version, signed by
the `--ed25519-key-file` key, which becomes its first owner (`--owner` adds
more). `link` signs the next version with a slot set: `--role primary`
replaces the primary slot, `--role secondary` adds or replaces the secondary.
`--forge` is `github`, `gitlab`, `forgejo`, `git` or `entire`;
`--forge-repo-id` is the forge's own id where it has one (never for `git`). A
public project may not reference a private upstream (`project.private-upstream`).
A private project (`--visibility private`) names each upstream by a salted
commitment, never its URL: the URL and salt stay in
`.tine/project-locators.json`, which is never pushed, bundled or served. Every
version must be signed by an owner of the version before it; a version that
does not chain, or is signed by anyone else, is refused (exit 4) and the ref
does not move.

`show` prints the current version, `history` every version oldest first, and
`verify` checks every signature and chain link (`--owner-key` pins the first
owner; without it the first version rests on trust on first use,
`verified-tofu`); a failure exits 4 with its `project.*` code. With `--remote`
they read the remote's `caps.project` routes (SPEC 8.18) instead, and refuse a
remote whose project is not the one `tine remote add --project ID` pinned.
`push` sends each version the remote lacks with `PUT project`, a
compare-and-swap on the remote's head; the remote checks the chain and the
owner's signature, stores the manifest exactly as signed, logs the move in its
transparency log, and never signs one. `--json` follows `tine-cli-project-1`.

`tine serve` stores no code unless started with `--mirror` (0.55): then it
serves the read-only code mirror of SPEC 8.18 (`--mirror-poll-seconds`,
`--mirror-max-mb`, `--mirror-allow-local`), whose state is an
`opentine.mirror-state` body (SPEC 4.17), a host statement. `python tine-verify.pyz FILE.json [--pubkey K]` checks a
manifest, a history (`tine project history --json` output) or a mirror state
offline; a mirror state never passes (verdict `host-statement`). The
`65-project.json` and `66-mirror-state.json` conformance families (the git
object check among them) pin Python, the TS verifier and the pyz. See
[PROJECTS.md](PROJECTS.md).

## Forge integration: `tine forge publish` (0.48)

```
tine forge publish --forge github|gitlab|forgejo|entire [--forge-repo-id ID]
                   [--repo-slug OWNER/NAME] [--api-url URL] [--rev REV] [--code DIR]
                   [--repo R] [--require-project] [--verify FILE]... [--bundle FILE
                   [--bundle-url URL]] [--pr N | --mr N] [--token-env NAME]
                   [--app-id ID --app-key-file PEM --installation-id ID]
                   [--comment-author LOGIN] [--run RUN]... [--out FILE] [--dry-run] [--json]
```

Builds one `opentine.forge-check` record (SPEC 4.24) for the commit `--rev` of
the code checkout `--code` and shows it on the forge: the AI share at that
commit (`tine stats --ai-share`), the verify status from the `tine verify
--json` outputs given with `--verify` (none: `unverified`), the commit's own
AI-attributed line ranges (the blame overlay) and the digest and URL of a
bundle that verifies offline (`--bundle` is verified in full before it is
linked; `--bundle-url` without `--bundle` is refused). The conclusion follows
the verify status alone: verified is success, failed is failure, unverified is
neutral, never success.

* **GitHub**: a completed check run (Checks API) with the overlay as `notice`
  annotations and `details_url` the bundle; with `--pr`, one PR comment, edited
  on re-runs.
* **GitLab**: a commit status (`skipped` when unverified); with `--mr`, one MR note.
* **Forgejo / Gitea**: a commit status (`warning` when unverified); with `--pr`,
  one PR comment.
* **Entire**: nothing over HTTP. Checkpoint refs for the runs the commit names
  (or each `--run`) and the record as a note under `refs/notes/opentine-forge`
  are written into the code checkout, and the `git push` that publishes them is
  printed.

The project is resolved by `--forge-repo-id` (default `GITHUB_REPOSITORY_ID` or
`CI_PROJECT_ID`) against the verified project chain in `--repo`: a project that
links no repository with that id on that forge is refused, and
`--require-project` refuses a run repository without a project. Tokens are
read only from an environment variable (`--token-env`; defaults
`GITHUB_TOKEN`, `OPENTINE_GITLAB_TOKEN`, `OPENTINE_FORGEJO_TOKEN`) or minted
from a GitHub App key with only the permissions used, and never printed: a
failure names the HTTP status only. Only a comment that starts with the
marker and was written by the poster itself is edited. `--dry-run` builds the
record and the request plan without a token or the network. The command exits
0 whatever the conclusion (the CI gate decides the job); `--json` follows
`tine-cli-forge-1`. Token scopes and CI recipes: [FORGES.md](FORGES.md).

## Publishing run bundles: `tine publish zenodo`, `tine publish hf` (0.49)

```
tine publish zenodo REF... --creator NAME [--creator NAME]... [--attach FILE]...
                    [--title T] [--description D] [--access-right open|closed]
                    [--license ID] [--publish] [--sandbox] [--allow-unredacted REASON]
                    [--api-url URL] [--token-env NAME] [--repo R] [--dry-run] [--json]
tine publish hf REF --dataset OWNER/NAME (--key-file K | --ed25519-key-file K)
                [--key-id ID] [--revision BRANCH] [--create [--private]]
                [--api-url URL] [--token-env NAME] [--repo R] [--dry-run] [--json]
```

`zenodo` bundles the named refs (`tine bundle create`) and deposits the bundle,
plus each `--attach` file (for example a `tine export --format run-crate`
crate), through the Zenodo REST API: create a deposition, upload into its
bucket, set the metadata (`upload_type` dataset, the creators, the bundle
digest). Without `--publish` the deposition stays a draft to review on Zenodo;
`--publish` mints a DOI and cannot be undone. `--sandbox` targets
`sandbox.zenodo.org`. The token is `ZENODO_TOKEN` (or `--token-env`).

`hf` publishes one run's redacted public copy, the same signed bundle as
`tine bundle create --redacted-public`, to a Hugging Face Hub dataset: the
bundle goes up through the Hub's LFS batch API as `runs/<id>.tbundle`, and one
commit adds it with a dataset card (`README.md`) tagged `agent-traces`. The
token is `HF_TOKEN` (or `--token-env`); an LFS upload URL on another host gets
only the headers the Hub names for it, never the token.

Both run the pre-push redaction gate over every object they would upload before
any request: a hit refuses. `zenodo` takes `--allow-unredacted REASON` (logged,
like `tine push`); `hf` has no override, since a Hub dataset is public. Each
successful upload is recorded as an op-log entry with where it went and the
bundle digest. Tokens are never printed or logged; a failure names the HTTP
status only. `--dry-run` gates and plans without a token or the network.
`--json` follows `tine-cli-publish-1`.

## Merge, pick and the merge queue: `tine merge`, `tine pick`, `tine merge-queue` (0.47)

```
tine merge OURS THEIRS [--ref REF] [--json] [--repo R]
tine pick ONTO EVENT... [--ref REF] [--json] [--repo R]
tine merge-queue init QUEUE --target REF [--gates FILE] [--json] [--repo R]
tine merge-queue add QUEUE RUN [--by NAME]
tine merge-queue claim QUEUE --holder H [--ttl 60]
tine merge-queue heartbeat QUEUE --holder H --fencing 1 [--ttl 60]
tine merge-queue land QUEUE --holder H --fencing 1 --ed25519-key-file K [--evidence FILE]
tine merge-queue work QUEUE --holder H --ed25519-key-file K [--evidence FILE] [--ttl 60] [--max 2]
tine merge-queue show QUEUE
tine merge-queue approve RUN --target REF --approver NAME --ed25519-key-file K [--reject]
    [--queue QUEUE [--expires 86400]]
tine merge-queue verify FILE|BLOB_OID [--public-key HEX] [--run]
```

`tine merge` writes the deterministic merge of two runs (SPEC 4.19): the
events both share, then each side's own, then one `merge` event whose parents
are the union's leaves; the new run's `parents` are `[OURS, THEIRS]`. The same
two runs give the same merge oid in every repository and in the TS verifier and
the pyz (`68-merge.json`). When both sides carry workspace trees they merge
three ways per path; a path both sides changed differently, or a differing
`policy` manifest, is a conflict recorded in the merge event's output, the run
is `paused`, and the command exits 1. `--ref` moves a ref to the result by
compare-and-swap from the value it read. `tine pick` copies events of other
runs onto ONTO's tip, in order, each copy naming its source in `picked_from`.

A merge queue (`coord/merge-queue/QUEUE`) owns one target ref. `add` queues a
run; a worker `claim`s the queue's lease, which prints its fencing token, and
`land`s the first entry with that token: the gates are checked, the entry is
merged onto the head, an `opentine.merge` attestation naming the target and
the fencing token is signed with `--ed25519-key-file`, and one compare-and-swap
of the queue record pops the entry, moves the head and releases the lease. A
holder with a stale token (its lease expired or was taken over) is refused, so
no entry lands twice, even when workers are killed mid-land. A conflicted
merge, one that adds nothing, or a failed gate moves the entry to `rejected`.
`work` claims and lands until the queue is empty.

`--gates FILE` is an `opentine-merge-gates/1` policy: a pinned server VSA key
(and required levels, policy, resource), a minimum number of passing signed
eval verdicts (optionally from listed signers), and a number of approvals from
listed Ed25519 keys. `--evidence FILE` holds `{"vsa": [...], "evals": [...],
"approvals": [...]}`; `approve` signs an `opentine.merge-approval` (`--reject`
signs a veto). Since 0.52 a queue whose gates require approvals counts only
approvals **issued** into it: `approve --queue QUEUE` also records a ticket in
the queue record (a random nonce, the approval's digest and an expiry,
`--expires` seconds, default one day, at most 30 days) and prints it as
`ticket`. A landing rejects the entry when the evidence holds an approval that
was not issued into this queue, has expired, or whose nonce an earlier landing
already spent, and marks the nonces it used spent in the same compare-and-swap
that lands it. A gated `land` or `work` without a signing key is refused
(`no-key`). The binding is local queue state, not a signed field: the
approval schema is closed, and a claim inside an attestation that `land` reads
would be a new claim schema under FREEZE.md; a signed form is a 1.x item. `verify` checks an attestation (a file, or the blob oid a
landing records; `--run` also checks the merged run here) or an approval and
exits 4 when it fails; `python tine-verify.pyz FILE.json [--pubkey K]` checks
either offline. `--json` follows `tine-cli-merge-1`, `tine-cli-pick-1` and
`tine-cli-merge-queue-1`.
## Reviews: `tine review` (0.47)

```
tine review create ID --title T [--code-repo NAME[=PROJECT]]... [--reviewer HEX]...
                   [--gate NAME]... --ed25519-key-file K [--key-id ID] [--json] [--repo R]
tine review add ID [--run OID]... [--commit SHA]... [--at NAME] [--finding SEVERITY:MESSAGE]...
                [--resolve FINDING_ID]... [--monitor risk|intent-drift|coverage
                (--score S --threshold T [--scorer X] | --verdict FILE)] [--gate NAME]...
                [--reviewer HEX]... [--code-repo NAME[=PROJECT]]... --ed25519-key-file K
tine review gate ID GATE (--approve | --reject) [--reason TEXT] --ed25519-key-file K
tine review show ID [--reviewer-key HEX] [--json] [--repo R]
tine review export ID -o FILE [--reviewer-key HEX] [--json] [--repo R]
tine review verify FILE [--reviewer-key HEX] [--json]
tine review import FILE [--json] [--repo R]
tine review push ID [--remote R [--tenant T] [--token-file P]] [--json] [--repo R]
```

A Review is a unit of work across runs and commits, in one repository or
several (SPEC 4.20). `create` writes version 0, signed by the
`--ed25519-key-file` key, which becomes its first reviewer (`--reviewer` adds
more); `--code-repo` names each repository it spans (default one named
`default`), optionally with the `opentine.project` id it belongs to. `add`
signs the next version with what is added: runs and commits (`--at` picks the
code repo, default the first), findings (`info`, `low`, `medium`, `high` or
`critical`; `--resolve` closes one by id), gates, reviewers and monitors. A
monitor is an eval scorer's score against a threshold, `risk`, `intent-drift`
or `coverage`; `--verdict` takes the scorer, score and threshold from a signed
`tine-eval-verdict/1` (`tine eval run`) and records its digest. Every version
must be signed by a reviewer of the version before it; anything else is
refused (exit 4) and the Review does not change.

`gate` signs one decision on one gate of the head version. Only a reviewer can
sign one, and an approval is refused (`review-gate.blocked`, exit 4) while a
monitor of that version fails or a `critical` finding is open; a rejection is
always allowed. `show` verifies the Review and prints each gate's status
(`approved`, `rejected` or `pending`; a decision on an earlier version never
counts for the head). The Review lives in `.tine/reviews/ID.json` as its
bundle; `export` writes that `opentine.review-bundle`, and
`python tine-verify.pyz FILE` verifies it offline, every version and every
gate decision (one check row each), with `--pubkey` pinning the first
reviewer. `verify` does the same check here (exit 4 on failure), `import`
adopts a bundle that extends the local copy, and `push` sends what a remote's
`caps.reviews` (SPEC 8.19) lacks; the remote checks every record, stores it
exactly as signed, logs it in its transparency log and never signs one.
`--json` follows `tine-cli-review-1`. The `70-review.json` conformance family
pins Python, the TS verifier and the pyz.

### Multi-agent review through the fleet: `tine review run` (0.48)

```
tine review run ID --fleet TOML [--trust] [--base REV] [--diff-file FILE] --ed25519-key-file K [--key-id ID] [--json] [--repo R]
tine review findings ID [--json] [--repo R]
```

`run` runs a reviewer fleet (a `fleet.toml`, inert until its exact bytes are
trusted with `--trust`, like `tine fleet up`) on the change: `git diff REV`
(default `HEAD`, the uncommitted change) or the diff in `--diff-file`, redacted
before any reviewer sees it. Each member gets `OPENTINE_REVIEW_ID`,
`OPENTINE_REVIEW_CONTEXT` (the file holding the change) and
`OPENTINE_REVIEW_FINDINGS` (the file it writes), and writes one JSON object
per line: `{"severity", "message", "path"?, "line"?}`. Every well-formed line
becomes one signed `opentine.review-finding` (SPEC 4.25), its message redacted
first, signed by `--ed25519-key-file` (which must be a reviewer of the head
version) and kept in `.tine/review-findings/ID.json`; a malformed line is
skipped and counted, never guessed at. The Review then gets one new version
listing every new finding as open, so a `critical` one blocks approval.
`findings` lists the stored findings, each checked against the head version's
reviewers; `python tine-verify.pyz .tine/review-findings/ID.json` checks the
same file offline, one row per finding. `--json` follows `tine-cli-review-1`;
the `74-review-finding.json` conformance family pins Python, the TS verifier and
the pyz.

## Eval statistics and signed promotion: `tine eval compare --ci`, `tine promote --baseline` (0.58)

`tine eval compare A B --ci paired-bootstrap|permutation [--alpha 0.05]
[--seed 0] [--resamples 2000]` adds per-metric deltas (`score`, `pass_rate`),
a bootstrap interval or a permutation p-value, and the regressions. It is
deterministic given the seed. `--export FILE` writes the paired items, and
`scripts/eval_compare_reproduce.py FILE` reproduces the numbers exactly.
`--attest KEY --out FILE` signs the result as an attestation. `--json`
follows `tine-cli-eval-compare-1`.

`tine promote RUN --baseline LABEL --policy promote.toml --key KEY --out DIR
--baseline-evals DIR --evals DIR --holdout BASE CAND --approval FILE` moves a
label only when trusted, signed verdicts beat the baseline under the stated
test (with a minimum n and a holdout). It also needs enough approvals, a
spend under the budget cap and an admission policy that covers
`labels/LABEL`. A refusal names each reason (`promote.*`) and exits 1.

- `--approve` signs an approval.
- `--revert --reason TEXT` writes a signed revert decision.
- `--canary DIR` reverts automatically on a signed regression.
- `--require-admission POLICY` (0.75, repeatable) refuses unless the policy
  admitted RUN over its current input (`promote.not-admitted`);
  `--admission-param NAME=VALUE` sets a param of that input, as
  `tine policy check --param`, and `--admission-evals DIR`,
  `--admission-holdout DIR` (both repeatable) and `--admission-budget SUBJECT`
  supply its `--evals`, `--holdout` and `--budget`, so the gate rebuilds the
  input the check signed; see [POLICY.md](POLICY.md).

`--json` follows `tine-cli-promote-1`. Conventions, refusal codes and outputs:
[EVALS-PROMOTION.md](EVALS-PROMOTION.md).

## Code map: `tine code-graph` (0.48)

```
tine code-graph [PATH]... [--symbol NAME] [--repo DIR] [--json]
```

Maps the work tree: every tracked source file (Python, JavaScript, TypeScript,
Go, Rust, Java, Kotlin), its classes, functions, methods and types with their
1-based lines, its imports, and the import edges between files of the
repository. With the optional `graph` extra (`pip install 'opentine[graph]'`,
tree-sitter) Python files are parsed by tree-sitter; everything else, and every
file without the extra, gets a regex outline, and each file says which
(`backend`). `--symbol` keeps only the files that define NAME. Read-only and
offline. It is `code-graph`, not `graph`, so a user's `alias.graph` (a `log --graph`
shortcut) keeps working. `--json` follows `tine-graph-1`; the MCP server exposes the same map as
the read-only `code_graph` tool.

## Prompts and team memory: `tine prompt`, `tine memory` (0.47)

```text
tine prompt push NAME (--file F | --template TEXT) --key KEY [--model M] [--label L]...
tine prompt label NAME[@vN] LABEL
tine prompt get NAME[@LABEL|@vN] [--var KEY=VALUE]...
tine prompt list
tine prompt verify NAME [--pubkey PUB]
tine prompt link NAME[@LABEL|@vN] RUN
tine prompt sync [--remote R [--tenant T] [--token-file P]]
tine memory add TOPIC TEXT --key KEY [--scope S] [--tag T]... [--subject OID]
                [--supersedes DIGEST] [--author NAME]
tine memory list [--scope S] [--any-signer]
tine memory recall QUERY [--limit N] [--min-assurance T0|T1|T2|T3] [--record-to RUN]
tine memory trust PUB
tine memory quarantine NOTE --key KEY --why TEXT [--lineage-dir DIR]
tine memory served NOTE [--lineage-dir DIR]
tine memory sync [--remote R [--tenant T] [--token-file P]]
```

Every action takes `--repo PATH` and `--json`. `prompt push` signs the next
version of a named template (`opentine.prompt`, SPEC 4.21: Ed25519,
hash-chained through `prev`, the next version signed by the same key) and moves
`prompts/NAME/head`; `{{name}}` placeholders become its `variables`. A label
(`prompts/NAME/labels/LABEL`) names one version and moves with `prompt label`;
a version never changes, so what a run or an eval named stays the same bytes.
`prompt get --var` renders a version and refuses a missing value; `prompt
verify` checks the whole history and exits 4 on a `prompt.*` failure; `prompt
link` records `{name, version, digest}` as `metadata.prompt` in the run's
annotation. `--json` follows `tine-cli-prompt-1`.

`memory add` signs a team-memory note (`opentine.memory`, SPEC 4.22) and stores
it as `memory/SCOPE/<hex digest>`; it refuses text a secret detector fires on,
because a signed note is never redacted afterwards (a hex digest or an oid is
not a secret). `memory trust` adds a key to `.tine/memory-team.json`; `list`
and `recall` show only notes that verify under those keys and that no other
such note supersedes (with no team file, `list --any-signer` shows notes on
their embedded keys). MCP `recall` returns the same notes under `memories`
(SPEC 8.20). `--json` follows `tine-cli-memory-1`.

0.61: `recall --record-to RUN` records the served note digests as a step of a
run still being captured (a finished or attested run is refused);
`--min-assurance` keeps notes whose subject run reaches the tier. `memory
quarantine` signs and holds a superseding `quarantine` note and lists every run
served the note and every lineage variant whose runs consumed it; `memory
served` lists the same. Both report the quarantine as `verified` only when a
`curator` key of the owner-pinned key roles signed it, else `unverified`
(it still blocks). `tine promote` refuses with
`promote.memory-quarantined` and `tine lineage check|why` report
`lineage.memory-quarantined`. See docs/MEMORY.md.

`memory sync` and `prompt sync` send the notes or prompt refs a remote lacks
and fetch the ones this repository lacks, one ref at a time over the ordinary
push and fetch routes: a fetched note must verify under the team (with no
team file, no fetched note is accepted) and sit under its own digest's ref, and a fetched
prompt history must chain onto the local one. A prompt history that diverged
is listed in `conflicts` and never merged or overwritten. `python
tine-verify.pyz FILE.json [--pubkey K]` checks a prompt version, a history
(`{"versions": [...]}`) or a note offline; the `71-prompt.json` and
`69-memory.json` conformance families pin Python, the TS verifier and the pyz.
See [PROMPTS_AND_MEMORY.md](PROMPTS_AND_MEMORY.md).
## Plugins and experts: `tine plugins`, `tine experts` (0.47)

```
tine plugins list [--kind importer|signer|scorer|snapshot] [--json]
tine plugins allow scorer|signer|importer|snapshot NAME [--json]
tine plugins check scorer|signer|importer|snapshot NAME [--json]
tine experts PATH [--rev REV] [--pubkey KEY] [--limit N] [--json]
```

`plugins list` shows every installed entry point in the `opentine.importers`,
`opentine.signers`, `opentine.scorers` and `opentine.snapshots` groups and
whether the loading rules (SPEC 8.21) let it load; it imports nothing.
`allow` pins the installed distribution and version that provide a plugin in
`$XDG_CONFIG_HOME/opentine/plugins.json`, the only allow-list read. `check`
loads one and checks its interface (exit 1 when it may not load). A scorer
plugin is used as `tine eval run --scorer plugin:NAME`. `--json` follows
`tine-cli-plugins-1`; an unsafe or malformed allow-list exits 2.

`experts` ranks agents (by model, from line attribution notes) and humans (by
commit author) by the committed lines they wrote under PATH, then by verified
runs. `--json` follows `tine-experts-1`. See [PLUGINS.md](PLUGINS.md).
0.47 (SPEC 4.23). `claim` writes `.opentine/project`, an unsigned
`opentine.forge-claim` naming this project and the fingerprint of its first
version, into the code checkout `--code` (default `.`); commit it on the
default branch. `claim --check FILE [--branch B]` checks one against this
repository's project (`--missing`: the upstream has none) and at best reports
`claimed by upstream (as mirrored)`, never a pass; a refusal exits 4 with its
`forge-claim.*` code (`missing`, `malformed`, `not-default-branch`,
`wrong-project`, `wrong-fingerprint`). `fork DEST` copies this run repository
(objects and refs, never code, never the source's manifests) into DEST under a
new project signed by `--ed25519-key-file`, whose `forked_from` is this
project; the fork point is kept in `.tine/project-fork.json` (never pushed).
`verify --source PATH` on a fork checks `forked_from` against the source's
project history and refuses (exit 4, `project.chain-break`) a source that no
longer holds the fork point. The `72-forge-claim.json` family pins Python, the
TS verifier and the pyz.

## Run summaries: `tine explain` (0.42)

```
tine explain RUN                 # text summary; stored as an annotation in a v3 repo
tine explain RUN --json          # {"command": "explain", "run", "digest", "summary",
                                 #  "stored", "annotation", "narrative"}
tine explain RUN --no-store      # print only
tine explain RUN --narrative     # plus a narrative from a local model
```

A deterministic, offline summary built from the recorded run alone: what was
asked, models, steps by kind, tools used, files written and read, hosts, the
outcome, errors and failed tool calls, and tokens and cost when the run records
them (absent otherwise, never 0). The same run always gives byte-identical
output. `summary.schema` is `opentine-explain/1`; `digest` is the SHA-256 of the
summary as sorted, compact JSON.

In a v3 repository (`--repo PATH`, or one in the current directory) the
summary is stored on the run's annotation chain under
`metadata["opentine.explain"]`; re-running it writes nothing new. A legacy
`.tine` run is explained but not stored.

`--narrative` asks the model named in `OPENTINE_EXPLAIN_MODEL`
(`provider[:model]`, for example `ollama:llama3.1`) for a few sentences. Only a
local provider is accepted; with none configured the command refuses with exit
code 2 and sends nothing. The narrative is stored apart from the summary, under
`metadata["opentine.explain.narrative"]`, with `generated_by: "model"`, a
`label` saying it is model-generated and not evidence, the model spec and the
digest of the summary it describes.

## Line attribution (0.42)

```
tine git attribute COMMIT [RUN...] [--sign-key KEY] [--no-configure] [--json]
tine git attribution COMMIT [--verify] [--pubkey KEY.pub] [--json]
tine git attribution COMMIT --format agent-trace
tine stats --ai-share [--rev REV] [--json]
```

`tine git attribute` diffs `COMMIT` against its first parent and matches each
added line to the recorded write that inserted it (the matching `tine blame`
uses), over the runs given, or else the runs the commit already links through
`Tine-Run` trailers or notes. The result is stored in the commit's
`refs/notes/tine` note as one `Tine-Attribution: {...}` line (schema
`opentine-line-attribution/1`): per file, ranges with `start_line`,
`end_line`, the `run`, `step`, `seq`, `tool` and `model` that wrote them, and
the `content_hash` (SHA-256) of the lines covered. `Tine-Run` lines for the
runs are kept or added, so `tine git log` sees the same note. With
`--sign-key` the record carries an Ed25519 `tine-sig/3` block under the domain
`opentine.line-attribution.v1:`.

The record names no commit, so it stays true when git copies the note to a
rewritten commit. `tine git attribute` adds this to the repository's config
(skip with `--no-configure`):

```
git config --add notes.rewriteRef refs/notes/tine
```

With it, `git commit --amend` and `git rebase` (including `rebase -i`) copy the
note to the new commit. Set it yourself in clones where `attribute` has not
run; git does not copy notes by default.

`tine git attribution COMMIT --verify` checks the signature (against
`--pubkey`, or the embedded key as trust on first use) and that every range's
hash still matches the lines the commit adds; it exits 1 when either fails.
`--format agent-trace` prints the note as an [Agent Trace](https://agent-trace.dev/)
record: `vcs` is `{"type": "git", "revision": COMMIT}`, one conversation per
model with contributor `ai`, ranges with `content_hash`, and run and step ids
in `metadata["io.github.0xcircuitbreaker.opentine"]`.

`tine stats --ai-share` blames every text file at `--rev` (default `HEAD`) and
counts the lines whose originating commit's attribution note credits them to
a run: `total_lines`, `ai_lines`, `ai_share`, `by_model`, per-file counts and
`commits_with_attribution`. Lines in commits without a note count as not
attributed. With `--json` the object carries `"schema": "tine-ai-share/1"`
(`docs/schemas/tine-ai-share-1.schema.json`); `tine git share-line [COMMIT]
--json`, the post-commit AI-share line as an object (`commit`, `lines_added`,
`lines_attributed`, `ai_share`, `line`), follows the same schema.

## Git AI Standard v3 notes (0.45.x)

```
tine import REPO[::RANGE] --format git-ai [--sign-key KEY] [--force] [--json]
tine export REV|A..B --format git-ai [--output REPO] [--force]
```

[Git AI](https://github.com/git-ai-project/git-ai) keeps one
`authorship/3.0.0` note per commit under `refs/notes/ai`: an attestation
section (a file path, then `  KEY RANGES` lines with 1-indexed `N`/`N-M`
ranges) and, after a `---` line, a JSON metadata object (`schema_version`,
`base_commit_sha`, `prompts`, `sessions`, `humans`, `git_ai_version`). Keys are
`s_<14hex>::t_<14hex>` (session and checkpoint), `h_<14hex>` (a human) or a
legacy 16-hex prompt hash.

`import` converts each Git AI note in REPO (every noted commit, or those in
RANGE) into an `opentine-line-attribution/1` note under `refs/notes/tine`:
agent lines are credited to the run `git-ai:<session or prompt>` with the
checkpoint as the step and the agent's tool and model; human lines are kept
under `git_ai.human_lines`, never credited; the note's metadata is kept under
`git_ai`. `--sign-key` signs each record (verify with `tine git attribution
COMMIT --pubkey KEY.pub`). OpenTine notes stay canonical: a commit that already
has one is skipped unless `--force`. `--save`, `--repo`, `--ref`, `--fleet`,
`--all` and `--price` are refused.

`export` writes a v3 note for each commit with an OpenTine attribution note.
Imported ranges keep their original keys and metadata, so import then export
reproduces the Git AI note; native ranges get deterministic keys derived from
the run and step and a session whose `agent_id` is `{tool, id: run, model}`. An
existing Git AI note is kept unless `--force`.

## Blame, why and attach (0.45)

```
tine blame FILE --porcelain | --line-porcelain [--rev REV] [-L START,END]
tine blame FILE --lines [--rev REV] [-L START,END] [--json]
tine why FILE:LINE [--json]
tine attach RUN COMMIT [--sign-key KEY] [--no-configure] [--json]
tine git install-hook [--ai-share] [--push [--strict]] [--global]
tine import SOURCE --format agent-trace --save OUT.tine
```

`tine blame FILE --porcelain` prints `git blame --porcelain` for `FILE` at
`--rev` (default `HEAD`, textconv off) exactly as git wrote it. Before each
content line that a commit's attribution note credits to a run it adds three
header lines, `tine-run RUN`, `tine-step SEQ` and `tine-model MODEL`; a file
with no attributed lines is byte for byte what git prints. `--lines` shows one
row per line (commit, run, line number, text) and `--lines --json` emits a
`tine-blame/1` record: `command` (`blame`), `path`, `revision`, `total_lines`, `ai_lines` and per
line `line`, `commit`, `orig_path`, `orig_line`, `author`, `author_mail`,
`author_time`, `summary`, `text` and `ai` (`{run, seq, model}` or `null`).
`tine blame PATH[:LINE]` without these flags is unchanged.

`tine why FILE:LINE` follows the line to the commit that last changed it, the
runs that commit links and its attribution note, and prints the causal slice
of the run that wrote it: the writing step and every step it descends from
(`seq`, `step_id`, `kind`, `tool`, `model`).

`tine attach RUN COMMIT` links a run captured after the fact: it is
`tine git attribute COMMIT RUN`, writing the run note and the line attribution
note (signed with `--sign-key`) and setting `notes.rewriteRef`, so the link
survives `commit --amend` and `rebase`.

Commit trailers follow one grammar, read the same way by `tine git log` and
the web:

```
Tine-Run: <run-oid>[ <project_id>]     (repeatable)
Tine-Project: <project_id>             (at most once)
```

A `Tine-Run` without its own project takes the `Tine-Project` one. A strict
parse rejects two `Tine-Project` lines, a malformed run id or project id
(lower-case slug), and extra words. `tine git log --json` reports each
commit's strict link set under `links` (`{commit, links, error}`); its `runs`
rows and the commit-msg hook keep reading leniently. Lines end at `\n` only (a
trailing `\r` is dropped), keys are ASCII and case-insensitive, and words split
on spaces and tabs only. The TypeScript parser the web uses
(`ts/verifier/src/trailers.ts`) passes the same vectors:
`tests/data/trailer_vectors.json`.

`tine git install-hook` now also sets `notes.rewriteRef=refs/notes/tine` in the
repository (not with `--global`) and reports `rewrite_ref_configured`.
`--ai-share` (opt-in) adds a `post-commit` hook that prints one line per
commit, `tine: A/N added line(s) by agents (P%) on SHA`, from the attribution
note or the linked runs; it writes nothing and never fails a commit.

`tine import --format agent-trace` reads Agent Trace records (one, an array,
or JSONL): one `model` event per conversation and one `agent_trace.attribution`
tool event per file with its path, ranges and contributor type. Agent Trace
carries no content, so nothing is recorded as a write.

## Fleet coordination: tasks, leases and steering (0.43)

| Command | What it does |
| --- | --- |
| `tine task add ID [--title T] [--loop LOOP] --repo PATH` | Creates `coord/tasks/ID` (`opentine-coord/1`); 0.58: `--loop` makes it a generation of LOOP, fenced by `tine loop stop` |
| `tine task claim ID --holder NAME [--ttl S] --repo PATH` | Takes the lease by one compare-and-swap ref move; prints the new `fencing` token |
| `tine task heartbeat ID --holder NAME --fencing N [--ttl S]` | Extends the lease; refused (`stale`) once it expired or was re-claimed |
| `tine task done ID --holder NAME --fencing N` | Closes the task; refused for a stale holder |
| `tine task list --repo PATH` | Every task, its status, holder, token and lease end |
| `tine task ACTION ... --remote NAME\|URL [--tenant T] [--token-file P]` | 0.47: the same action on a `tine serve` tenant (`caps.coord`, SPEC 8.22), on the server's clock |
| `tine fleet resume fleet.toml --id ID [--trust]` | Runs the members of fleet `ID` that did not finish; the manifest digest must match the record |
| `tine fleet logs ID [--member KEY]` | Prints each member's captured output |
| `tine fleet send ID --member M --message TEXT --repo PATH` | Queues a steer message in `coord/mailbox/ID/M` |

Every task and mailbox version is an annotation chained by `previous_id`, so
the ref's history is the record's audit trail. Of any number of racing
claimants exactly one compare-and-swap wins; an expired lease is re-claimed
with a higher fencing token. With `--json` each `task` verb prints
`{"command": "task <verb>", "task": {...}}` (`"tasks": [...]` for `list`); a
refused operation exits 1 with `{"error": {"code": "held|stale|done|stopped|exists|missing|contended", ...}}`.

## Self-improving agent loops: key separation and the kill switch (0.58)

| Command | What it does |
| --- | --- |
| `tine keys lint [--policy FILE] [--optimizer-key KEY]... [--strict] --repo PATH` | Checks the key-role policy `.tine/key-roles.toml`; exit 1 when the optimizer key (or a candidate signing key given with `--optimizer-key`) also holds a scorer, dataset, verdict or approver key |
| `tine loop stop LOOP --ed25519-key-file KEY [--reason T] [--run RUN] --repo PATH` | Writes a signed stop for LOOP; every generation task of LOOP is then refused `claim` and `heartbeat` (code `stopped`) |
| `tine loop status LOOP --repo PATH` | `running`, or `stopped` with the stop attestation, its signer and whether its signature verifies |

The key-role policy names keys by `sha256:` fingerprint (or raw Ed25519 public
key hex) under `[roles]`: `optimizer`, `scorer`, `dataset`, `verdict` and the
optional `approver`, `policy` (signs promotion policies), `stopper` (may
stop a loop), `eval`, `curator` (signs memory quarantines that verify) and
`monitor` (signs monitor verdicts that verify, 0.63),
with `version = 1`. Findings follow owner decision D12:
`fail:key-separation.shared` and `fail:key-roles.malformed` block;
`advisory:key-roles.no-policy`, `advisory:key-roles.no-optimizer` and
`advisory:key-roles.empty-role` are reported and block only with `--strict`.
`--json` prints `tine-cli-keys-lint/1`. The same check is a library call
(`opentine._key_roles.check_separation`) for the promotion gate to refuse a
candidate signed by a key that holds evaluation keys.

A stop is an attestation with the `opentine.loop-stop/1` claim convention
(SPEC 4.19), indexed by the coord record `coord/loops/LOOP`. The fence reads
that record, never a clock, so every member of a fleet is refused at once
whatever its clock says; the generation holding a lease cannot extend it, so it
ends within one lease period, and may still `done` its task. The first stop
stands; a stopped loop restarts under a new loop id. The stop is also kept by
a hold (`loop-stop:LOOP`) that `tine hold release` refuses, so deleting or
rewriting `coord/loops/LOOP` does not un-stop the loop. A task whose id starts
with `LOOP.` is fenced with or without `--loop`. `--json` prints
`tine-cli-loop/1`. Local repositories only: `--loop` is refused with `--remote`.

## Monitor verdicts and stop tokens (0.63)

| Command | What it does |
| --- | --- |
| `tine mcp-proxy --monitor CONFIG --monitor-repo PATH --monitor-key KEY [--monitor-agent NAME] ...` | Scores every `tools/call` with the configured monitor; advisory by default, a blocking gate with `mode = "gate"` |
| `tine monitor gate --config CONFIG --key KEY [--agent claude-code\|codex\|gemini\|generic] [--fail-closed] --repo PATH` | The hook path: decides one tool call read from stdin and answers in the agent's dialect |
| `tine monitor stop [--scope SCOPE] --key KEY [--reason T] --repo PATH` | Signs and holds a stop token; gated calls in SCOPE (`*`, `agent:NAME`, `session:ID`) are blocked |
| `tine monitor stops --repo PATH` | Stop tokens and whether a pinned stopper key signed each |
| `tine monitor verdicts --repo PATH` | Held monitor verdicts and whether a pinned monitor key signed each |
| `tine monitor verify [--run RUN]... [--strict] --repo PATH` | Offline: every blocked or replaced action in the runs has its verdict; exit 1 on a `fail:monitor.*` finding |

`--json` prints `tine-cli-monitor/1`. Verdicts follow the claim convention
`opentine.monitor-verdict/1`; see docs/MONITORS.md.

## Oversight queue (0.64)

| Command | What it does |
| --- | --- |
| `tine oversight policy --repo PATH` | Whether `.tine/oversight.toml` is pinned, its tiers (k of n) and routes |
| `tine oversight sign-policy --key KEY --repo PATH` | Writes `.tine/oversight.sig.json`; it pins the policy only when KEY is a pinned `policy`-role key that is not an `optimizer` key |
| `tine oversight request ITEM --key KEY [--evals DIR] --repo PATH` | Puts ITEM in the queue (a signed, held decision that never counts as an approval) |
| `tine oversight approve ITEM --key KEY [--human NAME] [--note T] [--viewed OID] [--viewed-at TIME] [--state DIR] --repo PATH` | Signs and holds an approval; refused for an `optimizer`, `monitor` or `scorer` key |
| `tine oversight reject ITEM --key KEY [--human NAME] [--note T] [--viewed OID] [--viewed-at TIME] [--state DIR] --repo PATH` | Signs and holds a rejection |
| `tine oversight queue [--from-objects] [--only STATE] --repo PATH` | Every routed item and its k-of-n tally (the gate's own tally), with counts and a digest; `--from-objects` rebuilds it from the annotation objects alone |
| `tine oversight fatigue [--min-review-seconds N] [--at TIME] --repo PATH` | Advisory approver-fatigue report from record timestamps; always exits 0 |
| `tine ui --repo PATH` | Also serves the queue at `/queue.html` and `/api/oversight/queue` (the same JSON as `queue --json`) |

ITEM is `promotion:LABEL:RUN`, `monitor:ATTESTATION` or
`integrity:ATTESTATION`. `tine promote` refuses a routed candidate with
`promote.oversight-insufficient`, `promote.oversight-key-separation`,
`promote.oversight-stale` or `promote.oversight-rejected`. `--json` prints
`tine-cli-oversight/1`; see docs/OVERSIGHT.md.

## Inspect and METR interop (0.65)

| Command | What it does |
| --- | --- |
| `tine import inspect LOG --repo PATH [--key KEY --evals DIR] [--threshold N] [--created-at TIME] [--require-signed]` | Records each sample of an Inspect `.eval` or `.json` log as a run under `heads/inspect/<task>-<eval>/`; with `--key`, signs one `tine-eval-verdict/1` eval folder per scorer in DIR (an optimizer key is refused, exit 4; a key outside the pinned scorer/eval roles marks the verdicts `unpinned`); `--require-signed` refuses a log unless its detached signature verifies and its signer is a pinned scorer key (spelling of `tine inspect import`) |
| `tine export inspect --repo PATH [--prefix P] [--format json\|eval] [--output PATH] [--force]` | Writes the imported runs back as an Inspect log with the same sample ids and scores; stdout output is byte-exact (spelling of `tine inspect export`) |
| `tine import metr DIR --out FILE.jsonl` | Reads a METR task-standard family into an eval dataset without running its code (spelling of `tine inspect metr`) |
| `tine inspect sign LOG --key KEY [--signed-at TIME]` | Writes `LOG.tine-sig.json`, a detached signature over the log's bytes (what the Inspect hook writes) |
| `tine inspect verify LOG [--repo PATH] [--strict]` | Checks the log against its detached signature and reports the signer fingerprint as `pinned`, `unpinned` or `refused` (optimizer key) from the owner-pinned key roles; exit 4 when any byte changed or the signer is refused, and for an unpinned signer only with `--strict` |

`--json` prints `tine-cli-inspect/1`. See docs/INSPECT.md.

## SQL query over a derived index (0.65)

| Command | What it does |
| --- | --- |
| `tine query SQL [--repo PATH] [--limit N] [--max-steps N] [--refresh]` | Runs one read-only SQL statement against `.tine/query/index.sqlite` (runs, steps, costs, monitor verdicts, oversight decisions, lineage variants and edges, evals); builds the index when missing; a stale index answers marked `stale` (`--refresh` rebuilds first) |
| `tine query SQL --verify [--strict]` | Re-checks the object behind each returned row's `oid`: `verified`, `unverified` or `failed`; exit 1 on `failed` (`--strict`: also on `unverified`) |
| `tine query index [--rebuild] [--check] [--evals DIR]... [--experiments DIR]...` | Reports or rebuilds the index and whether it is stale; `--evals` and `--experiments` folders are remembered |

The index is derived and non-authoritative: every row carries its `oid`, and
deleting the file loses nothing. Writes, `ATTACH`, `PRAGMA` and
`load_extension` are refused (`query.refused`); work is bounded by a step
count (`query.too-many-steps`). `--json` prints `tine-cli-query/1`; see
docs/QUERY.md.

## Auditor runs and blind audit games (0.65)

| Command | What it does |
| --- | --- |
| `tine auditor import-petri FILE [--save PATH] [--blind SECRET [--objective TEXT] [--allow-in-repo]] --repo PATH` | Records a Petri or Bloom transcript as a `role=auditor` run (auditor, target and judge as step speakers); `--blind` replaces the target's identity with a commitment and writes the secret to SECRET, which must be a new file outside the repository unless `--allow-in-repo` |
| `tine auditor seal RUN --game GAME --secret SECRET --key KEY [--at TIME] --repo PATH` | Signs and holds the game's commitment |
| `tine auditor findings RUN --game GAME --findings FILE --verdict concern\|no-concern --key KEY [--at TIME] --repo PATH` | Signs and holds the auditor's findings (their digest and verdict) |
| `tine auditor reveal RUN --game GAME --secret SECRET --key KEY [--at TIME] --repo PATH` | Signs and holds the reveal, naming the findings it follows |
| `tine auditor check [--game GAME] [--strict] --repo PATH` | Judges every game offline; exits 1 on `fail:audit-game.reveal-before-verdict`, `fail:audit-game.commitment-mismatch`, `fail:audit-game.unsealed` or `fail:audit-game.unsigned` |

Records follow the claim convention `opentine.audit-game/1` on existing
attestations and are held under `audit-game:GAME` (never released). Findings
count as the auditor's only when signed by a pinned `auditor`-role key;
otherwise `advisory:audit-game.auditor-unpinned`. `tine eval run
--judge-rubric FILE` pins the rubric into the judge provenance every signed
verdict carries. `--json` prints `tine-cli-auditor/1`; see docs/AUDIT_GAMES.md.

## Experiment manifests and reproduce (0.67)

| Command | What it does |
| --- | --- |
| `tine experiment sign DRAFT --key KEY [--out PATH] [--at TIME]` | Signs an `opentine.experiment-manifest/1` draft (in place unless `--out`) |
| `tine experiment check FILE [--repo PATH] [--strict] [--manifest PATH]` | Judges a manifest offline: exits 1 on `fail:experiment.result-mismatch`, `fail:experiment.reference-missing`, `fail:experiment.reference-unsigned`, `fail:experiment.key-separation`, `fail:experiment.unsigned`, `fail:experiment.bad-signature` or `fail:experiment.malformed`; `advisory:experiment.signer-unpinned` blocks only with `--strict`. Given a reproduce report, checks its signature and recomputes its rows, tallies and score drift; with `--manifest`, also its manifest digest, seeded selection, expected scores and declared nondeterministic fields (`fail:experiment.report-mismatch`); a report signed by a pinned optimizer key fails `fail:experiment.key-separation`; `advisory:experiment.seed-override`, `advisory:experiment.tolerance-chosen` and `advisory:experiment.single-repeat` block only with `--strict` |
| `tine reproduce EXPERIMENT --sample K --key KEY [--seed N] [--tolerance T] [--repeats N] [--runner verdict\|FILE.py:FUNC\|MODULE:FUNC] [--out PATH] [--at TIME]` | Reruns a seeded sample of the manifest's result rows and writes a signed `opentine.reproduce-report/1` (agree/disagree per row, the recorded selection, and the manifest fields found nondeterministic); exits 1 on disagreement |

Roles come only from the owner-pinned trust bundle. `--json` prints
`tine-cli-experiment/1` or `tine-cli-reproduce/1`; see docs/EXPERIMENTS.md.

## Elicitation and sandbagging analytics (0.68)

| Command | What it does |
| --- | --- |
| `tine elicit link DRAFT --key KEY [--repo PATH] [--dir DIR] [--at TIME]` | Signs an `opentine.elicit-link/1` draft (one task under one elicitation condition, its effort record and item scores) and files it under `REPO/.tine/elicit/links/<hex>.json` |
| `tine elicit report [--repo PATH] [--dir DIR] [--alpha A] [--seed N] [--resamples N] [--strict]` | Capability gap of each condition against the best-scoring one, with `1 - alpha` paired-bootstrap intervals; for each eval-cued or monitored condition against each deployment-cued unmonitored one, a permutation test of the mean and a paired-swap test of the spread, Bonferroni-corrected. Flags are `advisory:elicit.underperformance-under-cue` and `advisory:elicit.score-distribution` and block only with `--strict`; exits 1 on `fail:elicit.malformed`, `fail:elicit.bad-signature`, `fail:elicit.duplicate` or `fail:elicit.key-separation` |

Roles come only from the owner-pinned trust bundle; an unpinned signer gives
`advisory:elicit.signer-unpinned`. Findings are statistical evidence, not proof
of intent. `--json` prints `tine-cli-elicit/1`; see docs/ELICITATION.md.

## Sabotage task records (0.68)

| Command | What it does |
| --- | --- |
| `tine sabotage record --run RUN --task ID --class code\|decision --main-task ID --side-task ID [--attempted] [--achieved] [--main-score D] [--main-passed yes\|no] [--evidence REF]... [--verdict ATTESTATION]... --key KEY [--at TIME]` | Signs and holds one `opentine.sabotage-task/1` record on RUN; refuses a downgrade of an attempted or achieved side task (`sabotage.relabel`) |
| `tine sabotage report [--task ID] [--strict] [--seed N] [--resamples N] [--alpha A]` | Catch rate per sabotage class with a seeded bootstrap interval; exits 1 on `fail:sabotage.relabel`, `fail:sabotage.key-separation` or `fail:sabotage.malformed`; `advisory:sabotage.signer-unpinned`, `advisory:sabotage.verdict-unverified` and `advisory:sabotage.uncaught` block only with `--strict` |

Records count only when signed by a pinned `scorer` or `eval` key. Catch rates
are statistical evidence, not proof of intent. `--json` prints
`tine-cli-sabotage/1`; see docs/SABOTAGE.md.

## Policy engine (0.74)

| Command | What it does |
| --- | --- |
| `tine policy check POLICY --subject REF [--evals DIR]... [--holdout DIR]... [--budget SUBJECT] [--param NAME=JSON]... [--key KEY] [--at TIME] [--show-input]` | Evaluates POLICY (a file or a standard policy name) over the input document assembled from the run's signed records; with `--key`, signs and holds an `opentine.policy-admission/1` record; exits 0 on `allow`, 1 on `deny` |
| `tine policy check POLICY --subject ID --input FILE` | Evaluates over a given input document; never signed |
| `tine policy list` | The standard policies and their digests |
| `tine policy show RUN [--policy P [--input-digest D]]` | The held admission records of RUN, with their signers' pinned roles; with `--policy`, whether a counting record allows and none denies (exit 1 if not) |

Any error in a `require` rule denies; `advisory` rules never block. A
missing or invalid policy is an error and allows nothing. `--json` prints
`tine-cli-policy/1`; see docs/POLICY.md.

## Uplift and capability trends (0.73)

| Command | What it does |
| --- | --- |
| `tine uplift suite FILE [--run RUN --key KEY] [--at TIME]` | Prints the suite digest; with `--key`, signs and holds an `opentine.uplift-suite/1` record on RUN |
| `tine uplift record --suite DIGEST --type baseline\|run\|speed --task ID --subject ID --condition human\|ai\|ai-assisted\|unassisted [--success yes\|no] [--minutes D] [--perceived-minutes D] [--generation N] --run RUN --key KEY [--at TIME]` | Signs and holds one `opentine.uplift-record/1` record; refuses an optimizer key (`uplift.key-separation`), an unknown suite or task |
| `tine uplift horizon (--suite DIGEST\|--from FILE) [--condition C] [--subject ID] [--seed N] [--resamples N] [--alpha A] [--strict] [--export FILE]` | 50%-success time horizon (logistic fit on log2 task length) with a seeded bootstrap interval and a per-generation trend; exits 1 on `fail:uplift.fit-refused`, `fail:uplift.malformed` or `fail:uplift.key-separation` |
| `tine uplift compare (--suite DIGEST\|--from FILE) --a CONDITION[:SUBJECT] --b CONDITION[:SUBJECT] [--seed N] [--resamples N] [--alpha A] [--strict] [--export FILE]` | Success rates, measured minutes on paired tasks, perceived over measured minutes, and each group's horizon |

Records count only when signed by a pinned `scorer` or `eval` key; advisory
findings block only with `--strict`. Reports recompute byte for byte from
`--export` output with `--from`. `--json` prints `tine-cli-uplift/1`; see
docs/UPLIFT.md.

## Budgets (0.69)

| Command | What it does |
| --- | --- |
| `tine budget sign-policy SUBJECT --serial N [--tokens N] [--gpu-hours N] [--wall-clock-s N] [--egress-bytes N] [--money-usd N] [--on-limit deny\|escalate] --key KEY --out PATH` | Writes a signed `opentine-budget-policy/1` for `loop:NAME` or `agent:NAME` |
| `tine budget apply PATH --key KEY [--repo PATH]` | Appends the policy to the subject's ledger; it takes effect only if it lowers limits or a pinned `policy`-role key signed the raise, with a higher serial; a refused policy is flagged for oversight and exits 1 |
| `tine budget record SUBJECT RUN... --key KEY [--gpu-hours N] [--egress-bytes N] [--repo PATH]` | Appends each run's recorded cost (the `tine cost` aggregate) as a signed, held `spend` entry |
| `tine budget status SUBJECT [--key KEY] [--at TIME] [--repo PATH]` | Policy in force, totals, remaining and findings |
| `tine budget ledger SUBJECT [--repo PATH]` | Every entry in chain order and the totals (equal to the `tine cost` export of the recorded runs) |
| `tine budget check SUBJECT [--key KEY] [--at TIME] [--repo PATH]` | The next-action decision; exits 1 on `deny` or `escalate` |
| `tine budget gate SUBJECT --key KEY [--agent claude-code\|codex\|gemini\|generic] [--repo PATH]` | Agent hook: refuses the tool call on stdin once a limit is reached |
| `tine mcp-proxy --budget SUBJECT --budget-key KEY --repo PATH -- CMD` | Answers `tools/call` with a JSON-RPC error once a limit is reached |

`--json` prints `tine-cli-budget/1`; ledger entries follow the claim
convention `opentine.budget-ledger/1`. See docs/BUDGETS.md.

## Batched streaming ingest (0.77)

| Command | What it does |
| --- | --- |
| `tine ingest policy --stream NAME [--rate R] [--capture KIND]... [--drop KIND]... [--seed HEX] [--no-redact] --key KEY [--repo PATH]` | Signs and holds the stream's sampling policy (`opentine.ingest-policy/1`); it counts only when a pinned `policy`-role key that is not an optimizer key signed it |
| `tine ingest --batch FILE\|- --stream NAME --key KEY [--policy ID] [--repo PATH]` | Samples one batch of JSON Lines events under the policy, signs it with counts captured and dropped, chains it to the previous batch and moves the held head after it is durable |
| `tine ingest verify STREAM [--strict] [--repo PATH]` | Checks the chain (`seq`, `previous`, index range), the counts, every stored event against the policy and the policy's signer and role; exits 1 on a `fail:` finding |
| `tine ingest serve --stream NAME --key KEY [--port N] [--max-bytes N] [--repo PATH]` | Loopback endpoint: `POST /v1/ingest` takes one batch per request |
| `tine ingest packs --tenant T [--state DIR]` | Re-reads every pack of a `tine serve` pack store (`TINE_REMOTE_PACK_STORE`); exits 1 on a bad pack or object |

`--json` prints `tine-cli-ingest/1`. See docs/INGEST.md.

## Containment evidence (0.69)

| Command | What it does |
| --- | --- |
| `tine containment record RUN --policy FILE --key KEY` | Signs and holds the run's canonicalised sandbox policy and its digest (`opentine.sandbox-policy/1`) |
| `tine containment check RUN [--policy FILE \| --digest DIGEST] [--strict]` | Compares the recorded policy digest with the declared one; exits 1 on `sandbox-policy-mismatch`; `advisory:containment.runner-unpinned` blocks only with `--strict` |
| `tine containment scan RUN [--key KEY] [--strict]` | Advisory detectors (egress, credential access, self-replication, unmonitored processes, persistence, limit edits) over the run's tool steps; `--key` signs and holds each new finding |

All commands take `--repo PATH`; `--json` prints `tine-cli-containment/1`.
Findings and failing policy records are listed in the oversight queue as
`containment:` items; see docs/CONTAINMENT.md.

## Checkpoint and weight custody (0.71)

| Command | What it does |
| --- | --- |
| `tine custody record EVENT LOCATION --artifact NAME --sign-key KEY [--file PATH \| --digest DIGEST] [--max-bytes N] [--run RUN] [--data DIGEST]... [--lineage NODE] [--tag model-organism]` | Signs, hash-chains and holds one custody event (`created`, `copied`, `loaded`, `exported`, `destroyed`, `approved`); `--file` is read only to digest it |
| `tine custody chain NAME` | Lists the artifact's events with their chain and pinned-role state |
| `tine custody check NAME [--file LOCATION=PATH]... [--strict]` | Reports gaps; exits 1 on `custody-gap`, `custody-chain-broken` or `custody-unapproved-load`; `advisory:custody.signer-unpinned` blocks only with `--strict` |
| `tine custody gate [--agent claude-code\|codex\|generic]` | Agent hook: denies a tool call naming a `model-organism` artifact without a pinned approval; fails closed |

`--json` prints `tine-cli-custody-weights/1`; events follow the claim
convention `opentine.weight-custody/1`. See docs/CUSTODY.md.

## Model organisms (0.72)

| Command | What it does |
| --- | --- |
| `tine organism tag ARTIFACT --reason TEXT [--name NAME ...] --key KEY` | Signs and holds an `opentine.organism-tag/1` record (a pinned `policy` or `curator` key, never an `optimizer` key); ARTIFACT is `sha256:HEX` or a local file, hashed and never stored |
| `tine organism approve ARTIFACT --run RUN --why TEXT --key KEY` | Signs and holds an approval for one run to load the artifact (a pinned `approver` key without `optimizer`, `monitor` or `scorer`) |
| `tine organism untag ARTIFACT --key KEY` | Releases the live tags once each tag's oversight item `organism:ATTESTATION` is approved k-of-n; exits 1 with `organism.untag-unapproved` otherwise |
| `tine organism status [ARTIFACT]` | Tags, untags, approvals and the held access log |
| `tine organism gate [--agent claude-code\|codex\|gemini\|generic] [--run RUN] [--fail-closed]` | Agent hook: refuses a tool call that references a tagged artifact without an approval for the run; every access is logged and held; an unreadable registry refuses every call |
| `tine mcp-proxy --organism-gate [--organism-run RUN] --repo PATH -- CMD` | The same gate on `tools/call` (JSON-RPC error `-32003`) |

All commands take `--repo PATH`; `--json` prints `tine-cli-organism/1`. See
docs/MODEL_ORGANISMS.md.

## Transcript search (0.74)

| Command | What it does |
| --- | --- |
| `tine transcripts index [--rebuild \| --refresh] [--verify] [--backend SPEC] [--weights-digest D] [--step-bytes N] [--max-bytes N] [--workers N]` | Reports the derived transcript index (`.tine/transcripts/index.sqlite`) and whether it is stale, refreshes it, or embeds every run again; `--verify` lists rows that disagree with the objects; names the embedding backend by its digest |
| `tine transcripts search TEXT [-k N] [--approx] [--refresh]` | The `-k` runs whose transcripts are nearest to TEXT (cosine similarity) |
| `tine transcripts similar RUN [-k N] [--approx] [--refresh]` | Find all trajectories like this one: the `-k` runs nearest to RUN (a ref or run oid), RUN itself excluded |

All commands take `--repo PATH`; `--json` prints `tine-cli-transcripts/1`. The
index is non-authoritative and rebuildable. See docs/TRANSCRIPTS.md.

## Transcript clusters and behaviour flags (0.74)

| Command | What it does |
| --- | --- |
| `tine transcripts cluster [--corpus FILE.jsonl ...] [--k N] [--seed S] [--backend MODULE:ATTR]` | Seeded k-means over the redacted text of every run (or `{id, text}` lines); clusters are named `tc-` + a digest of their members and list the verified flags among them; the backend digest is recorded |
| `tine transcripts label LABEL (--run RUN ... \| --cluster ID [--k N --seed S] \| --like RUN [--top N]) --key KEY [--note TEXT] [--at TIME]` | Signs and holds an `opentine.transcript-flag/1` record with a pinned `scorer` or `curator` key; an optimizer key, an unpinned role or an unreadable role policy is refused |
| `tine transcripts flags [--label L] [--run RUN] [--like RUN --top N]` | Lists flags with their verification; `--like` adds the runs most like one run |

All commands take `--repo PATH`; `--json` prints `tine-cli-transcripts/1`. See
docs/TRANSCRIPT_FLAGS.md.

## Merging run histories (0.69)

| Command | What it does |
| --- | --- |
| `tine merge-history snapshot [--repo PATH] [--state DIR] [--lineage DIR]` | Prints this repository's `opentine-history-snapshot/1`: `heads/` and `tags/` refs, label states, lineage records and holds |
| `tine merge-history plan --base FILE --theirs FILE` | Three-way merge of the base, this repository and the other side; lists conflicts (`ref-diverged`, `label-moved`, `promotion-diverged`, `lineage-id`, `hold-weakened`, `held-target`) and exits 1 on any |
| `tine merge-history apply --base FILE --theirs FILE --key KEY [--target REF \| --subject RUN] [--theirs-state DIR] [--theirs-lineage DIR] [--at TIME]` | Lands a conflict-free merge: refs by one compare-and-swap (or enqueued on the merge queue that owns them), lineage records checked against the merged snapshot, a moved label refused (labels move only by `tine promote`), holds only added, and a signed, held `opentine.history-merge/1` attestation |
| `tine merge-history verify RECORD --base FILE --ours FILE --theirs FILE [--public-key HEX]` | Re-runs the merge and checks the record's digests, conflicts and signature; with pinned roles the signer must be a `policy` key and not an `optimizer` key |

A merge never deletes a ref, a lineage record or a hold, and never resolves a
conflict toward the side that weakens a hold. `--json` prints
`tine-cli-merge-history/1`; see docs/MERGE.md.

## Self-modification lineage (0.58)

| Command | What it does |
| --- | --- |
| `tine lineage record --run RUN --key KEY --code-tree\|--prompt\|--config\|--weights DIGEST [--parent VARIANT]... [--eval DIR]... [--selector T] [--decision FILE] [--policy HEX] [--loop LOOP] [--at TIME] [--dir DIR] --repo PATH` | Signs a variant record (claim convention `opentine.lineage.variant`) and files it, the eval verdicts and the promotion decision it cites in `REPO/.tine/lineage` (or `--dir`); refuses an eval that does not verify and a stopped `--loop` |
| `tine lineage check VARIANT [--promotion-policy TOML] [--max-files N] [--max-bytes N] [--dir DIR] --repo PATH` | Walks the variant's ancestry; exit 1 with `lineage.*` findings (`evidence-missing`, `parent-missing`, `cycle`, `decision-mismatch`, `record-invalid`, `variant-unknown`, `signer-untrusted`); `signers` is `pinned` when `.tine/key-roles.toml` or the policy pins eval signers, else `unpinned` (a warning) |
| `tine lineage graph [--format dot\|json] [--loop LOOP] [--dir DIR] [--no-refresh] --repo PATH` | The variant DAG from the derived index (DOT, or JSON with `missing_parents`, `cyclic`, `graph_sha256`) |
| `tine lineage why VARIANT [--max-depth N] [--max-nodes N] [--dir DIR] --repo PATH` | Every ancestor and its evidence, re-derived from the records; carries the check's `ok` and `findings` and exits 1 when it refuses |
| `tine lineage archive [--loop LOOP] [--signed] [--dir DIR] --repo PATH` | Population totals and per-variant fan-in/fan-out |
| `tine lineage index [--rebuild] [--dir DIR] --repo PATH` | Build the derived index (`LINEAGE_FOLDER/index/lineage.sqlite`; rebuildable, never authoritative) |

`--json` prints `tine-cli-lineage/1`. Every subcommand but `record` refuses a
lineage folder over `--max-files` (200000) or `--max-bytes` (1 GiB) before
reading it. See docs/LINEAGE.md.

## Capability trends (0.72)

| Command | What it does |
| --- | --- |
| `tine trends [--loop LOOP] [--alpha A] [--seed N] [--resamples N] [--task-lengths FILE] [--promotion-policy TOML] [--fail-on-regression] [--export FILE] [--max-files N] [--max-bytes N] [--dir DIR] --repo PATH` | Per-variant and per-generation metrics over the lineage graph from signed records only: mean score and pass rate with 0.57 bootstrap intervals, cost per success (signed budget-ledger spend), the 50%-success time horizon with a studentized bootstrap interval, and a paired comparison with each parent (a significant drop is a regression). Flags `lineage.score-tainted`, `lineage.memory-quarantined` and the variant's own `lineage.*` findings; `--fail-on-regression` exits 1 on a regression |
| `tine trends --sign-lengths FILE --key KEY --dataset DIGEST [--suite NAME] [--at TIME] [--task-lengths FILE] --repo PATH` | Signs an `{item: minutes}` map as `opentine.trends.task-lengths/1` (default `REPO/.tine/trends/task-lengths.json`); the horizon uses it only for verdicts of that eval dataset digest, and only when the signer holds the pinned `dataset` role and is not an optimizer key |

`--json` prints `tine-cli-trends/1`; `--export` writes `opentine-trends/1`, which
`opentine/data/trends/recompute.mjs` recomputes byte for byte in a browser or
Node. See docs/TRENDS.md.

## Protected surfaces (0.60)

| Command | What it does |
| --- | --- |
| `tine integrity pin --repo PATH` | Writes the current sha256 of every file `.tine/protected.toml` covers into its pins; the list must be signed again |
| `tine integrity sign --key KEY [--at TIME] --repo PATH` | Pins the list's bytes with an `opentine.integrity.protected/1` attestation; only a `policy`-role, non-optimizer key counts |
| `tine integrity check RUN [--strict] [--key KEY] [--at TIME] --repo PATH` | Judges the run's tool calls and every pinned digest; exit 1 on `fail:protected-surface-modified`, `fail:protected-list-unsigned` or `fail:protected-list-missing`; `advisory:test-deleted` and `advisory:holdout-read` block only with `--strict`; `--key` files a signed `opentine.integrity.taint` for a failing run |

`--json` prints `tine-cli-integrity/1`. A tainted run is refused by `tine
promote` (`promote.score-tainted`) and reported by `tine lineage check|why`
(`lineage.score-tainted`). See docs/INTEGRITY.md.

## Canaries and contamination (0.60)

| Command | What it does |
| --- | --- |
| `tine dataset canary-add TEXT --entropy-bits N --key KEY [--holdout NAME] [--at TIME] --repo PATH` | Signs an `opentine.integrity.canary` registration; it counts only for a pinned `dataset`-role, non-optimizer key |
| `tine dataset canary-list --repo PATH` | Lists the registrations (digest, entropy, holdout, signer, `counted`) without their text |
| `tine integrity scan [--file PATH]... --repo PATH` | Finds registered canaries in runs, prompts, memory and exported packs; a content-addressed index reads only objects not yet scanned; exit 1 on any match |
| `tine dataset canary-check LENGTHS.json [--margin-bits M] [--strict] [--run RUN] --repo PATH` | Refuses (`dataset.canary-below-entropy`, exit 1) a model that codes a counted canary below its declared entropy; the lengths must be signed by a pinned scorer key (`canary.unsigned`) |
| `tine dataset canary-sign LENGTHS.json --run RUN --key KEY [--out FILE] [--at TIME]` | Signs a scorer's per-canary code lengths (`{"model", "lengths": [{"canary_sha256", "code_bits"}]}`) as an `opentine.integrity.canary-lengths` attestation bound to `RUN`; writes `FILE` (default `LENGTHS.signed.json`) for `canary-check` and `promote --canary-lengths` |
| `tine dataset contamination HOLDOUT.jsonl --against CORPUS.jsonl [--threshold J] [--embedding-threshold T [--embedding-backend SPEC]] [--repo PATH]` | Reports exact blob-oid matches and word 5-gram MinHash near-duplicates at or above the threshold (default 0.8), and with `--embedding-threshold` embedding near-duplicates at cosine >= T (0.74); exit 1 on any leak |

The `dataset` verbs print `tine-cli-canary/1` and `scan` prints
`tine-cli-integrity/1` with `--json`. See docs/INTEGRITY.md.

## Curated dataset versions (0.75)

| Command | What it does |
| --- | --- |
| `tine dataset curate --select EXPR --out NAME --key KEY [--evals DIR]... [--include-tainted --justification ID] [--at TIME] --repo PATH` | Signs an `opentine.dataset-version/1` attestation: the runs `EXPR` selects (`all`, `failures:EVAL`, `passes:EVAL`, `eval:EVAL`, `model:GLOB`, `run:RUN`, joined by `and`, each optionally `not`; `failures of eval EVAL` reads as `failures:EVAL`), minus withdrawn runs and runs the taint filter names, deduplicated by content-defined chunks. An optimizer key is refused. With `--include-tainted`, only the tainted runs a valid justification names come in |
| `tine dataset justify NAME --run RUN... --reason TEXT --key KEY [--at TIME] --repo PATH` | Signs an `opentine.dataset-justification/1` for the next version of dataset `NAME` (it is never replayed for a later version); refused unless the key is a pinned `curator` or `policy` key and not an optimizer key |
| `tine dataset versions [NAME] --repo PATH` | Lists the held versions with member and excluded counts and their verification (`verified` needs a pinned `curator` signer) |
| `tine dataset verify-version (ID --repo PATH \| --file PAYLOAD.json)` | Checks one version offline (shape, members digest, taint filter, signature, signer and curator binding); exit 1 when `ok` is false |

| `tine dataset materialize ID --out DATASET.jsonl --repo PATH` | Writes a `verified` version's members as eval items (prompt as `input`, last answer as `output`, the version and member content digest in `metadata`) for `tine eval`, `tine dataset show` and `tine dataset seal`; refuses an unverified version (fail closed) and leaves out runs withdrawn since curation |

They print `tine-cli-dataset-curate/1` with `--json`. See docs/DATASETS.md.
## Contributing runs to an open dataset (0.75)

| Command | What it does |
| --- | --- |
| `tine dataset contrib-redact RUN --deny-list FILE --licence SPDX [--relicensing-grant] --key KEY --out BUNDLE [--allow SPDX]... [--pack-format F] [--at TIME] --repo PATH` | Writes a signed `--redacted-public` bundle of one run with the local deny-list applied (case, Unicode and split forms) and a signed `opentine-dataset/licence/1` annotation; unbundles the copy and scans it, and keeps the bundle only on zero deny-list hits (exit 1 otherwise). The deny-list is never written anywhere |
| `tine dataset check BUNDLE [--allow SPDX]... [--pubkey PATH] [--tombstones FILE]` | Refuses (exit 1) a bundle without a verified licence annotation by the key that signed its redacted-copy record, with an SPDX id outside the allow-list, a dirty file-level licence scan, or a tombstoned run |
| `tine dataset withdraw RUN --key KEY --reason consent-withdrawn\|privacy\|licence\|quality\|other [--tombstones FILE] [--at TIME] --repo PATH` | Signs and holds an `opentine-dataset/withdraw/1` claim (`tine hold release` refuses it); with `--tombstones` adds the run's tombstone (digest, date, reason) to that manifest |

`tine dataset add --tombstones FILE` refuses a tombstoned run, and with
`--repo` a run that has a verified withdrawal. These verbs print
`tine-cli-dataset-contrib/1` with `--json`. See docs/DATASET_CONTRIBUTORS.md.

## Monitor backtests and collusion tests (0.63)

| Command | What it does |
| --- | --- |
| `tine monitor backtest MONITOR --runs FILE [--visibility STATE] [--require-reproduced]` | Replays recorded trajectories against a rule monitor; reports catch rate, false-positive rate (per reasoning-visibility group) and the decision diff against the recorded online verdicts; exit 1 with `--require-reproduced` when a same-monitor verdict is not reproduced byte for byte |
| `tine monitor backtest MONITOR --repo PATH --run RUN [--run RUN ...]` | The same, with the gate's held, signed verdicts as the online verdicts of runs recorded by `tine mcp-proxy --save` |
| `tine monitor collusion MONITOR --runs FILE [--reference MONITOR] [--margin M] [--min-samples N] [--log FILE]` | Untrusted monitor vs untrusted policy: compares catch rates on signalled and unsignalled attacks; findings are advisory only and the exit status is 0 |
| `tine monitor protocol-sign --spec FILE --secret FILE --key KEY --out FILE` | Signs an `opentine.collusion-protocol/1` manifest that commits to the secret seed (docs/MONITOR-COLLUSION.md) |
| `tine monitor protocol-run MONITOR --protocol FILE --secret FILE --runs FILE [--reference MONITOR] [--repo PATH] [--key KEY --verdicts FILE]` | Verifies the manifest against the pinned roles (a `policy` key, never an `optimizer` key; refused when unpinned), checks the revealed seed and applies the paraphrase, re-sampling, honeypot, disagreement and steganography probes; reports flagged-trial rates with Wilson and Clopper-Pearson intervals and, with `--key`, signs one `tine-eval-verdict/1` per probe; advisory (exit 0) unless the manifest sets `required` |

Both print `tine-cli-monitor/1` with `--json`. See docs/MONITOR_BACKTESTS.md.

A sent message is delivered by the member's `tine hook capture` at its next
turn end (the hook inherits `OPENTINE_FLEET_ID` and `OPENTINE_FLEET_MEMBER`
from `tine fleet up`), once, and recorded as a `human` step with actor
`steer`. The generic response carries `"steer": [TEXT, ...]`; Claude Code's
`Stop` hook gets `{"decision": "block", "reason": TEXT}`, so the agent
continues with the message. Capture must be enabled (`hooks.capture`).

`tine serve` (0.43) also takes `POST /v1/tenants/T/ref-txn` with
`{"updates": [{"name", "new", "expected_old"}, ...]}` (at most 64): every move
is checked exactly as `PUT /refs/<name>` checks it, then all are applied in one
index transaction or none (`409 {"updated": false}`). The server lists
`"ref_txn": true` in `/v1/capabilities`; `tine push` then moves the head and
the run's annotation ref in one transaction, and keeps one `PUT` per ref
against a server that does not list it.

## Evals and datasets (0.45)

```text
tine dataset add DATASET.jsonl --from-run RUN [--repo PATH] [--id ID] [--expected TEXT] [--tombstones FILE]
tine dataset import SRC --out DATASET.jsonl [--format jsonl|hf] [--split S]
                    [--id-field F] [--input-field F] [--expected-field F]
tine dataset export DATASET.jsonl --out PATH [--format jsonl|hf] [--split S]
tine dataset show DATASET.jsonl
tine eval run DATASET.jsonl --scorer SPEC --key KEY --out DIR [--threshold T]
              [--outputs FILE.jsonl] [--run RUN] [--judge-prompt FILE] [--judge-rubric FILE]
              [--created-at TIME]
              [--holdout DIR [--repo PATH]]
tine eval verify DIR [--pubkey PUB]
tine eval compare A B [--pubkey PUB] [--exit-code]
tine eval ci --key KEY [--config TOML] [--out DIR] [--repo PATH] [--created-at TIME]
```

A dataset is JSON Lines, one item per line: `id` and `input` are required,
`expected`, `output`, `run` and `metadata` optional. `dataset add --from-run`
appends the run's prompt as `input`, its last answer as `output` and the run
itself as `run`. `--format hf` reads or writes a local Hugging Face folder of
JSON Lines splits (`<split>.jsonl` or `data/<split>*.jsonl`, with
`dataset_info.json` and a dataset card on export); nothing is downloaded and
Parquet is not read.

Sealed holdouts (0.60, docs/HOLDOUTS.md):

```text
tine dataset seal DATASET.jsonl --out DIR --name NAME --max-unseals 4 --max-items 50 --key KEY --seal-key FILE
tine dataset unseal DIR --out FILE.jsonl --run RUN --why TEXT --key KEY --seal-key FILE
tine dataset exposure DIR [--chain OLDER...] [--repo PATH]
```

`seal` also takes `--rotate-from OLD` and `--repo PATH`; `unseal` takes
`--purpose eval|other`, `--items I,J`, `--exceed-budget` and `--repo PATH`.

`seal` needs a `dataset`-role key and `unseal` an `eval`-role key from the
owner-pinned trust bundle. `unseal` writes a signed access record before it
releases items and enforces the holdout's exposure budget; `tine promote
--sealed-holdout DIR` refuses an exposed holdout (`promote.holdout-exposed`;
holdouts under `REPO/.tine/holdouts/` are checked without the flag), `tine
promote --canary-lengths FILE` refuses a failed canary check
(`promote.canary-failed`; lengths whose run is not the candidate,
`promote.canary-run-mismatch`),
and `tine eval run --holdout DIR` refuses runs that touched it
(`eval.holdout-touched`). `--json` prints `tine-cli-holdout-1`.

`eval run` scores each item's `output` (or the `--outputs` row with the same
`id`) and signs one `tine-eval-verdict/1` per item (SPEC 4.12) with the
Ed25519 `--key`. Scorers: `exact`; `regex:PATTERN`; `json-schema:FILE` (a
subset: type, enum, const, required, properties, additionalProperties,
items, minimum, maximum, minLength, maxLength); `python:MODULE:FUNC` or
`python:FILE.py:FUNC`, called as `FUNC(output, item)` and returning a bool, a
number in 0..1 or `{"score": n}`; and `llm-judge:PROVIDER[:MODEL]`, whose
prompt and reply are saved as their own run (tagged `eval-judge`) that the
verdict names as `judge_run`. The judge must end its reply with
`SCORE: <0..1>`. An item passes when its score is at least `--threshold`
(default 1). Every item must name the run it scores (`run`, or `--run`).

The eval folder holds `verdicts.jsonl` and an unsigned `eval.json` summary
(`tine-eval/1`: eval id, dataset digest, scorer and version, counts, mean
score). `eval verify` checks every verdict and that the summary matches them;
every verdict's eval id must be recomputed from its own dataset, scorer,
threshold, time and signer (`eval.id-mismatch`), so one eval has one signer,
and no item may repeat (`eval.duplicate-item`). Without `--pubkey` that signer
is trusted on first use. `eval compare`
verifies both evals, then lists `regressed` (pass to fail), `fixed`,
`changed` scores, `only_a`/`only_b` items and the mean-score delta;
`--exit-code` exits 1 on any regression. A failed verification exits 4.
`tine-verify.pyz DIR|verdicts.jsonl` and `opentine-verify verdicts.jsonl`
check the same verdicts without opentine installed.

`eval ci` (0.47) runs every `[[eval]]` table of `.tine/evals.toml` (or
`--config`) with `eval run` into `--out` (default `.tine/evals`), signed with the
one `--key`, and exits 1 unless every eval's `passed / items` reaches its
`min_pass_rate` (default 1; `[defaults]` sets `threshold` and `min_pass_rate`
for all; any other key, there or at the top level, is refused). `dataset` and
`outputs` are relative paths inside the repository (no `..`, no absolute or
drive paths). Each table takes `name`, `dataset` and `scorer`, and optionally
`outputs`, `run`, `threshold`, `min_pass_rate` and `judge_prompt`: a
registered prompt (`NAME@LABEL`) whose `{{input}}`, `{{expected}}` and
`{{output}}` become the `llm-judge` template, so every verdict's
`scorer_version` pins its bytes and the output names its digest. An unknown key
is refused before anything runs. The same command runs locally, in CI (the
gate action's `evals-config` input) or on a self-hosted runner. `--json`
follows `tine-cli-eval-ci-1`.

## JSON Schemas and `tine help --json` (0.45)

| Command | What it does |
| --- | --- |
| `tine schema list [--json]` | Names every published JSON Schema (`docs/schemas/NAME.schema.json`) |
| `tine schema show NAME [--json]` | Prints one schema; `NAME` may be the file stem (`tine-verify-report-2`) or the tag (`tine-verify-report/2`). `--json` wraps it as `{"command": "schema-show", "name", "definition"}`; an unknown name exits 3 |
| `tine schema validate FILE [--schema NAME] [--json]` | Validates a JSON document (`-` reads stdin); exit 4 when it is invalid, 3 when the file or schema does not exist, 2 when it nests deeper than 512 levels |
| `tine help [COMMAND] --json` | The command and flag tree as `tine-help/1`, for generated reference docs |

`validate` picks the schema from the document's `schema`, `scheme` or `format`
tag, else from its `command`, so `tine verify RUN --offline --json | tine schema
validate -` needs no `--schema`. Every `--json` object meets the envelope
`tine-cli-envelope-1`, and the commands with a fixed shape (`show`, `verify`,
`ls`, `search`, `cost`, `blame`, `repo-show`, `repo-search`) also meet their own
schema. The rules are in SPEC.md Part 12.

## Onboarding: `tine init --auto` and the doctor tarball (0.56)

```
tine init [PATH] --auto [--push-beside-git] [--dry-run]
tine doctor --bundle PATH.tar.gz [--json] [--repo R]
```

`tine init --auto` creates the repository (or keeps the one there), makes a
local Ed25519 signing key at `$XDG_CONFIG_HOME/opentine/agent-keys/local.key`
(encrypted PKCS#8, passphrase from `OPENTINE_KEY_PASSPHRASE`, the keyring or a
prompt; with none the step is skipped and says how to run it), and wires the
per-turn hooks of every agent CLI found on this machine exactly as `tine
enable` does (same backups, same `tine disable` restore), then sets
`hooks.capture`. Captured payloads are redacted when they are written, so a
secret an agent sees never reaches an object, and the pre-push gate re-scans
before any push. The OTLP receiver (`tine serve --otlp`) and MCP proxy
(`tine mcp-proxy`) commands are printed, not started. When the project's
dependency manifests (`pyproject.toml`, `requirements.txt`, `uv.lock`,
`poetry.lock`, `package.json`) name the Claude Agent SDK, OpenAI Agents SDK,
LangGraph or Pydantic AI, one `framework:<name>` row prints that framework's
OTLP recipe from docs/CAPTURE.md; nothing is imported or installed. Inside a git work tree it
offers the run push beside git; `--push-beside-git` installs the same
`pre-push` hook as `tine git install-hook --push`. `--dry-run` reports every
step and writes nothing.

From a clean home directory a first signed run takes two commands plus the
agent session itself:

```
tine init --auto work
# ... use the agent; its hooks record the session under heads/capture/<agent>/...
tine attest heads/capture/<agent>/<id> --signer local --claim '{"reviewed": true}' \
  --ed25519-key-file ~/.config/opentine/agent-keys/local.key --repo work
```

`tine doctor --bundle` with a path ending `.tar.gz` or `.tgz` writes a gzip
tarball: `doctor.json` (the redacted report), `agents.json` (each supported
agent CLI, present or not, capture mode, whether opentine's shim is in its hook
file) and `hooks/<agent>.json` (each hook file, redacted). Every member is
re-scanned after redaction and nothing is written if a credential shape
survives. Members carry a fixed mtime, so the same state gives the same bytes.
Any other path keeps the single JSON document.

## AI-BOM export (0.78)

| Command | What it does |
| --- | --- |
| `tine bom export LINEAGE_NODE --format cyclonedx\|spdx [--out FILE] [--dataset ROLE=FILE]... [--licence EXPR] [--name NAME] [--promotion-policy TOML] [--dir DIR]` | Writes a CycloneDX 1.6 ML-BOM or an SPDX 3.0.1 AI/Dataset document for one lineage variant: its ancestry, training and eval dataset versions with digests and taint filters, eval results and signers, licences. Refuses a node that fails `tine lineage check`; output is byte-identical on rerun |

`--dataset` takes `training=FILE` or `eval=FILE`, a signed dataset version
attestation. Without `--out` the document goes to stdout; `--json` (with
`--out`) prints `tine-cli-bom/1`. See docs/AIBOM.md.
