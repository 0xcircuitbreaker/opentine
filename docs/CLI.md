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

`tine trust policy set|list|show|rm|default` is new in 0.16 (no older spelling):
named trust policies for `tine verify --policy NAME` (see below).

`tine agent id|show|trust|keys` are unchanged. `tine GROUP --help` lists a group;
`tine help --all` lists every command.

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
has `--text`; giving both is an error. Commands without `--json` ignore the
setting and never read the file. A value other than `text`/`json` in the env var
or the file, or a malformed file, stops the command with a one-line error (exit
1) instead of guessing. `tine config set|get|unset` are the user settings;
`tine config KEY [VALUE]` still edits the repository's porcelain keys. With no
setting, every command's output is unchanged.

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
