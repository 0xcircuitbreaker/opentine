# Projects and the code mirror formats

A **project** is a run repository plus the code repositories it is linked to.
This page covers what the CLI ships in 0.46 so that opentine-web can read it
in 0.47: the project manifest, the mirror-state host statement, the git object
check and the `tine serve` routes. The normative text is SPEC
[4.16](SPEC.md#s-4.16), [4.17](SPEC.md#s-4.17), [4.18](SPEC.md#s-4.18) and
[8.18](SPEC.md#s-8.18); the plan is ROADMAP §11 "Projects and code mirror".

## The manifest: `opentine.project`

One version is a canonical JSON object signed by an owner (Ed25519,
`tine-sig/3` over `opentine.project.v1:` + JCS of `{body, header}`):

```json
{"kind": "opentine.project", "project_version": 1, "project_id": "app",
 "tenant": "acme", "seq": 1, "prev": "blob:sha256:<digest of version 0>",
 "visibility": "public", "owners": ["<ed25519 public key hex>"],
 "slots": [{"role": "primary", "forge": "github", "forge_repo_id": "R_kgDOExample",
            "upstream_visibility": "public",
            "locator": {"url": "https://github.com/example/app.git"},
            "default_branch": "main"}],
 "forked_from": null, "created_at": "2026-11-08T00:00:00Z", "signature": {...}}
```

- **Chained.** `prev` is the previous version's digest: the blob oid of its
  canonical bytes. `seq` counts from 0. Each version is signed by an owner of
  the version before it (the first by one of its own owners), so changing the
  owners, the upstream or the visibility is always a visible, owner-signed
  version. A server never signs one.
- **Slots.** A primary slot and at most one secondary, each naming its forge
  (`github`, `gitlab`, `forgejo`, `git`, `entire`), the forge's repository id
  where it has one, the default branch and a locator.
- **Visibility.** A public project names its upstream by `url` and may not
  reference a private upstream. A private project names it by `commitment`:
  `sha256(opentine.project.locator.v1: || salt || NUL || url)`. The URL and
  salt stay with the owner (`.tine/project-locators.json`), so neither the
  manifest nor the transparency log holds a private URL or repository name.
- **Where it lives.** Locally under the `project/manifest` ref (a blob). On a
  remote, beside the tenant's objects and outside the ref listing, so older
  clients fetch, clone and push exactly as before.

Refusal codes: `project.malformed`, `project.private-upstream`,
`project.plaintext-locator`, `project.unsigned`, `project.wrong-signer`,
`project.bad-signature`, `project.chain-break`.

## The host statement: `opentine.mirror-state`

A code mirror (an opentine-web service) records, for one slot of one manifest
version, the commit each ref pointed at when it last synced, a status
(`synced`, `stale`, `failed`, `paused`) and `mirror.*` reason codes. It is
signed by the **host service key**, never a user's (a statement signed by a
project owner is refused as `mirror-state.user-signed`). A verifier checks who
said it, not whether it is true, so it never reports a mirror state as a pass:
a good one reads `host statement, not verified by you`.

The ten project reason codes of `tine-verify-report/2`:

| Code | Outcome |
|---|---|
| `project.manifest-signature`, `project.manifest-chain`, `git-object.mismatch` | fail |
| `mirror.stale`, `mirror.history-truncated`, `mirror.host-statement`, `mirror.upstream-unverifiable` | caveat |
| `mirror.blob-not-mirrored`, `mirror.upstream-unreachable`, `mirror.limit-exceeded` | unavailable |

## The git object check

Given a type, bytes and a git object id, recompute the id (SHA-1 for 40 hex,
SHA-256 for 64 hex) and list what the object links (a tree's entries, a
commit's tree and parents, a tag's object). It runs in Python
(`opentine._git_object`), the TS verifier (`checkGitObject`, browser-safe
through `@noble/hashes`) and `tine-verify.pyz`. A match reads `matches its id
(checked by you)`; it says nothing about whether the upstream holds that id.
SHA-1DC collision detection is not implemented.

## `tine serve`

`caps.project`: `GET project`, `GET project/history?cursor=N` and `PUT
project` (writers and admins; a compare-and-swap on the head digest that
accepts only a manifest chained to the current one and signed by one of its
owners). `caps.social_export`: `GET social`, count-only stars and watches.
Reads the caller may not make answer the same `404` as a tenant without a
project; `tine serve` stores no code and has no upload-pack, receive-pack or
mirror capability.

## CLI

`tine project init|link|show|history|verify|push` and `tine remote add
--project ID` (see [CLI.md](CLI.md#projects-tine-project-046)).
`tine project verify --remote` also refuses (exit 4, `project.chain-break`) a
remote history that forks from this repository's: one must be a prefix of the
other.

## Conformance

`docs/conformance/vectors/65-project.json` (ops `project.verify`,
`project.chain`) and `66-mirror-state.json` (ops `mirror-state.verify`,
`git-object.check`), answered by Python, the TS verifier and the pyz.
