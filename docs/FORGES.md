# Forge integration (0.48)

OpenTine is the evidence layer under a forge, not a forge. `tine forge publish`
shows, on the commit and its pull or merge request, how much of the code an
agent wrote, whether the recorded runs verify, which lines came from which run
(the blame overlay), and a link to a bundle anyone can verify offline. What it
posts is one `opentine.forge-check` record (SPEC 4.24); the forge only displays
it, so the record never replaces `tine bundle verify`.

| Forge | What appears | API |
|---|---|---|
| GitHub | a check run named `opentine` (conclusion, summary, line annotations, "Details" → the bundle); one PR comment with `--pr` | Checks API, issue comments |
| GitLab | a commit status `opentine` (pipeline widget, "Details" → the bundle); one MR note with `--mr` | Commit statuses, MR notes |
| Forgejo / Gitea | a commit status `opentine`; one PR comment with `--pr` | `/repos/{o}/{r}/statuses`, issue comments |
| Entire | checkpoint refs per run and the record as a git note on the commit | git refs (no HTTP) |

Mapping: verified → success; failed → failure (GitLab `failed`); unverified →
neutral on GitHub, `skipped` on GitLab, `warning` on Forgejo. An unverified
commit is never shown as a success.

## Least-privilege credentials

A token is read from an environment variable only (`--token-env NAME`), sent
only in a request header to `--api-url`, and never printed or written: a
failed call reports the step and the HTTP status, nothing else.

| Forge | Credential | Scopes / permissions it needs | Not needed |
|---|---|---|---|
| GitHub (App, preferred) | `--app-id`, `--app-key-file`, `--installation-id` | App permissions **Checks: write**; **Pull requests: write** only with `--pr`. The installation token is requested with exactly these permissions and scoped to the one repository in `--repo-slug`, whatever else the App holds. | contents, metadata write, actions, administration |
| GitHub Actions | the job's `GITHUB_TOKEN` | `permissions: {checks: write, pull-requests: write}` (drop the second without `--pr`) | `contents: write` |
| GitHub, personal token | not supported for check runs | GitHub lets only App tokens (including `GITHUB_TOKEN`) create check runs | |
| GitLab | `OPENTINE_GITLAB_TOKEN`: a **project** access token, role Developer | `api` (GitLab has no narrower scope that writes a commit status or note). Store it masked and protected; expire it. | group or personal tokens, Maintainer role |
| Forgejo / Gitea | `OPENTINE_FORGEJO_TOKEN` | `write:repository` (status); `write:issue` with `--pr`; `read:user` only if you do not pass `--comment-author` | admin, organization, package scopes |
| Entire | none | push access to `refs/entire/*` and `refs/notes/*` on the remote, using the repository's existing credentials | |

The PR comment is edited in place on re-runs. Only a comment that starts with
`<!-- opentine-forge-check -->` and was written by the poster is edited
(GitHub: `github-actions[bot]` or `--comment-author`, required for an App;
GitLab: the token's user; Forgejo: the token's user or `--comment-author`), so
a PR author who pastes the marker cannot hijack it.

## Projects and `forge_repo_id`

With a project in the run repository (`tine project init|link --forge-repo-id`),
`tine forge publish --forge-repo-id ID` refuses unless the verified project
chain has a slot on that forge with that id. In CI the id defaults to
`GITHUB_REPOSITORY_ID` (GitHub) or `CI_PROJECT_ID` (GitLab); for Forgejo and
Entire pass it. `--require-project` also refuses a run repository with no project.

## CI recipes

GitHub Actions:

```yaml
permissions: {checks: write, pull-requests: write}
steps:
  - run: tine verify runs/*.tine --json > verify.json
  - run: tine bundle create --all evidence.tbundle
  # upload evidence.tbundle somewhere stable (a release asset, an artifact store)
  - run: >
      tine forge publish --forge github --verify verify.json
      --bundle evidence.tbundle --bundle-url "$BUNDLE_URL"
      --pr "${{ github.event.pull_request.number }}"
    env: {GITHUB_TOKEN: "${{ secrets.GITHUB_TOKEN }}"}
```

GitLab CI:

```yaml
opentine-forge:
  script:
    - tine verify runs/*.tine --json > verify.json
    - tine forge publish --forge gitlab --verify verify.json --mr "$CI_MERGE_REQUEST_IID"
```

Forgejo Actions / Woodpecker:

```sh
tine forge publish --forge forgejo --api-url https://codeberg.org/api/v1 \
  --repo-slug team/app --forge-repo-id team/app --verify verify.json --pr 5
```

Entire:

```sh
tine forge publish --forge entire --forge-repo-id team/app --verify verify.json
git push origin 'refs/entire/checkpoints/*:refs/entire/checkpoints/*' \
  refs/notes/opentine-forge:refs/notes/opentine-forge
```

## Verifying what a forge shows

1. Download the bundle the check links to.
2. `sha256sum` it and compare with the digest in the check.
3. `tine bundle verify FILE` (or `python tine-verify.pyz FILE`, or the TS
   verifier) with networking disabled.

The record itself checks with `forge-check.verify` (vectors
`73-forge-check.json`): its share, its conclusion and, given the bundle bytes,
the digest.

## Offline tests

`tests/test_048_forge.py` drives every forge through recorded API answers in
`tests/fixtures/forge/` (an in-process HTTP transport); no test opens a socket.
`--dry-run` shows the requests a run would make without a token.
