# CI integrations (0.46)

Three pieces, all in [`actions/`](../actions) and all running opentine's own
code from a pinned PyPI release (`opentine-version`, default `0.46.0`):

| Piece | Where | What it does |
|---|---|---|
| Gate (GitHub) | `actions/gate/action.yml` | `tine verify`, `tine eval verify`, a VSA gate and one PR comment |
| Gate (GitLab) | `actions/gitlab/templates/opentine-gate.yml` | the same, as a CI/CD component with an MR note |
| Preserve notes | `actions/preserve-notes/action.yml` | re-attaches `refs/notes/tine` after squash and rebase merges |

## The gate

```yaml
on: pull_request
permissions:
  contents: read
  pull-requests: write     # only for the PR comment
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<pinned sha>
      - uses: 0xcircuitbreaker/opentine/actions/gate@<tag or sha>
        with:
          runs: |
            runs/build.tine
          pubkey: keys/ci.pub
          eval-dirs: evals/nightly
          vsa: vsa/build.json
          vsa-key: keys/remote-vsa.pub
          subject: run:sha256:...
          vsa-policy: opentine:trust-policy/prod
          vsa-levels: OPENTINE_ADMITTED
```

Each path is checked with `tine verify --json` / `tine eval verify --json`;
the VSA with the SPEC 8.14 verifier under the pinned server key. The job fails
(exit 4) unless at least one check ran and every check passed. Outputs: `ok`
and `summary` (a `tine-ci-gate/1` document,
`docs/schemas/tine-ci-gate-1.schema.json`).

The comment is posted once and edited in place on re-runs (it carries
`<!-- opentine-ci-gate -->`). It is built from verdict classes and sanitized,
bounded names only: never raw tool output, environment variables or the token.
Every input reaches the shell through `env:`, never through `${{ }}` inside a
script, so a crafted input cannot run a command. No third-party action is used,
so there is nothing else to pin.

The same logic is `python -m opentine._ci_run` (inputs as environment
variables: `RUNS`, `EVAL_DIRS`, `PUBKEY`, `EVAL_PUBKEY`, `VSA`, `VSA_KEY`,
`SUBJECT`, `VSA_POLICY`, `VSA_LEVELS`, `OUT`), so any other CI can call it.

## GitLab

```yaml
include:
  - project: <group>/opentine
    ref: <tag>
    file: actions/gitlab/templates/opentine-gate.yml
    inputs:
      runs: runs/build.tine
      vsa: vsa/build.json
      vsa-key: keys/remote-vsa.pub
      subject: run:sha256:...
```

The gate needs no token. The MR note needs a project access token with `api`
scope in a masked, protected variable `OPENTINE_GITLAB_TOKEN`; without it the
note is skipped and the gate still decides the job.

## Server-side trust policy

The VSA comes from the remote: `tine serve --trust-policy prod=prod.json
--vsa-dir vsa/ --vsa-signing-key server.key` admits a ref update only when a named
`opentine.admission-policy` covers it and records that policy's name and file
digest in the VSA (see [CLI.md](CLI.md) and SPEC 8.14); the key a gate pins is in
`GET /v1/capabilities` as `vsa.keys`. The
server signs VSAs with its own key, never a user's, and nothing in a pushed
repository can choose the policy.

## Preserving attribution through squash and rebase

```yaml
on:
  pull_request:
    types: [closed]
permissions:
  contents: write          # push refs/notes/tine; nothing else
jobs:
  notes:
    if: github.event.pull_request.merged
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<pinned sha>
        with: {fetch-depth: 0}
      - uses: 0xcircuitbreaker/opentine/actions/preserve-notes@<tag or sha>
```

A merge commit keeps the PR's commits and their notes; nothing is done. For a
rebase merge each PR commit's note moves to the landed commit with the same
`git patch-id --stable`; for a squash merge every PR note is copied, in order,
onto the squash commit. A landed commit that already has a different note is
left alone. Notes are copied byte for byte, so signed notes stay verifiable.
If another job moved `refs/notes/tine` meanwhile, the action refetches and
retries (three attempts). The logic is `python -m opentine._ci_notes --base B
--head H --merged M`.
