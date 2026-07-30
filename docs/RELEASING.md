# Release Process

OpenTine releases use one validated wheel/sdist pair for both the GitHub release
and PyPI. The tag workflow does not rebuild between destinations and does not
store a PyPI password or API token.

## One-time trusted-publisher setup

These repository and PyPI settings are external to Git and must exist before a
tag is pushed:

1. Protect `main` with the complete `CI` workflow and add a tag ruleset that
   prevents updates or deletion of release tags matching `v*`.
2. In GitHub, create an environment named exactly `pypi`.
3. Require a reviewer for that environment and restrict deployments to release
   tags. Do not add a PyPI token as an environment secret.
4. Enable GitHub private vulnerability reporting for the repository so the
   reporting link in `SECURITY.md` is available to outside researchers.
5. In the existing PyPI `opentine` project's Publishing settings, add a GitHub
   trusted publisher with:

   - Owner: `0xcircuitbreaker`
   - Repository: `opentine`
   - Workflow: `publish.yml`
   - Environment: `pypi`

The environment name is part of PyPI's OIDC identity and must match the workflow.
`publish.yml` defines three jobs: `build`, `github-release`, and `pypi`. Two of
them hold `id-token: write`: `github-release` uses it to attest build
provenance, and `pypi` uses it to mint the PyPI publishing credential. Only
`pypi` declares `environment: pypi`, and PyPI's trusted-publisher binding
requires that environment claim in the OIDC token, so `github-release` cannot
publish despite holding the same permission. The `build` job, which runs the
tests and produces the artifacts, holds no identity-token permission at all.

## Release checklist

1. Confirm the working tree is clean and the version in `pyproject.toml` and
   `opentine/_version.py` is the intended release. Verify the bundled pricing
   catalog and confirm its private signing key is backed up in controlled storage
   outside both the checkout and CI:

   ```bash
   tine pricing check opentine/data/pricing_catalog.json
   ```
2. Update the two things no gate enforces, in the release commit itself:

   - Set the heading date of the top `CHANGELOG.md` entry to the date the tag
     will actually be pushed. Nothing checks it, and a stale date is the only
     record a reader has of when the release happened.
   - Bump every pinned documentation URL to the new version. They live in
     exactly two files: `README.md`, which carries a `raw.githubusercontent.com`
     logo and a set of `blob/<tag>/` documentation links, and `pyproject.toml`,
     whose `Documentation` and `Changelog` project URLs are pinned the same way.
     The pins are correct, because `pyproject.toml` sets `readme = "README.md"`
     and relative links in the PyPI long description resolve against `pypi.org`,
     but nothing bumps them, so they must be bumped by hand at every version.
     The failure mode of a missed pin is not a 404: a surviving `v0.3.0` link in
     a later release resolves and serves documentation for code the reader is
     not running. Do not work from a remembered count: run
     `grep -n 'v0\.3\.0' README.md pyproject.toml` with the outgoing version to
     enumerate every pin, bump each line it prints, and rerun the same command
     until it prints nothing.

   Note that until the tag is pushed these URLs do not resolve at all, so the
   rendered landing page and the built distribution metadata both carry dead
   links between the release commit and step 5. Check them after tagging, not
   before.
3. Merge the release commit to `main` and push it there. The tag must point at a
   commit that is an ancestor of `origin/main`: before it builds anything, the
   tag workflow runs `git merge-base --is-ancestor "$release_commit"
   origin/main` and fails closed. Tagging from an unmerged release branch burns
   the tag, and the tag ruleset in the setup above forbids moving or deleting
   it, so recovery requires a version bump.
4. Require the complete Linux/macOS/Windows CI matrix to pass on that exact
   commit. The tag workflow independently queries the Actions API for a
   successful `ci.yml` run and fails closed, and that query is scoped
   `branch=main&event=push` with `head_sha` equal to the tagged commit. Two
   consequences follow. A green `pull_request` run on the same SHA does not
   satisfy the check, because `ci.yml` records pull-request runs under
   `event=pull_request`. And the tagged commit must be the SHA `main` was
   actually pushed to: if the merge produced a new squash or merge commit, tag
   that commit rather than the pre-merge one, because only the new tip has a
   push run on `main`.
5. Create an annotated tag, preferably signed, whose name is exactly the package
   version prefixed with `v`, then push only that tag. Both properties are
   enforced rather than conventional: the workflow requires `git cat-file -t` on
   the tag name to report `tag`, which a lightweight tag does not, and it
   requires the version `import opentine` reports, prefixed with `v`, to equal
   the tag name. Signing is not checked. Tag the commit `main` was pushed to,
   not whatever the local checkout is on: fetch `main`, confirm its tip is the
   release commit, and name it explicitly.

   ```bash
   git fetch origin main
   git log -1 --oneline origin/main
   git tag -s v0.3.0 -m "OpenTine 0.3.0" origin/main
   git push origin v0.3.0
   ```

6. Review and approve the protected `pypi` deployment after the `build` and
   `github-release` jobs pass. `build` is one job: it runs the source and
   version checks, the CI gate, the fast gates and test suite, both builds, and
   the inventory, metadata, and installed-wheel checks.
7. Verify that PyPI and the GitHub release contain the same wheel and sdist.
   Check `SHA256SUMS` and the GitHub build-provenance attestation:

   ```bash
   sha256sum -c SHA256SUMS
   gh attestation verify opentine-0.3.0-py3-none-any.whl \
     --repo 0xcircuitbreaker/opentine
   ```
8. Now that the tag exists, follow the pinned URLs from step 2 and confirm they
   resolve: the rendered `README.md` on GitHub and the project links on PyPI.

PyPI distributions are immutable. If publication fails after either destination
has accepted an artifact, diagnose the existing workflow run; never rebuild and
upload different bytes under the same version.
