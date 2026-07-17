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
The publish job alone receives `id-token: write`; build and test jobs cannot mint
a PyPI publishing credential.

## Release checklist

1. Confirm the working tree is clean and the version in `pyproject.toml` and
   `opentine/_version.py` is the intended release.
2. Push the release commit and require the complete Linux/macOS/Windows CI
   matrix to pass on that exact commit. The tag workflow independently checks
   the Actions API for that successful exact-SHA `main` run and fails closed.
3. Create an annotated tag, preferably signed, whose name is exactly the package
   version prefixed with `v`, then push only that tag:

   ```bash
   git tag -s v0.3.0 -m "OpenTine 0.3.0"
   git push origin v0.3.0
   ```

4. Review and approve the protected `pypi` deployment after the build,
   inventory, metadata, installed-wheel, test, and GitHub-release jobs pass.
5. Verify that PyPI and the GitHub release contain the same wheel and sdist.
   Check `SHA256SUMS` and the GitHub build-provenance attestation:

   ```bash
   sha256sum -c SHA256SUMS
   gh attestation verify opentine-0.3.0-py3-none-any.whl \
     --repo 0xcircuitbreaker/opentine
   ```

PyPI distributions are immutable. If publication fails after either destination
has accepted an artifact, diagnose the existing workflow run; never rebuild and
upload different bytes under the same version.
