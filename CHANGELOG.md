# Changelog

## 0.1.0

Release-readiness pass for the current beta-classified 0.1.x surface.

- Added explicit `.tine` integrity verification through `Run.verify_integrity(...)` and `tine verify`.
- Added golden v1 `.tine` fixture coverage for load, save, fork, and diff behavior.
- Added security regression coverage for redaction, digest failure, path escape, symlink escape, private-network blocking, shell/Python denial, environment isolation, and output caps.
- Added a CI-sized graph performance smoke test for save, load, fork, and diff.
- Added wheel smoke testing for installed-package import, `tine --help`, and `tine verify`.
- Replaced PyPI publishing automation with a GitHub release artifact workflow that builds sdist/wheel, checks metadata, generates `SHA256SUMS`, and attaches artifacts to tagged GitHub releases.
- Documented the security model, current `.tine` v1 format policy, live validation matrix, troubleshooting notes, support policy, and release checklist.

Known scope:

- Package metadata remains `Development Status :: 4 - Beta`.
- `.tine` compatibility is current v1 only; migrations are future work.
- Artifact checksums are provided, but HMAC/signing and PyPI trusted publishing are not part of this pass.
