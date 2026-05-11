# Support Policy

## Supported Python Versions

Opentine 0.1.x supports Python 3.11, 3.12, and 3.13. CI is configured to run on Linux, macOS, and Windows for those versions.

## Package Stage

The package remains classified as:

`Development Status :: 4 - Beta`

That is intentional. The 0.1.x full-release readiness work validates the current surface, but it does not promise a 1.0-stable API or long-term `.tine` migration contract.

## `.tine` Compatibility

Current compatibility promise: `format_version == 1`.

Future format versions will be rejected until migration support is designed and tested. Patch releases may add validation, tests, or documentation around v1, but should not silently reinterpret future artifact versions.

## Security Reports

Report suspected security issues privately to the project maintainers before public disclosure. Include a minimal reproduction, the affected Opentine version or commit, operating system, Python version, and whether an external harness or model provider was involved.

## Integration Support Levels

- `Validated`: a repeatable gate passed in the release environment.
- `Scoped`: adapter or compatibility code exists, but live behavior depends on user environment or provider configuration.
- `Skipped`: a gate was attempted but prerequisite services were unavailable.
- `Unavailable`: the target was not installed, authenticated, or otherwise runnable in the release environment.
