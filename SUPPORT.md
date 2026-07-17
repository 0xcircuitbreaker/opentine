# Support Policy

## Supported Python Versions

OpenTine 0.3.x supports Python 3.11, 3.12, 3.13, and 3.14. CI runs on
Linux, macOS, and Windows for those versions.

## Package Stage

The package remains classified as:

`Development Status :: 4 - Beta`

That is intentional. The 0.3.x beta validates the current surface, but it does
not promise a 1.0-stable API. Released v1/v2 compatibility files and v3 object
identity vectors are covered by golden tests.

## `.tine` Compatibility

Portable files are written as `format_version == 2`; v1 and v2 are readable,
and v1 is migrated to v2 in memory. Repository object format v3 is stored under
`.tine/`. Future portable or object schema versions are rejected until an
explicit migration is implemented and tested. See `TINE_FORMAT.md`.

## Security Reports

Report suspected security issues privately to the project maintainers before public disclosure. Include a minimal reproduction, the affected Opentine version or commit, operating system, Python version, and whether an external harness or model provider was involved.

## Integration Support Levels

- `Validated`: a repeatable gate passed for the current beta.
- `Scoped`: adapter or compatibility code exists, but live behavior depends on user environment or provider configuration.
- `Skipped`: a gate was attempted but prerequisite services were unavailable.
- `Unavailable`: the target was not installed, authenticated, or otherwise runnable for the validation gate.
