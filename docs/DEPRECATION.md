# Deprecation policy

This is the deprecation policy that 1.0 criterion 7 asks for. It writes down the
release invariants in [ROADMAP §2](ROADMAP.md#2-invariants-for-every-release)
as rules a user, an integrator or another implementation can rely on. Where this
page and §2 disagree, §2 wins and this page is the bug.

The key words MUST, MUST NOT, SHOULD and MAY have their RFC 2119 meanings, as in
[SPEC "Conformance language"](SPEC.md#conformance-language).

## 1. What is covered

| Surface | Covered by | Where it is defined |
|---|---|---|
| Stored formats: `.tine` v1–v5, repository object formats, pack v1/v3, TINEPACK4/5, `tine-sig/1`–`3`, TINEAES1–4 and every object kind in the SPEC | §2 (readers) and §3 (writers) | [SPEC](SPEC.md), [TINE_FORMAT](TINE_FORMAT.md) |
| Wire formats: the HTTP API, `caps` negotiation, pack transfer | §4 | [API](API.md), [SPEC Part 8](SPEC.md) |
| CLI: commands, flags, exit codes, `--json` output | §5 | [CLI](CLI.md), `tine help --json`, [docs/schemas](schemas) |
| SPEC MUST rules | §6 | [SPEC](SPEC.md) |
| Python API | §7 | the `opentine` package |

The 0.48 release was the freeze cutoff: from 0.48 to 1.0 no object kind or wire
format is added (`tests/freeze_inventory.py`). This policy says how the frozen
set may still change: by adding, never by taking away from readers.

## 2. Readers: old formats stay readable for ever

1. Every format a release could write MUST stay readable by every later release,
   with no time limit. This covers `.tine` v1–v4 (and v5 from 0.40), pack
   v1/v3, TINEPACK4, `tine-sig/1`–`3` and TINEAES1–4, as listed in ROADMAP §2,
   and every object kind in `tests/freeze_inventory.py`.
2. A deprecated format is deprecated for **writing** only. Reading it is never
   deprecated, never warns and is never removed.
3. Verification of an old signature or digest MUST give the same verdict it gave
   when it was written. A signature that verified does not start failing because
   its scheme was deprecated.
4. Stored forms (compression, deltas, chunk manifests, dictionaries) MUST be
   reversible and MUST be checked against the object id on read. A new stored
   form MAY be added at any time; the forms before it stay readable.
5. Digests and signatures cover canonical RFC 8785 bytes only. A change that
   alters the canonical bytes for the same input, such as a new redaction
   ruleset, MUST be named in the release notes. Each run records the
   `redaction_ruleset` that produced it.
6. The compatibility fixtures under `tests/fixtures/compat/` come from the real
   published releases, and `tests/test_backwards_compat.py` gates every release
   on reading them. A fixture is never removed.

## 3. Writers: the deprecation window

1. **A new file format becomes the default no earlier than two minor releases
   after its reader ships.** A file cannot negotiate with its reader, so the
   window is how a reader gets to users before the files do. Example: the
   `.tine` v5 reader shipped in 0.40 and v5 became the default writer in 0.42.
2. The previous writer stays available behind an explicit choice for at least
   the same window after the default changes (today `tine --for-legacy`,
   `tine --format 4` or `OPENTINE_FORMAT=4`, see [CLI](CLI.md)).
3. A deprecated writer prints one deprecation warning per process on stderr,
   names its replacement, and is marked "Deprecated for writing (version+)" in
   the SPEC section that defines it.
4. A deprecated writer MAY be removed only in a major release, and only when the
   reader for its replacement has shipped for at least two minor releases. Its
   reader stays (§2).

## 4. Wire formats

1. A wire format MAY become the default sooner than a file format, but only
   toward a peer that advertises support for it through `caps` (or the pack
   format list). A peer that does not advertise it keeps getting the old form.
2. The **0.34 peer compatibility** job runs on every CI build: the published
   0.34 release reads the repository, pack and `--for-legacy` `.tine` files the
   current tree writes and a 0.34 HTTP client fetches from the current server (`scripts/peer_compat_034.py`, job
   `peer-compat-034` in `.github/workflows/ci.yml`). A gap the 0.34 reader
   cannot close by design is pinned in the script's `KNOWN_GAPS` with its
   reason. That list may only shrink.
3. A route or capability is retired only in a major release, and only after it
   was marked deprecated in [API](API.md) and in the OpenAPI document for at
   least two minor releases.

## 5. CLI: commands, flags, exit codes and `--json`

1. **Commands and flags.** A command or flag is never removed in a minor
   release. A renamed spelling keeps the old one working with the same output
   and exit code, as the 0.16 noun groups did (see the top of [CLI](CLI.md)).
   A deprecated flag prints one warning on stderr naming its replacement and is
   marked deprecated in `docs/CLI.md` and `tine help --json`. It MAY be removed
   in the next major release after at least two minor releases of warnings.
2. **Exit codes.** The codes in [CLI "Errors, `--json` and exit codes"](CLI.md)
   keep their meaning. A command MAY move from the generic `1` to a more
   specific code when it is revised, and the release notes MUST say so. A code
   never changes to mean something else.
3. **`--json` output.** Every `--json` document has a published JSON Schema in
   `docs/schemas` and the test suite validates the output against it. In a
   minor release a document MAY gain fields and MUST NOT remove, rename or
   change the type or meaning of one. A breaking change publishes a new schema
   id (for example `tine-cli-x-2` beside `tine-cli-x-1`); the old shape stays
   available behind an explicit flag for at least two minor releases and is
   removed only in a major release.
4. Human-readable output is not an interface and may change in any release.
   Scripts should use `--json`.

## 6. SPEC MUST rules

1. A MUST in the SPEC is a contract with other implementations (the TS verifier,
   the `tine-verify.pyz` and third parties). It is not relaxed or removed in a
   minor release.
2. A MUST may be tightened only when every reader that followed the old rule
   still accepts every file a conforming writer produces under the new one.
   Otherwise the change waits for a new format version, which then follows §3.
3. A new MUST, SHOULD or MAY is added with conformance vectors in
   `docs/conformance/vectors`, and Python, the TS verifier and the pyz answer
   them (`tests/test_048_freeze_cutoff.py`).
4. A section that defines a deprecated writer keeps its full reader rules,
   marked "Deprecated for writing", for as long as the format is readable, which
   is for ever.

## 7. Python API

The public `opentine` API follows the CLI rules in §5.1: a public name is never
removed in a minor release; a deprecated one raises `DeprecationWarning` for at
least two minor releases first. Names starting with `_` are private and may
change in any release.

## 8. Release notes

Every release's CHANGELOG has a **Compatibility** section. It lists any new
deprecation (with the release that may remove it), any change in canonical
bytes, any exit code that became more specific, and any pinned 0.34 peer gap
that was added or closed.
