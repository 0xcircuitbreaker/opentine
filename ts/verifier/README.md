# @opentine/verify

An independent TypeScript verifier for OpenTine: RFC 8785 and legacy
canonical JSON, object envelopes, every signature scheme (`tine-sig/1-3`,
`tine-attest/1-2`, `tine-actions/1`, with HMAC-SHA256, Ed25519, ML-DSA-65 and
the Ed25519 + ML-DSA-65 composite), `.tine` v1/v2 integrity and v4/v5
artifacts, repository layout and refs, network packs (`TINEPACK3/4/5`),
storage-v3 local packs with the 0.40 stored forms, `opentine-agent/1` refs and
`opentine-delegation/1` chains.

```
npm ci && npm test      # builds, then runs docs/conformance in-process
node dist/src/cli.js run.tine
```

## Conformance

`test/conformance.test.ts` runs every vector in `docs/conformance` and requires
every `reader` and `verifier` vector to pass, with Level 2 reason-code
agreement on every rejection. The only vectors not answered are four
writer-side redaction ops (`redact.blob`, `redact.value`, `object.put`,
`attest.sign`; `profile: writer`, SPEC 1.4/4.5): a verifier never rewrites
content, and a partial port of the reference redactor would disagree with it
silently outside the vectors.

zstd paths that no vector can pin (compressor output is not reproducible) are
checked against inputs written by the Python reference:
`python ts/verifier/test/fixtures/make_fixtures.py` regenerates
`test/fixtures/zstd-packs.json`. ML-DSA-65 is checked against the NIST ACVP
sigVer vectors in `tests/fixtures/acvp/` (`test/mldsa.test.ts`).

## Dependencies

Runtime dependencies are pinned exactly in `package.json` and the lockfile;
`npm ci --ignore-scripts` installs them (none has an install script).

| Package | Version | Licence | Why |
| --- | --- | --- | --- |
| `@noble/post-quantum` | 0.5.4 | MIT | ML-DSA-65 (FIPS 204) verification; audited, by Paul Miller. Node has no FIPS 204 primitive. |
| `@noble/curves` | 2.0.1 | MIT | transitive (of `@noble/post-quantum`) |
| `@noble/hashes` | 2.0.1 | MIT | transitive: SHAKE/SHA-3 for ML-DSA |
| `fzstd` | 0.1.1 | MIT | zstd decoding (codec 2 bodies, `TINEPACK4` zstd, the `TINEPACK5` long-mode frame); pure JS, decode only. |

Everything else (SHA-256, HMAC, Ed25519, zlib) is Node's built-in OpenSSL.
Before `fzstd` sees a frame, `src/zstd.ts` walks its structure and refuses a
second frame, a dictionary, a window above 2**27 or a short or trailing frame,
and output is bounded by the declared size. `fzstd` does not check the
optional frame checksum; every object read is checked against its id anyway.
xz (codec 4, opt-in archival) is refused with a clear message.

Requires Node 20.19 or newer (the `@noble` packages' floor).
