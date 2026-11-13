# @opentine/verify

An independent TypeScript verifier for OpenTine: RFC 8785 and legacy
canonical JSON, object envelopes, every signature scheme (`tine-sig/1-3`,
`tine-attest/1-2`, `tine-actions/1`, with HMAC-SHA256, Ed25519, ML-DSA-65 and
the Ed25519 + ML-DSA-65 composite), `.tine` v1/v2 integrity and v4/v5
artifacts, repository layout and refs, network packs (`TINEPACK3/4/5`),
storage-v3 local packs with the 0.40 stored forms, `opentine-agent/1` refs,
`opentine-delegation/1` chains, and RFC 9162 inclusion/consistency proofs with
C2SP `cosignature/v1` witness quorums (`src/tlog.ts`, SPEC 8.10-8.11), and
(0.45) `tine-eval-verdict/1` eval verdicts (`src/evalverdict.ts`, SPEC 4.12), and
(0.45.1) signed redaction reports (`src/redactreport.ts`, SPEC 4.13), and
(0.51) `tine bundle` files (`src/bundle.ts`): a streaming port of
`tine bundle verify` over a `ByteSource` (a browser `Blob`, a file, or bytes),
with Python's refusal messages and `bundle.*` reason codes, and
(0.51) codec-3 (zstd dictionary) pack blocks and owner-signed trust bundles
(`src/trustbundle.ts`, SPEC 8.26).

```
npm ci && npm test      # builds, then runs docs/conformance in-process
node dist/src/cli.js run.tine
node dist/src/cli.js ev/verdicts.jsonl --pubkey key.pub   # a tine eval's verdicts
node dist/src/cli.js runs.bundle                         # a tine bundle, streamed (0.51)
node dist/src/cli.js --version                           # the OpenTine release this build is for
node dist/src/cli.js run.tine --trust-bundle bundle.note --owner-vkey VKEY
```

## Bundles and browsers (0.51)

`verifyBundle(source)` checks a bundle as `tine bundle verify` does: the body
checksum, the canonical manifest, the pack digest and length, the pack, every
ref, the `tine-sig/3` sidecars (Ed25519 under their embedded keys), the
transparency receipts' shape, tombstones and a `--redacted-public` record. The
checksum, file digest and pack digest are one incremental SHA-256 pass in
4 MiB reads, and a `TINEPACK3` is inflated and matched against its canonical
manifest one object at a time (`src/bundlepack.ts`): each object is decoded,
checked against its id and dropped. That fast path only ever accepts; any
deviation re-reads the pack with the exact reader (`inspectPack`, under
Python's caps) so a refusal carries the pinned reason code. A `TINEPACK5` is
read in memory (under the same 256 MiB cap). Each report lists every check
as `pass`, `fail` or `unchecked` with its reason, and `opentine_version`.

The browser build (`src/browser/entry.ts`, shipped as
`opentine/data/ui/tine-verifier.js`) adds `blobSource(file)` and
`verifyRecord(value)` for one signed record of any 0.46-0.50 family. Its
`node:zlib` stand-in is pako's zlib port with Node's `inflateSync` contract.
`ts/browser-tests` runs the whole conformance set and the bundle corpus
through it in Chromium, Firefox and WebKit and requires Node's verdicts.
`docs/api/client-versions.json` names the release this build is for and the
oldest browser verifier the release still supports.

## Trust bundles (0.51)

A trust bundle (`tine trust bundle create`) is a signed note over existing
trust documents; `openTrustBundle(bytes, ownerVkey, {minSerial})` checks it
against the owner key the caller pins, and its `pins` (Ed25519 key
fingerprints) go into `VerifyKeys.pins`: a signature by a pinned key is
`verified`, by any other key `mismatch`, as `tine verify --pin` does. The
browser build exports both, and the run viewer applies a bundle its page names.

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
| `pako` | 2.1.0 | MIT AND Zlib | (0.51) incremental zlib inflate for streamed bundle packs, and the browser build's synchronous `inflateSync`; pure JS, no dependencies. |

Everything else (SHA-256, HMAC, Ed25519, the RFC 9162 Merkle proofs, zlib outside bundles) is Node's built-in OpenSSL.
Before `fzstd` sees a frame, `src/zstd.ts` walks its structure and refuses a
second frame, a dictionary, a window above 2**27 or a short or trailing frame,
and output is bounded by the declared size. `fzstd` does not check the
optional frame checksum; every object read is checked against its id anyway.

Codec 3 (0.51; zstd with a trained dictionary, only in local storage-v3 pack
blocks) is read when the caller can look a dictionary up by its SHA-256, as
`localpack.read` can (`args.dicts_b64`). `fzstd` has no dictionary support, so
`src/vendor/fzstd-blocks.ts` vendors its block decoder from the same pinned
0.1.1 release (MIT, lines 1-591 unchanged apart from exports and one added
bounds check, so a review is a short diff against upstream) and
`src/zstddict.ts` seeds a frame's Huffman and FSE tables, repeat offsets and
history from the dictionary (RFC 8878 section 5). A pure-TS port was chosen
over a WebAssembly build of libzstd: no new dependency, no binary to audit,
nothing fetched at runtime, and the browser bundle grows by a few kilobytes.
A dictionary that is missing, over 1 MiB or does not hash to the digest the
frame names is refused (`localpack.dictionary`).
xz (codec 4, opt-in archival) is refused with a clear message.

Requires Node 20.19 or newer (the `@noble` packages' floor).
