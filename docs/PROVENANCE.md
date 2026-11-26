# Provenance for produced artifacts

Added in 0.84. `tine provenance embed` ties a file a run produced (an image, a
PDF, a model card, a dataset export) to that run, and `tine provenance verify`
checks the tie. The record that counts is a **signed sidecar** next to the
file. Where the format has a standard metadata slot, the file also carries a
short **pointer** to the run, and PNG and JPEG files can carry a **C2PA
manifest** through an optional extra. The pointer and the manifest help a
reader find the run; they are never the authority.

```sh
tine provenance embed chart.png --run main --key runner.key
tine provenance verify chart.png
```

Both take `--repo PATH` (default `.`), `--sidecar PATH` (default
`ARTIFACT.provenance.json`) and `--json` (`tine-cli-provenance/1`).

## The sidecar

`ARTIFACT.provenance.json` is a signed file convention,
`opentine.artifact-provenance/1` (schema `opentine-artifact-provenance-1`). It
is not a new object kind:

```json
{"convention": "opentine.artifact-provenance/1",
 "subject": "artifact | model-card | dataset",
 "artifact": {"name": "chart.png", "media": "png", "digest": "sha256:...", "size": 1234},
 "run": "run:sha256:...", "pointer": "png-text | jpeg-comment | pdf-info | null",
 "c2pa": "sha256:... | null", "dataset_version": "attestation:sha256:... | null",
 "signer": "sha256:<key fingerprint>", "created_at": "2026-11-26T10:00:00Z",
 "signature": {"...": "tine-sig/3 Ed25519 block"}}
```

* The signature covers every field except `signature`, under the domain
  `opentine.artifact-provenance.v1:`.
* `signer` must be the key that signed (`used_key_fingerprint`); a sidecar
  whose signer field names another key fails with `artifact.bad-signature`.
* The signer is **verified** only as a `runner` key in the owner-signed trust
  bundle (`tine trust`), and never as an `optimizer` key. Unpinned roles, an
  unknown key or an optimizer key fail with `artifact.signer-unverified`.
* `created_at` is the current UTC time, or `SOURCE_DATE_EPOCH` when it is set
  (the rule upgrades already use).
* The same body is signed onto the run as an attestation and held
  (`custody:provenance:<digest>:...`), and the run itself is held
  (`custody:provenance:<digest>:run`). `tine hold release` refuses both, so a
  loop cannot delete the record or the run it names. `verify` reports
  `held: true` when such a record exists in the repository it checks.

`embed` refuses a run that does not exist or does not read back from the
repository, and a `--dataset-version` that is not a held dataset version.

## Model cards and datasets

Model cards and dataset exports use the sidecar like any other file: pass
`--subject model-card` or `--subject dataset`. A dataset export can name the
curated dataset version it was materialized from (docs/DATASETS.md) with
`--dataset-version ATTESTATION`; `verify` then also requires that version to be
held in the repository (`artifact.dataset-version-unknown` otherwise). Formats
without a pointer slot (JSON, JSONL, Markdown, safetensors and so on) carry the
sidecar only.

## The pointer and the artifact digest

| Format | Slot | Pointer |
| --- | --- | --- |
| PNG | a `tEXt` chunk (a plain `iTXt` chunk, uncompressed with empty language and translated keyword, is also read) before `IEND` | keyword `opentine:provenance`, text = the run id |
| JPEG | a `COM` segment right after `SOI` | `opentine:provenance <run id>` |
| PDF | an incremental update with a new `/Info` dictionary | `/OpentineProvenance (<run id>)` |
| anything else | none | sidecar only |

`--no-pointer` writes the sidecar alone for any format. A PDF whose last
section uses cross-reference streams (no classic `trailer`) also gets the
sidecar only. The new `/Info` dictionary holds only the pointer, so a viewer
shows no title or author from the earlier `/Info` after embedding.

The artifact digest is deterministic: it is the sha256 of the **canonical
bytes**, the file with the pointer region removed:

* **PNG**: drop every `tEXt`/`iTXt` chunk whose keyword is
  `opentine:provenance`, and every `caBX` chunk (a C2PA manifest store); keep
  every other chunk byte for byte, in order. Chunk CRCs are checked.
* **JPEG**: drop every `COM` segment starting `opentine:provenance ` and every
  `APP11` segment (C2PA) before the start of scan; keep everything else.
* **PDF**: drop the final incremental update only when it matches, byte for
  byte, the exact form `embed` writes (a marker comment
  `%opentine-provenance-update`, one object, a one-entry xref, a trailer and
  `%%EOF`). Anything else stays in the canonical bytes.
* **Other files**: the bytes as they are.

Embedding always starts from the canonical bytes, so running `embed` again
replaces the pointer (and drops an older C2PA manifest) and leaves the digest
unchanged. A malformed PNG or JPEG is refused, not guessed at.

### C2PA store binding

The C2PA stores are left out of the artifact digest, so the sidecar's `c2pa`
field signs them separately: `sha256:` of every `caBX` chunk (PNG) or `APP11`
segment (JPEG), raw and concatenated in file order, or `null` when the file
has none. Adding, removing or swapping a store is caught even without the
optional C2PA library.

## What verify checks

`tine provenance verify ARTIFACT` exits 0 with no findings, or 1 with one or
more of these command-level codes:

| Code | Meaning |
| --- | --- |
| `artifact.sidecar-missing` | no sidecar at the expected path |
| `artifact.sidecar-invalid` | not a well-formed `opentine.artifact-provenance/1` document (read through the nesting-bounded JSON reader, at most 64 KiB) |
| `artifact.bad-signature` | the signature does not verify, or was made by a key other than `signer` |
| `artifact.signer-unverified` | the signer is not a pinned, non-optimizer `runner` key |
| `artifact.digest-mismatch` | the canonical bytes changed (the file was **modified**) |
| `artifact.pointer-stripped` | the sidecar records a pointer and the file has none |
| `artifact.pointer-repointed` | the file's pointer names another run |
| `artifact.run-missing` | the run does not exist or does not read back in `--repo` |
| `artifact.c2pa-stripped` | the sidecar records a C2PA manifest and the file has none |
| `artifact.c2pa-invalid` | the file's C2PA store bytes differ from the store digest the sidecar signs (checked with or without the extra), the C2PA validator reports a failure, or the manifest names another run or digest |
| `artifact.dataset-version-unknown` | the named dataset version is not held |

These are codes of this command. They are not `tine verify` `fail:` codes, and
the freeze is unchanged.

## C2PA (optional)

```sh
pip install 'opentine[c2pa]'
tine provenance embed photo.jpg --run main --key runner.key \
  --c2pa-cert chain.pem --c2pa-key leaf.pem [--c2pa-alg es256]
```

The extra installs the open-source `c2pa-python` library; opentine never needs
it otherwise. The manifest carries a `c2pa.actions` assertion
(`c2pa.created`) and an `org.opentine.provenance` assertion
`{"run": RUN, "artifact_digest": DIGEST}`, and is written after the pointer, so
the manifest's own hash binding covers the pointer too. C2PA requires an X.509
certificate chain, which you supply. Whether a C2PA consumer trusts that chain
is a C2PA matter: `verify` runs the library's validator and treats every
failure as `artifact.c2pa-invalid` except `signingCredential.untrusted`, because
opentine's trust comes from the sidecar. Without the extra, a manifest present
in the file is reported as `c2pa: "unchecked"`, never as valid. C2PA manifests
are written for PNG and JPEG only.

## Query

`tine query` lists every provenance attestation as an `artifact_provenance`
row (subject, name, media type, canonical digest, size, pointer, C2PA store
digest, dataset version, `created_at`). `tine query --verify` re-derives each
row and marks it `verified` only for a pinned `runner` signer that does not
also hold `optimizer`. The row says what the run's record claims; `tine
provenance verify ARTIFACT` decides whether a file matches it.
