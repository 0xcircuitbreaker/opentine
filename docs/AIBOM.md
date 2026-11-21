# AI-BOM export (0.78)

`tine bom export` writes a bill of materials for one node of the
self-modification lineage (docs/LINEAGE.md) in one of two standard formats:

```text
tine bom export LINEAGE_NODE --format cyclonedx|spdx [--out FILE]
    [--dataset training=FILE | eval=FILE]... [--licence EXPR] [--name NAME]
    [--repo PATH] [--dir DIR] [--promotion-policy TOML] [--json]
```

- `--format cyclonedx`: a CycloneDX 1.6 ML-BOM.
- `--format spdx`: an SPDX 3.0.1 JSON-LD document using the Core, Software,
  AI, Dataset and SimpleLicensing profiles.

`LINEAGE_NODE` is a variant id (`sha256:HEX`) recorded with
`tine lineage record`. Without `--out` the document is written to stdout as
bytes. With `--out FILE --json` the command prints a `tine-cli-bom/1` summary
(format, file, sha256, size) instead.

## What the document contains

| Fact | CycloneDX 1.6 | SPDX 3.0.1 |
| --- | --- | --- |
| The exported variant | `metadata.component`, type `machine-learning-model`, `bom-ref` and `version` = variant id | `ai_AIPackage` (`rootElement`), `software_packageVersion` = variant id |
| Variant artifacts (code tree, prompt, config, weights) | `hashes` (SHA-256) and `opentine:artifact:*` properties | `verifiedUsing` hashes; the lineage-record annotation |
| Parent lineage | one model component per ancestor; `dependencies` (a variant depends on its parents) | one `ai_AIPackage` per ancestor; `ancestorOf` relationships |
| Training dataset versions | `data` components; `modelCard.modelParameters.datasets` of the exported variant | `dataset_DatasetPackage`; `trainedOn` |
| Eval dataset versions | `data` components referenced by each variant whose evals scored them | `dataset_DatasetPackage`; `testedOn` |
| Dataset digests | `hashes`, `version` | `verifiedUsing`, `software_packageVersion` |
| Taint filters | `opentine:taint-filter`, `opentine:taint-filter-sha256`, `opentine:taint-filter-recorded` properties | `dataset_dataPreprocessing` (`opentine:taint-filter sha256:... {...}`, or `none recorded`) |
| Eval results | `modelCard.quantitativeAnalysis.performanceMetrics` (`passed/items` per dataset) and an `opentine:eval` property per eval | `ai_metric` entries and the lineage-record annotation |
| Eval signers | in each `opentine:eval` property (`signers`) | in the lineage-record annotation |
| Record and dataset-version signers | `opentine:record-signer`, `opentine:dataset-signer` | annotations |
| Licences | `licenses[].expression` on the model (`--licence`); a dataset version asserts no licence, so datasets carry none (contributed-run licences are checked by `tine dataset check`, docs/DATASET_CONTRIBUTORS.md) | `simplelicensing_LicenseExpression` and `hasDeclaredLicense` |
| Mutation run, selector, loop, promotion policy and decision | `opentine:*` properties | the lineage-record annotation |

Training dataset versions are attached to the exported variant only; eval
datasets are attached to every variant whose evals scored them. An eval
dataset that no `--dataset eval=FILE` describes still appears, by digest,
with `taint-filter-recorded` `false`.

## Inputs and refusals

The node must pass `tine lineage check` (records Ed25519-signed by their
signer, parents present, justifying evals present and signed, decisions
consistent) and the 0.60/0.61 taint findings it adds
(`lineage.score-tainted`, `lineage.memory-quarantined`). Any finding refuses
the export with exit 1 and nothing is written. `--promotion-policy` pins eval
signers as in `tine lineage check`.

`--dataset ROLE=FILE` names a dataset version: an existing attestation
(Ed25519-signed, verifying under its embedded key, that key being the
`signer`) carrying an `opentine.dataset-version/1` claim (docs/DATASETS.md).
The export reads

```json
{"convention": "opentine.dataset-version/1", "name": "...", "version": 1,
 "members": [...], "members_digest": "sha256:HEX",
 "taint_filter": {...}, "curator": "sha256:FINGERPRINT", ...}
```

as written by `tine dataset curate`; the whole claim must pass the same
offline check as `tine dataset verify-version` (shape, members digest, taint
filter, signature, signer and curator binding).

`ROLE` is `training` or `eval`. The dataset's digest in the document is
`members_digest`, and the export recomputes it over `members` (sha256 of the
canonical JSON). Dataset versions, taint-filter records, withdrawal claims and
tombstones are claim conventions on existing attestations (docs/FREEZE.md: no
new object kind).

The export refuses, with exit 1 and nothing written:

- an unsigned or edited version, an unknown role, or another convention;
- a version that fails the `tine dataset verify-version` offline check;
- a `members_digest` that is not the digest of `members`;
- a version with no taint filter;
- a version whose signer is not a pinned `curator` key, or is also an
  `optimizer` key. Roles come only from the owner-signed trust bundle
  (`_key_roles_pin`). If no bundle is pinned, or the policy cannot be read,
  every `--dataset` is refused;
- an eval whose verdict rows disagree on dataset, scorer, scorer version or
  threshold, or that repeat a JSON key or carry NaN or Infinity.

## Determinism

The same lineage folder, dataset versions and options give byte-identical
output: keys are sorted, the encoding is UTF-8 with LF line endings and a
trailing newline, and no wall-clock value is read. The CycloneDX
`metadata.timestamp` and the SPDX `created` time are the exported record's
signing time. The CycloneDX `serialNumber` is a UUID derived from the sha256
of the rest of the document; SPDX `spdxId`s are `urn:opentine:` IRIs derived
from digests. The output names the `opentine` version that wrote it, so a
different version may write different bytes.

## Pinned schemas

The tests validate both documents against the official JSON schemas,
vendored under `tests/data/aibom/` and pinned by sha256 in
`tests/data/aibom/SHA256SUMS` (checked by `tests/test_078_aibom.py`):

| File | Source | sha256 |
| --- | --- | --- |
| `bom-1.6.schema.json` | https://cyclonedx.org/schema/bom-1.6.schema.json | `1ebcb88a2c845ecb6ff7bee7aeabdff9422cb0347f3d6875b241bd444b7e098f` |
| `spdx.schema.json` | https://cyclonedx.org/schema/spdx.schema.json (referenced by the CycloneDX schema) | `33863a360fc4d348e183d89c1ca7aa0877f481e7eb55be2d4102a30386188a10` |
| `jsf-0.82.schema.json` | https://cyclonedx.org/schema/jsf-0.82.schema.json (referenced by the CycloneDX schema) | `2faf5eb3651f2ae5f46091a131770d8d847bbd121139d19c85fc7051bfa58c46` |
| `spdx-json-schema-3.0.1.json` | https://spdx.org/schema/3.0.1/spdx-json-schema.json | `571dd17d52ad567cb5b44c2fdf0c57f013d08584f00e4f30b4f744dcca0fbb4c` |

The SPDX file is published with CRLF line endings (sha256
`582c64e809d5b3ef9bd0c4de13a32391b47b0284a3e8d199569fb96f649234b1` as
downloaded); the repository stores every text file with LF, so the vendored
copy has its line endings normalised and no other change. The CycloneDX
schemas are published under the Apache License 2.0; the SPDX 3.0.1 schema
under the Community Specification License 1.0.

Schema validation in the tests uses the `jsonschema` package when it is
installed (it is in the locked environment through the `mcp` extra) and is
skipped with a reason otherwise; OpenTine itself takes no dependency for the
export.
