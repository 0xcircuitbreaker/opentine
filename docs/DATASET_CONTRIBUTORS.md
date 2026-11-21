# Contributing runs to an open dataset (0.75)

This page is for people who want to share recorded runs with an open run
dataset. It covers the three steps a contribution goes through: redacting a
run into a signed public bundle, annotating it with a licence, and withdrawing
it later. Nothing here adds an object kind or a `tine verify` code: the
licence annotation and the withdrawal are claim conventions on attestations,
and the tombstone manifest is a file convention.

## 1. Redact: `tine dataset contrib-redact`

```
tine dataset contrib-redact RUN --deny-list deny.txt --licence CC-BY-4.0 \
    --key contributor.key --out run.bundle --repo .
```

One command runs the whole pass:

1. **Redaction.** The run's public copy is derived exactly as `tine bundle
   create --redacted-public` derives it (credential ruleset, then the
   publication ruleset for home paths, emails and login names), and then the
   contributor deny-list is applied to every blob, tree entry name and JSON
   payload. Each match becomes `[REDACTED:contributor]`.
2. **Licence annotation.** An `opentine-dataset/licence/1` attestation on the
   public run is signed with the contributor key and placed in the pack.
3. **Signed bundle.** The `opentine.redacted-copy` record is signed with the
   same Ed25519 key over the final pack. Its `ruleset` reads
   `opentine-redaction/2+publish/1+contributor/1`. This key is the bundle's
   *contributor key*.
4. **Mandatory leak scan.** The bundle is unbundled into a fresh, temporary
   repository and every object, every ref name and the manifest are scanned
   with the deny-list. The bundle is written only when the scan finds **zero**
   hits; otherwise nothing is written and the command exits 1.

### The deny-list

A UTF-8 text file with one term per line (names, emails, hostnames, project
names). `#` starts a comment. Each term needs at least three letters or
digits. Matching is on a normalised view of the text:

- Unicode compatibility forms are folded (full-width letters, ligatures),
  accents and other combining marks are dropped, zero-width and other format
  characters are ignored, case is folded, and common Cyrillic and Greek
  look-alike letters read as their Latin counterparts;
- a term keeps only its letters and digits, and up to four separators of any
  kind may sit between any two of them: `Jane Doe` also matches `jane.doe`,
  `JANE_DOE`, `janedoe`, `Jane ,  Doe` and `j-a-n-e d-o-e`.

Matching errs towards removing too much: `acme` also matches inside
`acmeville`. The digest of an object id (`run:sha256:<hex>`) is never
rewritten, because it is a content digest, not text; only the five object
kinds count as an id prefix, so a string such as `name:sha256:<hex>` is still
scanned in its prefix.

The list stays on your machine. It is read by the command and is never
written into the bundle, the signed record, the `--json` output or any
digest. The output reports how many matches were replaced (`totals`), never
which terms matched.

## 2. Licence and consent: `opentine-dataset/licence/1`

The annotation is a claim on an attestation whose target is the public run:

```json
{"convention": "opentine-dataset/licence/1",
 "run": "run:sha256:...",
 "spdx": "CC-BY-4.0",
 "relicensing_grant": false,
 "contributor": "sha256:<fingerprint of the signing Ed25519 key>",
 "annotated_at": "2026-11-20T00:00:00Z"}
```

- `spdx` is one SPDX licence id (no expressions). It must be on the
  allow-list both when the annotation is made and when the bundle is checked.
  The default allow-list is `CC0-1.0`, `CC-BY-4.0`, `CC-BY-SA-4.0`,
  `CDLA-Permissive-2.0`, `ODC-By-1.0`, `MIT` and `Apache-2.0`; `--allow ID`
  (repeatable) replaces it.
- `relicensing_grant` is an explicit opt-in (`--relicensing-grant`): it lets
  dataset curators relicense the contribution. It is `false` unless given.
- The payload `signer` and the claim's `contributor` must both be the key
  that signed (`used_key_fingerprint`).

### `tine dataset check BUNDLE`

Refuses (exit 1, `ok: false`, each reason in `problems`) a bundle when:

- it is not a `--redacted-public` bundle, or its redacted-copy record is not
  Ed25519-signed or does not verify (`--pubkey` requires a specific
  contributor key);
- it carries no licence annotation that verifies, names the public run, and
  is signed by the same key as the redacted-copy record;
- the annotation's SPDX id is outside the allow-list;
- the file-level licence scan is dirty: any `SPDX-License-Identifier:` tag in
  an object naming an id outside the allow-list, or a proprietary notice
  (`all rights reserved`, `proprietary and confidential`, `confidential and
  proprietary`, `not for redistribution`, `do not distribute`). Tags match in
  any letter case, notices across any run of whitespace, and UTF-16 text is
  read with its NUL bytes removed. Only a well-formed licence annotation is
  skipped; an attestation that merely names the convention is scanned;
- with `--tombstones FILE`, its public or source run is tombstoned.

`contrib-redact` and `withdraw` refuse a key that the owner-pinned trust
bundle names as an optimizer key.

## 3. Withdrawal: `tine dataset withdraw`

```
tine dataset withdraw RUN --key contributor.key --reason consent-withdrawn \
    --tombstones dataset.tombstones.json --repo .
```

signs an attestation on the run with the claim

```json
{"convention": "opentine-dataset/withdraw/1",
 "run": "run:sha256:...",
 "reason": "consent-withdrawn",
 "contributor": "sha256:<fingerprint>",
 "withdrawn_at": "2026-11-20T00:00:00Z"}
```

The reason is a category, one of `consent-withdrawn`, `privacy`, `licence`,
`quality`, `other`; there is no free text. The record is kept by a `tine
hold` row whose target starts `dataset-withdraw:`, and `tine hold release`
refuses it, so an automated loop cannot delete a withdrawal. A withdrawal is
`verified` only when its Ed25519 signature holds, the payload `signer` and
the claim's `contributor` are the key that signed, and that key may withdraw
the run:

- the contributor key: the key that signed the run's licence annotation
  (section 2). Keep that key: it is how you withdraw later. If the run carries
  annotations from more than one key, no contributor withdrawal counts;
- a pinned `curator` key: a maintainer takedown, with one of the reason
  categories above.

Any other key is refused by `withdraw` and its record is listed `unverified`;
a pinned optimizer key is refused even if it annotated the run. A contributor
who lost their key asks a maintainer for a curator-signed takedown of the run.

### Tombstones

A dataset manifest keeps what it must honour as tombstones: the run's digest,
the date and the reason category, and no content.

```json
{"format": "opentine-dataset/tombstones/1",
 "tombstones": [{"digest": "sha256:<hex of the run id>", "date": "2026-11-20",
                 "reason": "consent-withdrawn"}]}
```

`withdraw --tombstones FILE` merges the run's tombstone into that file. A
dataset build honours it: `tine dataset add --tombstones FILE` refuses a
tombstoned run (and with `--repo`, a run that has a verified withdrawal),
`tine dataset check --tombstones FILE` refuses a tombstoned bundle, and
`opentine._dataset_withdraw.honour(items, tombstones)` drops such items from a
built dataset. A malformed or unreadable tombstone file is refused, never
treated as empty.

## Schemas

`--json` output: `tine-cli-dataset-contrib/1`. Claims and the manifest:
`opentine-dataset-licence-1`, `opentine-dataset-withdraw-1`,
`opentine-dataset-tombstones-1` (docs/schemas). These are conventions, not
object kinds.

## Limits

- The deny-list matcher works on text. It does not decode base64 or other
  encodings inside a blob, and it does not catch paraphrases or nicknames
  that are not on the list.
- The leak scan uses the same matcher as the redaction pass; it guards
  against a stage that skipped a surface, not against a term missing from the
  list.
- Withdrawal stops future builds that honour the tombstones. It cannot recall
  copies of a bundle that were already shared.
