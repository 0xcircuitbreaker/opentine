# The format freeze

*0.50.0 freeze candidate. ROADMAP 1.0 criterion 2: "The formats are frozen, and
the Python, TS and pyz implementations pass the same vectors."*

0.48.0 was the freeze cutoff ([SPEC 5.5](SPEC.md#s-5.5)): it is the last release
before 1.0 that may add an object kind or a wire format. 0.49 and 0.50 fix,
test and document. This page is the frozen list, with the SPEC section that
defines each entry, and the result of the 0.50 freeze review.

Frozen means: a later 1.x release may **add** an optional field where the format
allows one ([SPEC 5.2](SPEC.md)), a new reader, or a new stored form that is
reversible and checked against the oid on read (ROADMAP §2 invariant 2). It may
not change the bytes an existing kind is signed, hashed or framed over, and
every format below stays readable for ever (ROADMAP §2 invariant 1). A writer
default changes only after the deprecation window in ROADMAP §2.

The machine-checked inventory is `tests/freeze_inventory.py`;
`tests/test_048_freeze_cutoff.py` enumerates kinds from SPEC headings,
`docs/schemas/` and the vector families and fails on any the inventory does
not list. `tests/test_050_parity.py` checks this page names every entry.

## Object kinds and signed documents

Every kind below has a conformance vector family that the reference (Python),
the TS verifier (`ts/verifier`) and the built `tine-verify.pyz` answer case by
case.

| Kind | SPEC | Names | Families |
|---|---|---|---|
| canonical JSON | 0.2, 0.3 | v3 (JCS), v2 | 01-selftest, 02-canon-v3, 03-canon-v2, 04-divergence, 09-canon-v4 |
| text and shape | 0.1, 0.5 | -- | 00-text, 05-shape |
| stored objects | 1.5.6, Part 6 | link existence, event metrics, run graph, annotation chain | 15-links, 15b-metrics, 15c-graph, 15d-load |
| v3 objects | 1.5 | `blob`, `event`, `run`, `attestation`, `annotation` | 12-envelope, 13-oid |
| .tine artifact | 3, 9, 10 | `.tine` v1-v5 | 31-artifact-v2, 35-integrity, 51-compat, 54-artifact-v5 |
| signatures | 4, 9.6, 9.7 | `tine-sig/1`, `tine-sig/2`, `tine-sig/3`, `tine-attest/1`, `tine-attest/2` | 42-signing, 47-verdict, 53-sig-v4, 55-sig-pq |
| actions | 4.8 | `tine-actions/1` | 48-actions |
| agent | 4.9 | `opentine-agent/1` | 49-agent |
| delegation | 4.10 | `opentine-delegation/1` | 56-delegation, 76-delegation-revocation |
| fleet | 4.11 | `opentine-fleet/1` | 78-fleet |
| eval verdict | 4.12 | `tine-eval-verdict/1` | 58-eval-verdict |
| redaction report | 4.13 | `opentine.redaction-report` | 60-redaction-report |
| redaction report v2 | 4.13.1 | `opentine-redaction/3` | 62-redaction-report-v2 |
| tombstone | 4.14 | `opentine.tombstone` | 63-tombstone |
| redacted copy | 4.15 | `opentine.redacted-copy` | 64-redacted-copy |
| project | 4.16, 4.17, 4.18 | `opentine.project`, `opentine.mirror-state` | 65-project, 66-mirror-state |
| merge | 4.19 | `opentine.merge` | 68-merge |
| review | 4.20 | `opentine.review`, `opentine.review-gate` | 70-review |
| prompt | 4.21 | `opentine.prompt` | 71-prompt |
| memory | 4.22 | `opentine.memory` | 69-memory |
| forge claim | 4.23 | `opentine.forge-claim` | 72-forge-claim |
| forge check | 4.24 | `opentine.forge-check` | 73-forge-check |
| review finding | 4.25 | `opentine.review-finding` | 74-review-finding |
| OMS model signature | 4.26 | -- | 75-oms |
| transparency log | 8.10 | `opentine-log/1` | 57-tlog |
| keyless signing time | 8.12.1 | -- | 77-keyless-tsa |
| webhook | 8.13 | `tine-webhook/1` | 59-webhook |
| hook | 8.16 | `opentine-hook/1` | 67-hook |
| admission VSA | 8.17 | -- | 61-vsa |
| verify report | 8.1, 8.7 | `tine-verify-report/2` | 79-verify-report |
| custody | 8.4, 8.9 | `tine-custody/1`, `opentine-custody/1` | 80-custody |
| replay predicate | 8.8 | `replay/v1` | 81-replay |
| sealed objects | 11 | `TINEAES6` | 82-sealed6 |
| line attribution | 8.24 | `opentine-line-attribution/1` | 83-line-attribution |
| cost statement | 8.25 | `tine-cost-statement/1` | 84-cost-statement |

## Wire formats

| Format | SPEC |
|---|---|
| Envelope framing (`<canonical header>\n<body>`) and the typed oid `type:sha256:<hex>` | 1.2, 1.3 |
| Signature blocks: the five-key header, HMAC-SHA256, Ed25519, ML-DSA-65 and the composite | 4.1, 4.2, 4.6, 9.6 |
| DSSE / in-toto statements (`replay/v1`, admission VSAs, keyless bundles) | 8.8, 8.12, 8.17 |
| Transfer packs: TINEPACK3, and TINEPACK4 toward a peer that advertises it | 2.8 |
| Transparency log: C2SP tlog-tiles, signed-note checkpoints, `cosignature/v1` | 8.10, 8.11 |
| RFC 3161 timestamp tokens and the `sig:sha256:` binding | 8.6, 8.12.1 |
| Signed webhooks (`tine-webhook/1` header and body) | 8.13 |
| Remote HTTP API v1 and its capabilities | 8.14, 8.15, 8.18, 8.19, 8.22 |
| The agent hook protocol (`opentine-hook/1`) | 8.16 |

## File formats

| Format | SPEC |
|---|---|
| `.tine` v1/v2 artifact and its integrity digest | 3 |
| `.tine` v4 artifact | 9 |
| `.tine` v5 artifact (text blobs) | 10 |
| Repository layout: `config.json`, `objects/`, `refs/`, `logs/` (reflog), `shallow` | 2.1-2.7 |
| Stored-object wrapper `TINEZ1\0` (raw, zlib, zstd; reversible, checked against the oid on read) | 2.3 |
| Local packs `.tpk` (`TINELP1`, `TINELP3`) and transfer packs | 2.8 |
| External blob pointers | 2.10 |
| Remote at-rest sealing `TINEAES6` (`TINEAES1`-`5` stay readable) | 11 |
| Evidence folder (`MANIFEST.sha256`, `custody.jsonl`) and the audit kit | 8.4, 8.4.1 |
| Published JSON Schemas and the `--json` envelope | 12 |

## The 0.50 freeze review

**Result: no disagreement and no unanswered case on the pinned suite, with
one scoped exclusion.** Criterion 2 is not declared met here: the pyz does not
answer the eight repository storage families below (by design), so "the same
vectors" holds for every family except those, and accepting that reading is a
decision for the release owner. The CI `parity` job has not yet run on a pushed
commit; until it is green there, the numbers below are from a local run. On the
61 families and 1163 cases of `docs/conformance` (MANIFEST totals),
`scripts/check_parity.py` reports:

| Implementation | Cases answered and agreeing | Not answered, by design |
|---|---|---|
| Python reference | 1163 / 1163 | -- |
| TS verifier | 1149 / 1149 | 14 writer-side redaction cases (`object.put`, `redact.*`, `attest.sign`): a verifier never writes |
| `tine-verify.pyz` | every reader and verifier case outside the repository storage families (990 at this census) | writer-profile cases, and the storage families 16-bounds, 22-layout, 24-refs, 26-reflog, 27-shallow, 28-pack, 29-localpack, 99-repair |

The pyz reads exported files and never opens a repository, so refs, reflogs,
shallow files, the repository config and packs are outside it; the reference
and the TS verifier answer those families. Every other family is answered by
the pyz case by case from the built archive.

What the review changed (no kind and no format was added):

- The freeze-audit allow-lists in `tests/freeze_inventory.py` are empty:
  `PYZ_FILE_LEVEL` (families 31, 35, 42, 47 and 51, previously checked by the
  pyz only as whole files), `PYZ_OP_GAPS` (`text.validate`, `artifact.parse`,
  `integrity.digest`, `integrity.verify`, `sig.message`, `sig.verify`,
  `object.load`) and `DEFERRED` (six kinds without vectors). The 16 families
  that reached the pyz only through a named test are now answered by
  `_pyz/_conform` case by case. The stored-object families 15-15d left the
  storage list.
- Families 79-84 add vectors for the six kinds that predated the cutoff without
  any: `tine-verify-report/2`, `tine-custody/1` (and the `opentine-custody/1`
  log records of 8.9), `replay/v1`, `TINEAES6`, `opentine-line-attribution/1`
  and `tine-cost-statement/1`. SPEC 8.24 and 8.25 now document the last two.
- `scripts/check_parity.py` and the CI job `parity` fail on any disagreement or
  any unanswered case between the three implementations.

What the vectors do not cover, recorded rather than hidden:

- **RFC 3161 tokens inside a verify report** (`signature_timestamps`): checking
  them needs the operator's TSA roots, so family 79 pins reports without
  tokens, and the pyz and TS ops refuse a report that carries them
  (`verify-report.timestamps-unsupported`) instead of ignoring them. Token
  verification is covered by family 77 and the 8.6 tests.
- **`TINEAES6` decryption**: family 82 pins the header; opening a sealed object
  needs a tenant key no verifier of exported files holds, and XAES-256-GCM is
  covered by its own known-answer tests.
- **RFC 3161 tokens inside custody records** (`action: "timestamp"`): the
  `custody.chain` op checks the hash chain and each record's signature, which
  binds the token bytes, but does not verify the token (that needs TSA roots)
  and reports no signing time from it. `tine custody verify` checks the tokens.
- **Reason codes**: a refusal is compared by reason code only when the
  implementation names one (the TS verifier always does; the reference and the
  pyz mostly raise uncoded errors, see `tests/conformance/reasons.py`). A
  programming error (`KeyError`, `TypeError` and the like) never counts as a
  refusal.
- **Line attribution against git**: family 83 gives the commit's added lines as
  input; reading them from git is the CLI's job, not the format's.
- **Cost statements against a run**: family 84 gives the statement the run
  yields as input; recomputing it from a run is covered by the cost tests.

The other 1.0 criteria are not decided here: the third-party audit (1), 30
days of green nightly stress (5) and the compression bench (6) are tracked in
ROADMAP 0.50.0.

## Rulings after the freeze (0.51)

### Predicates and claim schemas inside frozen envelopes

**Adopted by the owner on 2026-11-13 (decision D1), as an explicit
relaxation of the strict reading, not a clarification.** Without this
ruling a new in-toto `predicateType`, or a new claim schema with its own
vectors, counts as a new wire format.

> A new in-toto `predicateType` or `attestation.claim` schema carried inside
> an existing frozen envelope (`attestation` SPEC §1.5.4, DSSE/`tine-attest/2`)
> may be added before 1.0 only if:
>
> - (a) envelope bytes, framing, hashing and signature algorithms are
>   unchanged, so no new signature scheme is allowed;
> - (b) Python, TS and pyz verifiers that do not know it report `unchecked:`
>   and never `pass` or `fail`, and a vector proves this in the **existing**
>   attestation family;
> - (c) its vectors live in an existing vector family, with no new family and
>   no new `docs/schemas` file;
> - (d) it is listed by name in FREEZE.md and in `KINDS` under its envelope's
>   entry, with full Python, TS and pyz conformance;
> - (e) the owner signs off each one by name.

What the ruling does not do: it adds no new escape list to
`tests/freeze_inventory.py`, and it does not cover new signature algorithms
(WebAuthn, for example), new bound forms (RFC 4998) or new object kinds.
Those wait for 1.x.

**Granted predicates: none.**

Each grant is recorded here by name, with its date and release. The
candidates on the 0.51-0.60 plan (ROADMAP §12) are E1
`https://opentine.dev/hardware-key/v1` (decided at 0.56, and only with this
ruling in force), and E2 `https://opentine.dev/promotion/v1` and E3 the
`memory-provenance` claim schema (decided at the end of 0.55). Each has a
frozen-safe form that ships if it is refused.

How condition (b) stands in 0.51: no verify path reads `attestation.claim`
to reach a verdict. The reference, the pyz and the TS verifier check the
envelope's signature and give the claim no verdict at all, so no claim can
`pass` or `fail`. The rule that the first granted predicate's checker must
follow is in one helper per implementation: the reference
(`opentine/_claim_status.py`), the pyz (`opentine/_pyz/_claim.py`) and the TS
verifier (`ts/verifier/src/claim.ts`, exported as `claimStatus`). Each helper
returns `unchecked` (`claim.unknown-predicate`, or `claim.unnamed`) for any
claim with no granted checker. No `verify` report shows that status yet:
wiring it into the reports and the `--json` output schemas comes with the
first grant. With no predicate granted there is no vector to add, so
`tests/test_051_unknown_claim.py` and `ts/verifier/test/claim.test.ts` test
the helpers and the unchanged envelope check over the shared fixture
`tests/data/unknown_claim_attestation.json`. The fixture holds a
`tine-attest/1` and a `tine-attest/2` attestation that name an ungranted
predicate. The first granted predicate brings its own `unchecked` case into
the existing attestation family under condition (b).

### The pyz storage-family exclusion

**Signed off by the owner on 2026-11-13.** Criterion 2 ("the Python, TS and
pyz implementations pass the same vectors") is read as excluding, for the pyz
only, the repository storage families 16-bounds, 22-layout, 24-refs,
26-reflog, 27-shallow, 28-pack, 29-localpack and 99-repair (`STORAGE` in
`tests/freeze_inventory.py`). The pyz reads exported files and never opens a
repository; the reference and the TS verifier answer those families. The list
may only shrink.

### RFC 4998 evidence records

**Deferred to 1.1 (decision D2, 2026-11-13).** No RFC 4998 bound form is added
before 1.0: it would be a new bound form and would reopen the freeze while the
audit is reading it. The caveat, which every compliance profile repeats:
long-term timestamp renewal before 1.1 covers **up to 16 root-bound tokens; it
is not a hash-tree renewal; it does not survive a SHA-256 break.**
