# The OpenTine Format Specification

**Status:** normative for opentine 0.9.0-dev. **Formats covered:** portable
`.tine` artifact `format_version` 1 and 2; the v3 `.tine/` repository object
model, wire format and pack format; the three signature schemes `tine-sig/1`,
`tine-sig/2` and `tine-attest/1`.

This document is written for someone implementing a **reader, writer or
verifier in another language**. Everything here is derived from the reference
implementation's source, and every load-bearing constant, name and test vector
in it is pinned against that source by `tests/test_format_spec_drift.py`. If a
statement here and the code disagree, that is a bug in this document — file it.

**One rule governs this document: it describes what the code does, not what it
ideally would do.** Where the behaviour is surprising, the surprise is
documented rather than smoothed over; those places are marked **⚠ Hazard**.

## How to cite

> *The OpenTine Format Specification*, opentine `docs/SPEC.md`, version 0.9.0.
> https://github.com/0xcircuitbreaker/opentine/blob/main/docs/SPEC.md

Companion documents: [TINE_FORMAT.md](TINE_FORMAT.md) (format *policy* and the
v2 delta history), [REPOSITORY.md](REPOSITORY.md) (CLI/remote protocol),
[SECURITY_MODEL.md](SECURITY_MODEL.md) (what a signature does and does not
prove).

## Conformance language

MUST / MUST NOT / SHOULD / MAY carry their RFC 2119 meanings. "Reject" means:
refuse the whole object or file; never repair it, never substitute a
replacement character, never drop a field. An implementation that silently
repairs input is not conformant, because every repair changes a digest that
claims fidelity to recorded model output.

Reference-implementation identifiers are given as `module.NAME` so a claim can
be checked against source directly.

---

# Part 0 — Primitives shared by both formats

## 0.1 Text validity

Every string in either format is a sequence of **Unicode scalar values**
encoded as UTF-8. An unpaired UTF-16 surrogate (U+D800–U+DFFF) is not a scalar
value. It has no UTF-8 spelling, so:

* the v3 canonical form cannot encode it, and
* independent readers disagree about it — Go substitutes U+FFFD (changing every
  digest computed over the value), serde refuses.

Both formats therefore **reject** a string containing one, at write and at
read, naming the offending field path. The rejection lives at the *format*
boundary, not in either canonicalizer: `_artifact_io.parse_artifact_json` and
`_artifact_io.assert_loadable` enforce it for `.tine` artifacts, and
`_v3_guards.guarded_redaction` enforces it for v3 objects, while
`kernel.canonical_json` fails on one only because UTF-8 cannot encode it and
`_canon._canonical_bytes` **accepts** it, emitting the `\udXXX` escape.
An implementation that partitions its code the way this one does must put the
check where these two do, not inside its canonicalizer. (Conformance vectors
`canon.v2.surrogate.value-accepts` / `canon.v3.surrogate.value`.) This includes the byte spelling: raw
CESU-8 / WTF-8 surrogate bytes `ED A0 80`–`ED BF BF` decode to the same code
unit without ever appearing as a `\uXXXX` escape and are rejected identically.
`ED 80 80`–`ED 9F BF` is ordinary U+D000–U+D7FF text and is unaffected. A
correctly paired escape is a normal scalar value; emoji are valid.

Reference: `opentine._unicode_text.assert_unicode_text`.

**One exception:** raw `blob` bytes are opaque. A blob of CESU-8 bytes stores
unchanged, because a blob is a byte string, not text.

## 0.2 v3 canonical JSON (`kernel.canonical_json`)

The v3 object model uses an RFC 8785 / JCS-compatible canonical form. Written
out completely, because an implementer cannot derive it from "JCS" alone:

1. **Output encoding** is UTF-8, no BOM. Non-ASCII characters are emitted
   **literally** (`ensure_ascii` off), not as `\uXXXX` escapes.
2. **Separators** are `,` and `:` with no whitespace anywhere. No trailing
   newline.
3. **Object member order** is by the key's **UTF-16BE code-unit sequence**
   (`sorted(value, key=lambda k: k.encode("utf-16be"))`). For BMP keys this
   equals code-point order; for non-BMP keys it does not — see §0.4.
4. **Object keys MUST be strings.** A non-string key is rejected, not coerced.
5. **Strings** are escaped exactly as JSON requires: `\"`, `\\`, `\b`, `\f`,
   `\n`, `\r`, `\t`, and `\u00XX` for any other character below U+0020. Nothing
   else is escaped — `/`, DEL (U+007F) and all non-ASCII go through literally.
6. **`null` / `true` / `false`** spelled exactly so.
7. **Integers** are rendered as their shortest decimal spelling. An integer
   whose absolute value exceeds **9007199254740991** (2⁵³−1) is **rejected**,
   not rounded. Encode 64-bit ids, nanosecond timestamps and
   arbitrary-precision amounts as strings.
8. **Floats**: `NaN` and ±`Infinity` are rejected. Otherwise, given the
   shortest round-tripping decimal representation of the value:
   * `0.0` and `-0.0` both render as `0` (the sign of zero is **not**
     preserved);
   * if `1e-6 <= |v| < 1e21`, render in **positional** notation with no
     trailing zeros and no trailing `.` — `1.0` → `1`, `1e20` →
     `100000000000000000000`, `1e-6` → `0.000001`;
   * otherwise render as `<coefficient>e<±exponent>` with the coefficient
     stripped of trailing zeros and `.`, and the exponent always carrying an
     explicit sign and no leading zeros — `1e21` → `1e+21`, `1e-7` → `1e-7`.
9. **Arrays** keep their given order. Canonicalization never sorts an array.
10. **Depth**: encoding rejects a container nested at depth
    `kernel.MAX_JSON_DEPTH` = **512** or beyond, counting the outermost
    container as depth 0 — so **at most 512 nested containers**: 512 accept,
    513 reject. (Conformance vectors `canon.v3.depth.at-512` /
    `canon.v3.depth.at-513`.)

> **⚠ Hazard — a float can canonicalize to an integer literal.** By rule 8, any
> finite float with `2**53 <= |v| < 1e21` renders as a bare integer literal, so
> `1e20` is stored as `100000000000000000000`. Parsing that back with a plain
> JSON parser yields an *integer* larger than 2⁵³−1, which rule 7 then refuses
> to re-encode — turning a legitimately written object into one your reader
> calls corrupt. When parsing a **canonicalized body** — a `json`-encoded object
> body (§1.2), a `.tine` document, or any value about to be recanonicalized — a
> conformant reader MUST demote an integer literal whose value exceeds 2⁵³−1
> back to the float it came from (`float(literal)`). This is
> `kernel._parse_int`, and it is what makes the canonical form a genuine
> fixpoint.
>
> The **three-key envelope header** is the one place the reference parses
> without it (`ObjectEnvelope.decode`): §1.2 bounds `schema` at
> `1 <= schema < 2**53`, so a header integer past 2⁵³−1 is already invalid and
> demoting it could only turn one rejection into another. An input at exactly
> `2**53` therefore breaks two rules at once and either answer is conformant.
> (Conformance vector `env.schema.at-2-53`, which accepts the integer code and
> both schema codes.)

## 0.3 v2 canonical JSON (`_canon._canonical_bytes`)

The v2 artifact integrity digest — and, see §4.4 and §5.4, **all three
signature schemes** — use a *different* canonical form: exactly what CPython's
`json.dumps(value, sort_keys=True, separators=(",", ":"))` produces, over a
value first coerced by `_canon._jsonable`. Written out:

1. **Output encoding** is UTF-8, but `ensure_ascii` is **on** (the default), so
   every non-ASCII character is emitted as a `\uXXXX` escape (surrogate pair
   for non-BMP) and the byte stream is pure ASCII.
2. **Separators** `,` and `:`, no whitespace, no trailing newline.
3. **Object member order** is by the key's **Unicode code-point sequence**
   (Python's `str` ordering under `sort_keys=True`).
4. **Integers** render as their full decimal spelling with **no magnitude
   bound**. v2 does not have the 2⁵³ rule; the practical bound is
   `_artifact_io.MAX_TINE_INTEGER_DIGITS` = **4096** decimal digits, enforced
   at save and at read.
5. **Floats** render as CPython `repr()`:
   * `NaN`/`Infinity` are rejected (`json.dumps(..., allow_nan=False)` at save,
     an explicit check in `_jsonable`);
   * an integral value keeps a `.0` suffix — `1.0` → `1.0`, not `1`;
   * `-0.0` renders as `-0.0` — the sign of zero **is** preserved;
   * scientific notation is used iff `|v| >= 1e16` or `0 < |v| < 1e-4`, spelled
     with an explicit exponent sign and at least two exponent digits —
     `1e+16`, `1e-05`, `1e+308`;
   * otherwise positional — `0.0001`, `1000000000000000.0`.
6. **`_jsonable` coercion**, applied before serialization: `StrEnum` → its
   `.value`; dataclass → a mapping of its fields, walked field by field, with
   field names sorted; mapping keys → `str(key)`; list/tuple → array; any other
   type → `repr(value)`. Depth beyond `_canon_redact.MAX_CANONICAL_DEPTH` =
   **768** is rejected. For a value that is already plain JSON — which is what a
   third-party implementer reading a `.tine` file has — this coercion is the
   identity, so a reader can recanonicalize the parsed document directly.

## 0.4 ⚠ Hazard — the v2/v3 canonicalization divergence

**v2 orders object keys by Unicode code point. v3 orders them by UTF-16BE code
units. The two disagree, and only for non-BMP keys.**

A non-BMP character (U+10000 and above) is a UTF-16 surrogate pair whose lead
unit lies in `0xD800..0xDBFF`, which sorts *below* every BMP character in
`U+E000..U+FFFF`. Take a two-key object whose keys are U+E000 (BMP, private
use) and U+10000 (non-BMP, surrogate pair `D800 DC00`) — written below in
`\uXXXX` notation so the bytes are unambiguous:

```text
input   {"\ue000": 1, "\ud800\udc00": 2}

v2      {"\ue000":1,"\ud800\udc00":2}     U+E000 first; literally these ASCII bytes
v3      {"\ud800\udc00":2,"\ue000":1}     U+10000 first; keys shown in \u notation, but v3 emits raw UTF-8:
                                          7b 22 f0 90 80 80 22 3a 32 2c 22 ee 80 80 22 3a 31 7d
```

The two also disagree on number spelling (§0.2 rule 8 vs §0.3 rule 5) and on
non-ASCII escaping (§0.2 rule 1 vs §0.3 rule 1).

**This is not a live bug, and the distinction matters.** No value in the
reference implementation is canonicalized by one function and compared against
the other: a v2 digest or `tine-sig/*` signature is computed and verified by
`_canonical_bytes` on both sides, a v3 object id is computed and verified by
`canonical_json` on both sides. Each domain is internally consistent, so the
divergence produces no inconsistent verdict today.

**It is a specification hazard, in two directions:**

1. *Do not unify them.* Every stored v2 integrity digest and signature was
   computed under §0.3, and every v3 object id under §0.2. "Fixing" either to
   match the other silently invalidates all historical data. The divergence is
   pinned by
   `tests/test_tine_format.py::test_v2_and_v3_canonicalizations_order_keys_differently_and_must_stay_that_way`.
2. *Do not assume the v3 object model uses the v3 canonicalizer for
   everything.* It does not — see the next hazard.

> **⚠ Hazard — `tine-attest/1` signs a v3 object using the *v2* canonicalizer.**
> An attestation's **stored body** is `kernel.canonical_json` (§0.2). Its
> **signed message** is `_canon._canonical_bytes` (§0.3) over a projection of
> that same payload. Both sides of verification use `_canonical_bytes`, so the
> scheme is self-consistent — but an implementer who reaches for JCS because
> "it is a v3 object" will compute the wrong message. Concretely, for the
> payload `{"claim": {"n": 1e20, "\ud800\udc00": 1, "\ue000": 2}, ...}`:
>
> ```text
> stored body    …"claim":{"n":100000000000000000000,"\ud800\udc00":1,"\ue000":2}…   (raw UTF-8 on disk)
> signed message …"claim":{"n":1e+20,"\ue000":2,"\ud800\udc00":1}…                   (literal ASCII escapes)
> ```
>
> Same object. Two canonical forms. Both correct. Use §0.3 for the message.

## 0.5 Structural bound scanner (`kernel.validate_json_shape`)

Before any JSON body is parsed, its **bytes** are scanned for two bounds:

* **depth** — `[` and `{` increment, `]` and `}` decrement; the running depth
  MUST NOT exceed `MAX_JSON_DEPTH` = **512**;
* **structural tokens** — `[`, `{`, `,`, `:`, `]`, `}` each count 1; the total
  MUST NOT exceed the caller's `max_tokens`.

Characters inside JSON string literals are skipped (with `\` escape tracking).
This is a byte scanner, **not a parser**: it does not check bracket balance or
grammar, and its depth counter can go negative on malformed input. Grammar
errors surface from the subsequent parse.

`max_tokens` by call site:

| Caller | `max_tokens` |
|---|---|
| `ObjectEnvelope.create` / `.decode` (v3 JSON bodies) | 200 000 (default) |
| `repository/_config.validate_config` | 10 000 |
| `index.RunIndex._load` (`.tine_runs/index.json`) | 100 000 |
| `.tine` artifact read/save | `_artifact_io._structural_token_budget(len)` = `min(16_000_000, max(200_000, len // 4))` |
| compatibility JSON blob bodies | `_artifact_io.compact_token_budget(len)` = `min(16_000_000, max(200_000, len))` |

---

# Part 1 — The v3 object model and wire format

## 1.1 Object types

`kernel.OBJECT_TYPES` = exactly `{"blob", "event", "run", "attestation",
"annotation"}`. There is no extension point: an unknown type is rejected.

| Type | Encoding | Purpose |
|---|---|---|
| `blob` | `raw` | opaque bytes: prompts, outputs, patches, tool results, manifests |
| `event` | `json` | one normalized model / tool / human / policy activity |
| `run` | `json` | an event graph plus manifests and status |
| `attestation` | `json` | a signed or unsigned claim about a run |
| `annotation` | `json` | separately versioned mutable metadata for an object |

## 1.2 Envelope framing

An object is stored as:

```text
<canonical-json header> LF <body>
```

The header is a JSON object with **exactly three keys**, canonicalized per
§0.2, which fixes their order:

```text
{"encoding":"<raw|json>","schema":<int>,"type":"<object type>"}
```

* `encoding` MUST be `"raw"` if and only if `type` is `"blob"`, and `"json"`
  otherwise. A mismatch is rejected.
* `schema` MUST be an integer with `1 <= schema < 2**53`. It is **not** a
  boolean (`type(schema) is not int` rejects `True`). The reference
  implementation writes `1` for every object of every type and has no writer
  that passes anything else; a reader MUST still accept any value in range,
  and MUST treat a different `schema` as a different object (§1.3).
* The header is split off at the **first** LF byte. It MUST be at most **256
  bytes** and MUST be byte-identical to the canonical encoding of its own
  parsed value — a re-ordered, whitespace-padded or extra-key header is
  rejected.
* The body is everything after that LF, verbatim. For `raw` it is opaque bytes
  (it may contain LF, NUL, invalid UTF-8 — anything). For `json` it MUST pass
  §0.5 with `max_tokens = 200_000`, parse as JSON, and be **byte-identical** to
  the canonical encoding of its parsed value.

Reference: `kernel.ObjectEnvelope.encode` / `.decode`.

> **⚠ Hazard — a "JSON blob" is a `raw` blob.** The compatibility layer stores
> step inputs/outputs, transcripts and manifests as `blob` objects whose bytes
> happen to be canonical JSON (`_blob_guard.guarded_blob_body`). The kernel
> does not know that: their envelope says `"encoding":"raw"`, the 200 000-token
> envelope budget does **not** apply to them, and `compact_token_budget`
> (§0.5) does instead. A blob is never parsed by the kernel.

## 1.3 Object id derivation

```text
oid   = TYPE ":sha256:" lowercase_hex( SHA-256( framed ) )
framed = utf8(TYPE) || 0x00 || utf8(decimal(SCHEMA)) || 0x00 || BODY
```

`BODY` is the stored body of §1.2 — **not** the envelope, and **not** including
the header or its LF. `SCHEMA` is spelled in decimal with no sign, padding or
separators. The two NUL bytes are literal `0x00`.

The type and schema are inside the hash, so the header's contribution to
identity is complete (its third key, `encoding`, is a function of `type`).

An oid MUST match `kernel.OID_RE`:

```text
^(blob|event|run|attestation|annotation):sha256:([0-9a-f]{64})$
```

Hex digits are **lowercase only**; an uppercase spelling is not a valid oid.

**Worked vectors** (recomputable from this document alone):

```text
blob  body   = b"hello\n"
      stored = b'{"encoding":"raw","schema":1,"type":"blob"}\nhello\n'
      oid    = blob:sha256:c5251cf4c201ede74c8e3564dc6d02e597cbc20fbd91a84704a91179757bd008

event payload = {"cost": 0, "kind": "model", "parent_ids": []}
      body   = b'{"cost":0,"kind":"model","parent_ids":[]}'
      stored = b'{"encoding":"json","schema":1,"type":"event"}\n{"cost":0,"kind":"model","parent_ids":[]}'
      oid    = event:sha256:49501062e21825447aa20eef34bcb3ad391102db92d76f5631714813bf6c43a7
```

## 1.4 Redaction happens before hashing

Client-side credential redaction runs **before** canonicalization and hashing,
so the oid names the redacted bytes every reader will see, and a secret never
enters the store or a digest. Two halves:

* `redaction.redact_blob` — regex scans over raw blob bytes (assignments,
  headers, bearer tokens, known token shapes, PEM private keys), replacing the
  value with the literal `[REDACTED]`.
* `redaction.redact_value` + `_canon_redact._redact` — a walk over decoded JSON
  replacing credential-named fields with `"[REDACTED]"`.

`Repo.put(..., redact=False)` skips value redaction (used where the caller has
already produced the exact canonical bytes), but the Unicode check of §0.1
still runs. A conformant *reader* needs none of this; a conformant *writer*
that omits it merely stores secrets, and still produces valid objects.

## 1.5 Payload shapes

**The kernel constrains only what the graph depends on.** Any other field may
hold any JSON value and still be stored — that openness is what lets a newer
writer add a field an older reader round-trips without understanding. The
tables below therefore separate **enforced** rules from **conventional** fields
that the reference writers emit.

### 1.5.1 `blob`

No structure. Opaque bytes. No links.

### 1.5.2 `event`

Enforced (`kernel.validate_links`, `repository._run_graph.validate_event_metrics`):

| Field | Rule |
|---|---|
| `parent_ids` | absent or a list of **event** oids, no duplicates. Defaults to `[]`. |
| `causal_ids` | same rule as `parent_ids`. |
| `input_blob`, `output_blob`, `artifact_blob` | if present **and truthy**, MUST be a **blob** oid |
| `cost`, `duration` | absent or a finite, **non-negative** number. Default `0`. |
| `time_unix` | if the key is present, a finite number; **may be negative** |
| `usage` | if truthy, MUST be an object; each value MUST be exactly an `int` or `float` (a bool is rejected), finite and non-negative |
| `usage.<token dim>` | for `input`, `output`, `cache_read`, `cache_write_5m`, `cache_write_1h`, `reasoning`, `total`: MUST additionally be integral and ≤ 2⁵³−1 |

The payload MUST be a JSON object. No field is *required*: an event with an
empty payload `{}` is a valid, storable event.

> **⚠ Hazard — a numeric meter may be a string.** `cost`, `duration` and
> `time_unix` are validated by `Decimal(str(value))`, so the string `"1.5"` is
> accepted and stored, as is any numeric string up to 128 characters. A reader
> MUST NOT assume these fields are JSON numbers. (The value must also survive
> conversion to a finite IEEE-754 double: `Decimal("1e999999999")` is finite
> but `float()` of it is not, and is rejected — a bound added because such a
> value passed validation, was hashed into the store, and then failed every
> later read.)

> **⚠ Hazard — a falsy non-object `usage` is silently treated as absent.**
> `usage` is read as `payload.get("usage") or {}`, so `0`, `""`, `[]`, `false`
> and `null` all pass validation as "no usage", while `5` or `"x"` is rejected.

Conventional event fields written by opentine: `kind`, `model`, `provider`
(only when known — §6.2), `tool`, `error`, `billing`, `legacy_step_id`
(compatibility writer), and `actor`, `attributes`, `span_id`, `trace_id`,
`unresolved_span_refs` (trace recorder).

> **⚠ Hazard — `artifact_blob` is validated but never written.** No writer in
> the reference implementation emits it; `repository.ops.semantic_diff` reads
> it. Treat it as a reserved link field.

### 1.5.3 `run`

Enforced (`kernel.validate_links`, `repository._run_graph.validate_run_graph`):

| Field | Rule |
|---|---|
| `events` | absent or a list of **event** oids, no duplicates. Defaults to `[]`. |
| `roots`, `tips` | absent or a list of **event** oids, no duplicates, each a **subset of `events`** |
| `manifests` | absent or an **object** whose *values* are all **blob** oids |
| **any key ending `_blob`** | if truthy, MUST be a **blob** oid |
| `status` | absent (⇒ `"running"`) or one of `running`, `paused`, `completed`, `failed` |
| `legacy_refs` | absent or an object mapping **string** names to oids **in `events`** |
| ordering | for every locally present event in `events`, each of its `parent_ids` and `causal_ids` MUST appear at a **strictly earlier index** in `events` |
| `roots` / `tips` exactness | **only when every event in `events` is present locally**: `set(roots)` MUST equal the set of parentless events, and `set(tips)` MUST equal `events` minus every event named as someone's parent. When any event is missing (a shallow fetch), both checks are skipped. |

> **⚠ Hazard — the `_blob` suffix rule is open-ended.** It is not a fixed field
> list: *any* top-level run key whose name ends in `_blob` and whose value is
> truthy must be a blob oid. A writer adding `patch_blob` inherits the
> constraint automatically; a writer adding `patch_blob: {"a": 1}` is rejected.

Conventional run fields: `created_at`, `model`, `source_run_id`, `system_blob`,
`prompt_blob`, `session_id`, `forked_from`, and the manifest slots `budget`,
`cache`, `code`, `environment`, `policy`, `pricing`, `run`, `transcript`. A v2
migration additionally writes exactly the set
`_run_blobs.LEGACY_MIGRATION_FIELDS` = `legacy_blob`, `legacy_format`,
`legacy_verification`, `migration_map_blob`, `signature_scope` — and a writer
building on a stored payload MUST drop that whole set unless it is re-attaching
those same legacy bytes, because each field describes one exact artifact.

### 1.5.4 `attestation`

Enforced:

| Field | Rule |
|---|---|
| `target_id` | **REQUIRED**, and MUST be a **run** oid |
| `evidence_ids` | absent or a **list**; each entry MUST be a syntactically valid oid **of any type** (a non-list value is rejected) |
| — | the object MUST NOT link to itself |

`claim` (any JSON value), `signer` (string) and `signature` (§5.4, or `null`)
are **not** structurally validated by the kernel. The reference writer always
emits all four of `claim`, `evidence_ids`, `signer`, `target_id`, plus
`signature`.

### 1.5.5 `annotation`

Enforced:

| Field | Rule |
|---|---|
| `target_id` | optional; if truthy it is a link and MUST be a valid oid **of any type** |
| `previous_id` | optional; if truthy MUST be an **annotation** oid |
| `evidence_ids` | as for attestation |
| chain | if `previous_id` is set, that object MUST exist, be an annotation, and carry the **same `target_id`** |

The compatibility writer emits `compatibility: "run-metadata-v1"`,
`previous_id`, `target_id` (a run oid), and `value` = `{"metadata": {...},
"tags": [str, ...]}`.

Note the asymmetry with §1.5.4: an **attestation**'s `target_id` must be a run;
an **annotation**'s may be any object type, and may be absent.

### 1.5.6 Link existence

Every link extracted above MUST resolve: the object exists locally **or** its
oid is listed in the repository's shallow-boundary file (§2.7). An object MUST
NOT link to itself.

## 1.6 The complete rejection table

Every constant that can refuse a v3 object or repository read:

| Bound | Constant | Value | Source |
|---|---|---|---|
| JSON nesting depth | `kernel.MAX_JSON_DEPTH` | 512 | `kernel` |
| structural tokens, object body | default `max_tokens` | 200 000 | `kernel.validate_json_shape` |
| canonical integer magnitude | — | ±(2⁵³−1) = 9 007 199 254 740 991 | `kernel._number` |
| envelope schema range | — | `1 <= schema < 2**53` | `kernel.object_id` |
| envelope header size | — | 256 bytes | `kernel.ObjectEnvelope.decode` |
| write-side walk depth | `_canon_redact.MAX_CANONICAL_DEPTH` | 768 | `_canon_redact` |
| token-count dimensions | `_run_graph._MAX_SAFE_INTEGER` | 2⁵³−1 = 9 007 199 254 740 991 | `_run_graph` |
| numeric-meter string length | — | 128 chars | `_run_graph._meter` |
| ref file size | `_ref_store.MAX_REF_BYTES` | 256 bytes | `_ref_store` |
| ref name, total | — | 512 bytes | `_refs.normalize_ref` |
| ref name, per component | `_refs.MAX_REF_COMPONENT_BYTES` | 240 bytes | `_refs` |
| reflog actor | — | 4096 chars | `_reflog.reflog_entry` |
| config size | `_config.MAX_CONFIG_BYTES` | 65 536 bytes | `_config` |
| config structural tokens | — | 10 000 | `_config.validate_config` |
| shallow entries | `_shallow.MAX_SHALLOW_OBJECTS` | 10 000 | `_shallow` |
| shallow file size | `_shallow.MAX_SHALLOW_BYTES` | 1 048 576 bytes | `_shallow` |
| pack transfer size | `pack.MAX_PACK_BYTES` | 268 435 456 bytes | `pack` |
| pack manifest size | `pack.MAX_PACK_BODY_BYTES` | 268 435 456 bytes | `pack` |
| objects per pack | `pack.MAX_PACK_OBJECTS` | 10 000 | `= _traversal.MAX_TRAVERSAL_OBJECTS` |
| graph traversal | `_traversal.MAX_TRAVERSAL_OBJECTS` | 10 000 | `_traversal` |
| typed object scan | `_objects.MAX_TYPED_OBJECT_SCAN` | 100 000 | `_objects` |
| association scan | `_associations.MAX_ASSOCIATION_SCAN` | 100 000 | `_associations` |
| legacy annotation scan | `_annotations.MAX_LEGACY_OBJECTS` | 100 000 | `_annotations` |
| `.tine` artifact size | `_artifact_io.MAX_TINE_ARTIFACT_BYTES` | 268 435 456 bytes | `_artifact_io` |
| `.tine` integer digits | `_artifact_io.MAX_TINE_INTEGER_DIGITS` | 4096 | `_artifact_io` |
| HMAC key floor | `_signing_verify.MIN_HMAC_KEY_BYTES` | 16 bytes | `_signing_verify` |

---

# Part 2 — Repository layout

## 2.1 Directory tree

A repository is the directory `.tine/` (or, bare, any directory holding
`config.json`).

```text
.tine/
  config.json                      repository descriptor (§2.2)
  objects/<type>/<aa>/<62 hex>     loose objects (§2.3)
  refs/<namespace>/<name>          one oid per file (§2.4)
  logs/<namespace>/<name>          append-only reflog (§2.6)
  packs/<64 hex>.pack              TINEPACK3 frames (§2.8)
  indexes/                         reserved; created empty, never written
  shallow                          shallow-fetch boundary set (§2.7)
```

`_paths.LAYOUT_DIRS` = `("objects", "refs/annotations", "refs/heads",
"refs/tags", "logs", "packs", "indexes")` — created by `Repo.init` and
recreated by `Repo.open`, because git and tar drop empty directories and a
repository committed to version control would otherwise lose them.

All internal paths are confined: a component that is a symlink, a junction, a
non-regular/non-directory file, a hard-linked regular file, `.`, `..` or empty
is rejected, and the resolved path must stay under the root
(`_paths.internal_path`).

> **⚠ Wart — `indexes/` is a reserved empty directory.** It is created and
> recreated but nothing in this build reads or writes it. (The *legacy* run
> index is a separate, non-repository sidecar: `.tine_runs/index.json`, §4.6.)

## 2.2 `config.json`

Written by `Repo.init` as canonical JSON (§0.2) followed by a single LF:

```text
{"format":3,"object_hash":"sha256","repository":"opentine","version":1}\n
```

A reader MUST require exactly these four key/value pairs to be present and
equal. The file MUST be at most 65 536 bytes and pass §0.5 with `max_tokens`
10 000. Its presence is what identifies a directory as a repository; `Repo.open`
walks upward from the given path looking for `<dir>/config.json` or
`<dir>/.tine/config.json`.

> **⚠ Wart — unknown keys are accepted, and so is any formatting.** Validation
> checks only that the four required pairs match; extra keys pass, and the
> file need not be canonical or newline-terminated on read.

## 2.3 `objects/`

For `oid = TYPE:sha256:HEX`, the loose object lives at:

```text
objects/<TYPE>/<HEX[0:2]>/<HEX[2:64]>
```

so the directory component is 2 hex characters and the file name is the
remaining **62**. The file content is the envelope of §1.2, byte for byte.
Objects are immutable; a write to an existing path is skipped after verifying
the stored bytes still hash to the same oid.

Enumeration is **sorted at every level** — readdir order is a per-filesystem
hash order, and identical repositories must enumerate, diff and pack
identically everywhere. A directory under `objects/` whose name is not an
object type, a 2-character non-hex prefix directory, or a file whose name is
not 62 hex characters is **skipped, not an error** (one stray `.DS_Store` must
not take down `fsck`, `search` and `pack`).

## 2.4 `refs/`

A ref is a file containing one oid. Writers emit exactly:

```text
<oid> LF
```

Readers accept `<oid>`, `<oid>\n` or `<oid>\r\n`, reject any other trailing
bytes, reject any internal whitespace, require ASCII, require a file of at most
256 bytes, and require a regular file with link count ≤ 1 (a *hard-linked* ref
is rejected; link count 0 — an unlinked-but-open inode, which a concurrent
update legitimately produces — is fine).

### Ref names

The stored name has any leading `refs/` removed. It MUST match:

```text
^(?:annotations|heads|tags|experiments|promotions|remotes)/[a-z0-9._/-]+$
```

and additionally: be ≤ 512 bytes total; be equal to its own case-fold (i.e.
lowercase); have every `/`-separated component ≤ 240 bytes, non-empty, not `.`
or `..`, containing no `..`, not ending in `.lock` (case-insensitively), not
ending in `.` or a space, and whose pre-`.` prefix is not a Windows device name
(`con`, `prn`, `aux`, `nul`, `com1`–`com9`, `lpt1`–`lpt9`).

### Typed namespaces

`_refs.TYPED_REF_NAMESPACES`:

| Namespace | Target object type |
|---|---|
| `heads/` | `run` |
| `experiments/` | `run` |
| `promotions/` | `run` |
| `annotations/` | `annotation` |
| `tags/` | *(unconstrained)* |
| `remotes/` | *(unconstrained)* |

An `annotations/*` ref carries one further rule: its target annotation's
`target_id` MUST be a `run` oid, and the ref name after `annotations/` MUST
equal that run's 64-hex digest. So `annotations/<digest>` is the only
`annotations/*` name that may point at an annotation of `run:sha256:<digest>`.

### Update protocol

Ref updates are compare-and-swap and are performed under two files beside the
ref:

* `<ref>.lock` — the exclusive guard, created `O_CREAT|O_EXCL`. Its existence
  fails a concurrent writer rather than blocking.
* `<ref>..lock` — the staging file that is `rename()`d over the ref.

The doubled dot is deliberate: `normalize_ref` forbids a component ending in
`.lock`, `.` or a space, so `<ref>..lock` can be neither a legal ref nor the
guard lock of a legal ref. A plain `<ref>.new.lock` would be exactly the guard
lock of the legal sibling ref `<ref>.new`.

Sequence: acquire guard → read current value → compare against the caller's
expected value (rejecting a mismatch) → write staging file and `fsync` →
`rename` over the ref → `fsync` the directory → append the reflog row → release
staging and guard.

## 2.5 Ref target validation

Before a ref moves, the target object is fetched, its oid re-verified, and the
namespace type rule of §2.4 applied — on write, on read, on pack verification,
on remote ref update, and by `fsck`.

## 2.6 `logs/` — the reflog

One file per ref, at `logs/<the normalized ref path>` (e.g. `logs/heads/main`).
Append-only, one **canonical JSON object (§0.2) followed by LF** per row:

```text
{"actor":"local","new":"run:sha256:…","old":null,"ref":"heads/main","time_ns":"1757030400000000000"}
```

| Field | Type | Notes |
|---|---|---|
| `actor` | string | ≤ 4096 characters; `"local"` for local writes |
| `new` | string | the new oid |
| `old` | string \| null | the previous oid, `null` for a ref's first row |
| `ref` | string | the normalized ref name |
| `time_ns` | **string** | nanoseconds since the Unix epoch, **decimal digits in a JSON string** — because canonical JSON (§0.2 rule 7) rejects integers beyond 2⁵³−1 |

> **⚠ Wart — the reflog row is appended *after* the ref is replaced,** and the
> file has no size bound or rotation. A crash in that window leaves a moved ref
> with no log row. The reflog is history, not authority: never derive a ref's
> current value from it.

## 2.7 `shallow`

Optional file `.tine/shallow`, listing oids that a depth-limited fetch
deliberately cut away, so a reader can distinguish "absent by design" (stop
there, as `git log` does on a shallow clone) from "absent and broken".

* ASCII only; LF separators; no CR anywhere.
* Unique, each a syntactically valid oid.
* At most 10 000 entries and 1 048 576 bytes.
* MUST be a regular file with link count exactly 1.

A **writer** MUST additionally emit the set sorted and terminate the last line
(the file is empty when the set is empty). Both are writer properties: the
reader enforces uniqueness, ASCII and line shape only, and accepts an unsorted
or unterminated file. Inventing a rejection the code does not perform would
make a conformance suite lie about the format. (Conformance vectors
`shallow.unsorted-accepts`, `shallow.unterminated-accepts`.)

A link to an oid in this set satisfies §1.5.6 without the object being present.
Updates are serialized by `shallow.lock` (`O_CREAT|O_EXCL`).

## 2.8 `packs/` and the TINEPACK3 format

A pack is a single self-verifying frame. Files are stored at
`packs/<64 hex>.pack` where the hex is the pack's own digest.

### Frame layout

```text
offset  size  content
0       10    magic  b"TINEPACK3\x00"   (ASCII "TINEPACK3" + one NUL)
10      32    SHA-256 of the DECOMPRESSED manifest body, raw bytes
42      n     zlib stream (RFC 1950) of the manifest body
```

The pack id is the string `"sha256:" + hex(bytes[10:42])`, and the file name is
that hex plus `.pack`.

Reader algorithm:

1. Reject if the frame exceeds `MAX_PACK_BYTES` = 268 435 456 bytes, does not
   start with the magic, or is shorter than 42 bytes.
2. Inflate bytes 42.. with a **bounded** decompressor, refusing as soon as the
   output exceeds `MAX_PACK_BODY_BYTES` = 268 435 456 bytes; reject a truncated
   stream or any trailing bytes after the zlib end-of-stream.
3. Verify SHA-256 of the inflated body equals bytes 10..42.
4. Run §0.5 over the body, parse it, and require it to be **byte-identical to
   its own canonical encoding (§0.2)**.

Writers compress with zlib level 9. Because the manifest is canonical JSON, the
frame is deterministic for a given object set and object order.

### Manifest body

```json
{"objects":[{"data":"<base64>","id":"<oid>"},…],"shallow":["<oid>",…],"version":1}
```

* The top-level key set MUST be **exactly** `{"objects", "shallow", "version"}`.
* `version` MUST be the integer `1`.
* `objects` and `shallow` MUST be arrays, each of at most 10 000 entries.
* Each `objects` entry MUST be an object with key set **exactly** `{"data",
  "id"}`. `data` is the object's **stored envelope bytes** (§1.2) in **standard
  base64 with padding**, strictly validated (any character outside the base64
  alphabet is rejected). `id` is its oid, and the decoded bytes MUST decode as
  an envelope whose oid equals it.
* `id`s MUST be unique; `shallow` entries MUST be unique and valid oids; the
  two sets MUST be **disjoint**.
* `shallow` MUST be **exactly** the set of **links** (in the precise sense of
  §1.5 — the enumerated link *fields* of each object type, **not** every
  oid-shaped string in the payload) referenced by the packed objects that are
  not themselves in the pack — no more, no less. Both the writer and the
  installer enforce this equality. The distinction is load-bearing: an event's
  `input_blob` is a link and lands in `shallow`, while an arbitrary
  application field holding an oid is not a link, is invisible to
  `validate_links`, and MUST NOT appear.

The reference writer emits `objects` sorted by oid, but canonicalization does
not sort arrays (§0.2 rule 9), so **array order is not constrained** and a
reader MUST NOT rely on it.

### Installation ordering

An installer MUST write objects in **dependency order** — every link target
before the object citing it — so that an interrupted install (Ctrl-C, ENOSPC)
leaves a link-closed subset rather than an unreadable object whose targets were
never written.

## 2.9 `fsck`

A deep `fsck` (`repository.verify.fsck`) checks: every loose object re-hashes
to its own oid, decodes canonically, satisfies its link rules with existence
checks, passes annotation-chain and event-metric validation, and — for runs —
graph validation; every ref name is legal, its oid parses, its target exists
and satisfies the namespace type rule; every shallow entry is a valid oid;
every file in `packs/` has a legal `<64 hex>.pack` name, verifies, matches its
own filename, and contains objects byte-identical to the loose copies; and the
event graph (`parent_ids` + `causal_ids`) is acyclic, reported per cycle root.
`fsck` bounds itself at 1000 packs and 1 GiB of pack bytes.

---

# Part 3 — The portable `.tine` v2 artifact

## 3.1 File shape

A `.tine` file is a single JSON **object**, UTF-8, serialized by
`json.dumps(data, indent=2, sort_keys=True, allow_nan=False)` — so: two-space
indentation, keys in code-point order at every level, non-ASCII escaped as
`\uXXXX`, and no `NaN`/`Infinity`. It is written in **text mode**, so on
Windows every LF becomes CRLF on disk; readers MUST NOT assume the on-disk byte
length equals the in-memory string length.

`format_version` is currently **2** (`_canon.FORMAT_VERSION`). Readable
versions are **1 and 2** (`_canon.SUPPORTED_VERSIONS`); a v1 file is migrated
to v2 *in memory* on load and the file on disk is never rewritten. A missing,
older-unsupported or future `format_version` is rejected — except for the
legacy 0.1.0 "linear" shape, which is best-effort *imported* (not verified).

## 3.2 Top-level fields

`format_version`, `run_id`, `created_at`, `status`, `graph`, `refs`,
`transcript`, `manifest`, `policies`, `cache`, `metadata`, and — only on an
autosave checkpoint — `draft: true`.

`graph` is `{"order": [step id, …], "steps": {step id: step record}}`.
`status` is one of `running`, `paused`, `completed`, `failed`.

## 3.3 Step record (`_step_serde.step_to_dict`)

Always emitted: `cost`, `duration`, `error`, `id`, `inputs`, `kind`,
`model_info`, `outputs`, `parent_ids`, `timestamp`, `tool_info`.

Emitted **only when non-empty** (§6.2): `causal_ids`, `provider`, `usage`,
`billing`.

On read, `parent_ids` falls back to a single-element list built from a legacy
`parent_id`; `duration` and `cost` fall back to `0` only for an explicit
`null`; `provider` falls back to `""` for any non-string value rather than
failing the load.

## 3.4 `metadata`

`run_to_dict` always writes `model_info`, `system_prompt` and `user_prompt`
into `metadata`, plus every application-set key. `tags` is emitted only when
non-empty. `integrity` is added by the writer (§3.5). Other reserved keys:
`autosave` (draft checkpoints only; stripped on a final save), `migration`
(append-only migration chain), `fork` (0.4.0 fork-act identity basis),
`fork_reason`, `budget_state`, `warnings`, `replay`, `context`,
`next_harness`, `forked_from`, `fork_point`.

## 3.5 The integrity digest

```text
metadata.integrity = {"algorithm": "sha256", "digest": <64 lowercase hex>}
```

The digest is:

```text
SHA-256( v2_canonical_json( { every top-level key of the artifact EXCEPT "metadata" } ) )
```

using §0.3 — **not** the file's own bytes, which are indented and therefore not
canonical. Recompute it by parsing the file, deleting the top-level `metadata`
key, canonicalizing per §0.3, and hashing.

**Worked vector:**

```text
artifact (metadata omitted from the digest input):
  {"cache":{},"created_at":0,"format_version":2,"graph":{"order":[],"steps":{}},
   "manifest":{},"policies":{},"refs":{},"run_id":"demo","status":"completed",
   "transcript":[]}
digest = 3a9321a351b896fd41c5be9eabe1b3042da5c1a15e72968066bc04f11cd90e30
```

**`metadata` is excluded wholesale**, including `metadata.integrity` itself.
That exclusion is deliberate and load-bearing: it is what lets the digest live
*inside* `metadata.integrity` without self-reference. It is also a known,
documented boundary — metadata can be rewritten and the digest still matches.

**An unkeyed digest is a consistency check, not authenticity.** Anyone who can
edit the file can recompute it. It means "these bytes are internally
consistent", never "these bytes are genuine". Authenticity of a `.tine`
artifact comes only from a `tine-sig/2` signature (§5.3), which covers every
`metadata` key except `integrity` and is recomputed from content rather than
read from the stored digest — so a body edit plus a digest rewrite still fails
verification. Narrowing the exclusion would change the stored digest of every
artifact ever written, so it is deferred to a future `FORMAT_VERSION` bump.

`verify_integrity` reports `ok=False` with an explicit reason for: a missing or
non-object `integrity`, an algorithm other than `sha256`, a digest that is not
64 hex characters, an unsupported `format_version` (with a distinct message for
one written by a *newer* opentine), or a mismatch.

## 3.6 Step identity, and its known limitation

A v2 step id is SHA-256 over a canonical immutable payload: step kind, parent
links, inputs, outputs, model/tool metadata, and error. **Timestamps, duration,
cost and token `usage` are recorded data and are NOT part of the step id**, so
two steps with identical content but different cost share an id (and surface as
a `changed` pair in `diff`, never as add/delete).

> **⚠ Known limitation, retained for compatibility.** A step id can be formed
> from in-memory fields *before* save-time redaction, so the serialized step may
> contain a redacted value the id was not computed over. The artifact-level
> digest still verifies, but that individual step id may not identify the exact
> serialized bytes. V3 corrects this by redacting before canonicalization and
> hashing (§1.4); the v2→v3 migrator always recomputes ids and never carries
> this identity claim forward.

## 3.7 Write-side symmetry

Every reader bound is enforced at **save**, not just at load
(`_artifact_io.assert_loadable`): the 256 MiB size bound measured as it will be
on disk, the depth and structural-token budget, the 4096-digit integer bound,
Unicode validity (§0.1), the supported `format_version`, and the run/step record
shapes the loader validates. A rule enforced on read but not on write produces a
file that saves cleanly and then fails every later load — destroying the run it
was written to preserve.

The reader additionally refuses **parser differentials**: duplicate object keys,
`NaN`/`Infinity` literals, and NUL bytes.

## 3.8 The rebuildable sidecar

`.tine_runs/index.json` is a cache for `tine search` / `tine ls` filters. It is
**never** part of an artifact and **never** authoritative; a corrupt or
version-mismatched index is silently discarded and rebuilt. `index_version` is
1 and an index is dropped when its `covered_format_version` is not the current
`FORMAT_VERSION`.

---

# Part 4 — Signing

Three schemes exist. All three share one algorithm set, one header shape, one
block shape, one verdict vocabulary, and one canonicalizer (§0.3). They differ
**only in the domain prefix and in what the signed view covers** — which is the
whole meaning of a scheme, and why it is versioned.

## 4.1 The shared block

A signature block is a JSON object:

| Key | Type | Notes |
|---|---|---|
| `alg` | string | `"hmac-sha256"` or `"ed25519"` |
| `scheme` | string | `tine-sig/1`, `tine-sig/2` or `tine-attest/1` |
| `key_id` | string | optional |
| `signer` | string | optional |
| `signed_at` | string | optional |
| `value` | string | lowercase hex: **64** chars for `hmac-sha256`, **128** for `ed25519` |
| `public_key` | string | Ed25519 only: 64 hex chars of the raw public key |

`_signing_verify.HEADER_KEYS` is
`("alg", "key_id", "scheme", "signed_at", "signer")`
— the **signed header**, in every scheme of both families. The
scheme string is one of them, so a message under one scheme can never equal a
message under another over identical content.

> **⚠ Hazard — absent header values are signed as `null`, but omitted from the
> stored block.** The signed header always has all five keys, with `null` for
> any that were not supplied; the *stored* block drops the `null`s. This is what
> makes an absent `key_id` unforgeable after the fact: adding one later changes
> the message and the verdict goes `mismatch`. A verifier MUST rebuild the
> five-key header from the block, filling absent keys with `null`, before
> canonicalizing.

## 4.2 The message

```text
message = DOMAIN_PREFIX || v2_canonical_json( signed_view )
```

with §0.3 canonicalization in all three schemes.

| Scheme | Domain prefix | Source |
|---|---|---|
| `tine-sig/1` | `opentine.signature.v1:` | `_signing_view.DOMAIN_PREFIX` |
| `tine-sig/2` | `opentine.signature.v1:` | *(the same constant)* |
| `tine-attest/1` | `opentine.attestation.v1:` | `_attest_view.ATTEST_DOMAIN_PREFIX` |

> **⚠ Hazard — `tine-sig/1` and `tine-sig/2` share one domain prefix.** They are
> not separated by the prefix but by the `scheme` string inside the signed
> header, so a v1 message and a v2 message over the same artifact already differ
> in their canonical bytes. The *attestation* family has its own prefix, so no
> signature can ever be lifted between the artifact and attestation families.

## 4.3 `tine-sig/1` — legacy `.tine` artifact signature (0.3.0–0.7.0)

**Verified, never written.** Signed view:

```json
{"body": {every top-level artifact key except "metadata"},
 "header": {alg, key_id, scheme, signed_at, signer},
 "metadata": {only the keys present from the frozen allowlist}}
```

`_signing_view._SIGNED_METADATA_KEYS` (**FROZEN**, in this order — though
canonicalization re-sorts them): `model_info`, `system_prompt`, `user_prompt`,
`forked_from`, `fork_point`, `warnings`, `replay`, `context`, `next_harness`,
`migration`, `fork`.

The allowlist is frozen forever, not merely stable: it *is* the definition older
signatures were computed against. Adding a key would retroactively falsify
genuine older signatures over artifacts carrying it. (`fork_reason` is absent
because 0.3.0 wrote it but did not sign it; `fork` was safe to add in 0.4.0
precisely because 0.3.0 never wrote it.) **Not covered**: `metadata.tags`, so
re-tagging never broke a v1 signature.

## 4.4 `tine-sig/2` — current `.tine` artifact signature (0.7.1+)

Same view, with `metadata` covering **every key except `integrity`**:

```json
{"body": {every top-level artifact key except "metadata"},
 "header": {alg, key_id, scheme, signed_at, signer},
 "metadata": {every metadata key except "integrity"}}
```

Stored at `metadata.integrity.signature`. `integrity` is excluded because it
holds the signature block being computed (self-reference), alongside the unkeyed
digest, which is itself taken over body keys this view already covers in full.
Tags and application-added metadata are inside a v2 signature, which they never
were under v1.

The reference writer (`Run.save(path, sign_key=...)`, `_graph_serde.save_run`)
refuses to sign a **draft** checkpoint, a **non-terminal** run (status must be
`completed` or `failed`), and a **repository** target — a repository is
attested, not signed as an artifact. These are writer policy, not scheme rules:
`signing.verify_artifact` will still verify such a block if one exists.

## 4.5 `tine-attest/1` — v3 attestation signature (0.9.0+)

Stored at the attestation payload's `signature` key. Signed view:

```json
{"body": {every attestation payload key except "signature"},
 "header": {alg, key_id, scheme, signed_at, signer}}
```

**Covered:** `target_id` (*which run*), `claim` (*what is asserted*), `signer`
(*whose assertion*), `evidence_ids` (*what backs it*) — and any field a later
writer adds, without needing a new scheme — plus the five signed header keys, so
the algorithm cannot be downgraded, the scheme cannot be swapped, and the
timestamp cannot be moved after the fact.

**Excluded, deliberately:**

* `signature` itself — it is the value being computed. Its *header* is covered
  separately, which is what makes the exclusion safe: everything in the block
  except the opaque `value` (and, for Ed25519, the embedded `public_key`) is
  inside the signature.
* the object id and the envelope (`type` / `schema`). The oid is the digest of
  the stored payload **including** the signature, so signing it is impossible by
  construction; it needs no coverage either, because content addressing already
  makes the payload → oid direction tamper-evident, and the payload is what this
  view signs in full.

Two rules keep the verdict honest:

* **The body is the payload as stored** — after `Repo.put`'s redaction — so a
  claim carrying a credential-shaped field is signed in the form every reader
  will see, not the form the caller passed. (Redaction is idempotent, so the
  writer applies it before signing and `put` applies it again.)
* **The header's `signer` is the payload's `signer`.** There is one identity in
  an attestation, so the signer is read off the payload rather than accepted as
  a second value that could disagree with the claim being signed. A missing or
  empty `signer` is refused at signing time.

`Repo.attest` without a key writes the byte-identical unsigned object 0.3.0–
0.8.1 wrote — `"signature": null` included — which verifies as `unsigned`,
never `verified`. Passing both a prepared `signature` block and a `key` is
refused rather than silently resolved.

Remember §0.4: **this scheme's message uses the v2 canonicalizer over a v3
object's payload.**

**Worked vector** (HMAC-SHA256, key = the 32 ASCII bytes
`0123456789abcdef0123456789abcdef`):

```text
payload = {"claim":{"result":"pass"},"evidence_ids":[],"signer":"release-bot",
           "target_id":"run:sha256:1111111111111111111111111111111111111111111111111111111111111111"}
header  = {"alg":"hmac-sha256","key_id":"demo-key","scheme":"tine-attest/1",
           "signed_at":"2026-09-05T00:00:00Z","signer":"release-bot"}

message = b'opentine.attestation.v1:{"body":{"claim":{"result":"pass"},"evidence_ids":[],'
          b'"signer":"release-bot","target_id":"run:sha256:11111111111111111111111111111111'
          b'11111111111111111111111111111111"},"header":{"alg":"hmac-sha256","key_id":"demo-key",'
          b'"scheme":"tine-attest/1","signed_at":"2026-09-05T00:00:00Z","signer":"release-bot"}}'

value   = 6b9ea7e75bff9987920f417ba0419c12f6aadfe3088ec8ee8ce7eda271177164
```

## 4.6 Algorithms and keys

| Algorithm | `value` | Key |
|---|---|---|
| `hmac-sha256` | 64 hex chars | raw bytes, **at least 16** (`MIN_HMAC_KEY_BYTES`); a shorter key is refused at sign and at verify |
| `ed25519` | 128 hex chars | 32-byte seed (private) / 32-byte raw public key, or their 64-hex spellings |

A key read from a file has **exactly one** trailing LF stripped, and the file
must be at most 1 MiB.

## 4.7 The verdict vocabulary

`_signing_verify.SignatureResult` carries `(ok, state, algorithm, key_id,
signer, signed_at, reason)`. The vocabulary is **fail-closed**: `verified` and
`verified-tofu` are the *only* states carrying `ok=True`.

| `state` | `ok` | Meaning |
|---|---|---|
| `verified` | **true** | a key the caller supplied was applied and agreed |
| `verified-tofu` | **true** | Ed25519 only: verified against the **public key embedded in the block**, which the signature does not cover. Trust on first use — it proves the block is internally consistent, not that the key is anyone's. Requires an explicit `trust_embedded` opt-in. |
| `unsigned` | false | no signature block at all. Never an error, never verified. |
| `no-key` | false | a block is present but the caller supplied no key for its algorithm, so nothing was checked |
| `mismatch` | false | a key was applied and disagreed. The tamper verdict. |
| `error` | false | the block, its scheme, or the signed content is malformed |

Every branch **returns** one of these rather than raising, so a caller that
checks only `ok` cannot read a refusal as a pass. `error` covers: a non-object
root/metadata/integrity/block, a `scheme` not in the scheme list for that
family, a non-string `alg` or non-string optional header value, an unknown
algorithm, a `value` of the wrong length or not hex, content that cannot be
canonicalized, an HMAC key below the floor, a malformed embedded public key,
and (for `ed25519`) the `cryptography` extra not being installed.

A block is always verified **under the scheme it names**: a `tine-sig/1` block
keeps its narrower v1 view forever, and only a v2 block gets v2's coverage.

---

# Part 5 — The compatibility contract

## 5.1 The read guarantee

**From v0.3.0 onward, a newer opentine reads everything an older opentine
(≥ 0.3.0) wrote** — `.tine` artifacts and `.tine/` repositories alike. This is a
release gate, backed by golden fixtures per released version under
`tests/fixtures/`, not an aspiration. Concretely:

* `SUPPORTED_VERSIONS = (1, 2)`: a v1 artifact still loads (migrated in memory)
  and still verifies under v1's own rules.
* Every historical signature keeps verifying byte-identically, which is why
  `tine-sig/1` is still verified and its metadata allowlist is frozen (§4.3).
* Every historical object id stays reachable, which is why neither
  canonicalization may be "unified" (§0.4).

The reverse does not hold: a 0.1.x reader cannot read v2, and re-saving a v1
file upgrades it to v2 one-way.

## 5.2 What "additive" means for a field

A new field is **additive** only if adding it leaves the bytes of every
previously written record **byte-identical**. In practice that means one rule:

> **Emit the field only when it is non-empty.**

An unconditionally emitted key — even one whose value is `""`, `[]` or `null` —
changes the canonical bytes of every record, which changes every v3 object id
(re-addressing and duplicating every stored event) and breaks every stored v2
digest and signature.

This rule has governed every field added since 0.3.0:

| Field | Where | Emitted when |
|---|---|---|
| `causal_ids` | v2 step record | the step has causal edges |
| `provider` | v2 step record, v3 event payload | the run/span knows the provider |
| `signature` | v3 attestation | *always present* — but as the literal `null` that 0.3.0–0.8.1 already wrote, so unsigned attestation bytes are unchanged |
| `tags` | v2 `metadata` | the run has tags |
| `usage`, `billing` | v2 step record | non-empty |
| `draft` | v2 top level | autosave checkpoints only |

The `signature` row is the interesting one: the slot already existed and was
already written as `null`, so filling it was additive *without* the
emit-when-non-empty rule. A field with no such pre-existing slot does not have
that option.

## 5.3 What changes a v3 object id

Everything in the framed bytes of §1.3: the object **type**, the **schema**
integer, and every byte of the canonical body — which means every key, every
value, and the presence or absence of any key. Nothing else: the file path, the
envelope header (a function of type and schema), the ref that points at it, the
reflog, packs, and the repository config are all outside identity.

Two consequences worth stating plainly:

* **A v3 repository id is a content hash**, so two identical forks collapse to
  one object, and re-attesting an identical claim lands on the same object.
* **A v2 `.tine` fork id names the fork *act*** (lineage, retained slice,
  branch, declared intent, and a recorded nonce, stored in `metadata.fork` and
  provable with `verify_fork_id`), so forking the same point twice produces two
  distinct runs. Both are digests; neither lets an untrusted run id steer an
  output path.

## 5.4 The v2 → v3 migration boundary

Migration is strict by default: a source whose integrity check fails is refused
(`--allow-unverified` is the explicit recovery path), and if signature
verification was *requested*, a state other than `verified`/`verified-tofu` is
refused. It stores the **original v2 bytes unmodified** as a `blob`, records the
source artifact's integrity and signature results in `legacy_verification` with
`scope: "original-v2-artifact"`, creates newly redacted and hashed v3 content,
and writes a deterministic old→new step map. The run sets `signature_scope =
"legacy_blob_only"`: a legacy signature is a claim about the archived bytes, and
is **never** an attestation over the generated v3 objects.

---

# Part 6 — Conformance checklist

A minimal third-party **reader** is conformant when it:

1. rejects unpaired surrogates in text, in both escape and raw-byte spellings
   (§0.1);
2. implements §0.2 including the integer-literal demotion hazard, and §0.3 as a
   *separate* function, and never substitutes one for the other (§0.4);
3. verifies the envelope framing, the exactly-three-key canonical header, and
   the oid derivation of §1.2–§1.3 against the vectors given there;
4. enforces the link rules of §1.5 including the open-ended `_blob` suffix rule;
5. enforces every bound in §1.6 that applies to what it reads;
6. reads refs, reflogs, shallow state and TINEPACK3 frames per Part 2, treating
   array order in a pack manifest as unconstrained;
7. recomputes the v2 integrity digest per §3.5 and reports it as *consistency*,
   never as authenticity;
8. computes signature messages per §4.2 with the **v2** canonicalizer,
   reconstructs the five-key header with `null` for absent values, and returns
   the fail-closed vocabulary of §4.7 rather than raising;
9. never repairs, substitutes or drops anything it cannot represent.

## Where the constants live

Every value in this document is pinned against the code by
`tests/test_format_spec_drift.py`. If you change a constant, a name, a scheme, a
domain prefix or a verdict, that test fails until this document is updated with
it. That is the mechanism by which the spec stays true — not review discipline.

---

# Part 7 — Proving conformance

Everything above is prose. Prose does not let anyone *prove* an implementation
correct, so this specification ships a machine-readable vector suite alongside
it: **[`docs/conformance/`](conformance/README.md)**, 523 vectors covering the
nine checklist items of Part 6, runnable from any language against a
standard-library harness.

## What is there

| Path | What it is |
|---|---|
| [`conformance/README.md`](conformance/README.md) | how to run it, what it scores, and what a passing scorecard does **not** certify |
| [`conformance/PROTOCOL.md`](conformance/PROTOCOL.md) | the line-delimited-JSON adapter contract, and the tagged value encoding the inputs use |
| [`conformance/REASON_CODES.md`](conformance/REASON_CODES.md) | every rejection reason, anchored to a section of this document, with the live value of the bound it enforces and the repair it forbids |
| [`conformance/SPEC_NOTES.md`](conformance/SPEC_NOTES.md) | every place building a vector found this document and the code not lining up, each with a **mandatory** resolution |
| [`conformance/MANIFEST.json`](conformance/MANIFEST.json) | the single machine-parsed entry point: the op table, the alias groups, per-family counts, per-file digests, and which §1.6 row each vector covers |
| `conformance/vectors/` | 25 files, one per area of this document |
| `conformance/compat/index.json` | a pointer index into `tests/fixtures/compat/` — §5.1's read guarantee, over bytes eight published releases wrote |
| `conformance/run_conformance.py` | the neutral runner: standard library only, imports no opentine |

## The procedure, honestly

1. **Implement the tagged value reader** (`PROTOCOL.md`, about a dozen lines) and
   run `vectors/01-selftest.json`. Until it passes, no other result means
   anything.
2. **Write an adapter** — about eighty lines, one JSON object in and one out.
   `scripts/conformance_adapter.py` is the worked example.
3. **Run the suite.** Start with the `reader` profile; `canon.v3` +
   `envelope.decode` + `oid.derive` alone already produce a real table, because
   an op you have not implemented is reported *unimplemented* rather than
   failed.
4. **Read the three-column score.** `passed` alone is defeatable by an
   implementation that refuses everything, so `pairs` — both halves of every
   twinned case — is reported separately, and a blanket rejecter scores near
   zero there. `reason_agreement` is informational at Level 1 and required at
   Level 2.
5. **Run the compat family last.** It reads the golden fixtures directly, so
   passing it means your reader reaches this build's verdicts on artifacts and
   repositories written by opentine 0.3.0 through 0.8.0.

## What the vectors are, and are not

Every expected value in the suite is **generated** from the reference
implementation and **checked in**, and the generator refuses to emit when an
observation disagrees with the disposition its author declared. That makes the
numbers machine-true and makes a behaviour change visible as a one-line diff in
`tests/conformance/cases_*.py` rather than as a silent re-baselining.

It does not make them a second specification. The generator and the self-gate
share a codebase, so a shared misconception would produce vectors that confirm
it; running them from two different entry points and requiring byte-stable
regeneration narrows that and cannot close it.

> **This document is normative. The vectors are evidence about it.** If a vector
> and this document disagree, follow this document — and file the disagreement,
> because one of the two is wrong.

Well over a third of the vectors are **negative**: inputs this format requires be
refused. That is deliberate, and `vectors/99-repair.json` goes further — its
fourteen cases each carry the exact answer a *repairing* implementation returns,
so accepting one of them is reported as `REPAIRED` rather than as a plain
failure. Part 6 item 9 is the one rule a suite of accepts cannot check, and it
is the rule that decides whether a digest over recorded model output means
anything.
