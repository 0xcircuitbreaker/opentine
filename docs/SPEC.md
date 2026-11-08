# The OpenTine Format Specification

**Spec version:** 0.46.0 (draft until opentine 0.46.0 is tagged). **Previous
version:** 0.45.1. Changes between versions are listed in
[Spec changelog](#spec-changelog); section anchors are stable (see
[Stable anchors](#stable-anchors)).

**Status:** normative for the opentine release named by the spec version. **Formats covered:** portable
`.tine` artifact `format_version` 1 and 2; the v3 `.tine/` repository object
model, wire format and pack format; the three signature schemes `tine-sig/1`,
`tine-sig/2` and `tine-attest/1`; since 0.26.0, format v4 (Part 9, the
default writer until 0.42) with `tine-sig/3` and `tine-attest/2`; and, since
0.40.0, format v5 (Part 10: text blobs; the default writer since 0.42.0).

This document is written for someone implementing a **reader, writer or
verifier in another language**. Everything here is derived from the reference
implementation's source, and every load-bearing constant, name and test vector
in it is pinned against that source by `tests/test_format_spec_drift.py`. If a
statement here and the code disagree, that is a bug in this document — file it.

**One rule governs this document: it describes what the code does, not what it
ideally would do.** Where the behaviour is surprising, the surprise is
documented rather than smoothed over; those places are marked **⚠ Hazard**.

## How to cite

> *The OpenTine Format Specification*, opentine `docs/SPEC.md`, version 0.46.0.
> https://github.com/0xcircuitbreaker/opentine/blob/v0.46.0/docs/SPEC.md

Cite a version, not `main`: the tagged URL is immutable, and a citation of a
section should add its anchor (for example `#s-4.8` for `tine-actions/1`). The
spec version is the opentine release that last changed this document; a
release that leaves it unchanged does not bump it. The JSON Schemas of the
object kinds and `--json` outputs (Part 12) are published beside it in
`docs/schemas/` under the same version.

<a id="stable-anchors"></a>
### Stable anchors

Every part and every numbered section has an explicit HTML anchor on the line
above its heading: `part-N` for "Part N" and `s-N.M` for section N.M (`s-2.8`,
`s-9.3`). Anchors are only ever added. A section that is removed or renumbered
keeps its old anchor on the nearest successor, so a link into a cited version
of this document keeps resolving in later ones. `tests/test_045_spec.py` pins
the anchor set.

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

<a id="part-0"></a>
# Part 0 — Primitives shared by both formats

<a id="s-0.1"></a>
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

<a id="s-0.2"></a>
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

<a id="s-0.3"></a>
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

<a id="s-0.4"></a>
## 0.4 Historical — the v2/v3 canonicalization divergence

> **Historical (0.26.0+).** Format v4 (Part 9) is the default writer and uses
> §0.2 only; §0.3 survives to verify v2 data and the signatures made over it.
> The hazard below still applies to every v2 artifact and to anything written
> with the deprecated legacy writers (`OPENTINE_FORMAT=2`, `tine --format 2`).

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

<a id="s-0.5"></a>
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

<a id="part-1"></a>
# Part 1 — The v3 object model and wire format

<a id="s-1.1"></a>
## 1.1 Object types

`kernel.OBJECT_TYPES` = exactly `{"blob", "event", "run", "attestation",
"annotation"}`. There is no extension point: an unknown type is rejected. New
structured kinds therefore ride on a blob schema instead (the 0.38 tree,
§1.5.7), which older readers accept as opaque bytes.

| Type | Encoding | Purpose |
|---|---|---|
| `blob` | `raw` | opaque bytes: prompts, outputs, patches, tool results, manifests |
| `event` | `json` | one normalized model / tool / human / policy activity |
| `run` | `json` | an event graph plus manifests and status |
| `attestation` | `json` | a signed or unsigned claim about a run |
| `annotation` | `json` | separately versioned mutable metadata for an object |

<a id="s-1.2"></a>
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

<a id="s-1.3"></a>
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

### 1.3.1 The hash-algorithm tag (reserved, 0.41.0)

The middle field of an oid is a **hash-algorithm tag**:

```text
oid = TYPE ":" TAG ":" HEX
```

Every format so far defines exactly one tag, `sha256`, and `kernel.OID_RE`
accepts no other. The field is reserved so that a future format can mint, for
example, `blob:sha3-256:<hex>` or `blob:blake3:<hex>` without a new grammar.
The tags `sha3-256`, `sha512` and `blake3` are **reserved**: no current
writer produces them and no current reader accepts them.

* The tag is part of the oid and therefore of every link, ref and signature
  that names it. It is **never negotiated**, and a reader MUST NOT compute an
  oid under a different algorithm than its tag names.
* There is no hash agility inside one oid space: a repository or artifact is
  one algorithm, and moving to another is a migration (Part 5), not a mix.
* A reader that meets a well-formed `TYPE:TAG:HEX` whose `TAG` it does not
  implement MUST refuse it with an error naming the algorithm
  (`opentine._hash_tag.parse_oid`: *unsupported hash algorithm 'blake3' in
  object id ...*), reason code `oid.hash-unsupported`. It MUST NOT treat the
  oid as `sha256`, strip the tag, or store the object opaquely. Anything that
  is not `TYPE:TAG:HEX` at all stays `oid.malformed`.

The repository object store, the v4/v5 artifact reader and the conformance
adapter route oids through that wrapper; the kernel itself keeps its single
regex (and its line budget). Vectors: `oid.parse.reserved-hash-tag`,
`oid.parse.unknown-hash-tag` in `vectors/55-sig-pq.json`.

<a id="s-1.4"></a>
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

<a id="s-1.5"></a>
## 1.5 Payload shapes

**The kernel constrains only what the graph depends on.** Any other field may
hold any JSON value and still be stored — that openness is what lets a newer
writer add a field an older reader round-trips without understanding. The
tables below therefore separate **enforced** rules from **conventional** fields
that the reference writers emit.

### 1.5.1 `blob`

At schema 1 (and every schema other than 2): no structure, opaque bytes, no
links. A blob at **schema 2** is a *tree blob* (§1.5.7, 0.38+): its raw body is
canonical JSON and each `entries[].oid` is a link.

### 1.5.2 `event`

Enforced (`kernel.validate_links`, `repository._run_graph.validate_event_metrics`):

| Field | Rule |
|---|---|
| `parent_ids` | absent or a list of **event** oids, no duplicates. Defaults to `[]`. |
| `causal_ids` | same rule as `parent_ids`. |
| `input_blob`, `output_blob`, `artifact_blob` | if present **and truthy**, MUST be a **blob** oid |
| `tree` (0.38+) | if present **and truthy**, MUST be a **blob** oid: the workspace snapshot (a tree blob, §1.5.7) taken at this step |
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

#### Prompt parts: `input_parts` (0.38.0+)

| Field | Rule |
|---|---|
| `input_parts` | absent, or an object whose values, if truthy, MUST be **blob** oids (`kernel.validate_links`; any other shape is rejected). Each value is a link, so `fsck`, `gc`, packs and transfer keep the part blobs. |

A model call's request repeats the same system prompt and tool definitions on
every turn. From 0.38.0 the writers (`repository.runs.put_run`, the trace
recorder and importers, fork edits) split them out at record time
(`repository._prompt_parts`):

1. For each key `K` in `instructions`, `system`, `tools` (in that order) at the
   **top level** of a step's inputs whose value is a non-empty string, array or
   object, the writer stores the blob `{K: value}` — canonical JSON, guarded and
   redacted exactly as the whole input blob is — and sets `input_parts[K]` to its oid.
2. `input_blob` holds the inputs **without** those keys. With no key split,
   `input_parts` is omitted and the event is byte-identical to a 0.37 event.

A reader reconstructs the inputs as `input_blob`'s object plus, for every
`input_parts` entry, the one field its blob holds. It MUST refuse a part whose
key is not one of the three, whose blob is not an object with exactly that one
key, or whose key the base object already holds. The full inputs are therefore
the same value the step was recorded with; only their storage differs, and
identical prompts across steps and runs are one blob. Events written before
0.38.0 carry no `input_parts`, are read exactly as before, and keep their ids
and signatures (§5.2: the field is additive).

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
| `parents` (0.43+) | absent, or a **non-empty** list of **unique run** oids (at most 64), each a link (`kernel.validate_links`, `repository._run_parents`). A writer MUST omit it when there are none and MUST NOT write `[]` (rejected), so a run without parents has the oid it had before 0.43. |
| ordering | for every locally present event in `events`, each of its `parent_ids` and `causal_ids` MUST appear at a **strictly earlier index** in `events` |
| `roots` / `tips` exactness | **only when every event in `events` is present locally**: `set(roots)` MUST equal the set of parentless events, and `set(tips)` MUST equal `events` minus every event named as someone's parent. When any event is missing (a shallow fetch), both checks are skipped. |

> **⚠ Hazard — the `_blob` suffix rule is open-ended.** It is not a fixed field
> list: *any* top-level run key whose name ends in `_blob` and whose value is
> truthy must be a blob oid. A writer adding `patch_blob` inherits the
> constraint automatically; a writer adding `patch_blob: {"a": 1}` is rejected.

`parents` names the runs a merge combined (F2, `docs/design/F2-merge.md`);
it is distinct from `forked_from`, the one run a fork or resume continues, and a
fork of a run does not inherit its `parents`. A 0.42 reader validates and
hashes a run with `parents` correctly but does not follow the field as a link,
so its `gc` may drop a parent run no ref names; merges are not written before
the release that also sets `min_reader` for them (0.45+).

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
"tags": [str, ...]}`. Since 0.9.2 it leaves `model_info`, `system_prompt` and
`user_prompt` out of `metadata`, because the run carries them (`model`,
`system_blob`, `prompt_blob`); annotations written earlier may still repeat
them, and a reader takes the run's own fields.

Note the asymmetry with §1.5.4: an **attestation**'s `target_id` must be a run;
an **annotation**'s may be any object type, and may be absent.

### 1.5.7 Tree blobs (0.38+)

A workspace snapshot is a git-like **nested** tree: one tree blob per
directory, so an unchanged directory keeps its oid from turn to turn and a turn
stores only the files and directories on the path to what changed. A tree is a
`blob` envelope with `schema` 2 and `encoding` `raw`; the body is the RFC 8785
canonical JSON (§0.2) of:

```json
{"entries":[{"mode":"100644","name":"README.md","oid":"blob:sha256:…"},
            {"mode":"40000","name":"src","oid":"blob:sha256:…"}],
 "omitted":[{"name":"big.bin","reason":"size"}],
 "type":"opentine.tree"}
```

The oid is therefore `blob:sha256:` over `blob\0 2\0 <canonical bytes>` (§1.3),
distinct from a schema-1 blob with the same bytes.

Enforced by the kernel (`kernel.validate_links`, `TREE_SCHEMA = 2`): the body
parses as a JSON object; `entries` is a list of objects; each `oid` is a
**blob** oid and is a link (§1.5.6: it MUST resolve). Enforced by the tree
reader (`opentine._tree.parse_tree`), which every snapshot writer and restorer
uses:

| Field | Rule |
|---|---|
| `type` | exactly `"opentine.tree"` |
| body | byte-equal to its canonical re-encoding; no keys besides `entries`, `omitted`, `type` |
| `entries[].name` | one path component: non-empty UTF-8, not `.` or `..`, no `/`, `\` or NUL |
| `entries` order | sorted by the UTF-8 bytes of `name`, names unique |
| `entries[].mode` | `100644` file, `100755` executable file, `120000` symbolic link (the blob holds the link target's bytes; it is never followed), `40000` directory (the oid is a tree blob) |
| `entries[].redacted` | absent or `true`: the stored bytes were changed by redaction (§1.4), so the file cannot be restored byte for byte |
| `omitted` | absent or a list of `{"name", "reason"}`, names disjoint from `entries`: paths deliberately not captured (`size`, `unreadable`, `tineignore redact`); a restore leaves them alone |
| entry count | at most 100 000 per tree; nesting at most 256 levels |

A snapshot never contains a version-control directory (`.git`, `.tine`,
`.hg`, `.svn`, `.bzr`, `_darcs`, `.jj`, `.pijul`), paths matched by
`.gitignore` files met on the walk, `.tineignore` excludes, or the caller's
ignore patterns. Sockets, FIFOs and devices are skipped. A name that is not
valid UTF-8 is skipped (and reported to the caller), never encoded.

**Why a blob, not a sixth object type.** 0.34 readers reject an unknown object
type (`OBJECT_TYPES` has no extension point, §1.1) in `fsck`, in the pack
reader and on every `get`. They accept a blob at any schema `1 <= schema <
2**53`, decode it as opaque bytes and find no links in it, so a 0.34 `fsck`,
pack reader (`install_pack`) and `pack` accept a repository holding trees
(tested against the `v0.34.0` code in `tests/test_038_tree_snapshots.py`). A
0.34 reader does not *validate* tree links, but its `prune` reachability walk
also collects every oid that appears in an object's raw bytes, so it keeps a
reachable tree's children. An event's `tree` field is an unknown field to 0.34:
stored and round-tripped, not checked.

### 1.5.6 Link existence

Every link extracted above MUST resolve: the object exists locally **or** its
oid is listed in the repository's shallow-boundary file (§2.7). An object MUST
NOT link to itself.

<a id="s-1.6"></a>
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

Past the legacy annotation scan bound, the unheaded-annotation fallback adopts
nothing (no error); so does a damaged or over-limit `.tine/unadopted` record.

---

<a id="part-2"></a>
# Part 2 — Repository layout

<a id="s-2.1"></a>
## 2.1 Directory tree

A repository is the directory `.tine/` (or, bare, any directory holding
`config.json`).

```text
.tine/
  config.json                      repository descriptor (§2.2)
  objects/<type>/<aa>/<62 hex>     loose objects (§2.3)
  refs/<namespace>/<name>          one oid per file (§2.4)
  packed-refs                      every packed ref in one file (§2.4, 0.37+)
  logs/<namespace>/<name>          append-only reflog (§2.6)
  packs/<64 hex>.pack              TINEPACK3 frames (§2.8)
  indexes/                         non-normative caches (below)
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

`indexes/annotation-targets` and `indexes/attestation-targets` (0.10) are
non-normative caches mapping each annotation or attestation digest to its
`target_id`. Readers rebuild them from the object store (listing it on every
use, decoding unknown objects, dropping missing ones, rebuilding a damaged
file) and MUST NOT treat them as authoritative; every candidate they name is
still read and validated. (The *legacy* run index is a separate,
non-repository sidecar: `.tine_runs/index.json`, §4.6.)

<a id="s-2.2"></a>
## 2.2 `config.json`

Written by `Repo.init` as canonical JSON (§0.2) followed by a single LF. Since
0.26.0 a new repository is object format 4 (see the end of this section), so a
plain (`OPENTINE_COMPRESS=0`) `Repo.init` writes

```text
{"min_reader":"0.26.0","object_hash":"sha256","objects":4,"repository":"opentine","version":1}\n
```

and the deprecated legacy writer (`OPENTINE_FORMAT=2`/`3`), like every release
before 0.26, writes the object-format-3 descriptor:

```text
{"format":3,"object_hash":"sha256","repository":"opentine","version":1}\n
```

The rest of this paragraph describes the format-3 descriptor; §9.10 and the
end of this section the object-format-4 one.

A reader MUST require exactly these four key/value pairs to be present and
equal. The file MUST be at most 65 536 bytes and pass §0.5 with `max_tokens`
10 000. Its presence is what identifies a directory as a repository; `Repo.open`
walks upward from the given path looking for `<dir>/config.json` or
`<dir>/.tine/config.json`.

> **⚠ Wart — unknown keys are accepted, and so is any formatting.** Validation
> checks only that the four required pairs match; extra keys pass, and the
> file need not be canonical or newline-terminated on read. Since 0.9.2 the
> reference reader refuses a key that appears twice and a JSON boolean where a
> number is required (`true` is not `1`), and requires UTF-8 (a leading BOM is
> tolerated).

Since 0.11 a descriptor may instead carry `"version": 2` together with
`"storage": {"compression": "zstd" | "zlib" | "none"}`. A version-2 repository
may hold compressed loose objects (§2.3) and local packs (§2.8). Version 1
holds plain loose objects only. A reader that supports only version 1 MUST
refuse version 2. `Repo.init` writes version 2 by default; with
`OPENTINE_COMPRESS=0` or `tine --no-compress` it writes version 1 byte for byte
as shown above.

Since 0.13 a descriptor may carry `"version": 3` (with the same `storage` key,
and an informational `"note"` that readers ignore). Version 3 is opt-in only,
written by `tine gc --upgrade`, never by `Repo.init`, auto-pack or a plain
`tine gc`. A version-3 repository may additionally hold storage-v3 local packs
(§2.8, "Pack v3"); its loose objects are stored exactly as in version 2.
A reader that supports only versions 1 and 2 MUST refuse version 3; opentine
0.11–0.12 do so at open with `repository config is incompatible`, and 0.13
names the newer version when it meets one above 3. `tine gc --downgrade`
rewrites every pack in the version-1 pack format and then writes
`"version": 2`, after which 0.11–0.12 open the repository again. Upgrade writes
the descriptor *before* the first v3 pack, and downgrade writes it *after* the
last v3 pack is gone, so an interrupted run never leaves 0.12 a repository it
opens but cannot read; `fsck` reports a v3 pack under a lower version.

Since 0.26 a descriptor may declare **object format 4** (§9.10):
`"objects": 4` *in place of* `"format": 3`, together with
`"min_reader": "0.26.0"`:

```text
{"min_reader":"0.26.0","object_hash":"sha256","objects":4,"repository":"opentine","storage":{"compression":"zstd"},"version":2}\n
```

`objects` and `version` are independent: `version` (1, 2 or 3) keeps meaning
the storage layout above, and `tine gc --upgrade`/`--downgrade` change it
without touching the object format. Dropping `format` is deliberate: opentine
0.9–0.25 accept unknown keys, so `objects` alone would not stop them, but they
all require `format` to be 3 and so refuse an object-format-4 repository at
open (`repository config is incompatible`) rather than write into it with
v3-only rules (a wide integer stored as a string). A reader MUST refuse a
descriptor carrying both `format` and `objects`, `objects` without
`min_reader`, or `objects` other than the integer 4 (naming the newer format
when it is larger). Independently of `objects`, a reader MUST refuse a
`min_reader` that is not `MAJOR.MINOR.PATCH` or that names a release newer than
the format it implements (`_config.READER_VERSION`, 0.40.0 in this build),
naming the version needed. Unless the legacy writer is chosen, the first
object write into an object-format-3 repository rewrites the descriptor this
way **before** the object is stored (`_config.mark_v4`), the order `tine gc
--upgrade` uses, and `Repo.init` writes object format 4 directly. Every
descriptor read-modify-write (`mark_v4`, and gc's storage-version changes)
holds the short `config.lock` file lock (`_config.config_lock`), so a gc that
read the descriptor first cannot write the old object format back. Conformance vectors (`layout.config.objects-v4`,
`layout.config.min-reader-newer`, `layout.config.objects-and-format`).

<a id="s-2.3"></a>
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

### Stored form vs. canonical form

An object's id, a `.tine` artifact's digest (§3.5) and every signature are
computed over the canonical bytes defined above, never over the bytes on disk.

An implementation may store those bytes compressed. A stored body that begins
with `TINEZ1\0` has this layout:

```text
TINEZ1\0 ‖ codec (1 byte) ‖ uvarint(canonical length) ‖ frame
```

- **Codec byte:** 0 = raw, 1 = zlib (RFC 1950), 2 = zstd (RFC 8878, one frame).
- **Length:** a minimal LEB128 varint of at most 10 bytes.
- **Anything else:** a stored body that does not begin with `TINEZ1\0` is the
  canonical bytes themselves.

A reader MUST refuse a wrapped body when any of these holds:

- its declared length exceeds the reader's limit;
- its declared length exceeds 1000 × the frame length;
- it inflates to a different length than declared;
- it has bytes after its frame;
- its inflated bytes are themselves wrapped;
- its codec byte is unknown.

Writers MUST NOT emit a body that exceeds the ratio limit.

**Codec v2 frames (X13).** Since 0.35 a reader accepts a ratio of up to
100 000 × the frame length for bodies that declare at most 64 MiB. A body
past 1000:1 is a *codec v2 frame*. Since 0.37 a writer emits one only in a
transfer pack for a peer that advertises 0.35 or newer (a server's
`version` capability, or the `peer_version` a client sends with its fetch).
Writers MUST NOT emit one in a `.tine` file, in local storage, or for a peer
that does not advertise a version. Without that advertisement the body is
stored raw (codec 0).

<a id="s-2.4"></a>
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

### `packed-refs` (0.37+)

A repository may also hold refs in one file, `.tine/packed-refs`:

```text
# opentine packed-refs 1 LF
<oid> SP <ref name> LF            one line per ref, sorted by name, unique
```

A reader MUST look for the loose file first and use the packed value only when
there is none (a loose ref shadows its packed value), and MUST refuse a file
that does not begin with that header, does not end in LF, has a line whose oid
or name is invalid, or lists names out of order or twice. Writers move refs by
writing the loose file, as before; a delete removes the packed value first and
then the loose file, both under `packed-refs.lock`. `tine gc` packs refs only
in a repository whose descriptor carries `"refs": "packed"` together with a
`min_reader` of at least `0.37.0` (`tine gc --pack-refs` writes both; `tine
gc --unpack-refs` writes every ref loose again and removes them), so a release
that would ignore the file refuses the repository instead of missing its refs.

### Ref names

The stored name has any leading `refs/` removed. It MUST match:

```text
^(?:annotations|coord|heads|tags|experiments|promotions|remotes)/[a-z0-9._/-]+$
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
| `coord/` | `annotation` (0.43+, `opentine-coord/1`) |
| `tags/` | *(unconstrained)* |
| `remotes/` | *(unconstrained)* |

An `annotations/*` ref carries one further rule: its target annotation's
`target_id` MUST be a `run` oid, and the ref name after `annotations/` MUST
equal that run's 64-hex digest. So `annotations/<digest>` is the only
`annotations/*` name that may point at an annotation of `run:sha256:<digest>`.

### Update protocol

Ref updates are compare-and-swap and are performed under two files beside the
ref:

* `<ref>.lock` — the exclusive guard, created `O_CREAT|O_EXCL`. A concurrent
  writer that finds it waits with jittered exponential backoff (1 ms doubling
  to 50 ms) for at most 10 seconds, then fails; it never breaks a live lock.
* `<ref>..lock` — the staging file that is `rename()`d over the ref.

The doubled dot is deliberate: `normalize_ref` forbids a component ending in
`.lock`, `.` or a space, so `<ref>..lock` can be neither a legal ref nor the
guard lock of a legal ref. A plain `<ref>.new.lock` would be exactly the guard
lock of the legal sibling ref `<ref>.new`.

Sequence: acquire guard → read current value → compare against the caller's
expected value (rejecting a mismatch) → write staging file and `fsync` →
`rename` over the ref → `fsync` the directory → append the reflog row → release
staging and guard.

<a id="s-2.5"></a>
## 2.5 Ref target validation

Before a ref moves, the target object is fetched, its oid re-verified, and the
namespace type rule of §2.4 applied — on write, on read, on pack verification,
on remote ref update, and by `fsck`.

<a id="s-2.6"></a>
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

> **⚠ Wart — the reflog row is appended *after* the ref is replaced.** A crash
> in that window leaves a moved ref with no log row. The reflog is history, not
> authority: never derive a ref's current value from it. Since 0.9.2 each file
> is bounded at 1 MiB: when an append would pass the bound, the writer
> atomically replaces the file with its newest whole rows (about half the
> bound) plus the new row, so the oldest history is dropped. A reader MUST NOT
> assume a log reaches back to a ref's first row.
>
> Since 0.14 a live recorder (`Recorder.append`) moves its ref **without** a
> reflog row; the session's start, `import_events` and `finalize` each log
> one. A reader MUST NOT assume every past value of a ref has a row.

<a id="s-2.7"></a>
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

<a id="s-2.8"></a>
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
never written. Before writing any object, the installer records the pack's
shallow boundaries — with any existing boundary the pack fills — in the
`shallow` file, and prunes the boundaries the pack filled afterwards; an install
interrupted after the first object therefore never leaves a cut link that is
neither present nor recorded (a retry of the same fetch sends nothing, so it
could never heal one).

### TINEPACK5 (0.37+)

TINEPACK5 is a transfer pack for peers that list it in `pack_formats`. Only
0.37 and later installs with zstd list it. A peer at 0.34–0.36 lists
`TINEPACK4` and is sent that; a peer with neither gets TINEPACK3.

```text
b"TINEPACK5\0" | sha256(payload) | payload
payload  = uvarint(len(header)) | header | block 0 | block 1 | ...
header   = canonical JSON {"blocks": [[stored, raw], ...], "version": 1, "window_log": 27}
block 0  = canonical JSON {"objects": [[encoding, stored, size], ...], "shallow": [...]}
block 1+ = the objects' stored bytes in pack order, cut every 4 MiB
```

- **One zstd frame.** The blocks together form a single zstd frame, written
  with long-distance matching and `window_log` 27, at level 9. The frame is
  flushed at each block's end.
- **Window cap (X17).** A reader MUST cap the decoder window at 2^27. It
  refuses a frame that asks for more before allocating anything for it.
- **Block order.** Blocks inflate in order, and each MUST produce exactly its
  declared `raw` size.
- **Checks before the body inflates.** The reader checks the checksum and the
  canonical header. It checks that the declared sizes cover the payload and
  stay within `MAX_PACK_BODY_BYTES`, and that the manifest (block 0, at most
  16 MiB) adds up to the blocks. All of this happens before the body is
  inflated.
- **Recording order.** Objects come in recording order: blobs and events in
  the order the runs reached them, then each session's snapshots in append
  order.
- **Stored forms.** `encoding` is that of pack v3 (blob deltas, 3, are local-only): 0 `FULL`, 1 `RUN_DELTA`
  or 2 `EVENT_SLIM`. A `RUN_DELTA`'s base is the object just before it, which
  MUST be a run, and a delta chain is at most 64 deep.
- **Derived ids.** Ids are not listed. Each id is computed from the rebuilt
  canonical bytes and MUST be unique and disjoint from `shallow`.
- **Pack id.** The pack id is `"sha256:" + hex(bytes[10:42])`.

A bundle's pack is TINEPACK3 unless `tine bundle create --pack-format
TINEPACK5` is asked for. Only 0.37+ reads such a bundle.

### Local packs

A version-2 repository may also hold local packs, written by `tine gc`. Each
pack is two files, `packs/<sha256>.tpk` and `packs/<sha256>.tidx`, named by the
SHA-256 of the `.tpk` bytes.

- **`.tpk`:** `TINELP1\n` followed by blocks. Each block is a wrapped body (see
  "Stored form vs. canonical form" in §2.3) holding a concatenation of
  canonical objects.
- **`.tidx`:** a wrapped canonical-JSON document:

  ```text
  {"blocks": [[offset, length], …],
   "objects": [[oid, block, start, length], …],
   "pack": "<digest>",
   "version": 1}
  ```

  `objects` is sorted and unique, and `blocks` exactly covers the `.tpk`.

A packed object MUST be checked against its id when read. Local packs are a
storage detail: they never cross the network, and transfer packs (TINEPACK3)
always carry canonical bytes.

**Run packs (0.40+).** `Repo.put_run` and `Recorder.import_events` write all
of a run's new objects as one local pack of the repository's current pack
format (v1, or v3 in a storage-version-3 repository) instead of one loose file
per object, so readers since 0.11 read them unchanged. The writer MUST make
both files durable under temporary names (one fsync each), rename the `.tpk`
and then the `.tidx` into place, sync `packs/` once, and only then update any
ref (`_write_batch`). A crash before the ref update leaves an unreferenced
pack that verifies; no ref may name an object that is not yet durable. A
batch of a single object, a storage-version-1 repository, `"run_pack": false`
in `config.json` or `OPENTINE_RUN_PACK=0` keeps loose writes. Single-object
writes (`Recorder.append`, annotations) stay loose.

### Pack v3 (storage version 3, 0.13+)

A version-3 repository may also hold v3 packs, named the same way. A reader
tells the formats apart by magic; a version-3 repository may hold both.

- **`.tpk`:** `TINELP3\n` followed by blocks, each a wrapped body. A block
  holds objects of **one kind**. A block of several objects inflates to at most
  16 MiB (`MAX_BLOCK_BYTES`); a single object may have a block of its own up to
  the object limit. Writers order blobs and events by recording order and run
  snapshots by session and length, and default to 16 MiB blocks.
- **`.tidx`:** binary, big-endian:

  ```text
  "TINEIX3\n"  pack-sha256[32]  u32 block_count  u32 object_count
  block_count  × (u32 stored_len, u32 inflated_len, u8 kind)
  object_count × (u8 kind, digest[32], u32 block, u32 start, u32 length,
                  u32 canonical_size, u8 encoding)
  sha256[32] of every preceding byte
  ```

  `kind` indexes `annotation, attestation, blob, event, run` (alphabetical, so
  entry byte order is id order). The length MUST be exactly
  `48 + 9·blocks + 50·objects + 32` and the trailing SHA-256 MUST match before
  any field is used. Entries are strictly sorted; blocks tile the `.tpk` from
  offset 8; each entry's kind equals its block's; a block's entries tile it
  from 0 and sum to its `inflated_len`. A block's frame MUST declare exactly
  `inflated_len` before it is inflated.
- **`encoding`** (the stored form; canonical bytes are always rebuilt):
  - `0` full: the canonical envelope; `length == canonical_size`.
  - `1` run delta (runs only): the run's header line, LF, then canonical JSON
    `{"append": {key: [items]}, "drop": [keys], "set": {key: value}}`. Its base
    is the object stored immediately before it in the same block (so it never
    starts a block and a chain cannot loop). Rebuild: parse the base body,
    delete `drop`, extend each non-empty list in `append`, assign `set`, and
    canonicalize. A reader resolves at most 64 deltas for one object.
  - `2` slim event (events only): the event with the fields that hold their
    default left out (`actor ""`, `attributes {}`, `billing {}`,
    `causal_ids []`, `cost 0`, `duration 0`, `parent_ids []`, `usage {}`);
    a reader adds every missing one back and canonicalizes. Storing a default
    is refused.
  - `3` blob delta (blobs only, 0.40+): the blob's header line, LF, then
    `<base oid> SP <prefix> SP <suffix>` LF, then the *middle* bytes. The base
    is another **blob of the same pack**, named by its full `blob:sha256:` id
    (prefix and suffix are decimal without leading zeros). Rebuild: take the
    base's canonical body, keep its first `prefix` and last `suffix` bytes
    (`prefix + suffix` MUST NOT exceed the base body), put the middle between
    them, and prepend the header line. A reader follows bases by id, MUST
    refuse a chain that names an id it already visited (a cycle) or that holds
    more than 64 deltas of any kind (`MAX_DELTA_DEPTH`), and MUST refuse a base
    the pack does not list. Writers choose bases "middle-out" (the longest
    shared prefix plus suffix among the 16 blobs before it in pack order) and
    keep their chains to 32. A pack holding a blob delta is written only in a
    repository whose descriptor carries `"packs": "delta"` with a `min_reader`
    of at least `0.40.0` (`tine gc --blob-deltas`; `tine gc --no-blob-deltas`
    rewrites every pack without them before removing both), so a 0.37-0.39
    reader, which refuses encoding 3, refuses the repository instead. Transfer
    formats (wire packs, bundles, `.tine`) never carry it: they hold canonical
    objects.

Every rebuilt object — a delta's base included — MUST equal its
`canonical_size` and hash to its id, or the read fails. Ids, digests and
signatures are therefore unchanged by the stored form; vectors:
`29-localpack.json`.

<a id="s-2.9"></a>
## 2.9 `fsck`

A deep `fsck` (`repository.verify.fsck`) checks: every loose object re-hashes
to its own oid, decodes canonically, satisfies its link rules with existence
checks, passes annotation-chain and event-metric validation, and — for runs —
graph validation; every ref name is legal (a ref file whose name is not is
reported; dot-files under `refs/`, such as `.DS_Store`, are ignored as OS
litter), its oid parses, its target exists
and satisfies the namespace type rule; every shallow entry is a valid oid;
every file in `packs/` has a legal `<64 hex>.pack` name, verifies, matches its
own filename, and contains objects byte-identical to the loose copies; the
`unadopted` record, when present, parses; a run's `upgraded_from`, when
present, is well formed (§9.9); and the
event graph (`parent_ids` + `causal_ids`) is acyclic, reported per cycle root.
Runs written under object format 3 and 4 coexist: both are v3 envelopes.
`fsck` bounds itself at 1000 packs and 1 GiB of pack bytes.

<a id="s-2.10"></a>
## 2.10 External blob pointers (0.40+)

A blob may be held outside the repository (object storage, a shared disk, an
HTTPS URL) and named by a **pointer** in the side table
`external/<64 hex>.json`, where the hex is the blob oid's digest. The file is
canonical JSON plus LF:

```text
{"oid":"blob:sha256:<hex>","sha256":"<hex of SHA-256(content)>","size":N,"uri":"<uri>","version":1}
```

The blob oid keeps its §1.3 meaning, `object_id("blob", 1, content)`: a pointer
is not an object, has no oid of its own, and never enters a pack, a transfer or
a signature. A link to a blob that is only a pointer satisfies §1.5.6 link
existence for the writer; a reader that predates 0.40 ignores `external/` and
sees such a blob as absent (as after a shallow fetch).

- `uri` MUST be `file:`, `https:` or `http:`, without userinfo, `.`/`..` path
  segments or backslashes; `size` is 0..256 MiB; `sha256` is 64 lowercase hex.
- Content is not redacted (§1.4 does not apply): it is hashed as written.
- **Resolve** (`_external.resolve`) MUST refuse a `uri` that does not start
  with an allowed prefix (`config.json` `"external_blobs": {"allow": [...]}`,
  each ending in `/`; none by default), MUST NOT follow redirects, MUST resolve
  a `file:` path through symlinks and refuse it outside its allowed directory,
  MUST stop reading after `size` bytes, and MUST check, in order, the length,
  `sha256`, and that the content hashes to `oid`, before storing the blob as a
  loose object. The pointer itself is untrusted; the oid is the root of trust.
- **Offline verification** (`_external.status`, `fsck`) MUST NOT open a URI: a
  pointer whose blob is stored locally is `resolved`, else `unresolved`, and a
  malformed one `invalid`. `fsck` does not report an unresolved pointer as an
  error.

---

<a id="part-3"></a>
# Part 3 — The portable `.tine` v2 artifact

> **Deprecated for writing (0.26.0+).** `Run.save` writes format v4 (Part 9) by
> default. A v2 file is written only by the legacy writer — `OPENTINE_FORMAT=2`
> (or `3`), `tine --format 2`, `tine migrate --to 2`, or an autosave **draft**
> checkpoint (v4 has no draft marker) — and the legacy writer prints one
> deprecation warning per process on stderr. Every v1/v2 file stays readable
> and verifiable forever (§5.1); a read never rewrites it.

<a id="s-3.1"></a>
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

<a id="s-3.2"></a>
## 3.2 Top-level fields

`format_version`, `run_id`, `created_at`, `status`, `graph`, `refs`,
`transcript`, `manifest`, `policies`, `cache`, `metadata`, and — only on an
autosave checkpoint — `draft: true`.

`graph` is `{"order": [step id, …], "steps": {step id: step record}}`.
`status` is one of `running`, `paused`, `completed`, `failed`.

<a id="s-3.3"></a>
## 3.3 Step record (`_step_serde.step_to_dict`)

Always emitted: `cost`, `duration`, `error`, `id`, `inputs`, `kind`,
`model_info`, `outputs`, `parent_ids`, `timestamp`, `tool_info`.

Emitted **only when non-empty** (§6.2): `causal_ids`, `provider`, `usage`,
`billing`, and `v3_kind`. `v3_kind` (since 0.8.2) carries a step's v3 event kind
when the v2 `kind` enum cannot spell it — exactly `human`, `policy`, `approval`
or `subagent` — and is never written for any other step, whose `kind` already
says it. Without it a `subagent` roll-up saved to v2 read back as `model`, and a
pricing pass billed it a second time; readers that price steps MUST prefer
`v3_kind` over `kind` when it is present.

On read, `parent_ids` falls back to a single-element list built from a legacy
`parent_id`; `duration` and `cost` fall back to `0` only for an explicit
`null`; `provider` falls back to `""` for any non-string value rather than
failing the load; `v3_kind` is ignored unless it is one of the four values
above.

<a id="s-3.4"></a>
## 3.4 `metadata`

`run_to_dict` always writes `model_info`, `system_prompt` and `user_prompt`
into `metadata`, plus every application-set key. `tags` is emitted only when
non-empty. `integrity` is added by the writer (§3.5). Other reserved keys:
`autosave` (draft checkpoints only; stripped on a final save), `migration`
(append-only migration chain), `fork` (0.4.0 fork-act identity basis),
`fork_reason`, `budget_state`, `warnings`, `replay`, `context`,
`next_harness`, `forked_from`, `fork_point`, and `agent_identity` (0.13.0, an
`opentine-agent/1` record, §4.9).

<a id="s-3.5"></a>
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

<a id="s-3.6"></a>
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

<a id="s-3.7"></a>
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

<a id="s-3.8"></a>
## 3.8 The rebuildable sidecar

`.tine_runs/index.json` is a cache for `tine search` / `tine ls` filters. It is
**never** part of an artifact and **never** authoritative; a corrupt or
version-mismatched index is silently discarded and rebuilt. `index_version` is
1 and an index is dropped when its `covered_format_version` is not the current
`FORMAT_VERSION`.

---

<a id="part-4"></a>
# Part 4 — Signing

Three schemes exist. All three share one algorithm set, one header shape, one
block shape, one verdict vocabulary, and one canonicalizer (§0.3). They differ
**only in the domain prefix and in what the signed view covers** — which is the
whole meaning of a scheme, and why it is versioned.

<a id="s-4.1"></a>
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

A key absent from the signed header is absent from the stored block: a key whose
stored value is `null` is malformed (`error`), not a spelling of "absent" — two
spellings of one header would let one signature verify under two object ids. An
`ed25519` block always carries its own lowercase-hex `public_key`, whatever key
source the verifier uses.

<a id="s-4.2"></a>
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

<a id="s-4.3"></a>
## 4.3 `tine-sig/1` — legacy `.tine` artifact signature (0.3.0–0.7.0)

**Verified, never written.** (Final status since 0.26.0: verified forever.) Signed view:

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

<a id="s-4.4"></a>
## 4.4 `tine-sig/2` — `.tine` v2 artifact signature (0.7.1+, deprecated 0.26.0)

> **Deprecated (0.26.0+).** A signed `Run.save` writes `tine-sig/3` over a v4
> artifact (§9.6). `tine-sig/2` is written only over a v2 document: by the
> legacy writer, or by `signing.sign_artifact` handed a v2 dict (with the
> deprecation warning); under `OPENTINE_FORMAT=4` that call is refused.
> Existing `tine-sig/2` blocks verify forever.

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

<a id="s-4.5"></a>
## 4.5 `tine-attest/1` — v3 attestation signature (0.9.0+, deprecated 0.26.0)

> **Deprecated (0.26.0+).** An Ed25519 attestation on a run is written as
> `tine-attest/2` (§9.7). `tine-attest/1` is still written where `tine-attest/2`
> cannot express the attestation — an `hmac-sha256` key, or a target that is not
> a run — and by the legacy writer; under `OPENTINE_FORMAT=4` an HMAC key is
> refused instead. Existing `tine-attest/1` blocks verify forever.

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

<a id="s-4.6"></a>
## 4.6 Algorithms and keys

| Algorithm | `value` | Key |
|---|---|---|
| `hmac-sha256` | 64 hex chars | raw bytes, **at least 16** (`MIN_HMAC_KEY_BYTES`); a shorter key is refused at sign and at verify |
| `ed25519` | 128 hex chars | 32-byte seed (private) / 32-byte raw public key, or their 64-hex spellings |

A key read from a file has **exactly one** trailing LF stripped, and the file
must be at most 1 MiB.

### 4.6.1 Post-quantum algorithms (0.41.0)

Two further `alg` values exist for **`tine-sig/3`** blocks (Part 9.6). The
scheme, the signed message and the five-key header are unchanged, so the
signature still covers only the canonical view; the block additionally
carries `public_key`, as an Ed25519 block does. All values are lowercase hex.

| Algorithm | `value` | `public_key` |
|---|---|---|
| `ml-dsa-65` | 6618 hex chars: a 3309-byte FIPS 204 ML-DSA-65 signature | 3904 hex chars (1952 bytes) |
| `ed25519+ml-dsa-65` | 6746 hex chars: Ed25519 signature (64 bytes) ‖ ML-DSA-65 signature | 3968 hex chars: Ed25519 key (32 bytes) ‖ ML-DSA-65 key |

* `ml-dsa-65` is ML-DSA.Sign / ML-DSA.Verify (FIPS 204 Algorithms 2 and 3,
  "pure", no pre-hash) over the `tine-sig/3` message with the **empty**
  context string.
* `ed25519+ml-dsa-65` is a composite. Both halves sign the same message: the
  Ed25519 half as RFC 8032 Ed25519, the ML-DSA-65 half with the context
  string `opentine.tine-sig/3:ed25519+ml-dsa-65` (ASCII). The block verifies
  **only when both halves verify** under the two halves of `public_key`; a
  trusted key is the full 1984-byte concatenation. Because `alg` is in the
  signed header, neither half can be stripped out and relabelled as an
  `ed25519` or `ml-dsa-65` block: that block's message differs, and it is
  `mismatch`. The Ed25519 half's key is subject to the small-order refusal.
* Verdicts follow 4.7 exactly (`verified`, `verified-tofu` for the embedded
  key, `no-key`, `mismatch`, `error`). A trusted key of the wrong length for
  the block's algorithm is `mismatch`.
* A verifier MAY be asked to require a post-quantum block
  (`verify_artifact_v4(..., require_pq=True)`); then classical blocks do not
  count and a document with none is `unsigned`.

**Carriage and compatibility.** A post-quantum block is an ordinary entry in
the v4 `signatures` list (and therefore in the repository's detached
`tine-sig-sidecar/1` and in bundle manifests, which carry `tine-sig/3` blocks
as they are). A hybrid writer (`_signing_pq.sign_hybrid`) always writes a
classical `ed25519` block **first** and the composite block after it. The 0.34
verifier, run from the real v0.34.0 sources in
`tests/test_041_post_quantum.py`, refuses the post-quantum block as an unknown
algorithm and accepts the run through the classical block (its "first block
that verifies wins" rule, 9.6); given only a post-quantum block it fails
closed. That test passing is why the blocks are inline rather than in a new
sidecar format.

Signing requires `cryptography` with ML-DSA (the `crypto` extra, built against
OpenSSL 3.5 or later). Verification uses `cryptography` when it has ML-DSA and
otherwise the stdlib implementation `opentine/_pyz/_mldsa.py`, which
`tine-verify.pyz` also ships; it is checked against NIST ACVP ML-DSA-65
sigVer vectors and takes a few milliseconds per signature on CPython.

<a id="s-4.7"></a>
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

<a id="s-4.8"></a>
## 4.8 `tine-actions/1` — signed action manifest (0.13.0+)

A manifest is a JSON object `{"body": ..., "signature": block}` stored beside
the runs (never inside the run, whose content it signs), at
`<runs dir>/manifests/<sha256(run id)>.json` or `.tine/actions/<sha256(run id)>.json`.
The body:

```json
{"scheme": "tine-actions/1", "run_id", "run_digest", "agent_ref", "identity",
 "entries": [{"seq", "step_id", "tool", "verbs", "digest", "chain"}],
 "spawns": [step ids], "head"}
```

* `digest` is the SHA-256 of the v3 canonical JSON (§0.2) of the action's
  redacted record with its meters (`cost`, `ts`) zeroed; which fields a record
  holds is the reference implementation's action extractor, so a verifier
  **recomputes the body from the run** and compares it whole.
* `chain`: the seed is `sha256("tine-actions/1" 0x00 run_id)` and each link is
  `sha256(hex(previous) ":" hex(digest))` over ASCII hex; `head` is the last link
  (the seed when there are no entries). Dropping, reordering or editing an entry
  changes `head`.
* `run_id` and `run_digest` (SHA-256 of the v3 canonical JSON of
  `{"graph": <redacted step graph>, "run_id": ...}`) bind the manifest to one run:
  moved onto another run, even one with identical actions, it no longer matches.
* `identity` is the run's §4.9 record (or `null`); when it names a `key_fpr`, the
  signing key MUST be that key or the verdict is `mismatch`.

The signature is a §4.1 block with `scheme` `tine-actions/1` and `signer` equal to
the body's `agent_ref`. Unlike §4.3–§4.5 the message uses the **v3**
canonicalizer: `message = b"opentine.actions.v1:" + canonical_json({"body": body,
"header": header})`, a domain prefix no other family shares.

The trust state shown for a run is one of four, mapped from §4.7:
`unsigned` (no manifest or no block), `mismatch` (body differs from the
recomputed one, `mismatch`/`error` verdict, or wrong key), `unknown-key` (`no-key`,
or a valid `verified-tofu` by a key not pinned), `verified` (a supplied, pinned
or locally owned key). A verdict is never read from a cache.

**Worked vector** (HMAC-SHA256, key = the 32 ASCII bytes
`0123456789abcdef0123456789abcdef`; body and header as in
`docs/conformance/vectors/48-actions.json` `actions.worked-vector`):

```text
value = 901dcbee199515ad2dc86517342d092de071976398682a99dafe09787940d20c
chain("run-alpha", [11..11, 22..22]) =
  963de1e1d55419da3cac3e160cafb87df23a2f627882f59b5df66d60197a60cf,
  b1204cc7b91bf888baf15a663731b611002f8f8300718d76f4c644e29a1c3de7
```

<a id="s-4.9"></a>
## 4.9 `opentine-agent/1` — agent identity record (0.13.0+)

Stored at run `metadata.agent_identity`. Exactly these eleven string fields:
`scheme` (`"opentine-agent/1"`), `harness` (non-empty), `harness_version`,
`model`, `provider`, `definition_digest` (`""` or `sha256:` + 64 lower hex),
`key_fpr` (`""` or `sha256:` + 64 lower hex, §4.6 Ed25519 fingerprint),
`instance` (`""` or 32 lower hex, a per-run nonce), `parent` (`""` or a full agent
ref), `parent_run`, `spawn_step`. Name fields are at most 128 characters and MUST
already be NFKC-normalised, trimmed and free of control characters; a reader
refuses rather than normalises a record that is not. An unknown key is refused.

The **agent ref** is `"agt_"` + the first 32 hex characters of
`sha256(b"opentine.agent.v1:" + canonical_json({"definition_digest",
"harness", "key_fpr", "model"}))` (v3 canonicalizer). `instance` and the lineage
fields are excluded, so every run of one agent shares a ref. Refs are compared
in full; a prefix is never a ref. `definition_digest` hashes the agent's
definition files (relative POSIX path and SHA-256 of the bytes with CRLF folded
to LF) — the content is never recorded. A run without a valid record has the
ref `legacy:<harness label>`.

A record is a claim. A lineage link (child → parent) is trusted only when both
runs' §4.8 manifests verify, the parent run's ref equals the child's `parent`,
and the parent's signed `spawns` list contains the child's `spawn_step`.

**Worked vector:** the record in `49-agent.json` `agent.worked-vector` has the ref
`agt_7151540cb1895e1d66ae5b90f9a5012d`.

<a id="s-4.10"></a>
## 4.10 `opentine-delegation/1` — delegation certificates (0.43.0+)

A principal key hands scoped authority to an agent key, so a fleet member's
identity rests on a signature rather than on its own claim (X32). A certificate
is a JSON object with exactly these keys:

| Key | Value |
|---|---|
| `scheme` | `"opentine-delegation/1"` |
| `issuer` / `subject` | `sha256:` + 64 lower hex, §4.6 Ed25519 fingerprints |
| `scope` | `{agents, actions, max_depth}`: two sorted, duplicate-free, non-empty lists of names (`[A-Za-z0-9_.:*/-]{1,128}`, `"*"` is any) and an integer `0..7`, the further delegations the subject may issue |
| `not_before` / `not_after` | RFC 3339 with a zone; `not_after` later |
| `parent` | `""` (root) or the digest of the certificate above it |
| `signature` | a `tine-sig/3` block (§9.6 header, Ed25519, embedded `public_key`) over `b"opentine.delegation.v1:"` + JCS(`{"body": <the certificate without signature>, "header": <header>}`) |

A certificate's **digest** is `sha256:` + hex SHA-256 of
`b"opentine.delegation.v1:"` + JCS of the whole certificate, signature included.
A **chain** is a list of 1–8 certificates, root first. A verifier, given the
fingerprint of the key that signed the work, the signing time, and optionally the
agent names and tools used, MUST refuse, with the first applicable code:
`delegation.malformed`; `delegation.bad-signature` (the signature fails, or the
embedded key is not `issuer`); `delegation.broken-chain` (a root with a
`parent`, a root other than a trusted one, or a link whose `issuer` is not the
previous `subject` or whose `parent` is not the previous digest);
`delegation.too-deep` (a parent with `max_depth` 0, or a child `max_depth` not
below its parent's); `delegation.scope-violation` (a child list or window wider
than its parent's, or an agent or tool outside the leaf scope);
`delegation.expired` (the time outside a window, `not_after` exclusive);
`delegation.wrong-signer` (the leaf `subject` is not the signer). Everything
needed is in the certificates: verification is offline. The root is trusted
only by pinning its fingerprint.

A run captured with `OPENTINE_DELEGATION=<chain file>` stores the chain at
`metadata.delegation`; `tine verify --offline` adds a required `delegation`
check against the run's signer, its agent ref, harness, fleet member or role,
and its tool names; it passes with `delegation.verified`, or fails with
`delegation.unsigned` (the run's signature did not verify) or one of the codes
above. Vectors: `56-delegation.json`.

<a id="s-4.11"></a>
## 4.11 `opentine-fleet/1` — fleet member record (0.43.0+)

Stored at run `metadata.fleet` from `OPENTINE_FLEET_ID`, `_MEMBER`, `_ROLE` and
`_PARENT` (the variables `tine fleet up` sets): exactly `scheme`
(`"opentine-fleet/1"`), `fleet_id` (`[A-Za-z0-9_.-]{1,128}`), `member`, `role`,
`parent`, each a §4.9-normalised string. It is a claim. Signed, it is an
`opentine-fleet-record/1` document `{scheme, record, run_id, run_digest,
signature}` whose `tine-sig/3` block is over `b"opentine.fleet.v1:"` +
JCS(`{"body": {scheme, record, run_id, run_digest}, "header"}`), so it cannot
be moved to another run. The in-toto predicate
`https://opentine.dev/attestation/fleet/v1` has subject the run's digest and
predicate `{producer, fleet, agent_ref, delegation}` (`delegation` is the
chain's certificate digests, root first).

<a id="s-4.12"></a>
## 4.12 `tine-eval-verdict/1` — signed eval verdicts (0.45.0+)

`tine eval run` scores every item of a dataset and signs one verdict per item.
A verdict is a JSON object with exactly these keys:

| Key | Value |
|---|---|
| `scheme` | `"tine-eval-verdict/1"` |
| `eval` | `sha256:` + 64 lower hex: SHA-256 of `b"opentine.eval.v1:"` + JCS(`{dataset, scorer, scorer_version, threshold, created_at, signer}`) |
| `dataset` | `sha256:` + hex SHA-256 of `b"opentine.dataset.v1:"` + JCS of the list of item digests, in file order |
| `item` / `item_digest` | the item's id (`[A-Za-z0-9_.:/@+-]{1,256}`) and `sha256:` + hex SHA-256 of JCS(the item) |
| `run` | the run whose output was scored (same name grammar) |
| `scorer` / `scorer_version` | `[a-z0-9][a-z0-9-]{0,63}` (`exact`, `regex`, `json-schema`, `python`, `llm-judge`, ...) and `[A-Za-z0-9_.:+/-]{1,160}`; the version pins the configuration (`1+sha256:<16 hex>` of the pattern, schema, callable source or judge prompt and model) |
| `score` / `threshold` | decimal strings in 0..1, at most six places, no trailing zero: `0`, `1` or `0.` + digits ending in 1–9 |
| `passed` | boolean, equal to `score >= threshold` |
| `judge_run` | `""`, or for an `llm-judge` verdict the run that recorded the judge's prompt and reply |
| `signer` | `sha256:` + 64 lower hex, the §4.6 Ed25519 fingerprint of the signing key |
| `created_at` | `YYYY-MM-DDTHH:MM:SSZ` |
| `signature` | a `tine-sig/3` block (§9.6 header, Ed25519, embedded `public_key`) over `b"opentine.eval-verdict.v1:"` + JCS(`{"body": <the verdict without signature>, "header": <header>}`) |

A verifier MUST refuse, with the first applicable code:
`eval-verdict.malformed` (a missing, extra or ill-formed key);
`eval-verdict.bad-signature` (the embedded key is not `signer`, or the
signature fails); `eval-verdict.wrong-key` (a trusted key was supplied and the
embedded key is not it); `eval-verdict.inconsistent` (`passed` is not
`score >= threshold`); `eval-verdict.judge-mismatch` (an `llm-judge` verdict
without a `judge_run`, or another scorer with one). Without a trusted key a
passing verdict rests on its embedded key (trust on first use). An eval folder
holds `verdicts.jsonl` (one verdict per line) and an unsigned `eval.json`
summary that a verifier re-derives from the verdicts. Across a
`verdicts.jsonl` a verifier MUST also refuse a verdict whose `eval` is not
recomputed from its own pinned fields (`eval.id-mismatch`; this binds every
verdict of one eval to one signer, so a verdict signed by another key cannot be
spliced in even under trust on first use), a repeated `item`
(`eval.duplicate-item`), and a file naming more than one `eval`
(`eval.mixed-evals`). Vectors:
`58-eval-verdict.json`.

<a id="s-4.13"></a>
## 4.13 `opentine.redaction-report` — signed redaction reports (0.45.1+)

`tine redact check` re-scans every object reachable from a run with the current
redaction ruleset and writes one report per run. A report is a JSON object with
exactly these keys, plus an optional `signature`:

| Key | Value |
|---|---|
| `kind` | `"opentine.redaction-report"` |
| `report_version` | `1` |
| `ruleset` | the ruleset name (`opentine-redaction/2`); `tine redact rules --json` describes it (`tine-redaction-rules/1`) |
| `run` | the run oid (`[A-Za-z0-9_.:/@+-]{1,256}`) |
| `objects` | the number of objects re-scanned, a non-negative integer |
| `findings` | a list of `{oid, kind}`, one per object the ruleset would still change, at most `objects` long; never the matched bytes |
| `clean` | boolean, equal to "`findings` is empty" |
| `signature` | a `tine-sig/3` block (§9.6 header; HMAC-SHA256, or Ed25519 with embedded `public_key`) over `b"opentine.redaction-report.v1:"` + JCS(`{"body": <the report without signature>, "header": <header>}`) |

A verifier MUST refuse, with the first applicable code:
`redaction-report.malformed` (a missing, extra or ill-formed key);
`redaction-report.unsigned` (no `signature`); `redaction-report.no-key` (an
HMAC report checked without a key); `redaction-report.wrong-key` (a trusted
Ed25519 key was supplied and the embedded key is not it, or an HMAC key was
supplied and the report is not HMAC: a supplied key never falls back to the
embedded key);
`redaction-report.bad-signature` (the block does not verify);
`redaction-report.inconsistent` (`clean` is not "no findings"). Without a
trusted key an Ed25519 report rests on its embedded key (trust on first use,
state `verified-tofu`). Vectors: `60-redaction-report.json`.

<a id="s-4.14"></a>
## 4.14 `opentine.tombstone` — signed purge records (0.46.0+)

`tine purge OID --reason TEXT` removes one blob's bytes from a repository and
keeps its oid: every event and run that links the blob still hashes the same.
The purge leaves a tombstone, a JSON object with exactly these keys plus a
`signature`:

| Key | Value |
|---|---|
| `kind` | `"opentine.tombstone"` |
| `tombstone_version` | `1` |
| `oid` | the purged blob's oid (`blob:sha256:<64 hex>`; only a blob can be purged) |
| `reason` | why, as text: 1 to 1024 UTF-8 bytes, not only whitespace, no C0 control character or DEL; redacted before it is signed |
| `actor` | who purged it (`[A-Za-z0-9_.:/@+-]{1,256}`) |
| `purged_at` | when, `YYYY-MM-DDTHH:MM:SSZ` |
| `signature` | a `tine-sig/3` block (§9.6 header; HMAC-SHA256, or Ed25519 with embedded `public_key`) over `b"opentine.tombstone.v1:"` + JCS(`{"body": <the tombstone without signature>, "header": <header>}`) |

A tombstone is signed where the operator's key is; a remote stores and serves
the record exactly as signed and never signs one. A verifier MUST refuse, with
the first applicable code: `tombstone.malformed` (a missing, extra or
ill-formed key); `tombstone.unsigned` (no `signature`); `tombstone.no-key` (an
HMAC tombstone checked without a key); `tombstone.wrong-key` (a supplied key
is not the one that signed, with no fallback to the embedded key);
`tombstone.bad-signature` (the block does not verify). Without a trusted key an
Ed25519 tombstone rests on its embedded key (state `verified-tofu`).

**Verifying a run with a purged blob.** A verifier walking a run's closure
(its links, §1.5) through the objects it holds reports a linked object that is
absent and named by a tombstone as **content-unavailable**, not as a failure:
the run's oid still binds the blob's oid, only the bytes are gone. The walk
needs the tombstones' shape (a malformed one is `tombstone.malformed`), not
their signatures, which are checked as above. Its result is `{run, objects,
content_unavailable, state}`, `state` being `content-unavailable` when any
object is, else `verified`. An absent object no tombstone names is
`tombstone.missing-content`; only a blob can be content-unavailable. Vectors:
`63-tombstone.json` (ops `tombstone.verify` and `tombstone.closure`).

**Where tombstones live.** A repository keeps one canonical-JSON tombstone per
purged blob at `tombstones/<blob hex>.json` and lists the oid in `shallow`
(§2), so links to it still resolve; `fsck` reports the oid under
`content_unavailable`, never as an error. A pack that would have carried the
blob carries it as a shallow boundary instead. The tombstones of a pack's
boundaries travel beside it: a bundle manifest's optional `tombstones` list
(each record naming a distinct shallow boundary of the bundled pack), and, on a
remote whose capabilities list `tombstones: true`, `PUT
/v1/tenants/<t>/tombstones/<oid>` before the pack is uploaded and `GET` of the
same path after a fetch (`404` when the tenant holds none, whatever the reason).
A received tombstone is stored only for a blob the receiver does not hold: it
never deletes bytes the receiver has. A remote purge (a `PUT` for a blob the
tenant holds) is refused for any object a hold reaches, and a remote never
stores a tombstoned blob again: a pushed pack that carries one is installed
without it.

<a id="s-4.15"></a>
## 4.15 `opentine.redacted-copy` — redacted public copies (0.46.0+)

`tine bundle create FILE REF --redacted-public` derives a public copy of the
run REF names: every blob it reaches (graph only; annotations and attestations
stay private) is redacted with the current ruleset until stable, every JSON
payload is redacted again, and each oid an event or run names is rewritten to
the oid of the object derived from it. A blob the repository does not hold
keeps its oid and stays a boundary. The bundle holds only the derived objects,
the one ref REF naming the derived run, the tombstones of its boundaries, and
under the manifest key `redacted_public` a record with exactly these keys plus
a `signature`:

| Key | Value |
|---|---|
| `kind` | `"opentine.redacted-copy"` |
| `copy_version` | `1` |
| `source_run` | the private run's oid |
| `public_run` | the derived run's oid (a ref target of the bundle) |
| `ruleset` | the redaction ruleset name |
| `objects` | the number of objects in the pack |
| `redacted` | how many of them differ from the object they derive from |
| `pack` | `sha256:<64 hex>` of the bundled pack bytes |
| `signature` | a `tine-sig/3` block over `b"opentine.redacted-copy.v1:"` + JCS(`{"body", "header"}`), as in §4.14 |

Content addressing makes the two run oids equal exactly when nothing changed.
A verifier MUST refuse, with the first applicable code:
`redacted-copy.malformed`; `redacted-copy.unsigned`; `redacted-copy.no-key`;
`redacted-copy.wrong-key`; `redacted-copy.bad-signature` (each as in §4.14);
`redacted-copy.inconsistent` (`redacted` exceeds `objects`, or `redacted == 0`
and `source_run == public_run` disagree); `redacted-copy.pack-mismatch` (the
record names a pack other than the one it came with). Vectors:
`64-redacted-copy.json`.

---

<a id="part-5"></a>
# Part 5 — The compatibility contract

<a id="s-5.1"></a>
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

<a id="s-5.2"></a>
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
| `v3_kind` | v2 step record | the step's v3 kind has no v2 `kind` member (since 0.8.2) |
| `draft` | v2 top level | autosave checkpoints only |

The `signature` row is the interesting one: the slot already existed and was
already written as `null`, so filling it was additive *without* the
emit-when-non-empty rule. A field with no such pre-existing slot does not have
that option.

<a id="s-5.3"></a>
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

<a id="s-5.4"></a>
## 5.4 The v2 → v3 migration boundary

> **Since 0.26.0** a migration writes into an object-format-4 repository
> (§2.2, §9.10) unless the legacy writer is chosen, so it refuses an integer
> beyond 2**53-1 or a non-finite number instead of stringifying it. The
> portable upgrade path is `tine migrate --to v4` (§9.9, now the default
> `--to`); `tine migrate --to 2` is the deprecated legacy target. A
> v2 → v3 migration keeps every guarantee below.

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

<a id="part-6"></a>
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

<a id="part-7"></a>
# Part 7 — Proving conformance

Everything above is prose. Prose does not let anyone *prove* an implementation
correct, so this specification ships a machine-readable vector suite alongside
it: **[`docs/conformance/`](conformance/README.md)**, 683 vectors covering the
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
| `conformance/minimal_verifier.py` | an independent offline verifier (Part 8): standard library only, imports no opentine |

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

---

<a id="part-8"></a>
# Part 8 — Verifying without opentine

`tine verify RUN --offline` (0.25.0) runs every check it can from material on
disk alone, under a guard that refuses any network call, and writes one
report. This part specifies that report, the dataset and evidence forms around
it, and the hashing a verifier needs to reproduce them **without opentine**.
[`conformance/minimal_verifier.py`](conformance/minimal_verifier.py) is a
standard-library implementation of this part (about 300 lines, imports no
opentine) and `tests/test_minimal_verifier_0_25.py` holds its verdicts to the
reference's.

<a id="s-8.1"></a>
## 8.1 The `tine-verify-report/2` document (`/1` before 0.39)

One JSON object (`_verify_report.JSON_SCHEMA`, JSON Schema 2020-12):

| Key | Type | Notes |
|---|---|---|
| `schema` | string | `"tine-verify-report/2"` (0.39; `/1` documents differ only in lacking the 0.39 keys below) |
| `command` / `offline` | const | `"verify"` / `true` |
| `path`, `strict` | string, boolean | the target and whether `--strict` was given |
| `verdict` / `ok` | `"pass"`\|`"fail"` / boolean | see below |
| `authorship` | string or null | the trust basis that shows **who** signed; `null` when only internal consistency was shown |
| `checks` | array | ordered; each `{name, outcome, reason, detail, trust_basis, required}` |
| `unavailable_required` | array of string | required checks that could not run offline |
| `location` | object | `--locate` only: `{region, reason, detail, field_path, …}` |
| `timestamps` | array of object | 0.31.0, present only when a check ran on a stored token (§8.6): `{bound, binding, outcome, reason, gen_time, tsa, policy, hash_algorithm, serial}`; `binding` (0.39) is `root` or `signature` |
| `signing_time` | string | 0.39 (X20): the earliest `gen_time` of a passing token bound to one of the run's signatures; absent otherwise |
| `signature` | object | 0.39 (X22), `--sign-key` only: the report's `tine-sig/3` block (§8.7) |
| `signature_timestamps` | array of object | 0.39, unsigned: `{bound, token}` RFC 3161 tokens over `signature` (§8.7) |
| `crypto` | object | 0.41 (X30), under `--fips` only: `{mode, provider_fips, openssl}` — `"fips"`, whether `cryptography`'s OpenSSL has the FIPS provider active, and its version text |

`outcome` is one of `pass`, `fail`, `unavailable-offline`, `not-applicable`.
Check names, in order: `digest`, `signature`, `provenance` (§9.9, never
required), `attestation`, `rekor-receipt`,
`certificate`, `sct`, `timestamp` (§8.6, one per token, never required),
`action-manifest`, `action-policy`, `claims` (and
`network` if the guard refused a connection). The verdict is `fail` when any
check failed and, under `--strict`, also when a required check is
`unavailable-offline`; otherwise `pass`. **A missing key or root is
`unavailable-offline`, never a pass**, and a pass is only as strong as its
`trust_basis` (`internal consistency only`, `supplied key …`, `pinned key …`,
`trusted_root.json sha256 …`).

<a id="s-8.2"></a>
## 8.2 Reason codes

Reason codes are dotted `area.detail` strings matching
`^[a-z0-9-]+(\.[a-z0-9-]+)+$`. Where a rule already has a code in
[`conformance/REASON_CODES.md`](conformance/REASON_CODES.md) it is reused.

| Area | Codes |
|---|---|
| digest (§3.5) | `digest.match`, `digest.mismatch`, `digest.missing`, `digest.malformed`, `digest.unsupported-algorithm`, `digest.unsupported-format`, `digest.unreadable`, `artifact.malformed-json` |
| signature (Part 4) | `signature.<state>` for every state of §4.7 (`signature.verified`, `signature.verified-tofu`, `signature.unsigned`, `signature.no-key`, `signature.mismatch`, `signature.error`), plus `signature.integrity-failed` (not checked: the digest failed) |
| attestation | `attestation.<status>` of the in-toto verdict (`attestation.verified`, `attestation.verified-tofu`, …), `attestation.none`, `attestation.no-key`, `attestation.unreadable`, `attestation.subject-mismatch`; `receipt.<status>`, `receipt.absent`, `receipt.unchecked`; `certificate.<status>` (`certificate.verified`, …), `certificate.not-keyless`; `sct.verified`, `sct.no-key`, `sct.not-reached` |
| actions (§4.8) | `actions.<state>` (`verified`, `mismatch`, `unknown-key`), `actions.absent`, `actions.no-run`; `policy.ok`, `policy.warn`, `policy.deny`, `policy.none`, `policy.no-run`, `policy.unreadable` |
| claims | `claims.match`, `claims.absent`, `claims.no-run`, `claims.no-tool-step`, `claims.output-mismatch`, `claims.digest-mismatch`, `claims.unclaimed-step`, `claims.unreadable`, `claims.unrecomputable` |
| locate | `locate.digest-field`, `locate.digest-malformed`, `locate.graph-meters-changed`, `locate.step-id-mismatch`, `locate.step-key-mismatch`, `locate.manifest-entry`, `locate.action-digest-mismatch`, `locate.signature`, `locate.nothing-to-locate`, `locate.unlocalisable`, `locate.unreadable` |
| provenance (§9.9) | `provenance.none` (no `upgraded_from`, or not v4), `provenance.recorded` (the record is shown as a claim, `unavailable-offline`), `provenance.source-match`, `provenance.source-mismatch` (with `--source PATH`) |
| timestamp (§8.6) | `timestamp.verified`, `timestamp.absent`, `timestamp.integrity-failed`, `timestamp.malformed`, `timestamp.bound-mismatch`, `timestamp.imprint-mismatch`, `timestamp.bad-signature`, `timestamp.unsupported-algorithm`, `timestamp.missing-eku`, `timestamp.outside-validity`, `timestamp.no-roots` (`unavailable-offline`), `timestamp.untrusted-root`, `timestamp.roots-unreadable` |
| delegation (§4.10) | `delegation.verified`, `delegation.unsigned`, and the chain codes of §4.10 |
| offline | `offline.network-refused` — a check tried to open a connection and was refused; the run fails |

The minimal verifier adds codes for what only it reports:
`signature.crypto-unavailable` (Ed25519 needs the `cryptography` package and it
is not importable — `unavailable-offline`, never a pass),
`evidence.manifest-match`, `evidence.manifest-mismatch`,
`evidence.manifest-unreadable`, `evidence.custody-linked`,
`evidence.custody-manifest-mismatch`, `evidence.custody-unreadable`, and
`dataset.run` (one per run of a dataset or evidence folder).

<a id="s-8.3"></a>
## 8.3 Datasets and the Merkle root

`tine verify --offline DIR` reports `tine-verify-dataset/1`:
`{schema, command, offline, path, kind, strict, verdict, ok, count, merkle:
{algorithm, root}, checks, runs}`. For a **directory**, every `*.tine` below it
(sorted, symlinks skipped) gets a full §8.1 report, and its entry is
`{run_id, path, digest, ok, failed, report}`; `digest` is the recomputed §3.5
digest when the digest check passed and `""` otherwise. For a **repository**,
`checks` holds one `repository` fsck check and each run a ref names contributes
`{run_id: "run:…", digest: <tine-actions/1 run_digest>, ok, reason}`.

The root is computed over the entries sorted by `(run_id, digest)`
(`_verify_dataset.merkle_root`):

```text
leaf  = SHA-256( 0x00 || v3_canonical_json([run_id, digest]) )      §0.2
node  = SHA-256( 0x01 || left || right )
```

Each level pairs nodes left to right; an odd last node is carried up unchanged;
the root of zero leaves is SHA-256 of the empty string. The `0x00`/`0x01`
prefixes keep a leaf from ever equalling a node.

<a id="s-8.4"></a>
## 8.4 The evidence folder and `tine-custody/1`

`tine evidence export RUN… --out DIR` writes `runs/` (the run files byte for
byte), `verify-report.json` (`tine-evidence-verify/1`: `{schema, ok, runs}`,
one §8.1 report per run), `timeline.jsonl`/`timeline.csv`, `trust/` (the
`--pubkey`, `--action-policy`, `--attestation` and `--trusted-root` files the
reports used, and `custody-signer.pub`), `MANIFEST.sha256` and
`custody.jsonl`.

`MANIFEST.sha256` is `sha256sum` text — `<64 hex>  <relative path>\n` — for
every file except itself and `custody.jsonl`, sorted by path. A verifier
checks every listed file **and** that no unlisted file exists.

`custody.jsonl` is one `tine-custody/1` record, the only non-deterministic
file (it carries the export time), which is why it sits outside the manifest
and names the manifest instead:

```json
{"schema": "tine-custody/1", "exported_by": "...", "exported_at": "<ISO 8601>",
 "opentine_version": "...", "manifest_sha256": "<sha256 of MANIFEST.sha256>",
 "runs": [{"run_id": "...", "file": "runs/...", "sha256": "..."}],
 "signature": {"algorithm": "ed25519", "public_key": "<64 hex>",
               "key_fingerprint": "...", "value": "<128 hex>"}}
```

`signature` is optional (`--sign`). Its message is
`opentine.custody.v1:` ‖ v3_canonical_json(record without `signature`) (§0.2 —
unlike the artifact signatures of Part 4, which use §0.3). It verifies under
the record's own key, so on its own it shows consistency; compare
`public_key` with `trust/custody-signer.pub` obtained out of band.

<a id="s-8.5"></a>
## 8.5 Writing an independent verifier

1. Read the file; strip a `TINEZ1\0` wrapper (§2.3: codec 0 raw, 1 zlib, 2
   zstd, uvarint length). Parse JSON refusing duplicate keys and
   `NaN`/`Infinity`.
2. Accept `format_version` 1 or 2; recompute §3.5 with §0.3 (both versions use
   the same digest rule). Map refusals to the `digest.*` codes of §8.2.
3. With a trusted Ed25519 key, rebuild the five-key header (§4.1) and the view
   for the block's scheme (§4.3/§4.4) and verify `opentine.signature.v1:` ‖
   §0.3 bytes. Without a key the check is `unavailable-offline`
   (`signature.no-key`, or `signature.unsigned` when there is no block).
4. For a v4 file (§9.3): recompute every envelope id with §1.3 over the §0.2
   body (doubles in ECMAScript form, §9.2; a wide integer literal read as a
   double) or the base64-decoded blob, require the root to name a carried
   run, and verify `tine-sig/3` (§9.6) with a trusted Ed25519 key. Map a
   failure to `digest.mismatch`; report `digest.match` as `root <oid>`.
5. Report `provenance` from the root run's `upgraded_from` (§9.9): with a
   source file, sha256 of its bytes after the §2.3 unwrap must equal
   `digest`.
6. For a folder, compute §8.3; for an evidence export, check §8.4.

`docs/conformance/minimal_verifier.py` does steps 1–6 in the standard library
alone. It leaves the link-closure rule of §9.4 to a full reader.

---

<a id="s-8.6"></a>
## 8.6 RFC 3161 timestamp tokens (0.31.0)

A run file may carry RFC 3161 tokens in a sidecar beside it,
`<run file>.timestamps.json`:
`{"entries": [{"bound": <string>, "token": <base64 DER>}, ...], "kind": "tine-timestamp-sidecar/1"}`
(canonical JSON, at most 16 entries). `bound` is the run's digest as
`tine verify` recomputes it: `sha256:<hex>` for a v2/v3 file, the root oid
`run:sha256:<hex>` for v4. A token's `messageImprint` is the hash
(SHA-256, -384 or -512) of the UTF-8 bytes of `bound`.
`tine timestamp data RUN` prints those bytes (no newline) for
`openssl ts -query -data`; obtaining the response from a TSA is the user's job
and opentine never contacts one. `tine timestamp attach RUN TOKEN.tsr` accepts a
DER `TimeStampResp` (status granted) or a bare `TimeStampToken`, checks that it
parses and that its imprint covers the current digest, and stores it.

`tine verify RUN --offline [--tsa-roots FILE.pem]` adds one `timestamp` check
per stored token, run under the network guard, against the trust anchors in
`--tsa-roots` plus the `timestampAuthorities` of `--trusted-root` when an
attestation is checked. In order, the first failure is the verdict: the DER
parses (`timestamp.malformed`); `bound` equals the recomputed digest
(`timestamp.bound-mismatch`); the imprint matches (`timestamp.imprint-mismatch`);
the signed attributes name `id-ct-TSTInfo` and carry its digest, and the TSA's
RSA PKCS#1 v1.5, ECDSA or Ed25519 signature over them verifies
(`timestamp.bad-signature`); the signer certificate (found by issuer and
serial, or subject key identifier, among the token's certificates) has the
`id-kp-timeStamping` EKU (`timestamp.missing-eku`) and is valid at `genTime`
(`timestamp.outside-validity`); and its chain, each link a CA valid at
`genTime`, reaches a supplied root (`timestamp.untrusted-root`; no root at all
is `timestamp.no-roots`, `unavailable-offline`). A timestamp check is never
required and never establishes authorship: it shows *when* the digest
existed, not *who* recorded it. With no token and no `--tsa-roots` the report
is unchanged from 0.30. Not checked: revocation (no CRL or OCSP offline),
the `nonce`, `accuracy`, the TSA `tsa` name field, and RSASSA-PSS signatures
(reported `timestamp.unsupported-algorithm`).

**Signature binding (0.39, X20).** `bound` may instead be
`sig:sha256:<hex>`: the SHA-256 of the canonical JSON (§0.2) of one signature
block the run stores (a v4 `signatures[i]`, or a v2/v3 `metadata.integrity.signature`).
`tine timestamp data RUN --signature [N]` prints it for block N (default 0).
Such a token must name a block the run still carries
(`timestamp.signature-mismatch` otherwise) and is then checked exactly as
above against those bytes. Its timestamps entry has `binding: "signature"`,
and the earliest passing one is the report's `signing_time`: the **verified
signing time**, an upper bound on when that signature was made. Key validity
against that time is not checked before 0.41. Root-bound tokens keep their
0.31 meaning (`binding: "root"`).

<a id="s-8.7"></a>
## 8.7 Signed verify reports (0.39, X22)

`tine verify RUN --offline --report PATH --sign-key KEY` writes the report as
canonical JSON (§0.2) plus a newline, with a `signature` member: an Ed25519
`tine-sig/3` block (§9 header and value rules) whose message is
`opentine.verify-report.v2:` + JCS of `{"body": <the report without
signature and signature_timestamps>, "header": <alg, key_id, scheme,
signed_at, signer>}`. The domain prefix keeps a report signature from ever
verifying as a run or custody signature. `--timestamp` also writes
`PATH.tsdata`, the `sig:sha256:<hex>` of that block; a TSA token over it is
stored with `tine verify-report attach PATH TOKEN.tsr` in
`signature_timestamps` (outside the signed bytes, at most 16).
`tine verify-report data PATH` prints the same bytes.

`tine verify-report check PATH [--pubkey P] [--tsa-roots PEM]
[--trusted-root FILE]` verifies offline: the signature (against `--pubkey`;
without it the embedded key, reported as trust on first use) and each token
(§8.6 rules, `bound` must equal the block's binding). Exit 0 means the report
is authentic -- whatever verdict it records -- and 4 means a signature or
token failed. A `/1` or unsigned `/2` report is read and summarised
(`evidence: false`, `reason: report.unsigned`) and exits 4 unless
`--allow-unsigned`.

<a id="s-8.8"></a>
## 8.8 The in-toto `replay/v1` predicate (0.39)

Predicate type URI: **`https://opentine.dev/attestation/replay/v1`**.
`tine replay RUN --verify --attest OUT --attest-key KEY` writes one DSSE v1
envelope (payload type `application/vnd.in-toto+json`, Ed25519, `keyid` the
key's `did:key`) around an in-toto Statement v1 whose single subject is the
source run (`name` its id, `digest.sha256` its content digest's hex) and whose
predicate is:

| Key | Type | Notes |
|---|---|---|
| `verifier` | object | `{id: "https://opentine.dev/tine", version}` |
| `mode` | `"cache"`\|`"rerun"` | the replay mode |
| `replay` | object | `{replay_id, second_id, fork_point, expected_steps, reused_steps}` |
| `result` | object | `{reproduced, identity_ok, integrity_ok, ignore_cost_drift}` booleans, `slice_ok` boolean or null, `structural_drift` / `accounting_drift` field-name lists |
| `fidelity` | object | the `--json` verdict's `fidelity` object |
| `verified_at` | string | UTC `YYYY-MM-DDTHH:MM:SSZ` |

A drifting replay is attested too (`reproduced: false`); the command still
exits 1. No prompt, completion or tool text appears in the predicate.
`opentine._intoto_replay.validate_predicate` is the shape check.

<a id="s-8.9"></a>
## 8.9 Custody records on `opentine-log/1` (0.39)

`tine custody record ACTION SUBJECT --sign-key KEY [--actor A] [--note N]`
appends one `opentine-custody/1` record to the repository log
`.tine/log/custody` (origin `opentine.local/log/custody`), the same tlog-tiles
layout and signed-note checkpoint as the op log (§2). A record is canonical
JSON `{action, actor, format, id, note, prev, signature, subject, time[, token]}`:
`action` is one of `received`, `exported`, `verified`, `transferred`,
`stored`, `timestamp`; `prev` is the previous entry's leaf hash
(`SHA-256(0x00 || entry)`) or null; `signature` is an Ed25519 `tine-sig/3`
block by the actor's key over `opentine.custody.v1:` + JCS of `{"body": <the
record without signature>, "header": ...}`. A `timestamp` record's `subject`
is the `sig:sha256:` binding of an earlier record's signature and `token` an
RFC 3161 token (base64 DER) over it; that token's genTime is the earlier
record's verified signing time. `tine custody verify [--pubkey P] [--vkey V]
[--tsa-roots PEM]` checks, offline, the checkpoint signature and Merkle root,
the tiles, the hash chain, every record signature and every token, and exits 4
on the first failure. `tine custody log` lists records with their `sig_bound`.

<a id="s-8.10"></a>
## 8.10 Transparency: proofs, receipts and the remote audit log (0.44, X33)

**Proofs.** Every `opentine-log/1` log (§8.9, §2) is an RFC 6962 tree; 0.44
adds RFC 9162 §2.1.3 inclusion and §2.1.4 consistency proofs, computed from the
C2SP tlog-tiles hash tiles (`opentine.repository._tlog_proof`) and verified
with nothing but SHA-256. A consistency check refuses a smaller tree
(*rollback*) and a different root at the same size or a failing proof (*fork*).

**Receipt.** An `opentine-tlog-receipt/1` is JSON `{checkpoint, entry, format,
index, inclusion, vkey}`: the signed-note checkpoint text (with any
cosignatures), the base64 entry, its index, the base64 inclusion path and the
log's verifier key. It verifies alone: the checkpoint under the pinned key (or
`vkey`, reported as trust on first use), then the inclusion of
`SHA-256(0x00 || entry)` at `index` in that checkpoint's tree.

**Remote audit log.** The server appends every committed audit row to a tlog
beside its database (`<db>.tlog`, origin `opentine.remote/log/audit/<16 hex>`,
random per server). An entry is canonical JSON `{action, event_id, format:
"opentine-audit/1", outcome, row_hash, tenant, timestamp[, name, new]}`;
`row_hash` is the row's keyed chain hash, so actor and details are bound without
being published. `GET /v1/tenants/<t>/transparency/checkpoint`,
`consistency?old=M[&new=N]` and `receipt?name=REF&new=OID` (permission
`read_ref`; a receipt only for the caller's tenant) return JSON with
`checkpoint`, `size`, `vkey` and `proof` or a receipt. The client pins the
log key on first contact in `.tine/log/remotes/<id>/` and stores the newest
checkpoint; each fetch checks consistency *before importing* and each push
fetches, verifies and stores the receipt of its `update_ref` row. A server
with no log is `unavailable`; one that had a log and stops serving it is
refused.

**Bundles.** `opentine-bundle/1` manifests may carry `transparency`: a list of
receipts, the newest op-log entry recording each bundled `ref -> oid`
(`opentine-op/1` rows carry each reflog row's digest) and any stored push
receipt for it. Each must verify and cover a bundled ref. The key is optional
and written only on request, because readers before 0.44 refuse unknown keys.

<a id="s-8.11"></a>
## 8.11 Witness cosignatures (0.44)

A witness cosignature is C2SP tlog-cosignature `cosignature/v1` over Ed25519:
the signed message is `cosignature/v1\ntime <T>\n` followed by the checkpoint
body, `T` POSIX seconds in decimal; the signature line is `— <name>
base64(key id || uint64be(T) || signature)` with key id
`SHA-256(name || 0x0A || 0x04 || public key)[:4]`, and the witness verifier key
is `name+hex(key id)+base64(0x04 || public key)`. `verify --witnesses N-of-M`
requires exactly M distinct pinned keys and N verifying cosignatures on every
checkpoint. A witness cosigns only a checkpoint consistent with the last one it
cosigned for that origin, so a split view cannot reach a quorum of honest
witnesses. Vectors for 8.10 and 8.11: `57-tlog.json`.

<a id="s-8.12"></a>
## 8.12 Rekor v2, SigningConfig and SCITT (0.44, X34)

**Rekor v2.** A `TransparencyLogEntry` with `kindVersion.version` `0.0.2` is a
tile-log receipt: no signed entry timestamp; `inclusionProof` to the signed-note
checkpoint in `checkpoint.envelope`. Its `logId.keyId` is the checkpoint key's
signed-note id `SHA-256(origin || 0x0A || 0x01 || Ed25519 key)` (type `0x02`
over the SPKI DER for ECDSA, best effort), where origin is the trusted root
`baseUrl` host; the body is a `dsse` v0.0.2 entry whose payload hash and
signatures must match the envelope. Proof, checkpoint and body are checked
offline; keyless verification still reports such a receipt `unchecked`,
because a v2 signing time comes from an RFC 3161 token, which 0.44 does not yet
bind. **SigningConfig** (`signing_config.v0.2.json`, media type
`application/vnd.dev.sigstore.signingconfig.v0.2+json`) is read from the
Sigstore config directory to choose the Rekor URL: services valid now, of a
supported major version, newest first, one per operator, then the
`ALL`/`ANY`/`EXACT` selector. It is never fetched by the verifier.

**SCITT (experimental).** A signed statement is a COSE_Sign1 (tag 18; ES256,
ES384, ES512, EdDSA) verified against a pinned key. A receipt is a COSE_Sign1
with protected `vds` (395) = 1 (RFC9162_SHA256), unprotected `vdp` (396) =
`{-1: [bstr .cbor [tree_size, leaf_index, path]]}`, and a detached payload: the
root the proof implies from leaf `SHA-256(0x00 || statement)` (the statement
re-encoded without header 394). This leaf rule is opentine's reading of the
drafts and is not verified against scitt-api-emulator.

<a id="s-8.13"></a>
## 8.13 Signed webhook payloads, `tine-webhook/1` (0.45.1)

A remote that lists `webhooks` in `GET /v1/capabilities` signs each webhook
delivery with an Ed25519 key it advertises there as `webhooks.keys`: entries
`{"kid", "alg": "ed25519", "public_key"}` where `public_key` is the raw 32-byte
key in unpadded base64url and `kid` is `ed25519:` followed by the first 16
lowercase hex digits of `SHA-256(public key)`. A receiver refuses an entry whose
`kid` does not match its key.

The body is a `tine-webhook/1` object (`format`, `delivery`, `webhook`, and
`event`, a `tine-event/1` object), serialized as canonical JSON: sorted keys,
`,`/`:` separators, no whitespace, non-ASCII escaped as `\uXXXX`. The
`OpenTine-Signature` header is exactly `t=<T>,kid=<kid>,sig=<S>`: `T` is 1-12
decimal digits (Unix seconds), `S` the 86-character unpadded base64url Ed25519
signature over

    "opentine-webhook/1" || 0x0A || decimal(T) || 0x0A || body

where `decimal(T)` has no leading zeros and `body` is the bytes received. A
verifier answers, in this order: **malformed** (the header does not match that
grammar, or the body exceeds 256 KiB), **stale** (`|now - T|` exceeds the replay
window, 300 s by default; the bound is inclusive), **unknown-key** (`kid` is not
pinned), **bad-signature**, then **malformed** again if the verified body is not
a JSON object whose `format` is `tine-webhook/1`; otherwise **valid**. The
sender re-signs `T` on every retry and keeps `delivery` unchanged, so a receiver
de-duplicates by `delivery`. Vectors for 8.13: `59-webhook.json`.

<a id="s-8.14"></a>
## 8.14 Hosted-beta remote capabilities (0.46, draft)

A remote MAY list these entries in `GET /v1/capabilities`; a client MUST NOT
use a route whose entry is absent, and every 0.45 key keeps its meaning, so a
0.34–0.45 client is unaffected. All tenant routes sit under
`/v1/tenants/<t>/` and authorize the bearer identity for that tenant on every
request.

- `object_read_http`: `GET objects/<oid>` returns the stored object envelope
  (`application/vnd.opentine.object`) with `ETag: "<oid>"`,
  `Cache-Control: private, max-age=31536000, immutable` and
  `Vary: Authorization`; it MUST NOT be `public`. `If-None-Match` with the
  same ETag answers 304 after authorization.
- `run_closure`: `POST runs/<oid>/closure` with `{haves, depth, lazy_blobs,
  pack_formats, pack_codecs}` returns the run's closure minus `haves` as one
  pack, negotiated like `fetch`. With `lazy_blobs: true` blobs are left out and
  become the pack's shallow boundary; `OpenTine-Lazy-Blobs` counts them, and
  each is read, and authorized, by `GET objects/<oid>`.
- `list`: `GET list/runs` and `GET list/refs` return `tine-list-page/1`
  pages (`items`, `next_cursor`), `limit` 1–500. A cursor is opaque.
- `search`: `POST search` also takes `text` (1–256 characters): run oids whose
  stored record holds it, case-insensitively, newest first.
- `log_http`: `GET log/entries` pages this tenant's transparency-log entries
  (§8.10) with their log indexes.
- `admin`: `GET admin/stats` (admin role) counts objects by type, refs and
  active share links.
- `share`: `POST shares` `{run, ttl, scope}` (writer or admin) returns a
  `tine-share/1` record with a `token` (`tine_share_` + 43 base64url
  characters) shown once; the server keeps only its SHA-256. `GET shares`
  lists records without tokens, `DELETE shares/<id>` revokes. Without a
  bearer, `GET /v1/share/<token>`, `POST /v1/share/<token>/closure` and
  `GET /v1/share/<token>/objects/<oid>` read the bound run and only objects
  in its closure.

An object that is absent, in another tenant, outside a share, or not
authorized, and a share token that is unknown, expired or revoked, all answer
the same `404` with body `{"error":"not found"}`: no route is an oracle for
whether an oid exists. Failed share lookups count against the client like
failed logins (429 with `Retry-After`); a successful share read MUST NOT
clear that count, or one live token would let its holder keep guessing. On
share routes `haves` count only inside the bound run's closure, every answer
carries `Referrer-Policy: no-referrer`, and the token MUST NOT appear in
access logs. The server never signs as a user: a
share grants read access to bytes the viewer re-verifies against the run's own
signatures.

<a id="s-8.15"></a>
## 8.15 Remote HTTP API v1 (0.46.0)

The HTTP API of a remote (`tine serve`, and the hosted service) is specified by
the OpenAPI 3.1 document [`docs/api/openapi-v1.yaml`](api/openapi-v1.yaml),
`info.version` `1.0.0`. It is generated from the server's route table
(`opentine/remote/_api_routes.py`), and `tests/test_api_v1_openapi.py` fails if
the document, the table and the dispatcher disagree. Every operation carries
`x-opentine-cap` (the key in `GET /v1/capabilities` that advertises it, or
`null` for the core protocol) and `x-opentine-status`: `stable` routes are
served by this release; `planned` routes are reserved shapes for the 0.46
capabilities and a client calls one only when its cap is advertised.

Rules every implementation keeps: tenant routes are private by default (no
anonymous read; `401` without valid credentials); every read is authorized
per tenant; a request for an object the caller may not read answers exactly
like one for an object that does not exist (a uniform `404`, or, for `fetch`,
an empty pack), and a tenant-level refusal (`401`/`403`) never depends on the oid
asked for or on whether the tenant exists, so no response is an oid- or
tenant-existence oracle; repeated failed
authentication and exhausted quotas answer `429` with `Retry-After`; and the
server never signs as a user: signed objects (runs, attestations, project
manifests) arrive client-signed and are stored as received. A client verifies
what it fetches by recomputing every oid (2.8, and the TS SDK's
`@opentine/sdk/verified`). `tests/api_conformance/` is the black-box suite an
implementation runs against its base URL. No byte format changed.

<a id="s-8.16"></a>
## 8.16 Admission VSAs and named server trust policies (0.46.0)

A remote run as `tine serve --vsa-dir DIR` or `--trust-policy NAME=FILE`
records every admitted ref update as an in-toto Statement v1 whose
`predicateType` is `https://slsa.dev/verification_summary/v1` (a SLSA VSA):
one `subject` `{"name": <oid>, "digest": {"sha256": <oid hex>}}`, and a
`predicate` with `verifier.id`, `timeVerified`, `resourceUri`
(`tine://<tenant>/<ref>`), `policy`, `inputAttestations` (empty),
`verificationResult` (`PASSED`) and the sorted `verifiedLevels`. With a server
key it is wrapped in a DSSE envelope (`payloadType`
`application/vnd.in-toto+json`, Ed25519 over the DSSE v1 PAE, as 9.x
`tine-attest` envelopes). The key is the server's own: a remote never signs as
a user. `GET /v1/capabilities` advertises it as `vsa.keys` (entries
`{"kid", "alg": "ed25519", "public_key"}` exactly as `webhooks.keys` in 8.13),
with `vsa.predicate_type`, `vsa.verifier` and the configured `vsa.policies`
URIs.

A named policy is an `opentine.admission-policy` version 1 JSON document
(`docs/schemas/opentine-admission-policy-1.schema.json`): required `refs`
(fnmatch globs over the normalized ref name), optional `tenants`, `roles`
(any one), `subjects`, `object_types` (of the ref's target) and `levels`
(default `["OPENTINE_ADMITTED"]`). Policies are tried in the order given; the
first whose `tenants` and `refs` cover the update decides it, and an update no
policy covers is refused. The VSA's `predicate.policy` is then
`{"uri": "opentine:trust-policy/<NAME>", "digest": {"sha256": <sha256 of the
policy file's bytes>}}`; without a named policy it is
`{"uri": "opentine:admission/default"}`.

A verifier holding the server's 32-byte key pinned checks an envelope for an
expected subject, optionally a required policy URI, and a set of required
levels, and answers in this order: **malformed** (not a DSSE envelope of that
payload type, a non-base64 payload or signature, a signature entry with keys
other than `keyid`/`sig`, or no signatures), **bad-signature** (no signature
verifies under the pinned key), **malformed** (the signed payload is not a
Statement v1 VSA with exactly one subject carrying a 64-hex sha256, a
`verifiedLevels` string list and a `policy.uri` string), **wrong-subject**,
**failed** (`verificationResult` is not `PASSED`), **wrong-policy**,
**missing-level**; otherwise **valid**. Reference: `opentine/_vsa_verify.py`
(standard library plus an injectable Ed25519, vendored into
`tine-verify.pyz`). Vectors for 8.16: `61-vsa.json`.

<a id="part-9"></a>
# Part 9 — Format v4 (0.26.0)

**Status:** normative since 0.26.0. Format v4 unifies the portable `.tine`
artifact (Part 3) and the v3 object model (Part 1) into one single-file bundle
of v3 objects. It was the **default writer** from 0.26 to 0.41; since 0.42 the
default `.tine` spelling is v5 (Part 10), which carries the same v4 objects,
root and signatures. `Run.save`, `tine import --save`, `tine record`, forks
and replays write v4 under `tine --for-legacy` (or `--format 4`,
`OPENTINE_FORMAT=4`), and v5 otherwise; new repositories are object format 4
(§9.10) and `tine migrate` upgrades to v4 by default. The older writers are
deprecated and opt-in: `OPENTINE_FORMAT=2` (or `3`; for repositories, object
format 3), or `tine --format 2` for one command, select them and print one
deprecation warning per process on stderr. `OPENTINE_FORMAT=4` is the strict
spelling: no deprecated block is written even where v4 cannot express it
(§4.4, §4.5). v4 signatures are `tine-sig/3` (§9.6) and v4 attestations
`tine-attest/2` (§9.7). A file or repository written by 0.26 needs opentine
0.26 or newer to read; every older file stays readable forever (§5.1).

<a id="s-9.1"></a>
## 9.1 Design rules

1. **One canonical form.** v4 bytes are produced by the §0.2 function, which
   for every value it accepts is exactly RFC 8785 (JCS). §0.3 survives only to
   verify v2 data and the signatures made over it.
2. **The root commits to the content.** The root is the run's v3 oid (§1.3);
   through the links of §1.5 it reaches every event and blob, so it covers the
   whole run. A v4 artifact and the same run saved by `put_run` into a v3
   repository name the **same** root.
3. **Mutable things stay outside the root.** Tags and run metadata travel as
   the run's annotation chain (§1.4), which targets the root but is not
   reachable from it.
4. **Upgrade on write only.** A v1/v2 artifact or a v3 repository run becomes
   v4 only when it is written again; no reader rewrites an original.
5. **Packs are unchanged.** TINEPACK3, TINEPACK4 and TINELP3 are not affected.

<a id="s-9.2"></a>
## 9.2 The canonical form

v4 canonical JSON is §0.2: RFC 8785 member order (UTF-16 code units, so
U+1F600 sorts before U+FB33), RFC 8785 string escaping (only `"`, `\` and
U+0000–U+001F are escaped; `/`, DEL, U+2028 and U+2029 are literal; `\u00XX`
uses lowercase hex), and ECMAScript `Number.prototype.toString` for doubles,
including the shortest-round-trip tie cases (`333333333.33333325`,
`1424953923781206.2`) and `-0` written as `0`. Two rules are stricter than
JCS, and a writer MUST refuse rather than repair either: an **integer** whose
magnitude exceeds 2**53-1 (the I-JSON bound JCS assumes; never rounded, never
stringified), and text holding a lone surrogate. The vectors `canon.v4.*`
(`docs/conformance/vectors/09-canon-v4.json`) carry the RFC 8785 Appendix B /
cyberphone IEEE-754 corpus; they run through the `canon.v3` op because they
test the same function.

⚠ Hazard: the v3 repository writer stores a wide integer as a string
(`json_safe`); a v4 write refuses the run instead, naming the field.

<a id="s-9.3"></a>
## 9.3 The artifact

A v4 file is one JCS object, optionally inside the `TINEZ1\0` wrapper of §2.3:

| Key | Value |
|---|---|
| `format_version` | the integer `4` |
| `kind` | the string `tine-artifact/4` |
| `root` | the run oid |
| `objects` | `{oid: envelope}` — every blob, event and run object the root reaches, and nothing else |
| `annotations` | the root's annotation chain, oldest first; each entry is an envelope plus its `id` |
| `signatures` | a list of `tine-sig/3` blocks (§9.6), possibly empty |

An envelope spells one stored object (§1.2) as JSON:
`{"encoding": "raw", "schema": N, "type": "blob", "data": <base64>}` for a raw
blob (RFC 4648 with padding, no line breaks, canonical), or
`{"encoding": "json", "schema": N, "type": T, "body": <value>}` for a JSON
object, whose stored body is the §0.2 encoding of `body`. Detection is by
`format_version` **and** `kind` together. Any other top-level key is refused;
provenance lives inside the root run's payload (§9.9).

<a id="s-9.4"></a>
## 9.4 Reading

A reader MUST, and this build does, refuse the artifact when: a top-level key
is unknown or a required one is missing; `objects` holds more than
`_format_v4.MAX_V4_OBJECTS` (1 000 000) envelopes or an annotation/attestation;
`annotations` holds more than `_format_v4.MAX_V4_ANNOTATIONS` (1024) entries,
an entry that is not an annotation of the root, or a chain whose
`previous_id` links are broken; an envelope has any key besides the four
above, `data` on a JSON object or `body` on a blob, or non-canonical base64;
any envelope's re-derived oid (§1.3) differs from its key; the root is not a
run the artifact carries; a link is missing or an object is unreachable from
the root; any §1.5–§1.6 rule fails; or `signatures` is not a list of at most
16 objects each naming `tine-sig/3` (keyed verification is §9.6).
The bounds of §3 (256 MiB, depth, structural tokens) apply to the file. A wide
integer literal inside a body is read as the double it spells (§0.2's
integer-literal demotion), because a conforming writer never emits a wide
integer.

Step ids (0.26.0+): the writer records each step's own id as its event's
`legacy_step_id`. When every event of the run carries a non-empty one that is
not itself an event oid, and they are unique, the reference reader gives each
step back that id (renaming parent ids, causal ids and `refs` targets to
match), so a run keeps the ids its transcript and pricing manifest name across
a save, and re-writing it re-derives byte-identical events. Otherwise (a run
recorded straight into a repository) step ids are the event oids, as `load_run`
reads a repository.

<a id="s-9.5"></a>
## 9.5 Writing

`Run.save` writes v4 unless the legacy writer is chosen (autosave drafts stay
v2, since v4 has no draft marker; a signing key appends one `tine-sig/3` block,
§9.6). An explicit write (`Run.save`, `put_run`, `tine migrate`) refuses an
integer beyond 2**53-1 or a non-finite number, naming the field. A live
recorder (the harness wrapper and autosaver, `tine record`, `tine run` with a
bundled model, trace and OTLP import, hooks) must not lose a run over one
value: its run is marked lenient (`_v4_values.mark_lenient`, or
`Run.save(..., lenient=True)`), and such a value is stored as its exact decimal
string (never rounded) with a `metadata.warnings` entry naming the field path.
A trace event, which has no metadata, lists the same entries under its
`attributes["opentine.warnings"]` (a usage meter moves to
`attributes["usage.<name>"]`). The writer converts the run
with the v3 `put_run` conversion into memory — redacting before hashing exactly
as §1.4 does — then emits the closure of the root and its annotation chain. A
writer MUST refuse what its own reader would: wide integers, non-finite
numbers, and a document past the §3 size or structure bounds. Re-writing a run
read from v4 re-addresses nothing: unchanged content yields byte-identical
output.

The object bound is v4's own (it is not the 10 000-object network pack bound
`pack.MAX_PACK_OBJECTS`); reader and writer share the one constant, and the
§3 artifact byte cap (256 MiB) is the practical ceiling.

⚠ Hazard: v4 carries the v3 rules, which are stricter than v2 in places a v2
file tolerated: a pricing manifest or transcript entry naming a step the run
does not hold, and a run past `MAX_V4_OBJECTS` objects, cannot be written as
v4. Recording never loses a run over this: the **default** writer
(`OPENTINE_FORMAT` unset) falls back to a v2 file, prints one stderr warning
naming the reason (`opentine: warning: pricing manifest references an unknown
step; saved as format 2`) and appends the same text to `metadata.warnings`.
`OPENTINE_FORMAT=4` (strict) refuses instead and writes nothing. Wide integers
are not a structural misfit: an explicit save still refuses them, a recorder's
save still stringifies them (§9.5).

<a id="s-9.6"></a>
## 9.6 `tine-sig/3` — v4 artifact signature (0.26.0+)

The message is the domain prefix `opentine.signature.v3:` followed by the §0.2
(JCS) bytes of

```
{"annotations_head": <id of the last annotations entry, or null>,
 "format_version": 4, "header": <the five-key header of §4.1, null for absent>,
 "kind": "tine-artifact/4", "root": <root oid>}
```

The root commits to the whole run (§9.1), including `upgraded_from` (§9.9),
and the annotation head to its tags and metadata. Blocks have the §4.1 shape
(`hmac-sha256` for local use, or `ed25519` with `public_key`, keys per §4.6)
and are stored in `signatures`, at most `_signing_v4.MAX_V4_SIGNATURES` (16) of
them. A verifier MUST first verify the artifact per §9.4: content that does not
match its root is `mismatch`, as an edited v2 body is. A block naming any other
scheme is `error`. With several blocks the first one the caller's key verifies
decides; otherwise the first block's verdict is returned, in the §4.7
vocabulary. Since 0.26.0 `tine-sig/1` is never written and `tine-sig/2` and
`tine-attest/1` only as §4.4–§4.5 describe; all three verify forever.

<a id="s-9.7"></a>
## 9.7 `tine-attest/2` — attestation on a v4 root (0.26.0+)

The message is `opentine.attestation.v2:` followed by the §0.2 bytes of
`{"body": <payload without signature>, "header": <five-key header>}`. It is
**Ed25519 only** (an HMAC block under this scheme is `error`) and `target_id`
MUST be a run oid (else `error`). Attestations stay outside a v4 artifact's
`objects`. The in-toto export of a v4 run names the root's hex digest as its
subject and, when signed with a file key, carries a `tine-attest/2` record on
that root (signed by the envelope's key) at `predicate.attestation`; a verifier
checks that record's target and signature before accepting the subject.

<a id="s-9.8"></a>
## 9.8 Offline verification of v4

`tine verify --offline` reports a v4 digest check as `root <oid>`; in a dataset
(§8.3) a v4 run's leaf digest is its root oid, and its `run_id` is the root run
object's `source_run_id`. `tine migrate` reports a v4 file as already migrated
and never rewrites it as v2.

<a id="s-9.9"></a>
## 9.9 `upgraded_from` — provenance inside the run (0.26.0+)

`tine migrate --to v4` records where a run came from as the optional
`upgraded_from` field of the **run payload** (§1.5), so the root, and every
`tine-sig/3` over it, covers it:

```
{"format": "tine/1"|"tine/2"|"tine-repo/3", "digest_algorithm": "sha256",
 "digest": <hex sha256 of the source bytes after the §2.3 unwrap, or the v3 run oid>,
 "integrity_digest": <the source's recorded §3.5 digest, or null>,
 "signature": {"scheme", "state", "key_fingerprint", "trust_basis"},
 "upgraded_at": <ISO 8601>, "tool": "opentine/<version>"}
```

`signature.state` is the §4.7 verdict on the source at upgrade time (or
`not-applicable` for a repository source): a claim by the upgrader, not
something the v4 file proves. A run without the field hashes exactly as
before; v3 readers ignore it. A v4 reader MUST refuse a malformed record. A
fork drops it; any other rewrite keeps it. `tine migrate` never touches the
original unless `--in-place` is given (which keeps `NAME.tine.v2.bak`), and it
refuses an integer beyond 2**53-1. `SOURCE_DATE_EPOCH` pins `upgraded_at`. The
0.1.0 linear layout records `tine/1`, and its loader stamps a `created_at`, so
its root differs between upgrades. `tine verify --offline` reports the record
as the `provenance` check (§8.2); `--source PATH` re-hashes the source and
re-verifies its signature (a source signature that was `verified` and now is
`mismatch` or `error` is `provenance.source-mismatch`).
Since §9.10, `tine migrate --to v4 --repo` no longer writes a `tine-repo/3`
record (the root is the repository oid itself); readers still accept one.

<a id="s-9.10"></a>
## 9.10 Repositories (0.26.0+)

A v4 file and a v3 repository hold the same envelopes, so they share oids.

- **Descriptor.** `Repo.init` writes object format 4, and an existing
  object-format-3 repository is marked object format 4 (§2.2) before the first
  object a 0.26 writer stores in it. Repositories that hold v4 runs without the
  mark (written by the legacy writer) stay readable by 0.13+: the envelopes are
  v3, and v3 readers ignore `upgraded_from`.
- **`put_run`.** Unless the legacy writer is chosen, it refuses an integer
  beyond 2**53-1 and a non-finite number, naming the field, instead of
  `json_safe`'s stringification (a recorder's run is softened, §9.5), and
  carries `upgraded_from` (§9.9). A fork of a repository run, written as v4,
  reuses the source's stored envelopes for every unchanged step, so its root
  equals what `put_run` of the same fork stores. The repository oid of a
  run equals the root of the same run written as a v4 file; `Run.save` of a
  repository-loaded run reuses the stored envelopes of that run.
- **Import.** `tine import FILE --repo PATH` (with `--format auto`) recognizes
  a `tine-artifact/4` file, verifies it per §9.4, and installs every envelope's
  own bytes (links first), so no oid changes; `--ref` (default `heads/main`)
  moves to the root. The annotation chain is adopted when the repository has
  none for the root or the file's chain extends it; a diverged repository chain
  is kept. `tine-sig/3` blocks are not objects (they sign the root and the
  annotation head), so they are kept in the sidecar
  `signatures/v4/<root hex>.json`:
  `{"entries": [{"annotations_head", "block"}...], "kind": "tine-sig-sidecar/1", "root"}`
  (canonical JSON, at most 256 entries; it names the root, so `gc` keeps the
  run). Packs do not carry sidecars (they carry objects); `tine bundle` and
  `bundle push/fetch` carry them in the bundle manifest under the optional key
  `signatures` (`{<run oid>: [{"annotations_head", "block"}...]}`, written only
  when a bundled run has blocks, every root inside the pack, every block
  `tine-sig/3`), merged into the receiver's sidecars on import. A bundle
  without the key is byte-identical to what 0.25 wrote; 0.25 refuses one that
  carries it (its manifest keys are fixed) rather than drop the signatures.
- **Export.** `tine migrate --to v4 --repo PATH RUN` writes the run's stored
  closure and annotation chain verbatim, so the root is the repository oid,
  and attaches the sidecar blocks whose `annotations_head` matches the current
  chain head: import then export reproduces the file byte for byte. Every
  repository run is representable (§0.2 already refuses what v4 refuses).
- **Bundles and packs** carry v4 runs unchanged (§9.1 rule 5).


<a id="part-10"></a>
# Part 10 — Format v5: text blobs (0.40.0)

**Status:** normative since 0.40.0 for **readers** and, since 0.42.0, the
**default writer**. Format v5 is a second
*spelling* of a format v4 document (Part 9) in which blobs that are UTF-8 text
travel as JSON strings instead of base64. It changes no object, no oid, no
root and no signature: a v5 file and the v4 file of the same run carry the
same envelopes and the same `tine-sig/3` blocks. Since 0.42 it is the
**default writer** (`_format_v4.writer_format`), following ROADMAP §2 (a new
file format becomes the default only two minor releases after its reader
ships). `tine --for-legacy ...`, `tine --format 4 ...` or `OPENTINE_FORMAT=4`
write v4 for readers before 0.40, and `tine evidence export` always copies runs
into the evidence folder as v4 (§10.3 conversion, same root and signatures).
A v5 file needs opentine 0.40 or
newer (or the 0.40 TypeScript verifier) to read; 0.26–0.39 refuse it as an
unknown format, never misread it.

Reference: `opentine/_tine_v5.py` (standard library only; `tine-verify.pyz`
vendors it verbatim).

<a id="s-10.1"></a>
## 10.1 The document

A v5 file is one JCS object (§0.2), optionally inside the `TINEZ1\0` wrapper of
§2.3, with exactly the six top-level keys of §9.3. It differs from a v4
document in three places only:

| Key | v4 | v5 |
|---|---|---|
| `format_version` | the integer `4` | the integer `5` |
| `kind` | `tine-artifact/4` | `tine-artifact/5` |
| `objects` blob envelopes | `{"encoding": "raw", "schema": N, "type": "blob", "data": <base64>}` | a **text envelope** when the blob bytes are UTF-8 text (§10.2), else the v4 raw envelope unchanged |

A **text envelope** has exactly the four keys
`{"encoding": "text", "schema": N, "text": S, "type": "blob"}`, where `S` is a
JSON string. JSON-encoded objects (`"encoding": "json"`), `annotations`,
`root` and `signatures` are spelled exactly as in v4. Detection is by
`format_version` **and** `kind` together (`_tine_v5.is_v5_artifact`).

<a id="s-10.2"></a>
## 10.2 Which spelling: exactly one per blob

A reader tells the spellings apart by the envelope's `encoding` member alone:
`"text"` is a text envelope, `"raw"` is base64, `"json"` is a JSON object.

Let `B` be a raw blob's stored body bytes. `B` is **UTF-8 text** when it is
well-formed UTF-8 per RFC 3629 / Unicode Table 3-7: no byte `C0`, `C1` or
`F5`–`FF`, no overlong form, no encoded surrogate (`ED A0 80`–`ED BF BF`), no
scalar above U+10FFFF, no truncated sequence. The empty body is UTF-8 text.
U+0000, CR, CRLF, a leading U+FEFF, U+2028/U+2029 and every other scalar value
are text. (This is exactly what a strict decoder such as Python's
`bytes.decode("utf-8")` or WHATWG `TextDecoder("utf-8", {fatal: true,
ignoreBOM: true})` accepts.)

- A writer MUST spell a raw blob as a text envelope when `B` is UTF-8 text,
  with `S` the string whose UTF-8 encoding is `B`, and as the v4 raw envelope
  (canonical base64, §9.3) when it is not.
- A reader MUST refuse a raw envelope whose base64 decodes to UTF-8 text (a
  second spelling of the same blob), a text envelope whose `type` is not
  `blob` or whose keys are not exactly the four above, and a `text` that is
  not a string or that holds an unpaired surrogate (§0.1; `\ud800` escapes
  are refused by the §3.7 parser before this point).

Because the choice is forced and the document is JCS, the v5 bytes of a run
are a function of its v4 bytes: re-writing yields byte-identical output.

<a id="s-10.3"></a>
## 10.3 Rebuilding canonical bytes

A reader converts a v5 document to the v4 document it spells
(`_tine_v5.to_v4`) and then applies §9.4 unchanged:

1. Replace `format_version` with `4` and `kind` with `tine-artifact/4`.
2. Replace each text envelope `{"encoding": "text", "schema": N, "text": S,
   "type": "blob"}` with `{"data": base64(UTF-8(S)), "encoding": "raw",
   "schema": N, "type": "blob"}` (RFC 4648 with padding).
3. Leave every other member as it is.

The stored envelope (§1.2) is therefore `JCS({"encoding": "raw", "schema": N,
"type": "blob"}) || 0x0A || UTF-8(S)`: the header still says `raw`, because
`text` is a transport spelling and never a stored encoding. The oid is §1.3
over those bytes, so it is identical to the v4 oid. JSON escaping inside `S`
(`\n`, `\r`, `\u0000`, `\"`, …) is undone by the JSON parser before step 2;
nothing else is normalized — no newline conversion, no Unicode normalization,
no BOM stripping.

<a id="s-10.4"></a>
## 10.4 Signatures and attestations

`tine-sig/3` (§9.6) signs `format_version: 4` and `kind: tine-artifact/4`
whatever the spelling, together with the root, the annotation head and the
header. A signature made over a v4 file therefore verifies, unchanged, over
the v5 spelling of the same file and back. `tine-attest/2` (§9.7) targets the
root and is unaffected.

<a id="s-10.5"></a>
## 10.5 Reading, verifying and installing

`Run.load`, `tine verify` (and `--offline`), `tine-verify.pyz`, datasets
(§8.3) and `tine import FILE --repo` read a v5 file as its §10.3 v4 document,
so every §9.4 refusal applies and every report names the v4 root. A tampered
text blob no longer re-derives its oid: integrity fails and a signature over
it is `mismatch`, exactly as for v4. Any tool that rewrites a v5 file (for
example `tine sign`, `tine migrate`) writes the current writer format, which
is v5 unless `--for-legacy` (or `--format 4`) is given. TINEPACK, bundles and repositories store
envelopes, not spellings, and are unaffected.

<a id="s-10.6"></a>
## 10.6 Size

On a transcript-shaped corpus (11 Claude Code sessions whose tool results are
source files, test output and grep output), v5 is 15.1% smaller raw, **26.5%
smaller after zstd-3** and **27.6% smaller after zstd-19** than v4. Base64
costs 4/3 in size and destroys the redundancy zstd would find in the text.
Binary blobs (images, compressed payloads) are unchanged.

<a id="s-10.7"></a>
## 10.7 Conformance

`docs/conformance/vectors/54-artifact-v5.json` carries the v5 cases: the
golden run re-spelled as v5 under `tine-sig/3` (verified, tampered text,
non-canonical base64 spelling, text on a non-blob, lone surrogate), and
`oid.derive` cases showing a text blob's oid is its v4 oid.

<a id="part-11"></a>
# Part 11 — Remote at-rest sealing: `TINEAES6` (0.41.0)

Roadmap item X28 is named "TINEAES5" in `docs/ROADMAP.md`; 0.35 had already
shipped `TINEAES5` as the KMS envelope (`_sealed_envelope`), so X28 is the
magic **`TINEAES6`**. The mapping is: roadmap "TINEAES5 (X28)" = on-disk
`TINEAES6`; on-disk `TINEAES5` = the 0.35 KMS envelope.

<a id="s-11.1"></a>
## 11.1 Layout

All integers big-endian:

| Field | Size | Notes |
|---|---|---|
| magic | 8 | `TINEAES6` |
| key id length | 1 | 1..64 |
| key id | n | ASCII |
| epoch | 4 | u32 |
| flags | 1 | bit 0: Padmé padded; other bits must be zero |
| codec | 1 | the `_codec` byte of the inner wrapper |
| size | 8 | the uncompressed plaintext length (checked against the reader's limit before decrypting) |
| nonce | 24 | random |
| ciphertext | rest | XAES-256-GCM, 16-byte tag |

The per-tenant key is `HMAC-SHA256(master, "opentine.tenant-key.v6\0" ||
lp(key_id) || lp(u32 epoch) || lp(tenant))` over a 32-byte master, where `lp(x)`
is a u32 length then `x`. The associated data is `"opentine.sealed.v6\0"`
followed by `lp` of purpose, tenant, context (oid, or upload id and offset), key
id, epoch, `flags||codec` and the u64 size, so the ciphertext cannot be moved to
another slot or relabelled to another key id, epoch, codec, size or padding.

XAES-256-GCM is <https://c2sp.org/XAES-256-GCM>: the first 12 nonce bytes derive
a per-message AES-256 key through the SP 800-108r1 counter KDF over AES-256-CMAC;
the last 12 bytes are the AES-256-GCM nonce. The implementation is checked
against the C2SP vectors.

The plaintext is the `_codec` wrapper (as in `TINEAES4`). When padded it is
`u64 len || wrapper || zeros`, zero-filled to the Padmé size of `8 + len`
(Nikitin et al., PURBs), which bounds the overhead at about 12% and leaks
O(log log L) bits of length. Non-zero padding is rejected. Padding exists in
`TINEAES6` only.

<a id="s-11.2"></a>
## 11.2 Readers

A `TINEAES6` reader holds a keyring of `(key_id, epoch) -> master`; an unknown
pair fails with a clear error. `TINEAES1`–`TINEAES4` keep opening through the
same master, `TINEAES5` through its KMS provider, and `tine serve reseal --to
aes6` rewrites older objects.

---

<a id="part-12"></a>
# Part 12 — Published JSON Schemas (0.45.0)

<a id="s-12.1"></a>
## 12.1 What is published

`docs/schemas/NAME.schema.json` holds one JSON Schema (draft 2020-12) per
object kind a third party reads and per `--json` output with a fixed shape.
`NAME` is the document's tag with `/` written `-` (`tine-verify-report/2` is
`tine-verify-report-2`); each schema's `$id` is
`https://opentine.com/schemas/NAME.schema.json`, and cross-schema `$ref`s use
the bare file name. The set, and the tag or `command` that selects each, is
`opentine._schemas.SCHEMAS` and `opentine._schema_defs_cli.COMMAND_SCHEMAS`;
`tine schema list` prints it.

The files are rendered from the definitions in `opentine/_schema_defs.py` and
`opentine/_schema_defs_cli.py` by `scripts/gen_schemas.py`; a test fails when
the two differ.

<a id="s-12.2"></a>
## 12.2 Rules

- A schema describes what the reference implementation writes. Within a
  major version a document gains fields and never loses or renames one, so
  object schemas are open (`additionalProperties` unset) unless the format is
  closed by its own definition (`opentine-delegation/1`, `opentine-fleet/1`,
  `tine-cost-statement/1`, `tine-verify-report/2`); a closed format changes
  only with a new tag.
- A schema is not a verifier. A document that validates may still fail its
  digest or signature check; Parts 4 and 8 decide that.
- `tine-eval-verdict-1` is a **draft** until the eval runner ships: its
  required fields (`run`, `item`, `scorer`, `score`, `pass`) are fixed, other
  fields may still be added.

<a id="s-12.3"></a>
## 12.3 The `--json` envelope

Every `tine ... --json` writes one JSON object (`tine-cli-envelope-1`): an
object with a non-empty `command` naming its shape, the fallback wrapper
`{"command", "exit_code", "output"}` of a command with no JSON of its own, or
`{"error": {"code", "exit_code", "message"}}`. The five v3 plumbing verbs
(`fsck`, `object`, `migrate-v3`, `fetch`, `push`) print bare JSON and are
outside the envelope. Where a schema is published for a `command`, the
object also validates against it. `tine help --json` writes `tine-help/1`,
the command and flag tree.

<a id="s-12.4"></a>
## 12.4 Validating

`tine schema validate FILE [--schema NAME]` picks the schema from the
document's `schema`, `scheme` or `format` tag, else its `command` (a document
with neither, such as a redaction report, by its `kind`), and exits 4 on an
invalid document. A document nested deeper than 512 levels is refused with
exit 2 (usage) before it is validated. The reference validator (`opentine._jsonschema`)
implements the keyword subset the published schemas use and refuses a schema
that uses any other keyword; any conforming 2020-12 validator gives the same
verdicts on these schemas.

---

<a id="spec-changelog"></a>
# Spec changelog

Versions are the opentine release that changed this document.

| Spec version | Change |
|---|---|
| 0.46.0 | 4.14, `opentine.tombstone` signed purge records, the `tombstones/` directory, the bundle `tombstones` key and the remote `tombstones` routes; 4.15, `opentine.redacted-copy` and the bundle `redacted_public` key; 8.16, admission VSAs, `opentine.admission-policy` named server trust policies and the VSA verification order; Part 12 adds their schemas and `opentine-admission-policy-1` and `tine-ci-gate-1`. No existing byte format changed. |
| 0.45.1 | 4.13, `opentine.redaction-report` signed redaction reports (a supplied HMAC key never falls back to the embedded key); 8.13, `tine-webhook/1` signed webhook payloads; Part 12 adds the event, webhook, watch, redaction and `tine-ai-share/1` schemas. No existing byte format changed. |
| 0.45.0 | Versioned header and citation; stable `part-N` / `s-N.M` anchors; Part 12, published JSON Schemas and the `--json` envelope. The offline `delegation` check passes with `delegation.verified` (was the bare `ok`, which the reason grammar of §8.2 does not allow). No byte format changed. |
| 0.41.0 | Part 11: `TINEAES6` remote at-rest sealing. |
| 0.40.0 | Part 10: format v5 text blobs; 2.10 external blob pointers. |
| 0.26.0 | Part 9: format v4, `tine-sig/3`, `tine-attest/2`. |
| 0.9.0 | First published version: `.tine` v1/v2, the v3 repository model and wire format, `tine-sig/1`, `tine-sig/2`, `tine-attest/1`. |

Releases between these added sections without a spec version of their own;
from 0.45.0 every change to this document bumps the spec version and adds a
row here.

