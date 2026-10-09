# The adapter protocol

`run_conformance.py` speaks line-delimited JSON to a program you write. That
program is the only thing you have to build to run this suite; the runner, the
scoring, the pairing and the report already exist.

One process handles the whole run. Process-per-vector was rejected: 523 cases
must be fast, and a read-a-line / write-a-line loop is the cheapest thing to
implement correctly in Rust, Go or TypeScript.

## The loop

Read one JSON object per line from stdin. Write one JSON object per line to
stdout and flush. Never write anything else to stdout — diagnostics go to
stderr.

**Request**

```json
{"id": "env.header.canonical", "op": "envelope.decode",
 "input": {"bytes_b64": "..."}, "args": {}}
```

`input` has exactly one of two shapes by the time it reaches you — the runner
resolves `blob`, `path` and `gen` inputs into bytes before sending:

* `{"bytes_b64": "<standard base64 with padding>"}`
* `{"value": <a tagged value tree, see below>}`

**Response**, one of:

```json
{"id": "...", "ok": true,  "output": { ... }}
{"id": "...", "ok": false, "reason": "<a REASON_CODES.md code>"}
{"id": "...", "ok": false, "unsupported": true}
```

`unsupported` means "I have not implemented this op". It is reported as
**unimplemented**, not as a failure, so a partial implementation gets a real
scorecard on day one — `canon.v3` + `envelope.decode` + `oid.derive` alone
already produce a meaningful table.

`reason` is ignored at Level 1 and required at Level 2. You supply it from a
one-time map between your own error identifiers and the codes in
`REASON_CODES.md`; `scripts/conformance_adapter.py` shows what such a map looks
like in about seventy lines.

## The tagged value tree

`input.value` is plain JSON with exactly four escapes, each recognised **only**
on a single-key object whose sole key is exactly `$i`, `$f`, `$u` or `$obj`:

| Spelling | Means |
|---|---|
| `{"$i": "-9007199254740993"}` | an integer of arbitrary magnitude |
| `{"$f": "1e+20"}` | an IEEE-754 double, given as a round-tripping literal |
| `{"$f": "nan"}`, `{"$f": "inf"}`, `{"$f": "-inf"}` | the three values JSON cannot spell |
| `{"$u": ["d800", "0041"]}` | a string given as its UTF-16 code units, four lowercase hex digits each |
| `{"$obj": {"$i": "x"}}` | a genuine object whose sole key begins with `$` |
| `{"$obj": [["a", 1], ["b", 2]]}` | a genuine object as `[key, value]` pairs, used when a key itself needs a tagged spelling |

Strings, booleans, `null`, arrays and multi-key objects are literal. **A bare
JSON number never appears inside `input.value`** — a drift gate enforces that —
so you never have to guess whether `1` is an integer or a double. That is the
entire bespoke surface of this suite, it is about a dozen lines to read, and
`vectors/01-selftest.json` proves your reader of it before any other result
means anything. Run that file first.

`$u` exists so the vector *files* stay parseable everywhere. A lone UTF-16
surrogate has no UTF-8 spelling and no `\uXXXX` escape a strict JSON parser will
hand back, so a file containing one directly is unreadable to a Rust or Go
runner before any adapter is involved. Every case that spells one carries
`"requires": ["wtf8"]`: run without `--capability wtf8` and they are reported
`skip`, which is the honest answer for a language whose string type cannot hold
the value at all.

Everything the tagged tree still cannot express — duplicate keys, non-string
keys, key insertion order — reaches you only as `input.bytes_b64`, where parsing
is the rule under test and the correct answer is **reject**. An implementation
whose string type cannot hold a lone surrogate satisfies *those* vectors by
construction and must report `reject`, not `skip`.

## Comparison

* **accept** — every field of `output` must equal the vector's, field for
  field. Arrays named in `MANIFEST.ops.<op>.unordered` are compared as sorted
  sequences, because SPEC §2.8 leaves pack array order unconstrained.
* **reject** — you must refuse. At Level 2 your `reason` must be the vector's
  `reason`, or any other code in that code's group in `MANIFEST.alias_groups`.
* **verdict** — you must **return** the pinned result. Raising is a failure;
  that is the entire content of SPEC §4.7's fail-closed vocabulary.
* **`forbidden`** — if you accept a reject case *and* your output matches the
  vector's `forbidden` fields, the status is **`REPAIRED`**, not `FAIL`. The
  table then prints the digest that proves you silently changed the input.
* **`must_differ`** — a claim about a *pair*: this case's output must (or must
  not) equal its `twin`'s. An implementation returning one constant answer
  would pass every individual comparison and still be wrong about the pair.
* **`output_sha256`** — three stress cases answer with hundreds of kilobytes.
  Those pin the SHA-256 of
  `json.dumps(output, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`
  with every unordered array sorted, instead of the value.

## Input assembly

If you write your own runner rather than using `run_conformance.py`, you need
the five `input` spellings and the five `gen` recipes:

| Spelling | Assembly |
|---|---|
| `bytes_b64` | standard base64, with padding |
| `value` | a tagged value tree |
| `blob` | read `docs/conformance/<the given path>` |
| `path` | read `<repository root>/<the given path>` — used only by the compat family, whose evidence is the golden fixtures themselves |
| `gen` | one of the recipes below |

| `gen.kind` | Assembly |
|---|---|
| `nest` | `open * depth + inner + close * depth`, ASCII |
| `repeat` | `prefix_b64 + unit_b64 * count + suffix_b64`; `prefix_b64` and `suffix_b64` default to empty |
| `fill` | the single byte `byte`, `count` times |
| `oids` | `count` lines of `<object_type>:sha256:<index as 64 lowercase hex>` followed by `terminator`, starting at `start`; `terminator` defaults to `"\n"` and `start` to `0` |
| `nest-value` | a *value*: `inner` (itself a tagged tree), wrapped `depth` times in whatever `container` names — `"array"`, the default, or `"object"`, which requires `key` |

Every default above is a default an assembler has to know, so none of them is
left to the runner's source: a recipe that omits `terminator`, `start`,
`prefix_b64`, `suffix_b64` or `container` means the value in this table.

Every byte-shaped input carries `input.sha256` over the assembled bytes, so a
recipe is exactly as trustworthy as a literal. Check it before you use it.

## The ops

`MANIFEST.ops` is the machine-readable table: for each of the 33 ops it gives
the profile, the input spellings it may receive, the arg names it may be given,
the output field names, which of those are unordered, and any capability *every*
case of that op requires. The `input` and `requires` columns are derived from the
emitted cases rather than hand-listed, so the two can never disagree.

**Capabilities are gated per case, not per op.** A case that needs `zlib`,
`ed25519` or `wtf8` carries it in its own `requires`, which is what a runner
must check; `MANIFEST.ops.<op>.requires` is the intersection over that op's
cases, and is there to tell an implementer which ops they cannot attempt at all.
A case whose `requires` is not covered by the capabilities a run declares is
reported `skip`.

`args` values are ordinary JSON — the tagged encoding applies to `input.value`
only. Two args carry object bytes: `objects` is a list of base64-encoded stored
envelopes (the repository the op reads against), and `present` is a list of oids
that exist without their content being supplied.
