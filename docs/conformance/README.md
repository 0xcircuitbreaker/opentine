# The OpenTine conformance vector suite

Machine-readable evidence for [`docs/SPEC.md`](../SPEC.md): 523 vectors that an
implementation in any language can run to demonstrate it reads, writes and
verifies OpenTine data the way the specification says.

**What you need:** SHA-256, HMAC-SHA256, base64 and a JSON parser. Three
capabilities beyond that are optional: zlib *inflate* for the pack family,
Ed25519 for a handful of verifier cases, and `wtf8` — a string type that can hold
an unpaired UTF-16 surrogate — for five canonicalization cases. Every case that
needs one carries it in its own `requires`, so a consumer that does not pass
`--capability` reports `skip` rather than `fail` for all of them. Nothing else.
No opentine, no Python, no build step.

## Start here

1. Read this file, then `docs/SPEC.md`.
2. Parse `MANIFEST.json` and verify every file's `sha256`. That includes the
   four files no generator writes — this README, `PROTOCOL.md`,
   `report.schema.json` and the runner itself — so the harness you execute and
   the adapter contract you implement are covered by the same check.
3. Implement the four-tag value reader in [`PROTOCOL.md`](PROTOCOL.md) —
   about a dozen lines — and run `vectors/01-selftest.json` **first**. If it does
   not pass, no other result means anything.
4. Write an adapter (about eighty lines) and run:

   ```
   python docs/conformance/run_conformance.py \
       --adapter "./target/release/tine-conformance" \
       --profile reader,verifier --level 2 --report conformance.json
   ```

   `scripts/conformance_adapter.py` is the worked example to port.
5. Optional, and the highest-value step of all: run `compat/index.json` against
   `tests/fixtures/compat/` and confirm your reader reaches the recorded
   verdicts for all eight released versions. That is SPEC §5.1's read
   guarantee, checked in your language against bytes real published releases
   wrote.

## What is in it

25 vector files, one per SPEC area. `MANIFEST.families` carries the current
census — case counts, reject counts, and the ops each family uses — so no
number is restated here where it could drift. **37% of the suite is negative:
inputs the format requires be refused.** That ratio is deliberate, and a drift
gate pins the figure against `MANIFEST.totals`.

**"Reject" is normative in this format.** An implementation that silently
repairs input is not conformant, because every repair changes a digest that
claims fidelity to recorded model output. Most published vector suites test
only accepts. `vectors/99-repair.json` is fourteen cases that exist only to
catch a repair, each carrying the exact answer a repairing implementation
returns.

Three files are worth knowing about before you start:

* **`vectors/04-divergence.json`** — SPEC §0.4's hazard, made checkable. v2
  orders object members by Unicode code point; v3 orders them by UTF-16BE code
  unit. They disagree only on non-BMP keys, and they also disagree on number
  spelling and non-ASCII escaping. Each half of a pair carries the *other*
  canonicalizer's answer as `forbidden`, so no single canonicalizer passes
  both. The centrepiece is `sig.attest.hazard.nonbmp-1e20`: SPEC §4.5's own
  worked vector is all-ASCII with no floats, so both canonicalizers coincide on
  it and an implementer who reaches for JCS passes §4.5 and fails only here.
* **`vectors/47-verdict.json`** — every case expects a *returned* verdict.
  An implementation that raises fails, which is the whole content of §4.7.
* **`vectors/51-compat.json`** — the only family that reads outside this
  directory. Its inputs are the golden fixtures under `tests/fixtures/compat/`,
  by path and digest, never copied: those bytes ARE the evidence for the read
  guarantee, and a second copy could drift from them.

## Scoring: three columns, and the second is the point

* **passed** — alone, defeatable by an implementation that refuses everything.
* **pairs** — both halves of every `twin` correct. A blanket rejecter scores
  100% on negatives and **near zero** here.
* **reason_agreement** — informational at Level 1, required at Level 2.

**Two levels.** Level 1 is reject-parity: every accept produces the exact
bytes, oid or verdict, and every reject is refused. Level 2 is
diagnostic-parity: each rejection is additionally reported with the vector's
reason code. `report.json` records which you claimed.

Where the reference implementation genuinely cannot tell two rules apart — its
byte scanner reports one message for a depth overrun and a token overrun — the
codes stay distinct, because the *rules* are distinct, and the pair is listed in
`MANIFEST.alias_groups`. At Level 2 a runner accepts any code from the expected
code's group, so diagnostics as coarse as the reference's are not marked wrong.

## Honest framing

**The generator and the self-gate share a codebase, so a shared misconception
produces vectors that confirm it.** Two different entry points (the low-level
functions and the public `Repo`/`Run` API) and byte-stable regeneration narrow
that; they cannot close it. **This suite proves an implementation agrees with
opentine. `docs/SPEC.md` remains the normative artifact; the vectors are
evidence about it.** If a vector and the specification disagree, the
specification is what an implementer should follow, and the disagreement is a
bug worth filing.

`SPEC_NOTES.md` records every place building a vector found the prose and the
behaviour not lining up, each with a **mandatory** resolution. An empty table
there is a success.

## What a passing scorecard does NOT certify

* **The storage layer.** Hard-linked refs, `st_nlink`, symlink and junction
  confinement, and the `.lock` / `..lock` compare-and-swap protocol of §2.4 and
  §2.7 have no byte-level input. They are covered by the reference's own tests
  and `scripts/win_fs_sim.py`.
* **`fsck` (§2.9), the v2 → v3 migration (§5.4), the remote protocol, the CLI
  JSON contract, replay, and pricing.** Out of scope for 0.9.0.
* **§3.6 v2 step-id derivation**, which SPEC documents as a known-broken
  identity claim retained for compatibility. Encoding it as a conformance
  requirement would ask third parties to reproduce a defect on purpose.
* **Every bound in `REASON_CODES.md`'s "Not vectored, and why" section**, each
  with the reason written out. A bound with no vector is a bound you cannot
  check, so none of them is left silent.

## Regenerating

```
uv run python scripts/gen_conformance_vectors.py           # rewrite
uv run python scripts/gen_conformance_vectors.py --check   # diff instead
```

Every expected value in this directory is **generated** from the reference
implementation and **checked in**. The generator refuses to emit when a case's
observed disposition disagrees with the one its author declared, so making
opentine accept what it used to reject requires a human to edit one line in
`tests/conformance/cases_*.py` — and that one-line diff reads "we now accept
what we used to reject", which is what review has to see. Regeneration is
byte-identical, so a hand-edited vector fails.

## Files

| Path | What it is |
|---|---|
| `MANIFEST.json` | the one file a runner parses: ops, alias groups, families, per-file digests (every file here except this one), bound coverage, retired ids |
| `PROTOCOL.md` | the adapter contract |
| `REASON_CODES.md` | every reason code, its SPEC section, the live value of the bound it enforces, and the repair it forbids |
| `SPEC_NOTES.md` | prose amendments found by building vectors, each with a resolution |
| `keys.json` | the six fixed, published test keys, in hex |
| `report.schema.json` | the shape of a runner's `report.json` |
| `run_conformance.py` | the neutral harness: standard library only, imports no opentine |
| `vectors/` | the cases |
| `frames/`, `blobs/` | oversized byte payloads, named by their own SHA-256 |
| `compat/index.json` | a pointer index into `tests/fixtures/compat/`, copying zero bytes |
