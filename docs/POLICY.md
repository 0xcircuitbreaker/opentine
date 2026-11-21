# Policy engine (0.74)

`tine policy check POLICY --subject RUN` decides whether a run may be
admitted (promoted, merged, released) by evaluating a small declarative policy
over a fixed input document assembled from the run's signed records. The
decision can be signed as an admission record. The same language and
semantics are implemented in Python (`opentine/_policy_lex.py`,
`opentine/_policy_lang.py`, `opentine/_policy_eval.py`) and in the TypeScript
verifier (`ts/verifier/src/policy.ts`, `ts/verifier/src/policyeval.ts`), and
both run the shared vectors in `tests/data/policy_vectors.json`.

No object kind and no `tine verify` code is added: a policy is a file, the
admission record is a claim convention on an existing attestation.

## Policy files

```json
{
  "schema": "opentine.policy/1",
  "name": "promote",
  "description": "Promote only if ...",
  "params": {"approvals": 2},
  "rules": [
    {"id": "k-of-n", "effect": "require",
     "expr": "size(oversight.approvers) >= params.approvals"},
    {"id": "quiet", "effect": "advisory", "expr": "size(containment) == 0"}
  ]
}
```

* `effect: require`: the decision is `allow` only when every `require` rule
  evaluates to `true`.
* `effect: advisory`: the outcome is recorded and never blocks (D12). A policy
  that wants an advisory signal to block says so by making that rule
  `require`.
* At most 64 rules; rule ids are 1-64 of `A-Z a-z 0-9 _ . : -`; a policy file
  is at most 256 KiB. Schema: `opentine-policy-1`.
* The policy digest is `sha256:` over `opentine.policy/1`, a NUL byte and the
  canonical JSON of the whole file, so params are covered.

`POLICY` is a path, or the name of a standard policy (`tine policy list`).

## The language

A strict subset of [CEL](https://github.com/google/cel-spec): every accepted
expression means the same in CEL, but most of CEL is refused.

| Accepted | Notes |
| --- | --- |
| `null`, `true`, `false` | |
| numbers `12`, `1.5`, `2e3` | one numeric type: `1 == 1.0`; no `u` suffix, hex or leading zeros |
| strings `"..."`, `'...'` | escapes `\\ \" \' \n \r \t \uXXXX \UXXXXXXXX`; a surrogate or a value above U+10FFFF is refused |
| `[a, b]` | list literals |
| `name`, `a.b`, `a[0]`, `m["k"]` | variables are the top-level keys of the input document |
| `!x`, `-x` | |
| `== != < <= > >=`, `in` | comparisons do not chain: `a < b < c` is refused |
| `&&`, `\|\|`, `( )` | |
| `has(a.b)`, `size(x)`, `x.size()` | |
| `x.all(v, p)`, `x.exists(v, p)` | the only macros |

Everything else is a parse error: arithmetic, the ternary operator, other
functions and macros (`map`, `filter`, `exists_one`, `startsWith`, ...),
map literals, `uint`/`bytes`/`timestamp`, and user functions.

### Semantics

* `==`/`!=`: values of different types are unequal, never an error (`1 ==
  true` is `false`). Lists and maps compare element by element.
* `< <= > >=`: number with number, string with string, bool with bool
  (`false < true`); anything else is `policy.type`. Strings compare by
  Unicode code point (not by UTF-16 unit), and are not normalised: the NFC
  and NFD spellings of `é` are different strings.
* `size` counts code points of a string, items of a list, keys of a map.
* `x in list` is membership by `==`; `k in map` asks for a key (a non-string
  `k` is `false`).
* A missing key (`a.f`, `m["k"]`) is `policy.no-such-key`; `has(a.f)` asks
  without failing. A list index is an integral number in range
  (`policy.index`, `policy.type` otherwise). An unknown variable is
  `policy.no-such-var`.
* `&&` and `||` evaluate both sides, left first, and are commutative over
  errors as in CEL: `false && error` and `error && false` are `false`, `true
  || error` is `true`; otherwise the first error is the result. A non-boolean
  operand is `policy.type`.
* `all` and `exists` evaluate every element: `all` is `false` if any element
  is false, else the first error, else `true`; `exists` is `true` if any is
  true, else the first error, else `false`. Over a map they range over its
  keys in code-point order.

### Bounds

| Bound | Value | Error |
| --- | --- | --- |
| expression length | 4096 code points | `policy.parse` |
| nesting depth (parentheses, lists, unary operators) | 32 | `policy.parse` |
| nodes | 1024 | `policy.parse` |
| tree height (also bounds `a.b.c...` chains) | 64 | `policy.parse` |
| evaluation steps (one per node evaluated) | 10,000 | `policy.steps` (cannot be absorbed by `&&`/`\|\|`) |
| input document depth | 64 | `policy.input` |

Number literals and input numbers must be finite, and an integral value must
lie within ±(2^53 − 1), so Python and JavaScript read the same number;
otherwise `policy.parse` (literal) or `policy.input` (input). A lone
surrogate in an input string is `policy.input`. Nothing is timed: a bound is
a count.

### Errors deny

Every error is recorded with its code. An error in a `require` rule denies,
including a parse error, a bad input document (every rule is then an error)
and a rule whose value is not a boolean (`policy.not-bool`). A missing or
invalid policy file is a command error (exit 1) and allows nothing.

## The input document

Assembled for one run from signed records only. A record counts when its
Ed25519 signature verifies and its `signer` field names the key that signed.
Signers carry their roles from the owner-pinned key roles (an owner-signed
trust bundle) and from nothing else; a record signed by a pinned `optimizer`
key is left out. Lists are in object-id order, so the same records give the
same document and the same input digest (`sha256:` of its canonical JSON).

| Key | From |
| --- | --- |
| `subject` | `{run, status, model, steps}` of the run |
| `roles` | `pinned` or `unpinned` |
| `evals` | signed eval verdicts on the run in `--evals DIR` folders: `{eval, dataset, item, scorer_name, score, threshold, passed, signer, roles, pinned, holdout}`; `pinned` means a `scorer` or `eval` role, `holdout` that the dataset is a verified holdout |
| `holdouts` | names of `--holdout DIR` sealed holdouts whose commitment verifies and is signed by a pinned `dataset` key |
| `monitors` | monitor verdicts on the run |
| `oversight` | `{decisions, approvers}`: decisions on a `promotion:LABEL:RUN` item naming the run, and the distinct pinned `approver` keys that approved |
| `lineage` | `{variants}`: signed lineage records (at most 1000) |
| `integrity` | `{taints, fail_codes}`: signed taints on the run and live `fail:` integrity codes |
| `budget` | `null` without `--budget SUBJECT`, else `{subject, in_force, decision, over, fail_codes}` from the budget ledger |
| `sandbox` | the run's signed sandbox policies `{policy_digest, signer, roles}` |
| `containment` | the run's advisory containment findings |
| `params` | the policy's `params`, then `--param NAME=JSON` values |

An integral number beyond 2^53 − 1 in a record becomes its decimal string.
`--show-input` prints the document. `--input FILE` evaluates over a given
document instead; that result is never signed.

## Admission records

With `--key`, the decision is signed as an attestation on the run (a
verification summary), with the claim (schema `opentine-policy-admission-1`):

```json
{"convention": "opentine.policy-admission/1",
 "verificationResult": "PASSED",
 "decision": "allow",
 "policy": {"name": "promote", "digest": "sha256:..."},
 "subject": "run:sha256:...",
 "input_digest": "sha256:...",
 "rules": [{"id": "...", "effect": "require", "outcome": "true", "code": null}],
 "at": "2026-11-21T00:00:00Z"}
```

Denies are recorded too. The record is held under
`policy-admission:RUN-HEX` and `tine hold release` refuses it, so a loop
cannot delete a deny it received. Only a key pinned with the `policy` role
in the owner-pinned key roles signs one (`policy.signer-role`); a pinned
`optimizer` key is refused even if it also holds `policy`
(`policy.key-separation`). The claim is consistent by construction: the
decision follows from the `require` outcomes, and `subject` names the run
the attestation is attached to.

A record **counts** only when its signature verifies with the signer bound
to the signing key, the claim is valid, it targets and names the run, and
its signer holds the pinned `policy` role and not `optimizer`.
`tine policy show RUN --policy POLICY [--input-digest D]` reports
`admitted`: a counting record for that policy digest allows and none
denies. The check is order-free, since holds are kept sorted by id and `at`
is self-claimed: with `--input-digest D` only records naming D are
considered, so an allow over older records does not admit the current
input; without it, any counting deny refuses (deny wins). It exits 1 when
not admitted.

Policy files, `--param` values and `--input` documents are strict JSON:
duplicate keys, `NaN`/`Infinity` and integers beyond +-(2**53 - 1) are
refused. A bare standard name (`promote`) always means the shipped policy,
even if a file of that name is in the working directory; use `./promote`
for such a file.

## In the query index and the promotion gate

Every admission record is a row of the `policy_admissions` table in `tine
query` (docs/QUERY.md). Under `--verify` each returned row is re-derived from
its attestation and is `verified` only for a pinned `policy` signer that does
not hold `optimizer`; any other signer's record, and a record whose claim
names a run other than its target, is `unverified`, and a row
whose signature does not verify is `failed`. The index is non-authoritative:
`tine policy show` decides.

`tine promote RUN --baseline LABEL ... --require-admission POLICY` (repeatable;
a standard name, `./file` or a `sha256:` policy digest) refuses before the
label can move unless the policy admitted RUN over its *current* input: the
gate assembles the input `tine policy check` would, from the same arguments
(the policy's params, overridden by `--admission-param NAME=VALUE`;
`--admission-evals DIR`, `--admission-holdout DIR` and `--admission-budget
SUBJECT` as the check's `--evals`, `--holdout` and `--budget`), takes its input
digest and counts only admissions naming it. Pass the gate what you passed the
check: an allow over `--evals`, `--holdout` or `--budget` the gate does not see
is over another input and does not count. The budget block holds no clock
values, so it changes between check and gate only when the budget's state does. A run denied earlier is admitted by an allow over new
inputs; an allow over inputs that have since changed no longer counts. Refusals:
`promote.not-admitted`, or `promote.admission-policy` when the policy
cannot be read (fails closed). These are command-level codes. Advisory rules
never decide an admission, so they never block the gate (D12).

## Standard policies

Shipped in `opentine/data/policies/`:

| Name | Rule |
| --- | --- |
| `holdout-signed` | `evals.exists(e, e.holdout && e.pinned && e.passed)` |
| `no-integrity-fail` | `size(integrity.fail_codes) == 0 && integrity.taints == 0` |
| `k-of-n-approvals` | `size(oversight.approvers) >= params.approvals` (default 2) |
| `budget-within-cap` | a budget policy in force, decision `allow`, nothing over, no `fail:` |
| `sandbox-digest` | a sandbox policy signed by a pinned `runner` key has digest `params.sandbox_digest` |
| `promote` | all five as `require`, plus `size(containment) == 0` as `advisory` |

`sandbox-digest` ships with an empty `sandbox_digest`, which denies until it
is set (`--param sandbox_digest=sha256:...`); `budget-within-cap` denies
without `--budget SUBJECT`. Both fail closed.

## Conformance vectors

`tests/data/policy_vectors.json` holds the shared input document, expression
cases (values and error codes, including numeric limits, NFC/NFD, astral
versus BMP ordering, surrogates and every bound) and policy cases (decision
and per-rule outcomes). `scripts/gen_policy_vectors.py` regenerates the file
and refuses to write it if the Python evaluator disagrees with an expected
result; `tests/test_075_policy_vectors.py` and
`ts/verifier/test/policy.test.ts` run it.
