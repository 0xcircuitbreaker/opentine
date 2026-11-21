"""Generate tests/data/policy_vectors.json (0.74): expected values are written by hand below and
checked against the Python evaluator when generated (a mismatch aborts)."""

import json
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else str(__import__("pathlib").Path(__file__).parents[1])
sys.path.insert(0, ROOT)
from opentine import _policy  # noqa: E402

INPUT = {
    "n": 3,
    "f": 2.5,
    "z": 0,
    "neg": -7,
    "big": 9007199254740991,
    "s": "abc",
    "e": "",
    "t": True,
    "nul": None,
    "l": [1, 2, 3],
    "ls": ["a", "b"],
    "empty": [],
    "m": {"a": 1, "b": {"c": "x"}, "k": [True, False]},
    "nfc": "\u00e9",
    "nfd": "e\u0301",
    "astral": "\U0001f600",
    "bmp": "\uffff",
    "evals": [{"passed": True, "score": 0.9}, {"passed": False, "score": 0.1}],
}
V = []


def v(expr, value=None, *, error=None, inp=None, id_=None):
    V.append(
        {
            "id": id_ or f"c{len(V):03d}",
            "expr": expr,
            "input": inp,
            "expect": {"outcome": "error", "code": error}
            if error
            else {"outcome": "value", "value": value},
        }
    )


# literals and numbers
for e, x in [
    ("1 == 1.0", True),
    ("0.1 < 0.2", True),
    ("-0.0 == 0", True),
    ("2e3 == 2000", True),
    ("1e-3 < 0.01", True),
    ("n == 3", True),
    ("f > n", False),
    ("neg < z", True),
    ("big == 9007199254740991", True),
    ("-big < 0", True),
    ("[1, 2.0] == [1.0, 2]", True),
    ("1 == true", False),
    ("0 == false", False),
    ("null == nul", True),
    ("'a' == \"a\"", True),
    ("1 != 'a'", True),
    ("[] == empty", True),
    ("m.b.c == 'x'", True),
    ("(1 < 2) == true", True),
    ("true > false", True),
    ("'b' > 'a'", True),
    ("'abc' < 'abd'", True),
    ("'' < 'a'", True),
]:
    v(e, x)
v("9007199254740992 == 0", error="policy.parse")
v("1e400 > 0", error="policy.parse")
v("1e300 > 0", error="policy.parse")  # integral beyond 2**53 - 1
v("1.5 > 1", True)
v("01 == 1", error="policy.parse")
v("1. == 1", error="policy.parse")
v("1u == 1", error="policy.parse")
v("0x10 == 16", error="policy.parse")
v("1 < 'a'", error="policy.type")
v("[1] < [2]", error="policy.type")
v("null < null", error="policy.type")
v("-'a' == 'a'", error="policy.type")
v("--n == 3", True)
# unicode
v("nfc == nfd", False)
v("size(nfd) == 2 && size(nfc) == 1", True)
v("size(astral) == 1", True)
v("astral > bmp", True)  # code point order (UTF-16 units would say otherwise)
v("'\\U0001F600' == astral", True)
v("'\\u00e9' == nfc", True)
v("'\\ud800' == 'x'", error="policy.parse")
v("'\\U00110000' == 'x'", error="policy.parse")
v("'\\q' == 'x'", error="policy.parse")
v("'unterminated", error="policy.parse")
v("'caf\u00e9' == 'caf' + 'e'", error="policy.parse")
v("size('\u00e9\U0001f600') == 2", True)
v("s == 'abc'", error="policy.input", inp={"s": "abc", "bad": "\ud800"}, id_="lone-surrogate-input")
v("x > 0", error="policy.input", inp={"x": 9007199254740993}, id_="unsafe-int-input")
v("x > 0", error="policy.input", inp={"x": 1e300}, id_="unsafe-float-input")
v("x > 0", True, inp={"x": 1.5e-300}, id_="tiny-float-input")
v("x == '\u00e9'", True, inp={"x": "\u00e9"}, id_="non-ascii-in-string")
v("\u00e9 == 1", error="policy.parse")
# fields, index, has, size, in
for e, x in [
    ("m.a == 1", True),
    ("m['a'] == 1", True),
    ("has(m.a)", True),
    ("has(m.q)", False),
    ("has(m.b.c)", True),
    ("l[0] == 1", True),
    ("l[2.0] == 3", True),
    ("size(l) == 3", True),
    ("l.size() == 3", True),
    ("size(m) == 3", True),
    ("size(s) == 3", True),
    ("2 in l", True),
    ("2.0 in l", True),
    ("'a' in m", True),
    ("1 in m", False),
    ("'q' in m", False),
    ("'a' in ls", True),
    ("[1] in [[1]]", True),
    ("m.k[1] == false", True),
    ("size(e) == 0", True),
]:
    v(e, x)
v("m.q == 1", error="policy.no-such-key")
v("m['q'] == 1", error="policy.no-such-key")
v("l[3] == 1", error="policy.index")
v("l[-1] == 1", error="policy.index")
v("l[0.5] == 1", error="policy.type")
v("l['a'] == 1", error="policy.type")
v("m[1] == 1", error="policy.type")
v("s.a == 1", error="policy.type")
v("has(s.a)", error="policy.type")
v("has(m)", error="policy.parse")
v("size(1) == 1", error="policy.type")
v("1 in 1", error="policy.type")
v("'a' in 'abc'", error="policy.type")
v("q == 1", error="policy.no-such-var")
v("size(l, l) == 1", error="policy.parse")
v("l.size(1) == 1", error="policy.parse")
# boolean ops and error commutativity
for e, x in [
    ("true && true", True),
    ("true && false", False),
    ("false || true", True),
    ("!false", True),
    ("!(1 == 2)", True),
    ("false && q", False),
    ("q && false", False),
    ("true || q", True),
    ("q || true", True),
    ("false && 1", False),
    ("1 || true", True),
    ("true && (false || true)", True),
]:
    v(e, x)
v("true && q", error="policy.no-such-var")
v("q || false", error="policy.no-such-var")
v("m.q == 1 && q", error="policy.no-such-key")  # first error wins
v("q && m.q == 1", error="policy.no-such-var")
v("true && 1", error="policy.type")
v("!1", error="policy.type")
# macros
for e, x in [
    ("l.all(x, x > 0)", True),
    ("l.all(x, x > 1)", False),
    ("l.exists(x, x == 3)", True),
    ("l.exists(x, x == 4)", False),
    ("empty.all(x, false)", True),
    ("empty.exists(x, true)", False),
    ("evals.exists(e, e.passed && e.score > 0.5)", True),
    ("evals.all(e, e.passed)", False),
    ("m.all(k, k in m)", True),
    ("m.exists(k, k == 'b')", True),
    ("l.all(x, ls.exists(y, y == 'a'))", True),
    ("[1, 'a'].exists(x, x == 'a')", True),
    ("l.exists(x, x > 2 || q)", True),
]:
    v(e, x)
v("[1, 'a'].all(x, x > 1)", False)
v("['a', 1].all(x, x > 1)", False)
v("['a', 2].all(x, x > 1)", error="policy.type")
v("['a', 0].exists(x, x > 1)", error="policy.type")
v("[1, 'a'].all(x, x > 0)", error="policy.type")
v("[0, 'a'].exists(x, x > 0)", error="policy.type")
v("l.all(x, x)", error="policy.type")
v("s.all(x, true)", error="policy.type")
v("l.all(1, true)", error="policy.parse")
v("l.map(x, x)", error="policy.parse")
v("l.filter(x, x > 1)", error="policy.parse")
v("l.all(x, x > 0, 1)", error="policy.parse")
# non-bool results are values here; policies turn them into errors
v("n", 3)
v("s", "abc")
v("[n, s]", [3, "abc"])
# syntax and bounds
v("1 < 2 < 3", error="policy.parse")
v("1 == 1 == true", error="policy.parse")
v("1 in l in l", error="policy.parse")
v("(1 < 2) == (2 < 3)", True)
v("", error="policy.parse")
v("1 +", error="policy.parse")
v("1 + 1 == 2", error="policy.parse")
v("n ? 1 : 2", error="policy.parse")
v("f(1)", error="policy.parse")
v("m.in == 1", error="policy.parse")
v("m.true == 1", error="policy.parse")
v("in == 1", error="policy.parse")
v("!" * 40 + "true", error="policy.parse", id_="unary-depth")
v("(" * 40 + "true" + ")" * 40, error="policy.parse", id_="paren-depth")
v("(" * 20 + "true" + ")" * 20, True, id_="paren-depth-ok")
v("m" + ".a" * 70 + " == 1", error="policy.parse", id_="select-height")
v("true" + " && true" * 1100, error="policy.parse", id_="node-count")
v("'" + "a" * 4100 + "' == ''", error="policy.parse", id_="source-length")
v("'" + "\U0001f600" * 4000 + "' == ''", False, id_="source-length-astral-ok")
v(
    "l.all(a, l.all(b, l.all(c, l.all(d, l.all(e, l.all(f, l.all(g, l.all(h, "
    "l.all(i, true)))))))))",
    error="policy.steps",
    id_="step-limit",
)
v(
    "[" + ",".join(["[1,2,3,4,5,6,7,8,9,10]"] * 30) + "].all(a, a.all(b, true))",
    True,
    id_="steps-under-limit",
)
v("1 == 1\n&&\t2 == 2", True)
v("'a\\n' == \"a\\n\"", True)
v("'\\'' == \"'\"", True)

POLICIES = [
    {
        "id": "allow-all-require-true",
        "policy": {
            "schema": "opentine.policy/1",
            "name": "p",
            "rules": [
                {"id": "a", "effect": "require", "expr": "n == 3"},
                {"id": "b", "effect": "advisory", "expr": "n == 4"},
            ],
        },
        "decision": "allow",
        "outcomes": ["true", "false"],
    },
    {
        "id": "advisory-error-does-not-block",
        "policy": {
            "schema": "opentine.policy/1",
            "name": "p",
            "rules": [
                {"id": "a", "effect": "require", "expr": "true"},
                {"id": "b", "effect": "advisory", "expr": "q"},
            ],
        },
        "decision": "allow",
        "outcomes": ["true", "error"],
    },
    {
        "id": "require-error-denies",
        "policy": {
            "schema": "opentine.policy/1",
            "name": "p",
            "rules": [{"id": "a", "effect": "require", "expr": "m.q"}],
        },
        "decision": "deny",
        "outcomes": ["error"],
    },
    {
        "id": "non-bool-denies",
        "policy": {
            "schema": "opentine.policy/1",
            "name": "p",
            "rules": [{"id": "a", "effect": "require", "expr": "n"}],
        },
        "decision": "deny",
        "outcomes": ["error"],
        "codes": ["policy.not-bool"],
    },
    {
        "id": "parse-error-denies",
        "policy": {
            "schema": "opentine.policy/1",
            "name": "p",
            "rules": [{"id": "a", "effect": "require", "expr": "n +"}],
        },
        "decision": "deny",
        "outcomes": ["error"],
        "codes": ["policy.parse"],
    },
    {
        "id": "bad-input-denies-every-rule",
        "input": {"x": 1e300},
        "policy": {
            "schema": "opentine.policy/1",
            "name": "p",
            "rules": [
                {"id": "a", "effect": "require", "expr": "true"},
                {"id": "b", "effect": "advisory", "expr": "true"},
            ],
        },
        "decision": "deny",
        "outcomes": ["error", "error"],
        "codes": ["policy.input"] * 2,
    },
    {
        "id": "require-false-denies",
        "policy": {
            "schema": "opentine.policy/1",
            "name": "p",
            "rules": [{"id": "a", "effect": "require", "expr": "evals.all(e, e.passed)"}],
        },
        "decision": "deny",
        "outcomes": ["false"],
    },
]


def main(root: str) -> None:
    from opentine._policy_eval import check_input, evaluate
    from opentine._policy_lang import PolicyError, parse

    bad = []
    for case in V:
        inp = INPUT if case["input"] is None else case["input"]
        try:
            check_input(inp)
            got = {"outcome": "value", "value": evaluate(parse(case["expr"]), inp)}
        except PolicyError as exc:
            got = {"outcome": "error", "code": exc.code}
        if got != case["expect"] or (
            got.get("value") is not None and type(got["value"]) is not type(case["expect"]["value"])
        ):
            bad.append((case["id"], case["expr"][:80], got, case["expect"]))
    for p in POLICIES:
        result = _policy.decide(p["policy"], p.get("input", INPUT))
        outs = [r["outcome"] for r in result["rules"]]
        codes = [r["code"] for r in result["rules"]]
        if (
            result["decision"] != p["decision"]
            or outs != p["outcomes"]
            or ("codes" in p and codes != p["codes"])
        ):
            bad.append((p["id"], result))
    for b in bad:
        print("MISMATCH", b)
    if bad:
        raise SystemExit(1)
    doc = {
        "comment": "Shared policy-language conformance vectors (0.74): run by "
        "tests/test_075_policy_vectors.py and ts/verifier/test/policy.test.ts. "
        "A case with input null uses the shared input.",
        "input": INPUT,
        "cases": V,
        "policies": POLICIES,
    }
    text = json.dumps(doc, indent=1, ensure_ascii=True) + "\n"
    with open(f"{root}/tests/data/policy_vectors.json", "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(len(V), "cases", len(POLICIES), "policies")


main(ROOT)
