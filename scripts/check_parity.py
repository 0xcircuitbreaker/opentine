"""Python, TS and pyz parity on the full pinned conformance vector set (0.50, criterion 2).

For every case of ``docs/conformance`` this asks three implementations for an
answer and compares each with the pinned one, case by case:

* **python** -- the reference adapter (``tests.conformance.engine.observe``);
* **pyz** -- ``tine_verify._pyz._conform`` imported from a freshly *built*
  ``tine-verify.pyz`` (not the source tree);
* **ts** -- ``ts/verifier``'s ``dist/src/parity.js`` (``npm run build`` first),
  which scores each case with the verifier's own suite runner.

An answer agrees when its disposition matches, an accepted case's output is
the pinned output (or its ``output_sha256``), and a refusal that names a code
names the pinned reason (or one of its alias group). The pyz answers every
reader and verifier case except the repository storage families listed in
``tests/freeze_inventory.STORAGE`` (refs, reflogs, shallow, layout, packs: it
never opens a repository); the TS verifier skips only the writer-side
redaction ops. Anything else unanswered is a gap, and a gap fails like a
disagreement.

    python scripts/check_parity.py            # python + pyz (+ ts when built)
    python scripts/check_parity.py --require-ts

Exits 1 on any disagreement or gap, 2 when ``--require-ts`` is given and the
TS build is missing. Offline; needs node only for the TS column.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib
import json
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from opentine._pyz_build import build_bytes  # noqa: E402
from tests import freeze_inventory as inventory  # noqa: E402
from tests.conformance.engine import canonical_output, observe, op_input  # noqa: E402
from tests.conformance.generate import families  # noqa: E402

SUITE = ROOT / "docs" / "conformance"
TS_PARITY = ROOT / "ts" / "verifier" / "dist" / "src" / "parity.js"
TS_SKIPS = {"object.put", "redact.blob", "redact.value", "attest.sign"}
#: A programming error is a crash, not a refusal: it never agrees with a reject case.
CRASHES = (
    AssertionError, AttributeError, ImportError, IndexError, KeyError, NameError,
    NotImplementedError, RecursionError, TypeError,
)  # fmt: skip


def _keys() -> dict[str, bytes]:
    raw = json.loads((SUITE / "keys.json").read_text("utf-8"))
    return {name: bytes.fromhex(text) for name, text in raw.items()}


def _records() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for path in sorted((SUITE / "vectors").glob("*.json")):
        for record in json.loads(path.read_text("utf-8"))["cases"]:
            out[record["id"]] = record
    return out


def _alias_groups() -> list[set[str]]:
    manifest = json.loads((SUITE / "MANIFEST.json").read_text("utf-8"))
    return [set(group) for group in manifest.get("alias_groups", [])]


def _agrees(record: dict, accepted: bool, output: object, code: str | None, groups) -> bool:
    if record["expect"] == "reject":
        if accepted:
            return False
        if code is None:
            return True
        allowed = set(record.get("reason_any") or [record["reason"]])
        for group in groups:
            if group & allowed:
                allowed |= group
        return code in allowed
    if not accepted:
        return False
    if "output_sha256" in record:
        return hashlib.sha256(canonical_output(output)).hexdigest() == record["output_sha256"]
    return "output" not in record or canonical_output(output) == canonical_output(record["output"])


@contextlib.contextmanager
def _built_pyz():
    """``tine_verify._pyz._conform`` from a freshly built archive, unloaded afterwards."""
    with tempfile.TemporaryDirectory() as scratch:
        archive = Path(scratch) / "tine-verify.pyz"
        archive.write_bytes(build_bytes())
        sys.path.insert(0, str(archive))
        try:
            module = importlib.import_module("tine_verify._pyz._conform")
            assert Path(module.__file__).as_posix().startswith(archive.as_posix())
            yield module
        finally:
            sys.path.remove(str(archive))
            for name in [n for n in sys.modules if n.split(".")[0] == "tine_verify"]:
                del sys.modules[name]


def _ts_rows() -> dict[str, dict] | None:
    node = shutil.which("node")
    if node is None or not TS_PARITY.is_file():
        return None
    done = subprocess.run(
        [node, str(TS_PARITY), str(ROOT)], capture_output=True, text=True, check=True, timeout=600
    )
    rows = [json.loads(line) for line in done.stdout.splitlines() if line.strip()]
    return {row["id"]: row for row in rows}


def run(require_ts: bool = False) -> int:
    records, groups, keys = _records(), _alias_groups(), _keys()
    ts = _ts_rows()
    if ts is None and require_ts:
        print("check_parity: ts/verifier is not built (npm ci && npm run build)", file=sys.stderr)
        return 2
    storage = set(inventory.STORAGE)
    tally: dict[str, Counter] = {}
    problems: list[str] = []
    with _built_pyz() as conform:
        for family in families():
            name = family.filename.removesuffix(".json")
            counts = tally.setdefault(name, Counter())
            for case in family.cases:
                record = records[case.id]
                seen = observe(case)
                code = getattr(seen.exception, "code", None)
                crashed = isinstance(seen.exception, CRASHES)
                ok = not crashed and _agrees(
                    record, seen.disposition != "reject", seen.output, code, groups
                )
                counts["python"] += ok
                if not ok:
                    problems.append(f"python disagrees: {case.id}")
                answers = case.op in conform.OPS or case.op in conform.KEYED
                if case.profile != "writer" and name not in storage:
                    if not answers:
                        problems.append(f"pyz gap: {case.id} ({case.op})")
                    else:
                        payload, _ = op_input(case)
                        try:
                            out = conform.answer(
                                case.op, payload.raw, payload.value, case.args, keys
                            )
                            ok = _agrees(record, True, out, None, groups)
                        except Exception as exc:  # noqa: BLE001 -- a refusal is the answer
                            code = getattr(exc, "code", None)
                            ok = not isinstance(exc, CRASHES) and _agrees(
                                record, False, None, code, groups
                            )
                        counts["pyz"] += ok
                        counts["pyz_cases"] += 1
                        if not ok:
                            problems.append(f"pyz disagrees: {case.id}")
                if ts is not None:
                    row = ts.get(case.id)
                    if row is None or (row["status"] == "skip" and case.op not in TS_SKIPS):
                        problems.append(f"ts gap: {case.id} ({case.op})")
                    elif row["status"] != "skip":
                        good = row["status"] == "pass"
                        if good and record["expect"] == "reject" and row["reason"]:
                            good = _agrees(record, False, None, row["reason"], groups)
                        counts["ts"] += good
                        counts["ts_cases"] += 1
                        if not good:
                            problems.append(f"ts disagrees: {case.id}: {row['detail']}")
                counts["cases"] += 1
    total = Counter()
    for name, counts in sorted(tally.items()):
        total.update(counts)
        pyz = f"{counts['pyz']}/{counts['pyz_cases']}" if counts["pyz_cases"] else "n/a"
        ts_col = f"{counts['ts']}/{counts['ts_cases']}" if ts is not None else "not built"
        print(f"{name:28} python {counts['python']}/{counts['cases']}  pyz {pyz}  ts {ts_col}")
    ts_total = f"{total['ts']}/{total['ts_cases']}" if ts is not None else "not built"
    print(f"total: {total['cases']} cases  python {total['python']}  "
          f"pyz {total['pyz']}/{total['pyz_cases']}  ts {ts_total}")  # fmt: skip
    for line in problems:
        print(line, file=sys.stderr)
    print(f"parity: {'FAIL' if problems else 'ok'} ({len(problems)} disagreement(s) or gap(s))")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(run(require_ts="--require-ts" in sys.argv[1:]))
