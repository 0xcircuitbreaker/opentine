"""Verify every object of a repository, bundle or record folder with all three verifiers.

``check_parity.py`` scores the three implementations against the pinned
conformance vectors. This script asks the same three implementations about
*your* data instead, and fails on any disagreement between them:

* **python** -- the reference adapter (``tests.conformance.engine.observe``);
* **pyz** -- ``tine_verify._pyz._conform`` from a freshly built ``tine-verify.pyz``;
* **ts** -- ``ts/verifier``'s ``dist/src/parity.js`` (``npm ci && npm run build``).

Each object of a repository becomes ``envelope.decode`` (under its own oid)
and ``links.extract`` (against the store); each signed record -- an
``attestation`` or ``annotation`` object with a signature block, or a
``*.json`` record file with one -- becomes ``sig.verify`` (embedded key, the
attestation family). The Python answer is written as the expected answer of a
throwaway suite; the pyz and the TS verifier must give the same answer
(acceptance, output, and the refusal code where both name one). A case all
three refuse is a problem too (``does not verify``) unless ``--allow-invalid``
is given, which reports disagreements only. A ``tine
bundle`` file is checked whole by the Python and TS verifiers, then unbundled
into a scratch repository and checked object by object.

    python scripts/verify_everywhere.py .tine
    python scripts/verify_everywhere.py run.bundle records/ --require-ts --json

Exit 0 when every verifier agrees on every case and every case verifies, 1 on
any disagreement, gap or invalid record,
2 on a usage error or when ``--require-ts`` is given and the TS build is
missing. Offline; needs node only for the TS column.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_parity import CRASHES, TS_PARITY, _agrees, _alias_groups, _built_pyz  # noqa: E402
from everywhere_inputs import bundle_cases, file_cases, repo_cases, tine_dir  # noqa: E402

from tests.conformance.cases import Case  # noqa: E402
from tests.conformance.engine import observe  # noqa: E402

SCHEMA = "opentine-verify-everywhere/1"


def _record(case: Case) -> tuple[dict[str, Any], bool]:
    """The Python answer as a suite record, and whether Python itself crashed."""
    seen = observe(case)
    raw = case.input["bytes"]
    record: dict[str, Any] = {
        "id": case.id, "op": case.op, "args": case.args, "profile": "verifier",
        "input": {"bytes_b64": base64.b64encode(raw).decode("ascii"),
                  "sha256": hashlib.sha256(raw).hexdigest()},
    }  # fmt: skip
    if seen.exception is None:
        record.update(expect="accept", output=seen.output)
    else:
        record.update(expect="reject", reason=getattr(seen.exception, "code", None))
    return record, isinstance(seen.exception, CRASHES)


def _pyz_answer(conform: Any, record: dict, raw: bytes, groups: list) -> str | None:
    if record["op"] not in conform.OPS and record["op"] not in conform.KEYED:
        return f"pyz gap: {record['id']} ({record['op']})"
    try:
        out = conform.answer(record["op"], raw, None, record["args"], {})
        ok = _agrees(record, True, out, None, groups)
    except Exception as exc:  # noqa: BLE001 -- a refusal is the answer
        code = getattr(exc, "code", None)
        ok = not isinstance(exc, CRASHES) and _agrees(record, False, None, code, groups)
    return None if ok else f"pyz disagrees: {record['id']}"


def _ts_rows(records: list[dict], scratch: Path) -> dict[str, dict] | None:
    node = shutil.which("node")
    if node is None or not TS_PARITY.is_file():
        return None
    suite = scratch / "docs" / "conformance"
    (suite / "vectors").mkdir(parents=True)
    family = {"file": "vectors/everywhere.json"}
    manifest = {"families": [family], "alias_groups": [sorted(g) for g in _alias_groups()]}
    (suite / "MANIFEST.json").write_bytes(json.dumps(manifest).encode("utf-8"))
    (suite / "keys.json").write_bytes(b"{}")
    (suite / family["file"]).write_bytes(json.dumps({"cases": records}).encode("utf-8"))
    done = subprocess.run([node, str(TS_PARITY), str(scratch)], capture_output=True,
                          check=True, timeout=600)  # fmt: skip
    rows = [json.loads(line) for line in done.stdout.decode("utf-8").splitlines() if line]
    return {row["id"]: row for row in rows}


def _ts_problem(record: dict, row: dict | None, groups: list) -> str | None:
    if row is None or row["status"] in ("skip", "unsupported"):
        return f"ts gap: {record['id']} ({record['op']})"
    good = row["status"] == "pass"
    if good and record["expect"] == "reject" and record.get("reason") and row["reason"]:
        good = _agrees(record, False, None, row["reason"], groups)
    return None if good else f"ts disagrees: {record['id']}: {row.get('detail', '')}"


def _valid(record: dict) -> bool:
    if record["expect"] == "reject":
        return False
    return record["op"] != "sig.verify" or bool((record.get("output") or {}).get("ok"))


def compare(cases: list[Case], *, require_ts: bool = False, allow_invalid: bool = False,
            pyz: Any = None, scratch: Path | None = None) -> dict[str, Any]:  # fmt: skip
    """Every verifier's answer to every case; ``pyz`` replaces the built archive (tests)."""
    groups = _alias_groups()
    records, problems = [], []
    for case in cases:
        record, crashed = _record(case)
        records.append(record)
        if crashed:
            problems.append(f"python crashed: {case.id}")
        elif not allow_invalid and not _valid(record):
            problems.append(f"does not verify: {case.id} ({record.get('reason') or 'signature'})")
    with tempfile.TemporaryDirectory(dir=scratch) as tmp:
        ts = _ts_rows(records, Path(tmp)) if records else {}
    if ts is None and require_ts:
        raise FileNotFoundError("ts/verifier is not built (npm ci && npm run build)")
    with _built_pyz() if pyz is None else _given(pyz) as conform:
        for case, record in zip(cases, records, strict=True):
            problems.append(_pyz_answer(conform, record, case.input["bytes"], groups))
            if ts is not None:
                problems.append(_ts_problem(record, ts.get(record["id"]), groups))
    found = [p for p in problems if p]
    return {"schema": SCHEMA, "ok": not found, "cases": len(cases), "ts": ts is not None,
            "verifiers": ["python", "pyz", *(["ts"] if ts is not None else [])],
            "problems": found}  # fmt: skip


class _given:
    def __init__(self, module: Any) -> None:
        self.module = module

    def __enter__(self) -> Any:
        return self.module

    def __exit__(self, *_exc: object) -> None:
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("targets", nargs="+", type=Path, help="repository, bundle or folder")
    parser.add_argument("--require-ts", action="store_true", help="fail when TS is not built")
    parser.add_argument("--json", action="store_true", help="print one JSON report")
    parser.add_argument(
        "--allow-invalid",
        action="store_true",
        help="report only disagreements, not records every verifier refuses",
    )
    args = parser.parse_args(argv)
    cases: list[Case] = []
    problems: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        for target in args.targets:
            tine = tine_dir(target)
            if tine is not None:
                cases += repo_cases(tine)
            elif target.is_file() and target.read_bytes()[:11] == b"TINEBUNDLE1":
                cases += bundle_cases(target, Path(tmp), problems, TS_PARITY.with_name("cli.js"))
            elif target.exists():
                cases += file_cases(target)
            else:
                parser.error(f"{target} does not exist")
        try:
            report = compare(cases, require_ts=args.require_ts, allow_invalid=args.allow_invalid)
        except FileNotFoundError as exc:
            print(f"verify_everywhere: {exc}", file=sys.stderr)
            return 2
    report["problems"] = problems + report["problems"]
    report["ok"] = not report["problems"]
    if args.json:
        sys.stdout.buffer.write(json.dumps(report, indent=2, sort_keys=True).encode() + b"\n")
    else:
        for line in report["problems"]:
            print(line, file=sys.stderr)
        verdict = "ok" if report["ok"] else "FAIL"
        who, count = ", ".join(report["verifiers"]), len(report["problems"])
        print(f"verify_everywhere: {verdict}: {report['cases']} case(s), {who}, {count} problem(s)")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
