"""Run the OpenTine conformance suite against any implementation.

Standard library only, and it imports no ``opentine``: this file is a harness,
not a second reference. It speaks the line-delimited JSON protocol in
``PROTOCOL.md`` to an adapter you write (about eighty lines in most languages),
so the work of proving conformance is implementing your own reader -- not
reimplementing a runner from prose.

    python docs/conformance/run_conformance.py \\
        --adapter "./target/release/tine-conformance" \\
        --profile reader,verifier --level 2 --report conformance.json

Exit status is 0 when nothing failed and nothing was silently repaired.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

SUITE = Path(__file__).resolve().parent
PASS, FAIL, REPAIRED, SKIP, UNSUPPORTED = "pass", "fail", "repaired", "skip", "unsupported"


# --------------------------------------------------------------------------- #
# The tagged value encoding (PROTOCOL.md); about a dozen lines in any language.
# The runner forwards input.value verbatim -- decoding the tags is the adapter's job.
# --------------------------------------------------------------------------- #


def assemble_value(recipe: dict[str, Any]) -> Any:
    node: Any = recipe["inner"]
    for _ in range(int(recipe["depth"])):
        node = [node] if recipe.get("container", "array") == "array" else {recipe["key"]: node}
    return node


def assemble_bytes(recipe: dict[str, Any]) -> bytes:
    kind = recipe["kind"]
    if kind == "nest":
        depth = int(recipe["depth"])
        return (recipe["open"] * depth + recipe["inner"] + recipe["close"] * depth).encode()
    if kind == "repeat":
        prefix = base64.b64decode(recipe.get("prefix_b64", ""))
        suffix = base64.b64decode(recipe.get("suffix_b64", ""))
        return prefix + base64.b64decode(recipe["unit_b64"]) * int(recipe["count"]) + suffix
    if kind == "fill":
        return bytes([int(recipe["byte"])]) * int(recipe["count"])
    if kind == "oids":
        start, count = int(recipe.get("start", 0)), int(recipe["count"])
        end = recipe.get("terminator", "\n")
        return "".join(
            f"{recipe['object_type']}:sha256:{index:064x}{end}"
            for index in range(start, start + count)
        ).encode("ascii")
    raise ValueError(f"unknown input.gen recipe: {kind!r}")


def resolve_input(spec: dict[str, Any], root: Path) -> tuple[dict[str, Any], bytes | None]:
    """The request's ``input`` field, plus the bytes to check ``input.sha256`` against."""
    if "value" in spec:
        return {"value": spec["value"]}, None
    if "gen" in spec and spec["gen"]["kind"] == "nest-value":
        return {"value": assemble_value(spec["gen"])}, None
    if "gen" in spec:
        raw = assemble_bytes(spec["gen"])
    elif "blob" in spec:
        raw = (SUITE / spec["blob"]).read_bytes()
    elif "path" in spec:
        raw = (root / spec["path"]).read_bytes()
    else:
        raw = base64.b64decode(spec["bytes_b64"])
    return {"bytes_b64": base64.b64encode(raw).decode("ascii")}, raw


def canonical_output(output: Any) -> bytes:
    return json.dumps(output, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


# --------------------------------------------------------------------------- #
# Comparison
# --------------------------------------------------------------------------- #


def normalize(output: Any, unordered: list[str]) -> Any:
    if not isinstance(output, dict):
        return output
    copied = dict(output)
    for field in unordered:
        if isinstance(copied.get(field), list):
            copied[field] = sorted(copied[field], key=repr)
    return copied


def matches(actual: Any, expected: Any, unordered: list[str]) -> bool:
    return normalize(actual, unordered) == normalize(expected, unordered)


def subset_matches(actual: Any, forbidden: Any, unordered: list[str]) -> bool:
    """``forbidden`` names only the fields that give the repair away."""
    if not isinstance(actual, dict) or not isinstance(forbidden, dict):
        return actual == forbidden
    left, right = normalize(actual, unordered), normalize(forbidden, unordered)
    return all(key in left and left[key] == value for key, value in right.items()) and bool(right)


def reason_ok(actual: Any, case: dict[str, Any], groups: list[list[str]]) -> bool:
    expected = set(case.get("reason_any") or ([case["reason"]] if case.get("reason") else []))
    if not expected:
        return True
    allowed = set(expected)
    for group in groups:
        if allowed & set(group):
            allowed |= set(group)
    return actual in allowed


# --------------------------------------------------------------------------- #
# The adapter process
# --------------------------------------------------------------------------- #


class Adapter:
    def __init__(self, command: str) -> None:
        # POSIX shell-word rules would read every backslash in a Windows path
        # ("D:\\a\\python.exe") as an escape, so on Windows the command is the
        # native command line it already is, parsed by CreateProcess itself.
        self.process = subprocess.Popen(
            command if os.name == "nt" else shlex.split(command),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def ask(self, request: dict[str, Any]) -> dict[str, Any]:
        assert self.process.stdin and self.process.stdout
        self.process.stdin.write(json.dumps(request, ensure_ascii=True) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError("the adapter closed its output before answering")
        return json.loads(line)

    def close(self) -> None:
        if self.process.stdin:
            self.process.stdin.close()
        self.process.wait(timeout=30)


# --------------------------------------------------------------------------- #
# The run
# --------------------------------------------------------------------------- #


def load_suite(manifest: dict[str, Any]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    found: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for family in manifest["families"]:
        data = json.loads((SUITE / family["file"]).read_text("utf-8"))
        for case in data["cases"]:
            found.append((family, case))
    return found


def verify_digests(manifest: dict[str, Any], root: Path) -> list[str]:
    problems = []
    for name, expected in sorted(manifest["files"].items()):
        path = SUITE / name if (SUITE / name).exists() else root / name
        if not path.is_file():
            problems.append(f"missing file: {name}")
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            problems.append(f"digest mismatch: {name}")
    return problems


def run_case(
    adapter: Adapter,
    case: dict[str, Any],
    ops: dict[str, Any],
    root: Path,
    level: int,
    groups: list[list[str]],
) -> dict[str, Any]:
    meta = ops.get(case["op"], {})
    unordered = list(meta.get("unordered") or [])
    row = {
        "id": case["id"],
        "op": case["op"],
        "section": case["section"],
        "expected": case["expect"],
        "reason_expected": case.get("reason"),
        "status": FAIL,
        "actual": None,
        "reason_actual": None,
        "detail": "",
    }
    resolved, raw = resolve_input(case["input"], root)
    if raw is not None and "sha256" in case["input"]:
        if hashlib.sha256(raw).hexdigest() != case["input"]["sha256"]:
            row["detail"] = "assembled input does not match input.sha256"
            return row
    response = adapter.ask(
        {"id": case["id"], "op": case["op"], "input": resolved, "args": case.get("args", {})}
    )
    if response.get("unsupported"):
        row["status"] = UNSUPPORTED
        return row
    accepted = bool(response.get("ok"))
    row["actual"] = "accept" if accepted else "reject"
    row["reason_actual"] = response.get("reason")
    if case["expect"] == "reject":
        if accepted:
            if case.get("forbidden") and subset_matches(
                response.get("output"), case["forbidden"], unordered
            ):
                row["status"] = REPAIRED
                row["detail"] = "accepted and silently repaired the input"
            else:
                row["detail"] = "accepted input the format requires be refused"
            return row
        if level >= 2 and not reason_ok(response.get("reason"), case, groups):
            row["detail"] = f"expected reason {case.get('reason')!r}"
            return row
        row["status"] = PASS
        return row
    if not accepted:
        row["detail"] = f"refused a valid input: {response.get('reason')!r}"
        return row
    output = response.get("output")
    if "output_sha256" in case:
        digest = hashlib.sha256(canonical_output(normalize(output, unordered))).hexdigest()
        if digest != case["output_sha256"]:
            row["detail"] = "output digest does not match output_sha256"
            return row
    elif not matches(output, case.get("output"), unordered):
        row["detail"] = f"output mismatch: {json.dumps(output, sort_keys=True)[:200]}"
        return row
    row["status"] = PASS
    row["output"] = output
    return row


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", required=True, help="command that speaks PROTOCOL.md")
    parser.add_argument("--profile", default="reader,writer,verifier")
    parser.add_argument("--level", type=int, default=1, choices=(1, 2))
    parser.add_argument("--tier", default="core", help="core, stress, or core,stress")
    parser.add_argument("--report", help="write report.json here")
    parser.add_argument("--root", default=str(SUITE.parents[1]), help="repository root")
    parser.add_argument("--name", default="unknown")
    parser.add_argument("--version", default="unknown")
    parser.add_argument("--language", default="unknown")
    parser.add_argument(
        "--capability",
        action="append",
        default=[],
        help="a capability you have, e.g. zlib or ed25519 (repeatable)",
    )
    options = parser.parse_args(argv)

    root = Path(options.root).resolve()
    manifest = json.loads((SUITE / "MANIFEST.json").read_text("utf-8"))
    problems = verify_digests(manifest, root)
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 2

    profiles = set(options.profile.split(","))
    tiers = set(options.tier.split(","))
    capabilities = set(options.capability)
    groups = [list(group) for group in manifest["alias_groups"]]
    ops = manifest["ops"]

    selected = [
        (family, case)
        for family, case in load_suite(manifest)
        if case["profile"] in profiles and case["tier"] in tiers
    ]
    # The tagged-number self-test runs first: no other result means anything
    # until an implementation reads the encoding the inputs are written in.
    selected.sort(key=lambda item: (item[0]["file"] != "vectors/01-selftest.json",))

    adapter = Adapter(options.adapter)
    results: list[dict[str, Any]] = []
    try:
        for _, case in selected:
            missing = set(case.get("requires") or []) - capabilities
            if missing:
                results.append(
                    {
                        "id": case["id"],
                        "op": case["op"],
                        "section": case["section"],
                        "expected": case["expect"],
                        "status": SKIP,
                        "actual": None,
                        "reason_expected": case.get("reason"),
                        "reason_actual": None,
                        "detail": f"requires {sorted(missing)}",
                    }
                )
                continue
            results.append(run_case(adapter, case, ops, root, options.level, groups))
    finally:
        adapter.close()

    # must_differ is checked here rather than inside a case: it is a claim about
    # *two* answers, and an implementation that returns one constant would pass
    # every individual comparison and still be wrong about the pair.
    outputs = {row["id"]: row.get("output") for row in results}
    for _, case in selected:
        if case.get("must_differ") is None or case["twin"] not in outputs:
            continue
        row = next(item for item in results if item["id"] == case["id"])
        if row["status"] != PASS:
            continue
        differ = outputs[case["id"]] != outputs[case["twin"]]
        if differ != case["must_differ"]:
            row["status"] = FAIL
            row["detail"] = (
                f"must_differ is {case['must_differ']} against {case['twin']}, "
                f"but the two answers {'differ' if differ else 'agree'}"
            )

    by_id = {row["id"]: row for row in results}
    twins = {
        case["id"]: case["twin"]
        for _, case in selected
        if case.get("twin") and case["twin"] in by_id and case["id"] in by_id
    }
    pairs_total = len(twins)
    pairs_passed = sum(
        1
        for left, right in twins.items()
        if by_id[left]["status"] == PASS and by_id[right]["status"] == PASS
    )
    totals = {
        state: sum(1 for row in results if row["status"] == state)
        for state in (PASS, FAIL, REPAIRED, SKIP, UNSUPPORTED)
    }
    checked = [
        row for row in results if row["status"] in (PASS, FAIL, REPAIRED) and row["reason_expected"]
    ]
    agreement = sum(
        1
        for row in checked
        if row["reason_actual"]
        and reason_ok(row["reason_actual"], {"reason": row["reason_expected"]}, groups)
    )
    report = {
        "suite_version": manifest["suite_version"],
        "spec_version": manifest["spec_version"],
        "implementation": {
            "name": options.name,
            "version": options.version,
            "language": options.language,
        },
        "level": options.level,
        "profiles": sorted(profiles),
        "tiers": sorted(tiers),
        "totals": totals,
        "pairs": {"total": pairs_total, "passed": pairs_passed},
        "reason_agreement": {"total": len(checked), "agreed": agreement},
        "results": results,
    }
    if options.report:
        Path(options.report).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    print(
        f"{totals[PASS]} pass  {totals[FAIL]} fail  {totals[REPAIRED]} repaired  "
        f"{totals[SKIP]} skip  {totals[UNSUPPORTED]} unimplemented  |  "
        f"pairs {pairs_passed}/{pairs_total}  |  "
        f"reason agreement {agreement}/{len(checked)}"
    )
    for row in results:
        if row["status"] in (FAIL, REPAIRED):
            print(
                f"  {row['status'].upper():8} SPEC {row['section']:<6} {row['id']}: {row['detail']}"
            )
    return 0 if totals[FAIL] == 0 and totals[REPAIRED] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
