"""Emit ``docs/conformance/`` from the authored cases, or check it is current.

Three properties, in order of importance:

1. **Refuse to emit on disagreement.** Every case is run through ``adapter``
   and its observed disposition compared with the one the case declares. On
   disagreement the generator exits 2 naming the case and writes nothing.
2. **Regeneration is a byte-identical no-op.** ``--check`` regenerates into a
   scratch directory and diffs, so a hand-edited vector or a stale suite fails.
3. **Every file is digested in ``MANIFEST.json``**, including the golden compat
   fixtures the compat index points at -- a byte-level pin the existing
   backwards-compatibility gate does not have.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from opentine._version import __version__ as OPENTINE_VERSION
from tests.conformance import (
    cases_artifact,
    cases_canon,
    cases_compat,
    cases_objects,
    cases_repair,
    cases_repo,
    cases_signing,
)
from tests.conformance.cases import ACCEPT, REJECT, VERDICT, Case, Family
from tests.conformance.engine import INLINE_BYTE_LIMIT, build_record, observe, op_input
from tests.conformance.keys import KEYS
from tests.conformance.notes import RESOLUTIONS
from tests.conformance.opsmeta import OP_META
from tests.conformance.reasons import (
    ALIAS_GROUPS,
    BOUND_COVERAGE,
    NOT_VECTORED,
    REASONS,
    constant_value,
)

ROOT = Path(__file__).resolve().parents[2]
SUITE = ROOT / "docs" / "conformance"
SPEC = ROOT / "docs" / "SPEC.md"
SUITE_VERSION = 1
#: The suite files no generator writes. They are digested into ``MANIFEST.files`` all
#: the same: README step 2 tells a third party to verify every file's sha256, and the
#: harness they execute and the adapter contract they implement are the two files that
#: most need that check. A hand edit to one of them changes MANIFEST.json, which the
#: byte-identity gate then reports.
HAND_WRITTEN = ("PROTOCOL.md", "README.md", "report.schema.json", "run_conformance.py")
#: Ids that existed in a published suite and were retired. Never reused.
RETIRED_IDS: tuple[str, ...] = ("chain.previous-not-an-annotation",)

FAMILY_MODULES = (
    cases_canon,
    cases_objects,
    cases_repo,
    cases_artifact,
    cases_signing,
    cases_compat,
    cases_repair,
)


class GenerationError(RuntimeError):
    pass


def families() -> tuple[Family, ...]:
    found: list[Family] = []
    for module in FAMILY_MODULES:
        found.extend(module.FAMILIES)
    return tuple(sorted(found, key=lambda family: family.filename))


def all_cases() -> tuple[Case, ...]:
    return tuple(case for family in families() for case in family.cases)


def spec_version() -> str:
    match = re.search(r"opentine `docs/SPEC\.md`, version ([0-9.]+)\.", SPEC.read_text("utf-8"))
    if not match:
        raise GenerationError("docs/SPEC.md has no 'How to cite' version line")
    return match.group(1)


def _canonical_json_text(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _side_file(case: Case, raw: bytes) -> tuple[str, str, bytes] | None:
    """``(relative path, blob reference, bytes)`` when a case's input needs one."""
    forced = case.input.get("store")
    if "path" in case.input or "gen" in case.input:
        return None
    if forced is None and len(raw) <= INLINE_BYTE_LIMIT:
        return None
    digest = hashlib.sha256(raw).hexdigest()
    if forced == "frame":
        return f"frames/{digest}.pack", f"frames/{digest}.pack", raw
    return f"blobs/{digest}.bin", f"blobs/{digest}.bin", raw


def build() -> dict[str, bytes]:
    """The whole suite as ``relative path -> bytes``. Pure; touches no disk."""
    out: dict[str, bytes] = {}
    family_rows: list[dict[str, Any]] = []
    observed: dict[str, set[str]] = {}
    required: dict[str, set[str]] = {}
    seen: set[str] = set()
    for family in families():
        records: list[dict[str, Any]] = []
        for case in family.cases:
            if case.id in seen:
                raise GenerationError(f"duplicate case id: {case.id}")
            seen.add(case.id)
            observation = observe(case)
            expected = REJECT if case.expect == REJECT else ACCEPT
            if observation.disposition != expected:
                detail = (
                    f"{observation.exception!r}"
                    if observation.exception is not None
                    else json.dumps(observation.output, sort_keys=True)[:300]
                )
                raise GenerationError(
                    f"{case.id}: declared {case.expect!r} but the reference "
                    f"{observation.disposition}ed it -- {detail}"
                )
            _, raw = op_input(case)
            side = _side_file(case, raw) if raw is not None else None
            if side is not None:
                out[side[0]] = side[2]
            record = build_record(case, observation, side[1] if side else None)
            observed.setdefault(case.op, set()).update(
                key for key in record["input"] if key != "sha256"
            )
            needs = set(record.get("requires") or ())
            required[case.op] = needs if case.op not in required else required[case.op] & needs
            records.append(record)
        records.sort(key=lambda record: record["id"])
        body = _canonical_json_text(
            {
                "suite_version": SUITE_VERSION,
                "section": family.section,
                "family": family.name,
                "cases": records,
            }
        ).encode("ascii")
        out[f"vectors/{family.filename}"] = body
        family_rows.append(
            {
                "file": f"vectors/{family.filename}",
                "section": family.section,
                "name": family.name,
                "count": len(records),
                "reject": sum(1 for record in records if record["expect"] == REJECT),
                "verdict": sum(1 for record in records if record["expect"] == VERDICT),
                "core": sum(1 for record in records if record["tier"] == "core"),
                "stress": sum(1 for record in records if record["tier"] == "stress"),
                "ops": sorted({record["op"] for record in records}),
            }
        )
    out["keys.json"] = _canonical_json_text(
        {name: value.hex() for name, value in KEYS.items()}
    ).encode("ascii")
    out["REASON_CODES.md"] = _reason_codes_md().encode("utf-8")
    out["SPEC_NOTES.md"] = _spec_notes_md().encode("utf-8")
    out["compat/index.json"] = _compat_index().encode("ascii")
    out["MANIFEST.json"] = _manifest(out, family_rows, observed, required).encode("ascii")
    return out


def ops_table(
    observed: dict[str, set[str]], required: dict[str, set[str]]
) -> dict[str, dict[str, Any]]:
    """``OP_META`` with ``input`` replaced by the spellings the cases actually use.

    Hand-listing them let the table under-report: PROTOCOL tells an implementer to
    trust ``MANIFEST.ops`` over any prose copy, so the table has to be derived from
    the same records a runner reads. ``requires`` becomes what *every* case of the op
    needs, which is the only reading a runner can act on -- per-case ``requires`` is
    what it gates on, and this is their intersection.
    """
    table: dict[str, dict[str, Any]] = {}
    for name, meta in OP_META.items():
        row = dict(meta)
        row["input"] = sorted(observed.get(name, set()))
        row["requires"] = sorted(required.get(name, set()))
        table[name] = row
    return table


def _manifest(
    files: dict[str, bytes],
    family_rows: list[dict[str, Any]],
    observed: dict[str, set[str]],
    required: dict[str, set[str]],
) -> str:
    digests = {name: hashlib.sha256(body).hexdigest() for name, body in sorted(files.items())}
    for name in HAND_WRITTEN:
        digests[name] = hashlib.sha256((SUITE / name).read_bytes()).hexdigest()
    compat = json.loads(files["compat/index.json"])
    for release in compat["releases"]:
        for entry in release["files"]:
            digests[entry["path"]] = entry["sha256"]
    totals = {
        "cases": sum(row["count"] for row in family_rows),
        "reject": sum(row["reject"] for row in family_rows),
        "verdict": sum(row["verdict"] for row in family_rows),
        "core": sum(row["core"] for row in family_rows),
        "stress": sum(row["stress"] for row in family_rows),
        "families": len(family_rows),
        "ops": len(OP_META),
        "reason_codes": len(REASONS),
    }
    return _canonical_json_text(
        {
            "suite_version": SUITE_VERSION,
            "spec_version": spec_version(),
            "generated_by": f"opentine {OPENTINE_VERSION}",
            "profiles": ["reader", "writer", "verifier"],
            "levels": {
                "1": "reject-parity: every accept produces the exact output, every "
                "reject is refused",
                "2": "diagnostic-parity: Level 1, plus each rejection reported with the "
                "vector's reason code (or any code in its alias group)",
            },
            "ops": ops_table(observed, required),
            "alias_groups": [list(group) for group in ALIAS_GROUPS],
            "families": sorted(family_rows, key=lambda row: row["file"]),
            "files": digests,
            "totals": totals,
            "bound_coverage": {name: list(ids) for name, ids in BOUND_COVERAGE.items()},
            "retired_ids": list(RETIRED_IDS),
            "not_vectored": NOT_VECTORED,
        }
    )


def _reason_codes_md() -> str:
    used: dict[str, int] = {}
    for case in all_cases():
        for code in (case.reason,) if case.reason else (case.reason_any or ()):
            used[code] = used.get(code, 0) + 1
    lines = [
        "# Reason codes",
        "",
        "Generated by `scripts/gen_conformance_vectors.py`. Do not edit.",
        "",
        "Every `reason` a vector can carry, anchored to a `docs/SPEC.md` section rather",
        "than to the reference implementation's message -- because those messages are",
        "conflated (a lone surrogate and a depth failure report the same string, a",
        "`schema` of `2**53` reports the *integer* error, an oversized header reports",
        "`malformed object envelope` rather than a size error). Each row's last column is",
        "the repair an",
        "implementation MUST NOT perform instead of refusing: doing it scores",
        "`REPAIRED`, which is worse than `FAIL`.",
        "",
        "## The single-fault rule",
        "",
        "Every vector violates **exactly one** rule. The reference's check order is",
        "fixed and undocumented -- `verify_block` checks `scheme` before `alg`, and",
        "`ObjectEnvelope.decode` runs the 256-byte header check *inside* the framing",
        "`try` -- so two honest implementations will disagree about any multi-fault",
        "input. The few deliberately compound cases carry `reason_any` (a set of",
        "acceptable codes) instead of `reason`; the two fields are mutually exclusive.",
        "",
        "## Alias groups",
        "",
        "Where the reference genuinely cannot tell two rules apart, the codes stay",
        "distinct -- the *rules* are distinct -- and the pair is listed here. At Level 2",
        "a runner accepts any code from the expected code's group, so an implementation",
        "whose diagnostics are as coarse as the reference's is not marked wrong for it.",
        "",
    ]
    for group in ALIAS_GROUPS:
        lines.append("* " + " == ".join(f"`{code}`" for code in group))
    lines += [
        "",
        f"## The codes ({len(REASONS)})",
        "",
        "| code | SPEC | bound | refuses | MUST NOT repair by |",
        "|---|---|---|---|---|",
    ]
    for code, reason in sorted(REASONS.items()):
        bound = "--"
        if reason.constant:
            live = constant_value(reason.constant)
            bound = f"`{reason.constant}`" + (f" = {live}" if live is not None else "")
        lines.append(
            f"| `{code}` | {reason.section} | {bound} | {reason.refuses} | {reason.never} |"
        )
    lines += [
        "",
        "## Not vectored, and why",
        "",
        "A bound with no vector is a bound an implementer cannot check, so each one is",
        "named here with its reason. `test_conformance_drift` requires every row of",
        "SPEC 1.6 to have either an at/over pair, a `reachable: false` case, or an entry",
        "below with non-empty prose.",
        "",
    ]
    for name, why in sorted(NOT_VECTORED.items()):
        lines.append(f"### `{name}`")
        lines.append("")
        lines.append(why)
        lines.append("")
    unused = sorted(set(REASONS) - set(used))
    if unused:
        raise GenerationError(f"registered but unused reason codes: {unused}")
    unknown = sorted(set(used) - set(REASONS))
    if unknown:
        raise GenerationError(f"cases use unregistered reason codes: {unknown}")
    return "\n".join(lines)


def _spec_notes_md() -> str:
    notes = sorted({case.spec_note for case in all_cases() if case.spec_note})
    lines = [
        "# Spec notes",
        "",
        "Generated by `scripts/gen_conformance_vectors.py`. Do not edit.",
        "",
        "Each row is a place where building a vector found `docs/SPEC.md`'s prose and",
        "the reference implementation's behaviour not quite lining up. **The resolution",
        "column is mandatory** -- a note with no resolution fails the drift gate -- so",
        "this file cannot become a graveyard of open disagreements. An empty table is a",
        "success.",
        "",
    ]
    if not notes:
        lines.append("_No open notes._")
    for note in notes:
        resolution = RESOLUTIONS.get(note)
        if not resolution:
            raise GenerationError(f"spec_note has no resolution in notes.RESOLUTIONS: {note!r}")
        cited = sorted(case.id for case in all_cases() if case.spec_note == note)
        lines += [
            f"## {cited[0]}",
            "",
            f"**Cases:** {', '.join(f'`{name}`' for name in cited)}",
            "",
            f"**Note:** {note}",
            "",
            f"**Resolution:** {resolution}",
            "",
        ]
    return "\n".join(lines)


def _compat_index() -> str:
    from tests.conformance.compat_index import build_index

    return _canonical_json_text(build_index())


def write(destination: Path) -> list[str]:
    built = build()
    for name, body in sorted(built.items()):
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    return sorted(built)


def check(destination: Path) -> list[str]:
    """Paths that differ between the built suite and what is on disk."""
    built = build()
    problems: list[str] = []
    for name, body in sorted(built.items()):
        path = destination / name
        if not path.is_file():
            problems.append(f"missing: {name}")
        elif path.read_bytes() != body:
            problems.append(f"stale: {name}")
    generated = set(built)
    for directory in ("vectors", "blobs", "frames", "compat"):
        base = destination / directory
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and path.relative_to(destination).as_posix() not in generated:
                problems.append(f"orphan: {path.relative_to(destination).as_posix()}")
    return problems


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        if "--check" in arguments:
            problems = check(SUITE)
            if problems:
                print("\n".join(problems), file=sys.stderr)
                return 1
            print(f"conformance suite is current: {len(build())} files")
            return 0
        written = write(SUITE)
        totals = json.loads((SUITE / "MANIFEST.json").read_text("utf-8"))["totals"]
        print(
            f"wrote {len(written)} files: {totals['cases']} cases "
            f"({totals['reject']} reject, {totals['verdict']} verdict, "
            f"{totals['stress']} stress) across {totals['families']} families"
        )
        return 0
    except GenerationError as exc:
        print(f"conformance generation refused: {exc}", file=sys.stderr)
        return 2
