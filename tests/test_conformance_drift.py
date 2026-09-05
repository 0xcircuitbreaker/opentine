"""The meta-gates that keep ``docs/conformance/`` honest.

The vectors are generated from the implementation, so their *values* are true by
construction. What is not true by construction is that the suite on disk is the
suite the generator would produce, that every code it names is documented, that
every bound the spec claims is actually reachable by some vector, and that the
compat index still describes the fixture set the compatibility gate iterates.
Those are this module's job.

This module shells ``git`` (gate 3) and is declared in
``tests/test_release_audit_round11_misc.py::BINARY_DEPENDENT_TEST_MODULES``.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.conformance import tagged
from tests.conformance.generate import (
    HAND_WRITTEN,
    SUITE,
    all_cases,
    build,
    families,
    spec_version,
)
from tests.conformance.notes import RESOLUTIONS
from tests.conformance.opsmeta import OP_META
from tests.conformance.reasons import (
    ALIAS_GROUPS,
    BOUND_COVERAGE,
    NOT_VECTORED,
    REASONS,
    constant_value,
)

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "docs" / "SPEC.md"
MANIFEST = json.loads((SUITE / "MANIFEST.json").read_text("utf-8"))
VECTOR_FILES = sorted((SUITE / "vectors").glob("*.json"))
#: Byte-compiled caches and dotfiles are not suite content. Importing the suite's
#: own ``run_conformance.py`` writes ``docs/conformance/__pycache__/``, which an
#: unfiltered walk reported as a stray generated file and as a git-ignored suite
#: file -- two failures that blamed the generator for a .pyc.
_SKIP_DIRS = {"__pycache__"}


def _suite_files() -> list[Path]:
    return [
        path
        for path in sorted(SUITE.rglob("*"))
        if path.is_file()
        and not (set(path.parts) & _SKIP_DIRS)
        and not any(part.startswith(".") for part in path.relative_to(SUITE).parts)
    ]


RECORDS = {
    record["id"]: record
    for path in VECTOR_FILES
    for record in json.loads(path.read_text("utf-8"))["cases"]
}

#: The per-family census this release ships. Restated here on purpose: gate 15
#: is the one place a silently dropped family or a quietly added case shows up
#: as a diff a human has to approve.
EXPECTED_COUNTS = {
    "vectors/00-text.json": (16, 10),
    "vectors/01-selftest.json": (7, 0),
    "vectors/02-canon-v3.json": (34, 8),
    "vectors/03-canon-v2.json": (26, 3),
    "vectors/04-divergence.json": (16, 1),
    "vectors/05-shape.json": (12, 6),
    "vectors/12-envelope.json": (26, 17),
    "vectors/13-oid.json": (16, 6),
    "vectors/14-redaction.json": (12, 0),
    "vectors/15-links.json": (39, 21),
    "vectors/15b-metrics.json": (22, 11),
    "vectors/15c-graph.json": (16, 8),
    "vectors/15d-load.json": (10, 5),
    "vectors/16-bounds.json": (30, 15),
    "vectors/22-layout.json": (12, 6),
    "vectors/24-refs.json": (34, 22),
    "vectors/26-reflog.json": (8, 2),
    "vectors/27-shallow.json": (14, 6),
    "vectors/28-pack.json": (30, 19),
    "vectors/31-artifact-v2.json": (20, 11),
    "vectors/35-integrity.json": (12, 0),
    "vectors/42-signing.json": (37, 4),
    "vectors/47-verdict.json": (20, 0),
    "vectors/51-compat.json": (40, 0),
    "vectors/99-repair.json": (14, 14),
}

#: The cases whose input genuinely breaks more than one rule, and which therefore
#: carry ``reason_any`` instead of pinning the reference's undocumented check
#: order. Pinned here so adding or removing one is a diff a human approves --
#: REASON_CODES.md's single-fault rule is only true while this set is right.
EXPECTED_COMPOUND = {
    "bounds.shallow.over-1-mib",
    "env.schema.at-2-53",
    "pack.install.unresolved-link",
}

#: The one capability a case can declare that the op table cannot: a string type
#: that holds an unpaired UTF-16 surrogate.
WTF8 = "wtf8"


# --- 1. regeneration ---------------------------------------------------------


def test_regenerating_the_suite_is_byte_identical(tmp_path: Path) -> None:
    """A hand-edited vector, or a stale suite, fails here and nowhere else."""
    built = build()
    on_disk = {
        path.relative_to(SUITE).as_posix(): path.read_bytes()
        for path in _suite_files()
        if path.name not in set(HAND_WRITTEN)
    }
    assert sorted(built) == sorted(on_disk), "the generated file set changed"
    for name in sorted(built):
        assert built[name] == on_disk[name], f"{name} is not what the generator produces"


# --- 2. digests --------------------------------------------------------------


def test_every_manifest_digest_recomputes() -> None:
    for name, expected in sorted(MANIFEST["files"].items()):
        path = SUITE / name if (SUITE / name).exists() else ROOT / name
        assert path.is_file(), name
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, name


# --- 3. nothing in the suite is invisible to git -----------------------------


def test_no_suite_file_is_git_ignored() -> None:
    """The root .gitignore excludes ``*.tine``; a suite file matching any ignore
    rule would be untracked, dropped from the sdist, and only caught by the
    release inventory gate long after review."""
    if shutil.which("git") is None:
        pytest.skip("git is not installed here")
    paths = [str(path.relative_to(ROOT)) for path in _suite_files()]
    assert paths
    result = subprocess.run(
        ["git", "-C", str(ROOT), "check-ignore", "--stdin"],
        input="\n".join(paths),
        capture_output=True,
        text=True,
    )
    assert not result.stdout.strip(), f"git ignores suite files:\n{result.stdout}"


# --- 4. encoding -------------------------------------------------------------


def test_every_vector_file_is_pure_ascii() -> None:
    for path in VECTOR_FILES:
        path.read_bytes().decode("ascii")  # raises if not


def test_no_bare_json_number_survives_in_a_tagged_input() -> None:
    """``input.value`` uses $i/$f for every number, so no consumer has to guess."""
    for record in RECORDS.values():
        if "value" in record["input"]:
            assert not tagged.contains_bare_number(record["input"]["value"]), record["id"]


# --- 5. input digests --------------------------------------------------------


def test_every_byte_shaped_input_matches_its_digest() -> None:
    from tests.conformance.engine import op_input

    for case in all_cases():
        _, raw = op_input(case)
        record = RECORDS[case.id]
        if raw is None:
            assert "sha256" not in record["input"], case.id
            continue
        assert hashlib.sha256(raw).hexdigest() == record["input"]["sha256"], case.id


# --- 6/7. the reason registry ------------------------------------------------


def test_every_reason_code_is_registered_and_every_registered_code_is_used() -> None:
    used: set[str] = set()
    for record in RECORDS.values():
        codes = record.get("reason_any") or ([record["reason"]] if record.get("reason") else [])
        used |= set(codes)
    assert used <= set(REASONS), sorted(used - set(REASONS))
    assert set(REASONS) <= used, sorted(set(REASONS) - used)


def test_reason_code_rows_carry_the_live_value_of_the_bound_they_name() -> None:
    document = (SUITE / "REASON_CODES.md").read_text("utf-8")
    checked = 0
    for code, reason in sorted(REASONS.items()):
        if not reason.constant:
            continue
        live = constant_value(reason.constant)
        expected = f"`{reason.constant}`" + (f" = {live}" if live is not None else "")
        assert f"| `{code}` |" in document, code
        row = next(line for line in document.splitlines() if line.startswith(f"| `{code}` |"))
        assert expected in row, f"{code}: expected {expected!r} in {row!r}"
        checked += live is not None
    assert checked >= 8


def test_alias_groups_only_name_registered_codes() -> None:
    for group in ALIAS_GROUPS:
        assert set(group) <= set(REASONS), group
        assert len(set(group)) == len(group), group


# --- 8. sections -------------------------------------------------------------


def test_every_section_string_occurs_in_the_spec() -> None:
    spec = SPEC.read_text("utf-8")
    for record in RECORDS.values():
        section = record["section"]
        assert re.search(rf"^#+ {re.escape(section)}[ .]", spec, re.M) or (
            f"SPEC {section}" in spec or f"§{section}" in spec or f"Part {section}" in spec
        ), f"{record['id']} cites SPEC {section}, which the document has no heading for"


# --- 9. the rejection table --------------------------------------------------


def _spec_bound_rows() -> list[str]:
    spec = SPEC.read_text("utf-8")
    start = spec.index("## 1.6 The complete rejection table")
    end = spec.index("\n---", start)
    rows = []
    for line in spec[start:end].splitlines():
        if not line.startswith("|") or line.startswith("|---") or "| Bound " in line:
            continue
        rows.append(line.split("|")[1].strip())
    return rows


def test_every_rejection_table_row_is_vectored_or_has_a_written_reason() -> None:
    rows = _spec_bound_rows()
    assert len(rows) >= 25
    for bound in rows:
        assert bound in BOUND_COVERAGE, f"SPEC 1.6 row {bound!r} has no conformance coverage"
        for entry in BOUND_COVERAGE[bound]:
            if entry.startswith("NOT_VECTORED:"):
                key = entry.split(":", 1)[1]
                assert key in NOT_VECTORED, key
                assert len(NOT_VECTORED[key]) > 80, key
            else:
                assert entry in RECORDS, f"{bound}: {entry} names no case"
    assert set(BOUND_COVERAGE) == set(rows), set(BOUND_COVERAGE) ^ set(rows)


def test_every_not_vectored_entry_has_prose() -> None:
    for name, why in NOT_VECTORED.items():
        assert len(why) > 80, name
        assert why == why.strip(), name


# --- 10/11. coverage ---------------------------------------------------------


def test_every_conformance_checklist_item_has_at_least_three_core_cases() -> None:
    counts = {item: 0 for item in range(1, 10)}
    for record in RECORDS.values():
        if record["tier"] != "core":
            continue
        for item in record["checklist"]:
            counts[item] = counts.get(item, 0) + 1
    thin = {item: count for item, count in counts.items() if count < 3}
    assert not thin, f"SPEC Part 6 items with fewer than three core cases: {thin}"


def test_every_op_has_at_least_one_core_case() -> None:
    covered = {record["op"] for record in RECORDS.values() if record["tier"] == "core"}
    assert covered == set(OP_META), set(OP_META) ^ covered


def test_every_case_profile_matches_its_op() -> None:
    for record in RECORDS.values():
        assert record["profile"] == OP_META[record["op"]]["profile"], record["id"]


# --- 12. twins ---------------------------------------------------------------


def test_every_twin_resolves() -> None:
    for record in RECORDS.values():
        twin = record.get("twin")
        if twin is None:
            continue
        assert twin in RECORDS, f"{record['id']} twins {twin}, which does not exist"
        assert twin != record["id"], record["id"]


def test_a_twin_pair_is_the_point_of_the_pair() -> None:
    """A twin either flips the disposition or pins a must_differ comparison."""
    for record in RECORDS.values():
        twin = record.get("twin")
        if twin is None:
            continue
        other = RECORDS[twin]
        flipped = record["expect"] != other["expect"]
        compared = record.get("must_differ") is not None or record["op"] != other["op"]
        assert flipped or compared, f"{record['id']} and {twin} prove nothing together"


def test_must_differ_says_the_truth_about_the_two_pinned_outputs() -> None:
    """The flag is checked here as well as by the runner, because a pair whose
    halves happen to agree would otherwise silently stop proving anything."""
    checked = 0
    for record in RECORDS.values():
        if record.get("must_differ") is None:
            continue
        other = RECORDS[record["twin"]]
        differ = record.get("output") != other.get("output")
        assert differ == record["must_differ"], record["id"]
        checked += 1
    assert checked >= 12


# --- 13. spec notes ----------------------------------------------------------


def test_every_spec_note_has_a_resolution_and_appears_verbatim() -> None:
    document = (SUITE / "SPEC_NOTES.md").read_text("utf-8")
    notes = {record["spec_note"] for record in RECORDS.values() if record.get("spec_note")}
    assert notes
    for note in sorted(notes):
        assert note in RESOLUTIONS, note
        assert RESOLUTIONS[note].strip(), note
        assert note in document, note
        assert RESOLUTIONS[note] in document, note
    assert set(RESOLUTIONS) == notes, set(RESOLUTIONS) ^ notes


# --- 14. one fault per vector ------------------------------------------------


def test_reason_and_reason_any_are_mutually_exclusive() -> None:
    for record in RECORDS.values():
        has_one = "reason" in record
        has_many = "reason_any" in record
        assert not (has_one and has_many), record["id"]
        assert (record["expect"] == "reject") == (has_one or has_many), record["id"]


def test_an_output_pinned_by_digest_is_stress_tier() -> None:
    for record in RECORDS.values():
        if "output_sha256" in record:
            assert record["tier"] == "stress", record["id"]
            assert "output" not in record, record["id"]


# --- 15. the census ----------------------------------------------------------


def test_family_counts_match_the_manifest_and_the_pinned_table() -> None:
    rows = {row["file"]: row for row in MANIFEST["families"]}
    assert set(rows) == set(EXPECTED_COUNTS)
    for name, (count, reject) in sorted(EXPECTED_COUNTS.items()):
        assert (rows[name]["count"], rows[name]["reject"]) == (count, reject), name
        data = json.loads((SUITE / name).read_text("utf-8"))
        assert len(data["cases"]) == count, name
    totals = MANIFEST["totals"]
    assert totals["cases"] == sum(count for count, _ in EXPECTED_COUNTS.values())
    assert totals["reject"] == sum(reject for _, reject in EXPECTED_COUNTS.values())


def test_case_ids_are_unique_and_never_reuse_a_retired_id() -> None:
    ids = [case.id for family in families() for case in family.cases]
    assert len(ids) == len(set(ids))
    assert not set(ids) & set(MANIFEST["retired_ids"])


def test_the_manifest_names_the_spec_version_the_document_cites() -> None:
    assert MANIFEST["spec_version"] == spec_version()


# --- 16. compat --------------------------------------------------------------


def test_the_compat_index_covers_exactly_the_backwards_compatibility_gate() -> None:
    from tests.test_backwards_compat import ARTIFACTS, GOLDEN

    index = json.loads((SUITE / "compat" / "index.json").read_text("utf-8"))
    releases = {entry["version"]: entry for entry in index["releases"]}
    assert set(releases) == {golden.version for golden in GOLDEN}
    for golden in GOLDEN:
        entry = releases[golden.version]
        assert entry["fork_records_identity"] == golden.fork_records_identity
        assert entry["repo"]["main_oid"] == golden.repo_main_oid
        assert entry["repo"]["fork_oid"] == golden.repo_fork_oid
        assert set(entry["artifacts"]) == set(ARTIFACTS)
        assert entry["artifacts"]["fork.tine"]["run_id"] == golden.fork_id
        assert entry["artifacts"]["fork.tine"]["fork_id_verdict"] == (
            "confirm" if golden.fork_records_identity else "abstain"
        )
        assert entry["repo"]["fsck_ok"] is True
        assert all(row["integrity_ok"] for row in entry["artifacts"].values())


def test_the_compat_index_pins_no_reflog_bytes() -> None:
    """Reflog rows embed ``time.time_ns()`` and are the one non-reproducible part
    of a fixture; pinning them would make the index a trap for the next release."""
    index = json.loads((SUITE / "compat" / "index.json").read_text("utf-8"))
    for release in index["releases"]:
        for entry in release["files"]:
            assert "/logs/" not in entry["path"], entry["path"]


def test_the_compat_index_digests_still_match_the_fixtures() -> None:
    index = json.loads((SUITE / "compat" / "index.json").read_text("utf-8"))
    for release in index["releases"]:
        for entry in release["files"]:
            path = ROOT / entry["path"]
            assert path.is_file(), entry["path"]
            assert hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"]


# --- the generator's own contract -------------------------------------------


def test_only_the_adapter_modules_import_opentine_at_run_time() -> None:
    """The neutral runner must stay neutral: it may not import ``opentine``."""
    source = (SUITE / "run_conformance.py").read_text("utf-8")
    for node in ast.walk(ast.parse(source)):
        names = []
        if isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        elif isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        for name in names:
            assert not name.startswith("opentine"), f"run_conformance.py imports {name}"


# --- 17. capabilities --------------------------------------------------------


def test_every_case_carries_the_capabilities_its_op_needs() -> None:
    """A runner gates on ``case.requires``; an op-level capability that never
    reached a case was inert, so ``--capability zlib`` changed nothing and 33
    pack cases were dispatched to consumers that had said they have no zlib."""
    ops = MANIFEST["ops"]
    for record in RECORDS.values():
        declared = set(ops[record["op"]]["requires"])
        carried = set(record.get("requires") or ())
        assert declared <= carried, f"{record['id']} is missing {sorted(declared - carried)}"


def test_an_op_declares_exactly_what_every_one_of_its_cases_requires() -> None:
    """``MANIFEST.ops.<op>.requires`` is the intersection over that op's cases --
    the only reading a runner can act on without over-skipping."""
    ops = MANIFEST["ops"]
    common: dict[str, set[str]] = {}
    for record in RECORDS.values():
        needs = set(record.get("requires") or ())
        name = record["op"]
        common[name] = needs if name not in common else common[name] & needs
    for name, needs in sorted(common.items()):
        assert set(ops[name]["requires"]) == needs, name


def test_a_capability_a_case_names_is_one_the_documentation_explains() -> None:
    known = {"zlib", "ed25519", WTF8}
    for record in RECORDS.values():
        assert set(record.get("requires") or ()) <= known, record["id"]
    readme = (SUITE / "README.md").read_text("utf-8")
    protocol = (SUITE / "PROTOCOL.md").read_text("utf-8")
    for capability in sorted(known):
        assert capability in readme or capability in protocol, capability


# --- 18. the op table is derived, not hand-listed ----------------------------


def test_every_input_spelling_a_case_uses_is_declared_by_its_op() -> None:
    ops = MANIFEST["ops"]
    for record in RECORDS.values():
        spellings = {key for key in record["input"] if key != "sha256"}
        declared = set(ops[record["op"]]["input"])
        assert spellings <= declared, f"{record['id']}: {sorted(spellings - declared)}"


def test_no_op_declares_an_input_spelling_or_arg_no_case_uses() -> None:
    ops = MANIFEST["ops"]
    used: dict[str, set[str]] = {name: set() for name in ops}
    for record in RECORDS.values():
        used[record["op"]] |= {key for key in record["input"] if key != "sha256"}
    for name, spellings in sorted(used.items()):
        assert set(ops[name]["input"]) == spellings, name


def test_every_arg_a_case_passes_is_declared_by_its_op() -> None:
    ops = MANIFEST["ops"]
    for record in RECORDS.values():
        declared = set(ops[record["op"]]["args"])
        passed = set(record.get("args") or {})
        assert passed <= declared, f"{record['id']}: {sorted(passed - declared)}"


# --- 19. the single-fault rule ------------------------------------------------


def test_only_the_pinned_compound_cases_carry_reason_any() -> None:
    """REASON_CODES.md promises every vector breaks exactly one rule, and that
    the deliberate exceptions carry ``reason_any``. Both halves are pinned here:
    a compound case that reverts to a single ``reason`` silently re-pins the
    reference's undocumented check order as if it were normative."""
    carried = {record["id"] for record in RECORDS.values() if "reason_any" in record}
    assert carried == EXPECTED_COMPOUND, carried ^ EXPECTED_COMPOUND
    for name in sorted(EXPECTED_COMPOUND):
        assert len(RECORDS[name]["reason_any"]) >= 2, name


# --- 20. language neutrality ---------------------------------------------------


def _strings(node: object):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from _strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _strings(value)


def test_no_vector_carries_a_lone_surrogate_outside_the_code_unit_escape() -> None:
    """A ``\\ud800`` escape in a vector file aborts a serde_json or encoding/json
    runner before any adapter is reached, so the file itself must never contain
    one: a surrogate is spelled ``{"$u": [...]}`` and the case declares ``wtf8``."""
    for path in VECTOR_FILES:
        for record in json.loads(path.read_text("utf-8"))["cases"]:
            for text in _strings({k: v for k, v in record.items() if k != "x_display"}):
                bad = [ch for ch in text if 0xD800 <= ord(ch) <= 0xDFFF]
                assert not bad, f"{record['id']}: {text!r}"


def test_every_case_spelling_a_code_unit_escape_declares_wtf8() -> None:
    checked = 0
    for record in RECORDS.values():
        spelled = "$u" in json.dumps(record["input"])
        if spelled:
            assert WTF8 in (record.get("requires") or ()), record["id"]
            checked += 1
        elif WTF8 in (record.get("requires") or ()):
            checked += 1
    assert checked >= 5


# --- 21. the prose that restates a number ------------------------------------


def test_the_readme_negative_share_matches_the_manifest() -> None:
    """The one census figure the README restates. It was 43% against a true 39%."""
    totals = MANIFEST["totals"]
    expected = round(100 * totals["reject"] / totals["cases"])
    readme = (SUITE / "README.md").read_text("utf-8")
    found = [int(match) for match in re.findall(r"(\d+)% of the suite", readme)]
    assert found, "README no longer states the negative share"
    assert all(value == expected for value in found), (found, expected)


def test_the_repo_facing_prose_restates_the_census_correctly() -> None:
    """The suite's own README is gated above, but the two documents that
    *advertise* it -- the repo README and the CHANGELOG entry -- restate the
    case, reject and op counts in prose. All three drifted the moment the
    census moved (506/196/31 against a true 523/195/33), because nothing
    pinned them. A published vector count is a claim about the artifact; gate
    it like one. Each pattern below is anchored to the wording that carries a
    number, so a rephrasing fails loudly rather than silently going unchecked.
    """
    totals = MANIFEST["totals"]
    claims = [
        ("README.md", r"(\d+) runnable conformance vectors", totals["cases"]),
        ("CHANGELOG.md", r"\*\*(\d+) conformance vectors\*\*", totals["cases"]),
        ("CHANGELOG.md", r"(\d+) of the (\d+) refuse input", (totals["reject"], totals["cases"])),
        ("CHANGELOG.md", r"point: (\d+) ops", totals["ops"]),
    ]
    for name, pattern, expected in claims:
        text = (ROOT / name).read_text("utf-8")
        found = re.findall(pattern, text)
        assert found, f"{name} no longer states the census via {pattern!r}"
        for match in found:
            actual = (
                tuple(int(value) for value in match)
                if isinstance(match, tuple)
                else int(match)
            )
            assert actual == expected, (
                f"{name} restates a stale conformance count {actual}; "
                f"the manifest says {expected}"
            )


def test_the_hand_written_files_are_digested_in_the_manifest() -> None:
    """README step 2 tells a third party to verify every file's sha256. The four
    files no generator writes -- the harness they run and the contract they
    implement -- were the four not covered by it."""
    for name in HAND_WRITTEN:
        assert name in MANIFEST["files"], name


# --- 22. the spec's own citations --------------------------------------------


def test_every_case_id_the_spec_or_readme_cites_resolves() -> None:
    """The mirror of gate 8. Renaming a case left the whole suite green while the
    normative document pointed at a vector that no longer existed."""
    cited: set[str] = set()
    spec = SPEC.read_text("utf-8")
    for match in re.finditer(r"[Cc]onformance vectors?([^)]{0,240})\)", spec):
        cited |= set(re.findall(r"`([a-z0-9][a-z0-9.\-]*\.[a-z0-9][a-z0-9.\-]*)`", match.group(1)))
    readme = (SUITE / "README.md").read_text("utf-8")
    cited |= {
        name
        for name in re.findall(r"`([a-z][a-z0-9]*\.[a-z0-9][a-z0-9.\-]*)`", readme)
        if name in RECORDS or name.count(".") >= 2
    }
    cited = {name for name in cited if not name.endswith((".json", ".py", ".md"))}
    assert len(cited) >= 6, sorted(cited)
    missing = sorted(name for name in cited if name not in RECORDS)
    assert not missing, f"cited but not a case id: {missing}"
