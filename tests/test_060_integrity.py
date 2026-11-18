"""0.60: protected surfaces, ``tine integrity check``, taint, promote and lineage.

Every file whose hash matters is written as bytes; nothing sleeps; every
repository lives under the test's own ``tmp_path``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import Run, StepKind, cli
from opentine._integrity import ProtectedError, check, matches, parse
from opentine._integrity_observe import touched
from opentine._integrity_run import LIST, PIN, TAINTS, promote_refusals, taints
from opentine.repository import Repo
from tests.integrity_helpers import FIXTURE, GRADER, PROTECTED_TOML, build_fixture, render
from tests.promote_helpers import AT, fingerprint

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")

POLICY, OPTIMIZER, TAINTER = "9e" * 32, "8d" * 32, "4f" * 32
LIST_TOML = """version = 1

[[surface]]
name = "graders"
kind = "grader"
globs = ["evals/graders/**"]

[[surface]]
name = "tests"
kind = "test"
globs = ["tests/**"]
"""


def _cli(capsys, *argv: str) -> tuple[int, dict]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, json.loads(capsys.readouterr().out)


def _keyfile(base: Path, seed: str) -> str:
    path = base / f"{seed[:2]}.key"
    path.write_bytes(seed.encode("ascii"))
    return path.as_posix()


def _tool(run: Run, name: str, **args) -> None:
    run.add_step(StepKind.tool, {"name": name, "input": args})


@pytest.fixture
def room(tmp_path: Path, capsys) -> Path:
    root = tmp_path / "repo"
    Repo.init(root)
    (root / "evals" / "graders").mkdir(parents=True)
    (root / "evals" / "graders" / "judge.py").write_bytes(b"def judge(x):\n    return x\n")
    (root / "tests").mkdir()
    (root / "tests" / "test_a.py").write_bytes(b"def test_a():\n    assert True\n")
    (root / "src").mkdir()
    (root / "src" / "app.py").write_bytes(b"print('hi')\n")
    roles = f'version = 1\n[roles]\npolicy = ["{fingerprint(POLICY)}"]\n'
    roles += f'optimizer = ["{fingerprint(OPTIMIZER)}"]\n'
    (root / ".tine" / "key-roles.toml").write_bytes(roles.encode("ascii"))
    (root / LIST).write_bytes(LIST_TOML.encode("ascii"))
    code, row = _cli(capsys, "integrity", "pin", "--repo", root.as_posix(), "--json")
    assert code == 0 and row["pins"] == 2 and row["signed"] is False
    code, row = _cli(capsys, "integrity", "sign", "--repo", root.as_posix(), "--key",
                     _keyfile(tmp_path, POLICY), "--at", AT, "--json")  # fmt: skip
    assert code == 0 and row["signer"] == fingerprint(POLICY)
    return root


def _store(root: Path, run: Run) -> str:
    return Repo.open(root).put_run(run).run_id


def test_the_shared_fixture_is_current_and_the_python_answers_match() -> None:
    assert FIXTURE.read_bytes() == render()
    fixture = build_fixture()
    for case in fixture["cases"]:
        got = [[f["code"], f["path"]] for f in check(fixture["protected"], case["observations"])]
        assert got == case["expect"], case["id"]


def test_parse_refuses_unknown_kinds_bad_pins_and_duplicates() -> None:
    assert len(parse(PROTECTED_TOML.encode())["surfaces"]) == 5
    for bad in ('version = 1\n[[surface]]\nname = "a"\nkind = "other"\n',
                'version = 1\n[[surface]]\nname = "a"\nkind = "test"\n[surface.pins]\n"x" = "1"\n',
                'version = 1\n[[surface]]\nname = "a"\nkind = "test"\n'
                '[[surface]]\nname = "a"\nkind = "test"\n', "version = 2\n"):  # fmt: skip
        with pytest.raises(ProtectedError):
            parse(bad.encode())


def test_glob_semantics() -> None:
    assert matches("tests/**", "tests/a/b.py") and matches("**/conftest.py", "conftest.py")
    assert not matches("sandbox/*.toml", "sandbox/a/b.toml")
    assert not matches("a.py", "aXpy")


def test_touched_reads_file_tools_and_shell_commands(tmp_path: Path) -> None:
    run = Run(id="t")
    _tool(run, "Edit", file_path=(tmp_path / "evals" / "graders" / "judge.py").as_posix())
    _tool(run, "Bash", command="rm -f tests/test_a.py && cat data/h.json > out.txt")
    _tool(run, "mcp__fs__read_file", path="./src/app.py")
    _tool(run, "Write", file_path="/elsewhere/x.py")
    got = {(row["path"], row["op"]) for row in touched(run, tmp_path)}
    assert got == {("evals/graders/judge.py", "write"), ("tests/test_a.py", "delete"),
                   ("data/h.json", "read"), ("out.txt", "write"),
                   ("src/app.py", "read")}  # fmt: skip


def test_a_benign_run_passes_and_a_grader_edit_is_tainted(room: Path, tmp_path, capsys) -> None:
    benign = Run(id="benign")
    _tool(benign, "Edit", file_path="src/app.py")
    _tool(benign, "Read", file_path=GRADER)
    good = _store(room, benign)
    code, row = _cli(capsys, "integrity", "check", good, "--repo", room.as_posix(), "--json")
    assert code == 0 and row["ok"] and row["findings"] == [] and row["taint"] is None
    hack = Run(id="hack")
    _tool(hack, "Write", file_path=GRADER, content="def judge(x):\n    return True\n")
    bad = _store(room, hack)
    code, row = _cli(capsys, "integrity", "check", bad, "--repo", room.as_posix(),
                     "--key", _keyfile(tmp_path, TAINTER), "--at", AT, "--json")  # fmt: skip
    assert code == 1 and not row["ok"] and row["blocking"] == 1
    assert [f["code"] for f in row["findings"]] == ["fail:protected-surface-modified"]
    assert row["taint"]["signer"] == fingerprint(TAINTER)
    assert taints(room, bad)[0]["codes"] == ["fail:protected-surface-modified"]
    assert taints(room, good) == []


def test_an_edited_list_is_unsigned_until_re_signed(room: Path, capsys) -> None:
    run = Run(id="read-tests")
    _tool(run, "Bash", command="cat tests/test_a.py")
    oid = _store(room, run)
    text = room / LIST
    text.write_bytes(text.read_bytes().replace(b'kind = "test"', b'kind = "holdout"'))
    # The list changed: until it is re-signed it is not trusted.
    code, row = _cli(capsys, "integrity", "check", oid, "--repo", room.as_posix(), "--json")
    assert code == 1 and [f["code"] for f in row["findings"]] == ["fail:protected-list-unsigned"]


def test_holdout_read_is_advisory(room: Path, tmp_path, capsys) -> None:
    text = room / LIST
    text.write_bytes(text.read_bytes().replace(b'kind = "test"', b'kind = "holdout"'))
    _cli(capsys, "integrity", "sign", "--repo", room.as_posix(), "--key",
         _keyfile(tmp_path, POLICY), "--json")  # fmt: skip
    run = Run(id="peek")
    _tool(run, "Read", file_path="tests/test_a.py")
    oid = _store(room, run)
    code, row = _cli(capsys, "integrity", "check", oid, "--repo", room.as_posix(), "--json")
    assert code == 0 and [f["code"] for f in row["findings"]] == ["advisory:holdout-read"]
    code, row = _cli(capsys, "integrity", "check", oid, "--repo", room.as_posix(), "--strict",
                     "--json")  # fmt: skip
    assert code == 1


def test_digest_drift_on_disk_is_a_fail(room: Path, capsys) -> None:
    (room / GRADER).write_bytes(b"def judge(x):\n    return 1\n")
    oid = _store(room, Run(id="quiet"))
    code, row = _cli(capsys, "integrity", "check", oid, "--repo", room.as_posix(), "--json")
    assert code == 1 and row["findings"][0]["path"] == GRADER


def test_an_optimizer_signed_or_missing_list_is_refused(room: Path, tmp_path, capsys) -> None:
    oid = _store(room, Run(id="any"))
    _cli(capsys, "integrity", "sign", "--repo", room.as_posix(), "--key",
         _keyfile(tmp_path, OPTIMIZER), "--json")  # fmt: skip
    code, row = _cli(capsys, "integrity", "check", oid, "--repo", room.as_posix(), "--json")
    assert code == 1 and row["findings"][0]["code"] == "fail:protected-list-unsigned"
    (room / PIN).unlink()
    (room / LIST).unlink()
    code, row = _cli(capsys, "integrity", "check", oid, "--repo", room.as_posix(), "--json")
    assert code == 1 and row["findings"][0]["code"] == "fail:protected-list-missing"


def test_promote_refuses_a_tainted_or_live_failing_candidate(room: Path, tmp_path, capsys):
    hack = Run(id="hack2")
    _tool(hack, "Bash", command="rm tests/test_a.py")
    bad = _store(room, hack)
    codes = {r["code"] for r in promote_refusals(room, bad)}
    assert codes == {"promote.score-tainted"}
    _cli(capsys, "integrity", "check", bad, "--repo", room.as_posix(), "--key",
         _keyfile(tmp_path, TAINTER), "--json")  # fmt: skip
    (room / LIST).unlink()  # the filed taint still refuses without the list
    assert [r["code"] for r in promote_refusals(room, bad)] == ["promote.score-tainted"]
    forged = room / TAINTS / f"{bad.rsplit(':', 1)[-1]}.json"
    doc = json.loads(forged.read_bytes())
    doc["claim"]["run"] = "run:sha256:" + "0" * 64
    forged.write_bytes(json.dumps(doc).encode())
    assert promote_refusals(room, bad) == []


def test_lineage_check_and_why_surface_taint(room: Path, tmp_path, capsys) -> None:
    from opentine._integrity_run import taint
    from tests.lineage_helpers import art
    from tests.promote_helpers import RUN_A, key

    code, rec = _cli(capsys, "lineage", "record", "--run", RUN_A, "--key",
                     _keyfile(tmp_path, OPTIMIZER), "--code-tree", art(0)["code_tree"],
                     "--repo", room.as_posix(), "--at", AT, "--json")  # fmt: skip
    assert code == 0
    variant = rec["variant"]
    code, row = _cli(capsys, "lineage", "check", variant, "--repo", room.as_posix(), "--json")
    assert code == 0 and row["ok"]
    fails = [{"level": "fail", "code": "fail:protected-surface-modified"}]
    taint(room, key(TAINTER), {"run": RUN_A, "findings": fails, "protected_sha256": None}, AT)
    for verb in ("check", "why"):
        code, row = _cli(capsys, "lineage", verb, variant, "--repo", room.as_posix(), "--json")
        assert code == 1 and not row["ok"], verb
        assert [f["code"] for f in row["findings"]] == ["lineage.score-tainted"]
