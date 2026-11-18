"""``tine integrity check --record`` runs the advisory detectors too (0.60).

Advisory findings are reported and never block by default (D12); only
``--strict`` makes them block, and a ``fail:`` blocks either way.
"""

from __future__ import annotations

import json
from pathlib import Path

from opentine import Run, cli
from opentine._schemas import validate_output
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_060_integrity import _cli, _store, _tool, room  # noqa: F401

HACK = {
    "id": "run-hack",
    "diff": [{"path": "tests/test_core.py", "status": "modified",
              "added": ["@pytest.mark.skip(reason='flaky')"], "removed": []}],
}  # fmt: skip
CLEAN = {"id": "run-clean", "diff": [{"path": "src/app.py", "status": "modified",
                                      "added": ["x = 1"], "removed": []}]}  # fmt: skip


def _record(base: Path, name: str, body: dict) -> str:
    path = base / f"{name}.json"
    path.write_bytes(json.dumps(body).encode("utf-8"))
    return path.as_posix()


def test_detectors_report_but_do_not_block(room: Path, tmp_path, capsys) -> None:  # noqa: F811
    run = Run(id="ok")
    _tool(run, "Read", file_path="src/app.py")
    oid = _store(room, run)
    args = ["integrity", "check", oid, "--repo", room.as_posix(), "--json", "--record"]
    code, row = _cli(capsys, *args, _record(tmp_path, "hack", HACK))
    assert code == 0 and row["ok"] is True and row["blocking"] == 0
    assert [f["code"] for f in row["findings"]] == ["advisory:test-skipped-added"]
    assert row["findings"][0]["surface"] == "detector"
    assert validate_output(row) == []
    code, row = _cli(capsys, *args, _record(tmp_path, "hack", HACK), "--strict")
    assert code == 1 and row["ok"] is False and row["blocking"] == 1
    code, row = _cli(capsys, *args, _record(tmp_path, "clean", CLEAN))
    assert code == 0 and row["findings"] == []


def test_a_fail_still_blocks_with_a_clean_record(room: Path, tmp_path, capsys) -> None:  # noqa: F811
    run = Run(id="hack")
    _tool(run, "Write", file_path="evals/graders/judge.py", content="x")
    oid = _store(room, run)
    code, row = _cli(capsys, "integrity", "check", oid, "--repo", room.as_posix(), "--json",
                     "--record", _record(tmp_path, "clean", CLEAN))  # fmt: skip
    assert code == 1 and row["findings"][0]["code"] == "fail:protected-surface-modified"
    assert validate_output(row) == []


def test_a_record_that_is_not_an_object_is_refused(room: Path, tmp_path) -> None:  # noqa: F811
    path = tmp_path / "bad.json"
    path.write_bytes(b"[]")
    code = 0
    try:
        cli.main(["integrity", "check", "run:sha256:" + "0" * 64, "--repo", room.as_posix(),
                  "--record", path.as_posix()])  # fmt: skip
    except SystemExit as exc:
        code = int(exc.code or 0)
    assert code != 0
