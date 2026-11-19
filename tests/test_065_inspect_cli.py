"""0.64: ``tine inspect`` and its ``tine import inspect`` / ``tine export inspect`` spellings,
the detached log signature the Inspect hook writes, and the METR task-family reader."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from opentine import _inspect_hook as hook
from opentine._cli_inspect import rewrite
from opentine._inspect_log import read_log
from opentine._metr_task import MetrTaskError, read_family
from opentine.cli import main
from opentine.repository import Repo

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "inspect"
KEY_HEX = "11" * 32


def _tine(capsys, *argv: str) -> tuple[int, str]:
    try:
        main(list(argv))
        code = 0
    except SystemExit as exc:
        code = exc.code or 0
    return code, capsys.readouterr().out


def test_the_import_and_export_spellings_route_to_tine_inspect(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert rewrite(["import", "inspect", "a.eval"]) == ["inspect", "import", "a.eval"]
    assert rewrite(["import", "metr", "fam"]) == ["inspect", "metr", "fam"]
    assert rewrite(["export", "inspect", "--repo", "r"]) == ["inspect", "export", "--repo", "r"]
    assert rewrite(["import", "inspect"]) == ["import", "inspect"]  # a bare SOURCE stays one
    (tmp_path / "inspect").write_bytes(b"{}")
    assert rewrite(["import", "inspect", "x"]) == ["import", "inspect", "x"]


def test_cli_import_signs_verdicts_and_export_writes_the_log_back(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Repo.init(tmp_path / "r")
    (tmp_path / "k.key").write_bytes(KEY_HEX.encode())
    log = (FIXTURES / "arc_easy.eval").as_posix()
    when = "2026-11-01T12:00:00Z"
    code, out = _tine(capsys, "import", "inspect", log, "--repo", "r", "--key", "k.key",
                      "--evals", "ev", "--created-at", when, "--json")  # fmt: skip
    assert code == 0, out
    body = json.loads(out)
    assert body["schema"] == "tine-cli-inspect/1" and len(body["samples"]) == 3
    assert body["verdicts"]["scorers"]["choice"]["items"] == 3
    code, out = _tine(capsys, "eval", "verify", "ev/choice", "--json")
    assert code == 0, out
    code, out = _tine(capsys, "export", "inspect", "--repo", "r", "--format", "eval",
                      "--output", "back.eval", "--json")  # fmt: skip
    assert code == 0 and json.loads(out)["samples"] == 3
    original, back = read_log(FIXTURES / "arc_easy.eval"), read_log(tmp_path / "back.eval")
    assert {(s["id"], json.dumps(s["scores"], sort_keys=True)) for s in back["samples"]} == {
        (s["id"], json.dumps(s["scores"], sort_keys=True)) for s in original["samples"]
    }


def test_export_to_stdout_is_byte_exact(tmp_path, capfdbinary, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Repo.init(tmp_path / "r")
    main(["inspect", "import", (FIXTURES / "gsm8k.json").as_posix(), "--repo", "r"])
    capfdbinary.readouterr()
    main(["inspect", "export", "--repo", "r"])
    sys.stdout.flush()
    data = capfdbinary.readouterr().out
    assert data.endswith(b"}\n") and b"\r\n" not in data
    assert [s["id"] for s in json.loads(data)["samples"]] == [1, 2, 3]


def test_a_signed_log_verifies_and_any_byte_change_fails(tmp_path, capsys):
    log = tmp_path / "x.eval"
    log.write_bytes((FIXTURES / "humaneval.eval").read_bytes())
    sig = hook.sign_log(log, KEY_HEX, signed_at="2026-11-01T12:00:00Z")
    assert sig.name == "x.eval.tine-sig.json"
    assert hook.verify_log(log)["ok"]
    code, out = _tine(capsys, "inspect", "verify", log.as_posix(), "--json")
    assert code == 0 and json.loads(out)["ok"] is True
    log.write_bytes(log.read_bytes() + b"\0")
    assert hook.verify_log(log)["reason"] == "log bytes changed since signing"
    code, _ = _tine(capsys, "inspect", "verify", log.as_posix())
    assert code == 4
    record = json.loads(sig.read_bytes())
    record["sha256"] = "sha256:" + "0" * 64
    sig.write_bytes(json.dumps(record).encode())
    assert not hook.verify_log(log)["ok"]


def test_the_inspect_hook_needs_inspect_ai_only_when_registered():
    try:
        import inspect_ai  # noqa: F401
    except ImportError:
        with pytest.raises(ImportError):
            hook.register(KEY_HEX)
    else:  # pragma: no cover - only where the optional extra is installed
        assert hook.register(KEY_HEX).__name__ == "OpenTineSignLogs"


FAMILY = """
class TaskFamily:
    standard_version = "0.3.0"
    required_environment_variables = ["OPENAI_API_KEY"]

    @staticmethod
    def get_tasks():
        return {"easy": {"n": 1, "pair": (1, 2)}, "hard": {"n": 9}}

    @staticmethod
    def get_permissions(t):
        return ["full_internet"]

    @staticmethod
    def score(v, submission):
        raise SystemExit("never executed")
"""


def test_a_metr_family_is_read_without_running_it(tmp_path, capsys):
    folder = tmp_path / "count_odds"
    folder.mkdir()
    (folder / "count_odds.py").write_bytes(FAMILY.encode())
    family = read_family(folder)
    assert [i["id"] for i in family["items"]] == ["count_odds/easy", "count_odds/hard"]
    assert family["items"][0]["input"]["data"] == {"n": 1, "pair": [1, 2]}
    assert family["items"][0]["metadata"]["standard_version"] == "0.3.0"
    assert family["items"][0]["metadata"]["permissions"] == ["full_internet"]
    code, out = _tine(capsys, "import", "metr", folder.as_posix(),
                      "--out", (tmp_path / "d.jsonl").as_posix(), "--json")  # fmt: skip
    assert code == 0 and json.loads(out)["tasks"] == 2
    lines = (tmp_path / "d.jsonl").read_bytes().splitlines()
    assert len(lines) == 2


def test_a_dynamic_or_broken_metr_family_is_reported_not_run(tmp_path):
    folder = tmp_path / "dyn"
    folder.mkdir()
    (folder / "dyn.py").write_bytes(
        b"class TaskFamily:\n    @staticmethod\n    def get_tasks():\n"
        b"        return {str(i): {} for i in range(3)}\n"
    )
    assert read_family(folder) == {"family": "dyn", "items": [], "dynamic": True}
    (folder / "dyn.py").write_bytes(b"def nope(:\n")
    with pytest.raises(MetrTaskError):
        read_family(folder)
