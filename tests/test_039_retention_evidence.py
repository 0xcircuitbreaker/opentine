"""0.39: retention policy for gc, and ``tine evidence report --format html|pdf``."""

from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, cli
from opentine._retention import RetentionError, RetentionPolicy
from opentine.repository import Repo, _holds

DAY = 86400
SECRET = "sk-ant-api03-" + "Q" * 40 + "AA"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "home" / ".config"))
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "off")
    monkeypatch.delenv("OPENTINE_OUTPUT", raising=False)


def _orphan(repo, text: str, days: float) -> str:
    oid = repo.put("blob", text.encode())
    stamp = time.time() - days * DAY
    os.utime(repo._object_path(oid), (stamp, stamp))
    return oid


def _gc(capsys, repo, *extra: str) -> dict:
    capsys.readouterr()
    cli.main(["gc", "--repo", str(repo.path), "--json", *extra])
    return json.loads(capsys.readouterr().out)


def test_default_gc_prunes_unreachable_objects_past_the_default_window(tmp_path, capsys):
    repo = Repo.init(tmp_path / "r")
    old = _orphan(repo, "old orphan", 30)
    young = _orphan(repo, "young orphan", 3)
    assert _gc(capsys, repo)["pruned"] == 1
    assert not repo.has(old) and repo.has(young)


def test_gc_prune_never_keeps_everything(tmp_path, capsys):
    repo = Repo.init(tmp_path / "r")
    old = _orphan(repo, "old orphan", 30)
    assert "pruned" not in _gc(capsys, repo, "--prune=never")
    assert repo.has(old)


def test_retention_prunes_only_outside_the_window_and_never_held(tmp_path, capsys):
    repo = Repo.init(tmp_path / "r")
    (repo.path / "retention.toml").write_text("keep_days = 60\n", encoding="utf-8")
    inside = _orphan(repo, "inside the window", 30)
    outside = _orphan(repo, "outside the window", 90)
    held = _orphan(repo, "held but ancient", 400)
    legal = _orphan(repo, "legal hold", 400)
    _holds.add(repo, held)
    _orphan(repo, "held but ancient", 400)  # adding the hold re-touched it
    with (repo.path / "retention.toml").open("a", encoding="utf-8") as fh:
        fh.write(f'legal_hold = ["{legal}"]\n')
    capsys.readouterr()
    cli.main(["retention", "check", "--repo", str(repo.path), "--json"])
    check = json.loads(capsys.readouterr().out)
    assert check["prune"] == [outside]
    assert check["retained"] >= 1  # in window (legal-hold oids in the file are roots too)
    assert repo.has(outside)  # check is a dry run
    assert _gc(capsys, repo)["pruned"] == 1
    assert not repo.has(outside)
    assert all(repo.has(oid) for oid in (inside, held, legal))


def test_policy_rules_take_the_longest_window_and_hook_refuses(tmp_path):
    policy = RetentionPolicy.loads(
        'keep_days = 10\n[refs]\n"heads/release/*" = 365\n[status]\nfailed = 2\n'
        "[tier]\nhigh = 3650\n"
    )
    assert policy.window_days({}) == 10
    assert policy.window_days({"status": "failed"}) == 10  # a rule never shortens
    assert policy.window_days({"ref": "heads/release/1.0"}) == 365
    assert policy.window_days({"tier": "high", "ref": "heads/release/x"}) == 3650
    policy.written = lambda _t, _o: time.time() - 20 * DAY
    assert policy.retain_until("t", "a" * 64) is not None
    policy.facts = lambda _t, _o: {"tier": "high"}
    with pytest.raises(PermissionError):
        policy.before_delete("t", "a" * 64)
    with pytest.raises(RetentionError):
        RetentionPolicy.loads("keep_days = -1\n")
    with pytest.raises(RetentionError):
        RetentionPolicy.loads("bogus = 1\n")


def test_retention_show_reports_the_policy(tmp_path, capsys):
    repo = Repo.init(tmp_path / "r")
    capsys.readouterr()
    cli.main(["retention", "show", "--repo", str(repo.path), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["policy"]["keep_days"] == 14 and doc["policy"]["source"] == "default"
    (repo.path / "retention.toml").write_text("keep_days = [\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        cli.main(["retention", "show", "--repo", str(repo.path), "--json"])
    assert exc.value.code == 1
    assert "error" in json.loads(capsys.readouterr().out)


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    run = Run(id="evidence_run", model_info="mock-model", user_prompt="report me")
    run.add_step(StepKind.think, {"text": f"the key is {SECRET}"})
    run.add_step(StepKind.tool, {"name": "bash", "arguments": {"api_key": SECRET}})
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    run.save(tmp_path / "run.tine")
    return tmp_path


def _report(room: Path, out: str, fmt: str = "html") -> bytes:
    cli.main(["evidence", "report", "run.tine", "--format", fmt, "-o", out])
    return (room / out).read_bytes()


def test_html_report_is_byte_identical_and_secret_free(room, capsys):
    first = _report(room, "a.html")
    time.sleep(1.1)  # a wall-clock timestamp would now differ
    shutil.copy(room / "run.tine", room / "copy.tine")
    assert _report(room, "b.html") == first
    text = first.decode("utf-8")
    assert SECRET not in text and "sk-ant-api03" not in text
    assert "script-src 'none'" in text and "<link" not in text
    assert str(room) not in text  # no machine path leaks into the page
    blob = text.split('id="tine-evidence">', 1)[1].split("</script>", 1)[0]
    doc = json.loads(blob)
    assert doc["run_id"] == "evidence_run" and doc["source"] == "run.tine"


def test_html_report_re_redacts_a_tampered_run(room, capsys):
    path = room / "run.tine"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, ValueError):
        pytest.skip("artifact is not plain JSON")
    data["user_prompt"] = f"leaked {SECRET}"
    path.write_text(json.dumps(data), encoding="utf-8")
    assert SECRET.encode() not in _report(room, "t.html")


def test_report_unknown_run_is_not_found(room, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["evidence", "report", "nope", "-o", "x.html"])
    assert exc.value.code == 3


def test_pdf_report_is_deterministic_and_embeds_the_evidence(room, capsys):
    pikepdf = pytest.importorskip("pikepdf")
    first = _report(room, "a.pdf", "pdf")
    assert _report(room, "b.pdf", "pdf") == first
    assert SECRET.encode() not in first
    with pikepdf.open(room / "a.pdf") as pdf:
        attached = pdf.attachments["evidence.json"].get_file().read_bytes()
    assert json.loads(attached)["run_id"] == "evidence_run"
