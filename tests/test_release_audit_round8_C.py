"""Regressions for the v0.3.0 pre-release audit, round 8 (group C).

Each test pins a defect that shipped-quality code had already passed review for,
so the assertions describe the *user-visible* failure rather than the mechanism.
"""

from __future__ import annotations

import sys

import pytest

from opentine import Run, RunStatus, StepKind, cli
from opentine._jsonsafe import json_safe
from opentine.autosave import Autosaver
from opentine.repo import Repo


def _invoke(monkeypatch, *args: str) -> None:
    monkeypatch.setattr(sys, "argv", ["tine", *args])
    cli.main()


def _completed_run(run_id: str) -> Run:
    run = Run(id=run_id, model_info="mock-model")
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    return run


def test_tag_applies_to_a_v3_repository_directory(monkeypatch, tmp_path, capsys):
    # cmd_tag read the target as a signed-artifact *file* to decide whether to
    # warn about signature stripping, so a v3 repo directory — a target every
    # other command accepts — crashed with a traceback before the tag was saved.
    monkeypatch.chdir(tmp_path)
    Repo.init(tmp_path / "repo3").put_run(_completed_run("repo-run"), ref="heads/main")

    _invoke(monkeypatch, "tag", "repo3", "--add", "hello")

    assert Run.load(tmp_path / "repo3").tags == ["hello"]
    assert "hello" in capsys.readouterr().out


def test_tagging_a_signed_file_still_warns_that_the_signature_is_stripped(
    monkeypatch, tmp_path, capsys
):
    # The repo-dir fix must not silence the deliberate warn-on-strip behaviour
    # for regular signed artifacts.
    monkeypatch.chdir(tmp_path)
    _completed_run("signed-run").save("signed.tine", sign_key=b"0123456789abcdef0123456789abcdef")

    _invoke(monkeypatch, "tag", "signed.tine", "--add", "mytag")

    out = capsys.readouterr().out
    assert "Signature removed" in out
    assert Run.load(tmp_path / "signed.tine").tags == ["mytag"]


def test_a_big_int_stored_the_way_json_safe_stores_it_still_saves(tmp_path):
    # json_safe converts any integer beyond 2**53 into a decimal string, and the
    # reader accepts digit strings of any length — but the writer's byte-level
    # oversized-integer regex could not tell a string from a number literal, so
    # Run.save refused the writer's own representation of valid data.
    run = Run(id="bigint-string")
    run.add_step(StepKind.tool, {"q": "factor"}, {"result": json_safe(2**14000)})
    path = run.save(tmp_path / "big.tine")

    loaded = Run.load(path)
    assert loaded.steps[0].outputs["result"] == str(2**14000)
    assert Run.verify_integrity(path).ok


def test_autosave_of_a_run_holding_a_long_digit_string_does_not_raise(tmp_path):
    # Autosaver.maybe_save has no error handling by design, so the false
    # rejection propagated out of record_step and aborted an otherwise healthy
    # live run mid-flight.
    run = Run(id="live-run")
    run.add_step(StepKind.tool, {"cmd": "compute"}, {"result": json_safe(2**14000)})

    saver = Autosaver(tmp_path / "live.tine", every_n_steps=1)
    assert saver.maybe_save(run) is True
    assert (tmp_path / "live.tine").exists()


def test_a_long_digit_run_in_ordinary_tool_output_still_saves(tmp_path):
    # No big-int math needed: any tool log with >= 4097 consecutive digits hit
    # the same false rejection.
    run = Run(id="digit-log")
    run.add_step(StepKind.tool, {"cmd": "openssl"}, {"stdout": "modulus: " + "7" * 5000})
    loaded = Run.load(run.save(tmp_path / "log.tine"))
    assert loaded.steps[0].outputs["stdout"].endswith("7" * 5000)


def test_an_oversized_integer_literal_is_still_rejected_at_save(tmp_path):
    # The guard's true positive: a number *literal* the reader would refuse must
    # keep failing at save time, with the existing actionable message.
    run = Run(id="bigint-literal")
    run.add_step(StepKind.tool, {"q": "factor"}, {"modulus": 10**4200})
    with pytest.raises(ValueError, match="4096-digit"):
        run.save(tmp_path / "literal.tine")
    assert not (tmp_path / "literal.tine").exists()


def test_ls_with_an_unparseable_date_reports_a_clean_error(monkeypatch, tmp_path, capsys):
    # `tine ls --since yesterday` raised QueryError out of the filter
    # translation and reached the user as an interpreter traceback; search
    # already reported the same mistake cleanly.
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".tine_runs").mkdir()
    _completed_run("ls-run").save(tmp_path / ".tine_runs" / "ls-run.tine")

    for flag, value in (("--since", "yesterday"), ("--until", "2026/13/45")):
        with pytest.raises(SystemExit) as exit_info:
            _invoke(monkeypatch, "ls", flag, value)
        assert exit_info.value.code == 1
        out = capsys.readouterr().out
        assert "invalid date" in out
        assert "Traceback" not in out

    # A well-formed date still filters normally.
    _invoke(monkeypatch, "ls", "--since", "2020-01-01")
    assert "ls-run" in capsys.readouterr().out
