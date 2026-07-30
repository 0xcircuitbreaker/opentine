"""Fast CLI smoke coverage for .tine graph operations."""

from __future__ import annotations

import os
import stat
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, cli


def _write_run(path: Path, run_id: str = "cli_run") -> Run:
    run = Run(id=run_id, model_info="mock-model", user_prompt="test prompt")
    run.add_step(StepKind.think, {"text": "thinking"})
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    run.save(path)
    return run


def _invoke(monkeypatch, *args: str) -> None:
    monkeypatch.setattr(sys, "argv", ["tine", *args])
    cli.main()


def test_cli_show_fork_replay_inspect_cache_and_diff(monkeypatch, tmp_path, capsys):
    runs_dir = tmp_path / ".tine_runs"
    monkeypatch.setattr(cli, "RUNS_DIR", runs_dir)

    source_path = tmp_path / "source.tine"
    run = _write_run(source_path)
    fork_path = tmp_path / "forked.tine"
    replay_path = tmp_path / "replayed.tine"

    _invoke(monkeypatch, "show", str(source_path))
    _invoke(monkeypatch, "fork", str(source_path), "--from-step", "0", "--save", str(fork_path))
    _invoke(monkeypatch, "replay", str(source_path), "--inspect")
    _invoke(monkeypatch, "replay", str(source_path), "--mode", "cache", "--save", str(replay_path))
    _invoke(monkeypatch, "diff", str(source_path), str(fork_path))

    forked = Run.load(fork_path)
    replayed = Run.load(replay_path)

    assert forked.metadata["forked_from"] == run.id
    assert len(forked.steps) == 1
    assert replayed.metadata["replay"]["mode"] == "cache"
    assert replayed.metadata["replay"]["source_run"] == run.id
    assert replayed.status.value == "completed"

    captured = capsys.readouterr()
    assert "Cached replay" in captured.out


def test_cli_verify_success_and_failure(monkeypatch, tmp_path, capsys):
    runs_dir = tmp_path / ".tine_runs"
    monkeypatch.setattr(cli, "RUNS_DIR", runs_dir)
    source_path = tmp_path / "source.tine"
    run = _write_run(source_path)

    _invoke(monkeypatch, "verify", str(source_path))
    assert "OK" in capsys.readouterr().out

    data = source_path.read_text(encoding="utf-8").replace("done", "changed", 1)
    source_path.write_text(data, encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        _invoke(monkeypatch, "verify", str(source_path))

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "FAILED" in captured.out
    assert "digest mismatch" in captured.out
    assert run.id == "cli_run"


def test_cli_step_label_handles_structured_harness_content():
    run = Run(id="structured")
    think = run.add_step(
        StepKind.think,
        {"text": [{"type": "text", "content": "structured output"}]},
    )
    tool = run.add_step(
        StepKind.tool,
        {"name": "inspect", "arguments": [{"path": "README.md"}]},
    )

    think_label = cli._step_label(think)
    tool_label = cli._step_label(tool)

    assert "structured output" in think_label.plain
    assert "inspect" in tool_label.plain
    assert "README.md" in tool_label.plain


def test_cli_fork_rejects_bad_step_ref(monkeypatch, tmp_path, capsys):
    runs_dir = tmp_path / ".tine_runs"
    monkeypatch.setattr(cli, "RUNS_DIR", runs_dir)
    source_path = tmp_path / "source.tine"
    _write_run(source_path)

    with pytest.raises(SystemExit) as exc:
        _invoke(monkeypatch, "fork", str(source_path), "--from-step", "missing")

    assert exc.value.code == 1
    assert "Unknown step ref" in capsys.readouterr().out


def test_cli_fork_refuses_overwrite_without_force(monkeypatch, tmp_path, capsys):
    runs_dir = tmp_path / ".tine_runs"
    monkeypatch.setattr(cli, "RUNS_DIR", runs_dir)
    source_path = tmp_path / "source.tine"
    out_path = tmp_path / "existing.tine"
    _write_run(source_path)
    out_path.write_text("already here")

    with pytest.raises(SystemExit) as exc:
        _invoke(monkeypatch, "fork", str(source_path), "--from-step", "0", "--save", str(out_path))

    assert exc.value.code == 1
    assert "Refusing to overwrite" in capsys.readouterr().out


def test_cli_replay_refuses_overwrite_without_force(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    source_path = tmp_path / "source.tine"
    out_path = tmp_path / "existing.tine"
    _write_run(source_path)
    out_path.write_text("already here", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        _invoke(monkeypatch, "replay", str(source_path), "--save", str(out_path))

    assert exc.value.code == 1
    assert out_path.read_text(encoding="utf-8") == "already here"
    assert "Refusing to overwrite" in capsys.readouterr().out

    _invoke(monkeypatch, "replay", str(source_path), "--save", str(out_path), "--force")
    assert Run.load(out_path).metadata["replay"]["mode"] == "cache"


def test_cli_replay_rerun_requires_harness(monkeypatch, tmp_path, capsys):
    runs_dir = tmp_path / ".tine_runs"
    monkeypatch.setattr(cli, "RUNS_DIR", runs_dir)
    source_path = tmp_path / "source.tine"
    _write_run(source_path)

    with pytest.raises(SystemExit) as exc:
        _invoke(monkeypatch, "replay", str(source_path), "--mode", "rerun")

    assert exc.value.code == 1
    assert "Rerun replay requires an explicit --harness" in capsys.readouterr().out


def test_cli_ls_marks_corrupt_runs(monkeypatch, tmp_path, capsys):
    runs_dir = tmp_path / ".tine_runs"
    runs_dir.mkdir()
    monkeypatch.setattr(cli, "RUNS_DIR", runs_dir)
    (runs_dir / "bad.tine").write_text("not json")

    _invoke(monkeypatch, "ls")

    assert "corrupt" in capsys.readouterr().out


def test_cli_show_sanitizes_markup_and_terminal_control_sequences(monkeypatch, tmp_path, capsys):
    source = tmp_path / "hostile.tine"
    run = Run(id="[/bold]\x1b]52", model_info="[/bold]\x1b]52;c;clip\u202eboard\x1b\\")
    original = run.add_step(StepKind.done, {"text": "visible\x9b31m\x00 pay\u2066load\u2069"})
    hostile_id = "[/dim]\x1b]52;c;step\x1b\\"
    hostile = replace(original, id=hostile_id)
    run.graph.steps = {hostile_id: hostile}
    run.graph.order = [hostile_id]
    run.refs["main"] = hostile_id
    run.status = RunStatus.completed
    run.save(source)

    _invoke(monkeypatch, "show", str(source))

    output = capsys.readouterr().out
    assert "[/bold]" in output and "visible31m payload" in output
    assert not {"\x1b", "\x9b", "\x00", "\u202e", "\u2066", "\u2069"} & set(output)


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_cli_keygen_refuses_to_clobber_an_existing_key_without_force(monkeypatch, tmp_path):
    # Silently overwriting a private key destroys the only copy of a signing
    # identity and makes every artifact it signed unverifiable.
    private = tmp_path / "release.key"
    private.write_text("existing signing key", encoding="utf-8")

    with pytest.raises(SystemExit) as exit_info:
        _invoke(monkeypatch, "keygen", "--out", str(private))

    assert exit_info.value.code == 1
    assert private.read_text(encoding="utf-8") == "existing signing key"


def test_cli_keygen_atomically_restricts_existing_output_mode(monkeypatch, tmp_path):
    private = tmp_path / "release.key"
    private.write_text("public placeholder", encoding="utf-8")
    private.chmod(0o644)

    _invoke(monkeypatch, "keygen", "--out", str(private), "--force")

    # The atomic overwrite replaced the placeholder with a fresh 64-char hex seed;
    # this proves the write landed on every platform.
    written = private.read_text(encoding="utf-8").strip()
    assert written != "public placeholder"
    assert len(written) == 64 and all(char in "0123456789abcdef" for char in written)
    if os.name != "nt":
        # POSIX-only: Windows files report 0o666 and os.chmod is a near-noop, so
        # there is no 0o600 mode to assert even though keygen still requests it.
        assert stat.S_IMODE(private.stat().st_mode) == 0o600


def test_cached_replay_never_derives_an_output_path_from_untrusted_run_id(monkeypatch, tmp_path):
    runs_dir = tmp_path / "runs"
    monkeypatch.setattr(cli, "RUNS_DIR", runs_dir)
    source = tmp_path / "hostile-id.tine"
    run = Run(id="../owned")
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    run.save(source)

    _invoke(monkeypatch, "replay", str(source), "--mode", "cache")

    assert not (tmp_path / "owned-replay.tine").exists()
    outputs = list(runs_dir.glob("*.tine"))
    assert len(outputs) == 1
    assert outputs[0].resolve().is_relative_to(runs_dir.resolve())
    original = outputs[0].read_bytes()
    with pytest.raises(SystemExit):
        _invoke(monkeypatch, "replay", str(source), "--mode", "cache")
    assert outputs[0].read_bytes() == original
