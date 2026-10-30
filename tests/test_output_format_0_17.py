"""0.17 user default output format: ``output.format`` / ``OPENTINE_OUTPUT``.

The setting lives only in ``$XDG_CONFIG_HOME/opentine/settings.json``; the env var
wins over the file and an explicit ``--json``/``--text`` wins over both. With no
setting every command's output must be byte-identical to an unconfigured CLI.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, cli
from opentine._user_settings import settings_file


@pytest.fixture
def ws(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.delenv("OPENTINE_OUTPUT", raising=False)
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    run = Run(id="fmt_src", model_info="mock-model", user_prompt="hello")
    run.add_step(StepKind.model, {"prompt": "hello"}, outputs={"text": "hi"}, model_info="m")
    run.status = RunStatus.completed
    run.save(tmp_path / "run.tine")
    return tmp_path


def _run(capsys, *argv: str) -> tuple[int, str, str]:
    capsys.readouterr()
    try:
        cli.main(list(argv))
        code = 0
    except SystemExit as exc:
        code = int(exc.code or 0)
    out, err = capsys.readouterr()
    return code, out, err


def _is_json(text: str) -> bool:
    try:
        json.loads(text)
    except ValueError:
        return False
    return True


def test_no_setting_is_byte_identical(ws, capsys, monkeypatch) -> None:
    baseline = [_run(capsys, *argv) for argv in (["show", "run.tine"], ["pricing", "list"])]
    for argv, before in zip((["show", "run.tine"], ["pricing", "list"]), baseline, strict=True):
        assert not _is_json(before[1])
        assert _run(capsys, *argv, "--text") == before  # --text is the default
    monkeypatch.setenv("OPENTINE_OUTPUT", "")  # empty env means unset
    assert _run(capsys, "show", "run.tine") == baseline[0]
    assert not settings_file().exists()


def test_file_setting_defaults_json(ws, capsys) -> None:
    explicit = _run(capsys, "show", "run.tine", "--json")
    assert _run(capsys, "config", "set", "output.format", "json")[0] == 0
    assert settings_file().stat().st_mode & 0o077 == 0
    assert _run(capsys, "config", "get", "output.format")[1] == "json\n"
    assert _run(capsys, "show", "run.tine") == explicit
    assert _is_json(_run(capsys, "pricing", "list")[1])
    assert not _is_json(_run(capsys, "show", "run.tine", "--text")[1])
    assert _run(capsys, "config", "unset", "output.format")[0] == 0
    assert not _is_json(_run(capsys, "show", "run.tine")[1])
    assert _run(capsys, "config", "get", "output.format")[0] == 1


def test_env_wins_over_file_and_flag_wins_over_env(ws, capsys, monkeypatch) -> None:
    _run(capsys, "config", "set", "output.format", "json")
    monkeypatch.setenv("OPENTINE_OUTPUT", "text")
    assert not _is_json(_run(capsys, "show", "run.tine")[1])
    assert _is_json(_run(capsys, "show", "run.tine", "--json")[1])
    monkeypatch.setenv("OPENTINE_OUTPUT", "json")
    _run(capsys, "config", "set", "output.format", "text")
    assert _is_json(_run(capsys, "show", "run.tine")[1])
    assert not _is_json(_run(capsys, "show", "run.tine", "--text")[1])


def test_folded_spelling_keeps_text_override(ws, capsys, monkeypatch) -> None:
    monkeypatch.setenv("OPENTINE_OUTPUT", "json")
    assert _is_json(_run(capsys, "show", "run.tine", "--cost")[1])
    assert not _is_json(_run(capsys, "show", "run.tine", "--cost", "--text")[1])


def test_json_and_text_conflict(ws, capsys) -> None:
    code, _, err = _run(capsys, "show", "run.tine", "--json", "--text")
    assert code == 1 and "cannot be combined" in err


@pytest.mark.parametrize("value", ["yaml", "JSON", "1"])
def test_invalid_env_value_is_a_clear_error(ws, capsys, monkeypatch, value) -> None:
    monkeypatch.setenv("OPENTINE_OUTPUT", value)
    code, out, err = _run(capsys, "show", "run.tine")
    assert code == 1 and out == ""
    assert err == f"tine: OPENTINE_OUTPUT must be 'text' or 'json', got {value!r}\n"


def test_invalid_set_value_and_key(ws, capsys) -> None:
    code, _, err = _run(capsys, "config", "set", "output.format", "yaml")
    assert code == 1 and "output.format must be 'text' or 'json'" in err
    code, _, err = _run(capsys, "config", "set", "output.colour", "json")
    assert code == 1 and "unknown setting" in err
    assert not settings_file().exists()


@pytest.mark.parametrize(
    "content",
    [
        "{",
        "[]",
        '{"version": 1, "settings": {"output.format": "yaml"}}',
        '{"version": 2, "settings": {}}',
        '{"version": 1, "settings": {"bogus.key": "x"}}',
        '{"version": 1, "version": 1, "settings": {}}',
    ],
)
def test_corrupt_file_fails_closed(ws, capsys, content) -> None:
    path = settings_file()
    path.parent.mkdir(parents=True)
    path.write_text(content, encoding="utf-8")
    code, out, err = _run(capsys, "show", "run.tine")
    assert code == 1 and out == ""
    assert err.startswith("tine: ") and "malformed" in err and "Traceback" not in err
    assert _run(capsys, "config", "set", "output.format", "json")[0] == 1
    assert path.read_text(encoding="utf-8") == content  # never overwritten


def test_commands_without_json_ignore_setting(ws, capsys, monkeypatch) -> None:
    before = _run(capsys, "keygen", "--stdout")[0]
    path = settings_file()
    path.parent.mkdir(parents=True)
    path.write_text("{", encoding="utf-8")  # not even read: keygen has no --json
    monkeypatch.setenv("OPENTINE_OUTPUT", "bogus")
    assert _run(capsys, "keygen", "--stdout")[0] == before == 0


def test_repo_config_rejects_extra_argument(ws, capsys) -> None:
    code, _, err = _run(capsys, "config", "a.b", "c", "d")
    assert code == 2 and "unrecognized arguments: d" in err


def test_text_flag_sits_beside_every_json() -> None:
    import argparse

    parser = cli._build_parser()
    pending, seen = [parser], set()
    while pending:
        node = pending.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        flags = node._option_string_actions
        assert ("--json" in flags) == ("--text" in flags), node.prog
        for action in node._actions:
            if isinstance(action, argparse._SubParsersAction):
                pending.extend(action.choices.values())
