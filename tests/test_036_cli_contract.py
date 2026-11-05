"""0.36 A1-A3: one error helper, documented exit codes, ``--json`` on every leaf.

* errors go to stderr; under ``--json`` stdout carries ``{"error": {...}}``
  and nothing a JSON parser would choke on;
* the per-module ``_fail`` helpers all delegate to ``opentine._cli_errors``;
* every leaf subcommand in the argparse registry accepts ``--json``;
* ``fleet up`` and ``replay --dry-run`` honour ``--json``;
* docs/CLI.md documents the exit codes.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

import pytest

from opentine import cli
from opentine._cli_errors import CODES, fail, set_json_mode
from opentine._cli_parser import _build_parser

ROOT = Path(cli.__file__).resolve().parents[1]
PACKAGE = Path(cli.__file__).parent


def _leaves(parser: argparse.ArgumentParser, path: tuple[str, ...] = ()):
    subs = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]
    if not subs:
        yield path, parser
        return
    seen: set[int] = set()
    for action in subs:
        for name, child in action.choices.items():
            if id(child) not in seen:
                seen.add(id(child))
                yield from _leaves(child, (*path, name))


def _invoke(capsys, *argv: str) -> tuple[int, str, str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _json_error(out: str) -> dict:
    lines = [line for line in out.splitlines() if line.strip()]
    assert len(lines) == 1, out
    payload = json.loads(lines[0])
    assert set(payload["error"]) == {"code", "exit_code", "message"}
    return payload["error"]


def test_every_leaf_subcommand_accepts_json() -> None:
    leaves = list(_leaves(_build_parser()))
    assert len(leaves) > 100, "the registry walk found too few commands"
    missing = [
        " ".join(path) for path, parser in leaves if "--json" not in parser._option_string_actions
    ]
    assert missing == []


def test_fail_writes_stderr_and_json_only_under_json(capsys) -> None:
    with pytest.raises(SystemExit) as exit_:
        fail("no such run: x", 3)
    out, err = capsys.readouterr()
    assert exit_.value.code == 3 and out == "" and "no such run: x" in err
    previous = set_json_mode(True)
    try:
        with pytest.raises(SystemExit):
            fail("budget \x1b[2J gone", 5, prefix="fleet: ")
    finally:
        set_json_mode(previous)
    out, err = capsys.readouterr()
    assert _json_error(out) == {
        "code": "budget_exhausted",
        "exit_code": 5,
        "message": "fleet: budget [2J gone",
    }
    assert "\x1b" not in out and "budget" in err


def test_no_module_keeps_its_own_fail_printer() -> None:
    for path in sorted(PACKAGE.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == "_fail":
                body = ast.unparse(node)
                assert "console.print" not in body and "print(" not in body, path.name
                assert "fail(" in body or "error(" in body, path.name


def test_a_refusal_goes_to_stderr_not_stdout(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    code, out, err = _invoke(capsys, "trust", "policy", "rm", "nope")
    assert code == 1 and out == "" and "trust policy: unknown policy" in err


def test_native_json_command_error_is_json_on_stdout(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    code, out, err = _invoke(capsys, "show", "missing-run", "--json")
    assert code == 1 and "Run not found" in err
    assert _json_error(out) == {
        "code": "error",
        "exit_code": 1,
        "message": "Run not found: missing-run",
    }


def test_usage_error_under_json_is_exit_2_with_json(capsys) -> None:
    code, out, err = _invoke(capsys, "show", "r", "--json", "--no-such-flag")
    assert code == 2 and "usage:" in err
    error = _json_error(out)
    assert error["code"] == "usage" and "--no-such-flag" in error["message"]


def test_fallback_json_wraps_output_and_error(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    code, out, _ = _invoke(capsys, "keygen", "--json")
    payload = json.loads(out)
    assert code == 1 and payload["command"] == "keygen" and payload["exit_code"] == 1
    assert payload["error"]["code"] == "error" and "--out PATH" in payload["output"]
    out_file = tmp_path / "k.key"
    code, out, _ = _invoke(capsys, "keygen", "--out", str(out_file), "--json")
    payload = json.loads(out)
    assert code == 0 and payload["exit_code"] == 0 and "error" not in payload


def test_output_format_json_does_not_wrap_fallback_commands(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENTINE_OUTPUT", "json")
    _, args = cli.parse(["keygen", "--out", str(tmp_path / "k.key")])
    assert args.json is False
    _, args = cli.parse(["ls"])
    assert args.json is True


def _fleet(tmp_path: Path) -> Path:
    path = tmp_path / "fleet.toml"
    argv = json.dumps([sys.executable, "-c", "pass"])
    path.write_text(
        f'[fleet]\nname = "f"\n\n[[agents]]\nname = "coder"\nargv = {argv}\ncount = 2\n'
    )
    return path


def test_fleet_up_dry_run_honours_json(tmp_path, capsys) -> None:
    code, out, _ = _invoke(capsys, "fleet", "up", str(_fleet(tmp_path)), "--dry-run", "--json")
    payload = json.loads(out)
    assert code == 0 and payload["command"] == "fleet up" and payload["dry_run"] is True
    assert [m["agent"] for m in payload["members"]] == ["coder", "coder"]


def test_fleet_up_honours_json(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("OPENTINE_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.chdir(tmp_path)
    code, out, _ = _invoke(capsys, "fleet", "up", str(_fleet(tmp_path)), "--trust", "--json")
    payload = json.loads(out)  # one object: no progress lines mixed in
    assert payload["command"] == "fleet up" and payload["exit_code"] == code
    assert len(payload["members"]) == 2


def test_replay_dry_run_honours_json(tmp_path, monkeypatch, capsys) -> None:
    from opentine import Run, StepKind

    monkeypatch.chdir(tmp_path)
    run = Run(id="dry_run_json", model_info="mock-model", user_prompt="prompt")
    step = run.add_step(StepKind.model, {"text": "ask"}, {"text": "answer"})
    run.add_step(StepKind.done, {"text": "done"}, parent_id=step.id)
    artifact = tmp_path / "run.tine"
    run.save(artifact)
    code, out, _ = _invoke(capsys, "replay", str(artifact), "--dry-run", "--json")
    payload = json.loads(out)
    assert code == 0 and payload["dry_run"] is True and payload["reused"] == 2


def test_exit_codes_are_documented() -> None:
    text = (ROOT / "docs" / "CLI.md").read_text(encoding="utf-8")
    assert "## Errors, `--json` and exit codes" in text
    for code, name in CODES.items():
        assert f"| {code} | `{name}` |" in text
