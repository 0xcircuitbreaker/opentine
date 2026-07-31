"""Round 11 release-audit regressions: display parity, and a suite that ships green.

Two independent classes, both reported by round-10 fixers against files they were
forbidden to touch:

1. ``repository/_inspect.py`` resolved a step blob for *display* with a bare
   ``json.loads``.  ``canonical_json`` writes an integral float >= 2**53 as a bare
   digit run, so ``tine object <oid> --resolve-blobs`` and
   ``repo.inspect(resolve_blobs=True)`` rendered an OTel nanosecond timestamp as
   ``1700000000000000000`` while ``repo.load_run`` -- reading the *same bytes* with
   the kernel's ``parse_int`` hook -- returned ``1.7e+18``.  Two answers for one
   blob, and the structured ``payload`` beside it in the same response already used
   the hooked reader (``ObjectEnvelope.payload``), so a single dict disagreed with
   itself.  The tests below pin parity across the whole float-edge table and
   through the CLI, keep the existing text fallbacks intact, and freeze the class.

2. Three tests in ``tests/test_trace_capture_bounds.py`` shelled ``git`` with
   ``check=True``, and one in ``tests/test_release_audit_round10_lows.py`` asserted
   on a git-backed probe after checking only for a ``.git`` directory.  ``tests`` is
   shipped inside the sdist, so both ERRORed for a redistributor validating
   opentine-0.3.0.tar.gz with no git binary -- reporting a missing tool as an
   opentine defect.  The tests below assert those guards are inert in a checkout
   (so CI never loses the coverage), prove the shipped file skips cleanly with git
   removed from PATH, and freeze the class: every test module that shells an
   external binary by name, or reaches into ``.git``, must be guarded.
"""

from __future__ import annotations

import ast
import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

import tests.test_trace_capture_bounds as capture_bounds
from opentine import Repo, cli
from opentine._artifact_io import compact_token_budget
from opentine._blob_guard import guarded_blob_body, guarded_blob_parse
from opentine.repository import _inspect

from .test_release_audit_round10_blobread import NUMBER_EDGES, OTEL_RESULT, _run_with

ROOT = pathlib.Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# 1. inspect renders a blob body exactly as load_run reads it
# ---------------------------------------------------------------------------


def _step_run(repo: Repo, outputs: dict[str, object]):
    """Store a one-step run and return (result, step event oid)."""
    run = _run_with(outputs)
    result = repo.put_run(run, ref="heads/main")
    return result, result.event_map[run.steps[0].id]


def test_inspect_resolve_blobs_agrees_with_load_run_on_an_otel_timestamp(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    result, event = _step_run(repo, OTEL_RESULT)

    rendered = repo.inspect(event, resolve_blobs=True)["resolved_blobs"]["output_blob"]

    assert isinstance(rendered["startTimeUnixNano"], float)
    assert rendered["startTimeUnixNano"] == 1.7e18
    # The exact text an operator reads out of `tine object`.
    assert json.dumps(rendered["startTimeUnixNano"]) == "1.7e+18"
    assert rendered == repo.load_run(result.run_id).steps[0].outputs


def test_every_float_edge_renders_identically_in_inspect_and_in_load_run(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    outputs = {f"n{index}": value for index, value in enumerate(NUMBER_EDGES)}
    result, event = _step_run(repo, outputs)

    shown = repo.inspect(event, resolve_blobs=True)["resolved_blobs"]["output_blob"]
    loaded = repo.load_run(result.run_id).steps[0].outputs

    assert shown == loaded
    for name in outputs:
        # The canonical form is the contract, so display and loader must return the
        # identical Python object for it -- including the exact type, which is what
        # a hookless parse got wrong above the 2**53 integer ceiling.
        assert type(shown[name]) is type(loaded[name]), name
        assert repr(shown[name]) == repr(loaded[name]), name
    beyond = [name for name, value in outputs.items() if abs(value) >= 2**53]
    assert beyond, "the edge table must still exercise the integer ceiling"
    for name in beyond:
        assert isinstance(shown[name], float), name


def test_the_inspected_payload_and_its_resolved_blob_use_the_same_reader(tmp_path):
    """One response must not hold two answers for the same kind of number."""
    repo = Repo.init(tmp_path / "repo")
    blob = repo.put("blob", b'{"t":1.7e18}', redact=False)
    event = repo.put("event", {"cost": 1.7e18, "kind": "tool", "output_blob": blob})

    inspected = repo.inspect(event, resolve_blobs=True)

    # payload comes from ObjectEnvelope.payload (hooked since the kernel was written);
    # resolved_blobs used to come from a bare json.loads of the same canonical form.
    assert inspected["payload"]["cost"] == 1.7e18
    blob_value = inspected["resolved_blobs"]["output_blob"]["t"]
    assert blob_value == 1.7e18
    assert type(inspected["payload"]["cost"]) is type(blob_value)


def test_tine_object_resolve_blobs_prints_the_float_form(monkeypatch, tmp_path, capsys):
    repo = Repo.init(tmp_path / "repo")
    _, event = _step_run(repo, OTEL_RESULT)

    monkeypatch.setattr(
        sys,
        "argv",
        ["tine", "object", event, "--repo", str(tmp_path / "repo"), "--resolve-blobs"],
    )
    cli.main()
    out = capsys.readouterr().out

    assert "1.7e+18" in out
    assert "1700000000000000000" not in out
    assert json.loads(out)["resolved_blobs"]["output_blob"]["startTimeUnixNano"] == 1.7e18


def _holder(repo: Repo, body: bytes) -> str:
    oid = repo.put("blob", body, redact=False)
    return repo.put("event", {"kind": "tool", "output_blob": oid}, redact=False)


def test_a_blob_body_written_before_the_reader_fix_still_renders_as_a_float(tmp_path):
    # The bytes were always the canonical form; only this display path misread them.
    repo = Repo.init(tmp_path / "repo")
    holder = _holder(repo, b'{"t_ns":1700000000000000000}')

    resolved = repo.inspect(holder, resolve_blobs=True)["resolved_blobs"]["output_blob"]

    assert resolved == {"t_ns": 1.7e18}


def test_a_body_that_overflows_the_hook_still_falls_back_to_text(tmp_path):
    """KernelError is a ValueError, so the hook cannot escape the existing except."""
    repo = Repo.init(tmp_path / "repo")
    holder = _holder(repo, b'{"n":' + b"9" * 400 + b"}")

    shown = repo.inspect(holder, resolve_blobs=True)["resolved_blobs"]["output_blob"]

    assert isinstance(shown, str) and shown.startswith('{"n":999')


@pytest.mark.parametrize(
    "body",
    [
        b'{"n":1e999}',  # overflows to inf through parse_float
        b'{"n":NaN}',  # a bare JSON-extension constant
        b'{"n":Infinity}',
        b'{"n":-Infinity}',
        b'{"n":' + b"9" * 400 + b"}",  # overflows to inf through the parse_int hook
    ],
)
def test_a_body_no_json_reader_can_round_trip_renders_as_text_not_as_infinity(body, tmp_path):
    """Sibling class: the display must never emit Infinity/NaN, which is not JSON.

    ``json.dumps`` writes those as bare words, so `tine object --resolve-blobs`
    printed output its own MCP client could not parse; the loader refuses the same
    bodies (the canonical re-encode rejects a non-finite number).
    """
    repo = Repo.init(tmp_path / "repo")
    holder = _holder(repo, body)

    resolved = repo.inspect(holder, resolve_blobs=True)["resolved_blobs"]

    assert isinstance(resolved["output_blob"], str)
    # allow_nan=False is exactly the property `tine object` needs: strict JSON out.
    rendered = json.dumps(resolved, allow_nan=False)
    assert json.loads(rendered)["output_blob"] == body.decode()


def test_a_non_json_blob_body_still_falls_back_to_text(tmp_path):
    repo = Repo.init(tmp_path / "repo")
    holder = _holder(repo, b"not json at all")

    shown = repo.inspect(holder, resolve_blobs=True)["resolved_blobs"]["output_blob"]

    assert shown == "not json at all"


def test_a_wide_but_legal_blob_is_still_rendered_as_json_not_as_a_text_dump(tmp_path):
    """Sibling class: the display reader must not be stricter than the writer.

    ``guarded_blob_body`` accepts a body under ``compact_token_budget(len(body))``
    and ``blob_json`` reads it back under the same formula; inspect used a fixed
    100_000, so a 240 KB step blob of small integers -- saved, loaded and fsck-clean
    -- came back from `tine object --resolve-blobs` as an unparsed string.
    """
    repo = Repo.init(tmp_path / "repo")
    value = {"rows": [1] * 120_000}
    body = guarded_blob_body(value)
    assert 100_000 < len(body) <= _inspect.MAX_INSPECT_BLOB_BYTES
    assert compact_token_budget(len(body)) > 100_000
    assert guarded_blob_parse(body) == value  # the loader reads it

    holder = _holder(repo, body)
    shown = repo.inspect(holder, resolve_blobs=True)["resolved_blobs"]["output_blob"]

    assert shown == value


def test_the_display_reader_uses_the_shared_budget_formula():
    """Class guard: no second, hand-rolled token ceiling in this module."""
    source = (ROOT / "opentine/repository/_inspect.py").read_text(encoding="utf-8")

    assert "max_tokens=compact_token_budget(len(raw))" in source
    assert "max_tokens=100_000" not in source


def test_a_body_over_the_prefix_limit_is_still_reported_as_truncated_text(tmp_path):
    """The budget change must not swallow the truncation branch it sits behind."""
    repo = Repo.init(tmp_path / "repo")
    body = guarded_blob_body({"rows": [1] * 400_000})
    assert len(body) > _inspect.MAX_INSPECT_BLOB_BYTES
    holder = _holder(repo, body)

    shown = repo.inspect(holder, resolve_blobs=True)["resolved_blobs"]["output_blob"]

    assert shown["truncated"] is True
    assert shown["size_bytes"] == len(body)
    assert len(shown["text"]) < len(body)


def test_a_direct_blob_view_is_still_a_byte_view_not_a_reparse(tmp_path):
    """Justified sibling: `tine object <blob-oid>` shows the stored bytes verbatim."""
    repo = Repo.init(tmp_path / "repo")
    oid = repo.put("blob", b'{"t_ns":1700000000000000000}', redact=False)

    payload = repo.inspect(oid)["payload"]

    assert payload["encoding"] == "utf-8"
    assert payload["text"] == '{"t_ns":1700000000000000000}'
    assert payload["truncated"] is False


def _json_read_calls(source: str) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"load", "loads"}
        and getattr(node.func.value, "id", "") == "json"
    ]


def test_the_inspection_module_has_no_hookless_json_reader_left():
    """Class guard: every reader in the display path keeps the kernel's parse_int."""
    calls = _json_read_calls((ROOT / "opentine/repository/_inspect.py").read_text("utf-8"))

    assert calls, "the resolved-blob reader disappeared; re-point this guard"
    for call in calls:
        assert any(keyword.arg == "parse_int" for keyword in call.keywords)


# ---------------------------------------------------------------------------
# 2. the shipped test suite is green without git
# ---------------------------------------------------------------------------

#: Every test module that shells an external program *by name* must skip when the
#: program is missing.  ``sys.executable`` is exempt: it is the interpreter already
#: running.  Extend the mapping, never drop the guard.
BINARY_DEPENDENT_TEST_MODULES = {
    "tests/test_release_audit_round9_inventory.py": "git",
    "tests/test_release_inventory.py": "git",
    "tests/test_trace_capture_bounds.py": "git",
}

#: Modules that reason about a ``.git`` directory.  A ``.git`` that exists is not a
#: usable git, so each must decide with a skip and must tolerate a missing binary --
#: either by testing for it or by containing the OSError the spawn raises.
CHECKOUT_AWARE_TEST_MODULES = {
    "tests/test_release_audit_round10_lows.py",
}


def test_the_git_guard_is_inert_inside_this_checkout():
    """A false skip would silently drop the capture bounds; fail loudly instead."""
    if shutil.which("git") is None:
        pytest.skip("git is not installed here, so the guard is doing its job")

    mark = capture_bounds.pytestmark

    assert (mark.markname, mark.args[0]) == ("skipif", False), mark
    assert "git is required" in mark.kwargs["reason"]


def _external_binaries(source: str) -> set[str]:
    """Literal ``argv[0]`` strings handed to a subprocess spawn in one module."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        target = node.func
        name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")
        if name not in {"run", "check_output", "check_call", "Popen"} or not node.args:
            continue
        argument = node.args[0]
        elements = argument.elts if isinstance(argument, (ast.List, ast.Tuple)) else []
        for element in elements[:1]:
            if isinstance(element, ast.Constant) and isinstance(element.value, str):
                found.add(element.value)
    return found


def test_every_test_module_shelling_a_binary_declares_and_guards_it():
    found = {}
    for path in sorted((ROOT / "tests").rglob("*.py")):
        binaries = _external_binaries(path.read_text(encoding="utf-8"))
        if binaries:
            found[path.relative_to(ROOT).as_posix()] = binaries

    assert found == {name: {tool} for name, tool in BINARY_DEPENDENT_TEST_MODULES.items()}
    for name, tool in BINARY_DEPENDENT_TEST_MODULES.items():
        source = (ROOT / name).read_text(encoding="utf-8")
        guarded = f'shutil.which("{tool}")' in source or "except OSError" in source
        assert guarded, name


def test_no_shipped_test_module_asserts_it_is_inside_a_git_checkout():
    """Reaching into .git must always be behind a skip, never a bare assertion."""
    found = set()
    for path in sorted((ROOT / "tests").rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        if '".git"' not in source or path == pathlib.Path(__file__).resolve():
            continue  # this module names .git only to describe the rule
        relative = path.relative_to(ROOT).as_posix()
        found.add(relative)
        tolerant = 'shutil.which("git")' in source or "except OSError" in source
        assert tolerant, relative
        assert "pytest.skip" in source or "skipif" in source, relative
    assert found == CHECKOUT_AWARE_TEST_MODULES


@pytest.mark.skipif(os.name != "posix", reason="PATH stripping is only reliable on POSIX")
def test_the_capture_bounds_module_skips_cleanly_with_no_git_on_path(tmp_path):
    """The hostile environment itself: an unpacked sdist on a machine without git."""
    empty = tmp_path / "bin"
    empty.mkdir()
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", capture_bounds.__file__],
        capture_output=True,
        cwd=ROOT,
        env={
            "HOME": str(tmp_path),
            "PATH": str(empty),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(ROOT),
        },
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "3 skipped" in result.stdout, result.stdout
    assert "FileNotFoundError" not in result.stdout


def test_the_sdist_ships_the_tests_and_scripts_these_guards_protect():
    """A skip is only honest about redistribution if the file is redistributed."""
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert '"/tests"' in pyproject and '"/scripts"' in pyproject
