"""0.9.1 security fixes on the CLI, import, export, pricing, search and MCP surfaces.

One test (or a few) per audit finding, named for what an attacker could do
before the fix:

* E-1  terminal escapes from an untrusted ``.tine`` via uncaught tracebacks
* E-2  terminal escapes and silent re-pricing from a workspace pricing overlay
* E-3  ``tine import`` container amplification (no structural pre-scan)
* E-4  the import byte cap skipped for pipes/FIFOs/devices and JSONL stdin
* E-5  ``export --output`` writing through a planted symlink
* E-7  an unsigned (model-written) evaluation deciding search rank
* H1/H2  invisible/format characters on the terminal and MCP text
* H5   credentials printed from an endpoint URL
"""

from __future__ import annotations

import io
import json
import os
import sys
import threading
from pathlib import Path

import pytest

from opentine import cli
from opentine._cli_common import _terminal
from opentine._cli_text import plain_text, without_userinfo
from opentine._mcp_safety import SafeErrors, clip
from opentine._step_usage import _usage_value
from opentine.billing.catalog import BUNDLED_CATALOG, catalog_hash
from opentine.billing.types import RateCard
from opentine.core import Run, RunStatus, StepKind
from opentine.kernel import KernelError
from opentine.mcp_repository import register_repository_tools
from opentine.repository import Repo
from opentine.repository._search_scores import best_score
from opentine.repository.runs import put_run
from opentine.trace import _import_guard
from opentine.trace.importers import jsonl_events

ESCAPES = "\x1b]52;c;UFdORUQ=\x07\x1b]0;PWNED\x07\x1b[2J\x9b31m‮"
HIDDEN = "​‍⁠﻿ \U000e0041"
CONTROL = ("\x1b", "\x07", "\x9b", "‮")


def _clean(text: str) -> bool:
    return not any(mark in text for mark in (*CONTROL, *HIDDEN))


def _saved_run(path: Path, *, run_id: str = "victim") -> Path:
    run = Run(id=run_id, model_info="mock-model")
    run.add_step(StepKind.model, {"prompt": "hi"}, outputs={"text": "ok"}, usage={"input": 1})
    run.status = RunStatus.completed
    run.save(path)
    return path


def _escape_usage_artifact(path: Path) -> Path:
    """A saved run whose step usage carries a terminal-escape key (the E-1 PoC)."""
    _saved_run(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    step = data["graph"]["steps"][data["graph"]["order"][0]]
    step["usage"] = {ESCAPES: "x"}
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def workspace(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENTINE_DEBUG", raising=False)
    return tmp_path


# --- E-1 ---------------------------------------------------------------------


def test_step_usage_errors_quote_the_artifact_name_instead_of_emitting_it():
    with pytest.raises(ValueError) as refused:
        _usage_value(ESCAPES, "x")
    assert "\x1b" not in str(refused.value) and "\\x1b" in str(refused.value)


@pytest.mark.parametrize(
    "verb",
    [
        ["show"],
        ["show", "--json"],
        ["cost"],
        ["price"],
        ["tag", "--list"],
        ["replay", "--dry-run"],
        ["resume"],
    ],
)
def test_an_escape_bearing_artifact_never_reaches_the_terminal_raw(workspace, capfd, verb):
    path = _escape_usage_artifact(workspace / "evil.tine")
    with pytest.raises(SystemExit) as exited:
        cli.main([verb[0], str(path), *verb[1:]])
    assert exited.value.code == 1
    out, err = capfd.readouterr()
    assert _clean(out + err), (out + err)[-400:]
    assert "Traceback" not in out + err


def test_an_uncaught_exception_becomes_one_sanitized_line(workspace, monkeypatch, capsys):
    def boom(args):
        raise RuntimeError(f"bad {ESCAPES}{HIDDEN} thing")

    monkeypatch.setitem(cli.LEGACY_COMMANDS, "ls", boom)
    with pytest.raises(SystemExit) as exited:
        cli.main(["ls"])
    assert exited.value.code == 1
    err = capsys.readouterr().err
    assert err.startswith("tine: bad ") and err.count("\n") == 1
    assert _clean(err)


def test_debug_env_restores_the_traceback(workspace, monkeypatch):
    def boom(args):
        raise RuntimeError("for the developer")

    monkeypatch.setitem(cli.LEGACY_COMMANDS, "ls", boom)
    monkeypatch.setenv("OPENTINE_DEBUG", "1")
    with pytest.raises(RuntimeError, match="for the developer"):
        cli.main(["ls"])


def test_mcp_tool_errors_are_sanitized_and_clean_ones_keep_their_type():
    class Server:
        def __init__(self):
            self.tools = {}

        def tool(self):
            def register(function):
                self.tools[function.__name__] = function
                return function

            return register

    server = Server()
    safe = SafeErrors(server)

    @safe.tool()
    def show_run(run_id: str) -> str:
        raise ValueError(f"step usage.{ESCAPES} must be finite")

    @safe.tool()
    def missing(run_id: str) -> str:
        raise FileNotFoundError("no such run")

    with pytest.raises(ValueError) as refused:
        server.tools["show_run"]("x")
    assert _clean(str(refused.value)) and "must be finite" in str(refused.value)
    with pytest.raises(FileNotFoundError, match="no such run"):
        server.tools["missing"]("x")


# --- E-2 ---------------------------------------------------------------------


def _card(**changes) -> dict:
    data = json.loads(BUNDLED_CATALOG.read_text(encoding="utf-8"))
    card = next(c for c in data["cards"] if c["provider"] == "openai" and c["model"] == "gpt-4o")
    return {**card, **changes}


@pytest.mark.parametrize("currency", ["usd", "US", "USDX", f"USD{ESCAPES}", ""])
def test_rate_card_currency_must_be_an_iso_code(currency):
    with pytest.raises(ValueError):
        RateCard.from_dict(_card(currency=currency))


def test_rate_card_accepts_iso_currencies():
    assert RateCard.from_dict(_card(currency="EUR", currency_to_usd="1.1")).currency == "EUR"


def _write_workspace_overlay(root: Path) -> None:
    data = json.loads(BUNDLED_CATALOG.read_text(encoding="utf-8"))
    overlay = {key: value for key, value in data.items() if key not in {"cards", "signature"}}
    overlay["cards"] = [_card(id="workspace:gpt-4o")]
    overlay.pop("catalog_id", None)
    overlay["catalog_id"] = "sha256:" + catalog_hash(overlay)
    (root / ".tine").mkdir(exist_ok=True)
    (root / ".tine" / "pricing.json").write_text(json.dumps(overlay), encoding="utf-8")


def test_an_unsigned_workspace_overlay_is_announced(workspace, monkeypatch, capsys):
    from opentine import _cli_guard

    monkeypatch.setattr(_cli_guard, "_warned", set())
    monkeypatch.setenv("XDG_CONFIG_HOME", str(workspace / "no-config"))
    monkeypatch.delenv("TINE_PRICING_CATALOG", raising=False)
    monkeypatch.delenv("OPENTINE_TRUST_WORKSPACE_PRICING", raising=False)
    _write_workspace_overlay(workspace)
    cli.main(["pricing", "show", "openai", "gpt-4o"])
    assert "unsigned workspace overlay" in capsys.readouterr().err

    monkeypatch.setattr(_cli_guard, "_warned", set())
    monkeypatch.setenv("OPENTINE_TRUST_WORKSPACE_PRICING", "1")
    cli.main(["pricing", "show", "openai", "gpt-4o"])
    assert "workspace overlay" not in capsys.readouterr().err


def test_the_overlay_hook_does_not_outlive_the_cli_call(workspace):
    from opentine.billing import catalog

    before = catalog.workspace_overlay_hook
    with pytest.raises(SystemExit):
        cli.main(["show", "no-such-run"])
    assert catalog.workspace_overlay_hook is before


# --- E-3 ---------------------------------------------------------------------


def _bomb(containers: int) -> bytes:
    return b"[" + b"{}," * containers + b"{}]"


def test_a_dense_document_is_refused_before_it_is_parsed():
    with pytest.raises(KernelError, match="structure exceeds"):
        _import_guard.shape_checked(_bomb(100_000))
    assert _import_guard.shape_checked(b'{"spans": []}') == b'{"spans": []}'


@pytest.mark.parametrize("source_format", ["otel-json", "otel-spans", "langchain"])
def test_tine_import_prescans_whole_documents(tmp_path, monkeypatch, source_format):
    from opentine import _cli_import_read

    path = tmp_path / "bomb.json"
    path.write_bytes(_bomb(100_000))
    parsed = []
    monkeypatch.setattr(_cli_import_read, "_records", lambda text: parsed.append(text) or [])
    with pytest.raises(KernelError, match="structure exceeds"):
        _cli_import_read.read_events(str(path), source_format)
    assert parsed == []


def test_a_jsonl_structure_bomb_line_is_skipped_like_any_unusable_line(tmp_path):
    path = tmp_path / "trace.jsonl"
    good = json.dumps({"kind": "model", "trace_id": "t", "span_id": "a"})
    path.write_bytes(_bomb(100_000) + b"\n" + good.encode() + b"\n")
    events = jsonl_events(path)
    assert [event.span_id for event in events] == ["a"]


# --- E-4 ---------------------------------------------------------------------


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a POSIX FIFO")
def test_a_fifo_source_is_read_only_up_to_the_cap(tmp_path, monkeypatch):
    from opentine import _cli_import_read

    monkeypatch.setattr(_cli_import_read, "MAX_TRACE_IMPORT_BYTES", 1000)
    fifo = tmp_path / "trace.fifo"
    os.mkfifo(fifo)
    written = [0]

    def writer():
        try:
            with open(fifo, "wb") as handle:
                for _ in range(1024):
                    handle.write(b" " * 1024)
                    written[0] += 1024
        except (BrokenPipeError, OSError):
            pass

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    with pytest.raises(ValueError, match="aggregate payload limit"):
        _cli_import_read.read_events(str(fifo), "otel-json")
    thread.join(timeout=10)
    # st_size is 0 for a FIFO; the old path then read the whole stream (1 MiB).
    assert written[0] < 1024 * 1024


def test_jsonl_on_stdin_is_read_in_bounded_lines(monkeypatch):
    from opentine import _cli_import_read

    sizes: list[int] = []

    class Spy(io.BytesIO):
        def readline(self, size=-1):
            sizes.append(size)
            return super().readline(size)

    good = json.dumps({"kind": "model", "trace_id": "t", "span_id": "b"}).encode()
    stream = Spy(b"x" * 500 + b"\n" + good + b"\n")
    monkeypatch.setattr(_cli_import_read, "MAX_JSONL_LINE_BYTES", 64)
    monkeypatch.setattr(sys, "stdin", type("Stdin", (), {"buffer": stream})())
    events = _cli_import_read.read_events("-", "jsonl")
    assert [event.span_id for event in events] == ["b"]
    assert sizes and all(0 < size <= 65 for size in sizes)


# --- E-5 ---------------------------------------------------------------------


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")


def test_export_refuses_a_dangling_symlink_destination(workspace, capsys):
    source = _saved_run(workspace / "source.tine")
    victim = workspace / "victim"
    victim.mkdir()
    link = workspace / "out.json"
    _symlink_or_skip(link, victim / "created_by_tine")
    with pytest.raises(SystemExit) as exited:
        cli.main(["export", str(source), "--output", str(link)])
    assert exited.value.code == 1
    assert not (victim / "created_by_tine").exists()


def test_export_force_replaces_the_link_and_never_writes_through_it(workspace):
    source = _saved_run(workspace / "source.tine")
    victim = workspace / "victim.txt"
    victim.write_text("keep me", encoding="utf-8")
    link = workspace / "out.json"
    _symlink_or_skip(link, victim)
    cli.main(["export", str(source), "--output", str(link), "--force"])
    assert victim.read_text(encoding="utf-8") == "keep me"
    assert not link.is_symlink()
    assert "resourceSpans" in link.read_text(encoding="utf-8")


# --- E-7 ---------------------------------------------------------------------


def test_a_signed_score_beats_any_unsigned_one():
    assert best_score([(1.7e308, False), (0.4, True)], signed_only=False) == (0.4, True)
    assert best_score([(0.9, False)], signed_only=False) == (0.9, False)
    assert best_score([(0.9, False)], signed_only=True) == (None, None)
    assert best_score([], signed_only=False) == (None, None)


def _completed(repo: Repo, name: str) -> str:
    run = Run(id=name, model_info="m")
    run.add_step(StepKind.model, {"text": name}, outputs={"text": "ok"})
    run.status = RunStatus.completed
    return put_run(repo, run, ref=f"heads/{name}").run_id


def test_search_ranks_signed_evaluations_above_injected_unsigned_ones(tmp_path):
    repo = Repo.init(tmp_path)
    good, evil = _completed(repo, "good"), _completed(repo, "evil")
    repo.attest(evil, {"kind": "evaluation", "scores": {"q": 1e300}}, signer="model")
    repo.attest(good, {"kind": "evaluation", "scores": {"q": 0.5}}, signer="ci", key=b"k" * 32)
    ranked = [(row.run_id, row.score_signed) for row in repo.search("")]
    assert ranked == [(good, True), (evil, False)]
    signed = {row.run_id: row.score for row in repo.search("", signed_only=True)}
    assert signed == {good: 0.5, evil: None}
    assert [row.run_id for row in repo.search("", min_score=0.1, signed_only=True)] == [good]


def test_mcp_evaluate_run_refuses_out_of_range_scores(tmp_path):
    repo = Repo.init(tmp_path)
    run = _completed(repo, "target")

    class Server:
        def __init__(self):
            self.tools = {}

        def tool(self):
            def register(function):
                self.tools[function.__name__] = function
                return function

            return register

        def resource(self, uri):
            return lambda function: function

    server = Server()
    register_repository_tools(server, str(tmp_path))
    for score in (1.7e308, -2e6, float("inf"), True):
        with pytest.raises(ValueError):
            server.tools["evaluate_run"](run, {"quality": score}, "ci")
    assert server.tools["evaluate_run"](run, {"quality": 0.75}, "ci")["attestation_id"]
    rows = server.tools["search_runs"]("", signed_only=True)
    assert rows and rows[0]["score"] is None and rows[0]["score_signed"] is None


def test_repo_search_cli_echoes_signed_only(tmp_path, capsys):
    repo = Repo.init(tmp_path)
    _completed(repo, "one")
    cli.main(["repo-search", "--repo", str(tmp_path), "--signed-only", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["signed_only"] is True
    assert payload["results"][0]["score_signed"] is None


# --- H1 / H2 -----------------------------------------------------------------


def test_terminal_and_mcp_text_drop_invisible_and_bidi_characters():
    text = f"a{HIDDEN}b{ESCAPES}c"
    assert _clean(_terminal(text))
    assert _clean(clip(text))
    assert _clean(plain_text(text))
    assert "a" in clip(text) and "c" in clip(text)
    assert clip("line1\nline2") == "line1\\nline2"
    assert plain_text("tab\there", keep="\t") == "tab\there"


# --- H5 ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "shown"),
    [
        ("https://user:secret@collector.example:4318/v1", "https://collector.example:4318/v1"),
        ("https://collector.example/v1", "https://collector.example/v1"),
        ("http://a@b@host/x", "http://host/x"),
    ],
)
def test_printed_endpoints_drop_their_credentials(url, shown):
    assert without_userinfo(url) == shown


def test_an_unreachable_endpoint_is_reported_without_its_password(workspace, capsys):
    source = _saved_run(workspace / "source.tine")
    with pytest.raises(SystemExit):
        cli.main(["export", str(source), "--endpoint", "http://user:hunter2@127.0.0.1:9/"])
    captured = capsys.readouterr()
    assert "hunter2" not in captured.out + captured.err
