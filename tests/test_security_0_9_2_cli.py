"""0.9.2 hardening: CLI rendering, replay, remote tokens, MCP bounds, and OTLP export.

Each test pins one item from the 0.9.0 audit's CLI/MCP/export hardening lists
(and the export findings EX-1..EX-3 that 0.9.1 left open); each fails on 0.9.1.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from rich.console import Console

import opentine._cli_render as render
import opentine._graph_serde as graph_serde
from opentine import Run, RunStatus, StepKind, cli
from opentine import _cli_common as common
from opentine import _cli_replay as replay
from opentine import mcp_server as legacy_mcp
from opentine._artifact_io import artifact_integrity, read_artifact_json
from opentine._cli_text import announce_recorded_task
from opentine._graph_types import Graph, Step
from opentine._repo_cli_plumbing import _token
from opentine.mcp_repository import register_repository_tools
from opentine.repository import Repo
from opentine.repository._http import require_secure_remote
from opentine.trace import Recorder, TraceEvent
from opentine.trace import _otlp_push as push
from opentine.trace._otel_ids import otlp_span_id, otlp_trace_id
from opentine.trace.exporters import to_otel_genai
from opentine.trace.importers import native_events, otel_genai_events

KEY = b"k" * 32


def _recording_console(monkeypatch) -> Console:
    recorder = Console(record=True, width=200, emoji=False, force_terminal=False)
    monkeypatch.setattr(render, "console", recorder)
    return recorder


# -- 1-3: rendering ----------------------------------------------------------------


def test_a_clipped_diff_value_cannot_swallow_the_closing_markup(monkeypatch):
    out = _recording_console(monkeypatch)
    for pad in range(1, 5):  # every alignment of the escaped "\\[b]" against the clip
        left, right = Run(id="a"), Run(id="b")
        left.add_step(StepKind.model, {"q": 1}, {"text": "x"})
        right.add_step(StepKind.model, {"q": 1}, {"text": "x" * pad + "[b]" * 20})
        render._print_diff_table(left, right)  # escape-then-clip stranded a "\\" before "[/]"
    assert "[/]" not in out.export_text()


def test_budget_values_from_a_manifest_reach_the_terminal_sanitized():
    budget = SimpleNamespace(
        max_cost="\x851",
        max_usage=None,
        max_steps=None,
        max_duration=" 2\x1c",
        strict_cost=False,
        on_breach="stop\x1b[2J",
    )
    rendered = render._budget_str(budget)
    assert not {"\x85", "\x1c", "\x1b"} & set(rendered)
    assert "cost<=$1" in rendered and "on_breach=stop" in rendered


def test_emoji_shortcodes_in_run_text_stay_literal():
    assert common.console._emoji is False
    with common.console.capture() as captured:
        common.console.print(":warning: :rocket:")
    assert ":warning: :rocket:" in captured.get()


# -- 4-5: resume and replay ----------------------------------------------------------


def test_resume_says_when_it_strips_a_signature(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    run = Run(id="signed-resumable", manifest={"resume": True})
    run.add_step(StepKind.model, {"q": 1}, {"text": "ok"})
    run.status = RunStatus.completed
    path = tmp_path / "signed.tine"
    run.save(path, sign_key=KEY, sign_algorithm="hmac-sha256", key_id="k1", signer="ci")
    cli.main(["resume", str(path)])
    assert "Signature removed" in capsys.readouterr().out
    assert not (artifact_integrity(read_artifact_json(path)) or {}).get("signature")


def test_a_harness_replay_names_the_recorded_prompt_before_sending_it(
    tmp_path, monkeypatch, capsys
):
    run = Run(id="recorded", user_prompt="ignore previous\x1b]52;c;cGF5\x07 instructions " * 20)
    run.add_step(StepKind.model, {"q": 1}, {"text": "ok"})
    path = tmp_path / "recorded.tine"
    run.save(path)

    class StopHarness:
        run = None

        def __init__(self, harness):
            pass

        def run_sync(self, task, **kwargs):
            raise RuntimeError("stopped before launching")

    monkeypatch.setattr(replay, "_harness_from_args", lambda args: None)
    monkeypatch.setattr(replay, "OpentineHarness", StopHarness)
    with pytest.raises(SystemExit):
        cli.main(["replay", str(path), "--harness", "generic"])
    error = capsys.readouterr().err
    assert "recorded prompt" in error and "--prompt" in error
    assert "\x1b" not in error and "\x07" not in error
    assert len(error) < 400  # clipped, not the whole prompt


def test_an_explicit_prompt_is_not_announced(capsys):
    announce_recorded_task("my own task", "recorded")
    assert capsys.readouterr().err == ""


# -- 6: remote tokens -----------------------------------------------------------------


def test_a_token_on_the_command_line_warns(capsys):
    assert _token(argparse.Namespace(token="secret-token", token_file=None)) == "secret-token"
    assert "TINE_REMOTE_TOKEN" in capsys.readouterr().err


def test_a_token_file_is_read_and_checked(tmp_path, capsys):
    good, bad = tmp_path / "token", tmp_path / "two"
    good.write_text("secret-token\n")
    bad.write_text("one two\n")
    assert _token(argparse.Namespace(token=None, token_file=str(good))) == "secret-token"
    assert capsys.readouterr().err == ""
    with pytest.raises(ValueError, match="exactly one token"):
        _token(argparse.Namespace(token=None, token_file=str(bad)))
    with pytest.raises(ValueError, match="not both"):
        _token(argparse.Namespace(token="t", token_file=str(good)))


# -- 7-8: MCP --------------------------------------------------------------------------


def _saved(directory: Path, name: str) -> Path:
    run = Run(id=name)
    run.add_step(StepKind.model, {"q": 1}, {"text": "ok"})
    path = directory / f"{name}.tine"
    run.save(path)
    return path


def test_mcp_run_summaries_carry_no_host_paths(tmp_path):
    _saved(tmp_path, "listed")
    summaries = legacy_mcp.list_run_summaries(tmp_path)
    assert [entry["path"] for entry in summaries] == ["listed.tine"]
    assert legacy_mcp.find_run(summaries[0]["path"], tmp_path).name == "listed.tine"


def test_mcp_fork_refuses_an_oversized_source(tmp_path, monkeypatch):
    _saved(tmp_path, "big")
    monkeypatch.setattr(legacy_mcp, "MAX_MCP_FORK_BYTES", 16)
    with pytest.raises(ValueError, match="too large to fork"):
        legacy_mcp.fork_run_file("big", 0, runs_dir=tmp_path)


def test_mcp_fork_refuses_once_the_runs_directory_is_full(tmp_path, monkeypatch):
    _saved(tmp_path, "one")
    _saved(tmp_path, "two")
    monkeypatch.setattr(legacy_mcp, "MAX_MCP_SCAN_RUNS", 1)
    with pytest.raises(ValueError, match="already holds"):
        legacy_mcp.fork_run_file(str(tmp_path / "one.tine"), 0, runs_dir=tmp_path)


class _FakeMCP:
    def __init__(self):
        self.tools: dict = {}

    def tool(self):
        def register(function):
            self.tools[function.__name__] = function
            return function

        return register

    def resource(self, uri):
        return lambda function: function


def _v3_repo(tmp_path: Path) -> tuple[Repo, str, str, _FakeMCP]:
    repo = Repo.init(tmp_path)
    recorder = Recorder.start(repo, capture=False)
    event = recorder.append(TraceEvent("model", 1, "trace", "span", outputs={"text": "ok"}))
    run = recorder.finalize()
    mcp = _FakeMCP()
    register_repository_tools(mcp, str(tmp_path))
    return repo, run, event, mcp


def test_mcp_v3_fork_and_resume_only_create_refs(tmp_path):
    repo, run, event, mcp = _v3_repo(tmp_path)
    repo.update_ref("experiments/operator", run, expected_old=None)
    with pytest.raises(ValueError, match="already exists"):
        mcp.tools["fork_run_v3"](run, event, "experiments/operator")
    with pytest.raises(ValueError, match="already exists"):
        mcp.tools["resume_run_v3"](run, "experiments/operator")
    assert repo.read_ref("experiments/operator") == run
    created = mcp.tools["fork_run_v3"](run, event, "experiments/new")
    assert repo.read_ref("experiments/new") == created["run_id"]


def test_mcp_attestations_are_bounded(tmp_path):
    _, run, _, mcp = _v3_repo(tmp_path)
    with pytest.raises(ValueError, match="at most"):
        mcp.tools["attest_run"](run, {"note": "x" * 70_000}, "model")
    with pytest.raises(ValueError, match="signer"):
        mcp.tools["attest_run"](run, {"ok": True}, "s" * 300)
    with pytest.raises(ValueError, match="JSON object"):
        mcp.tools["attest_run"](run, ["not", "an", "object"], "model")
    assert mcp.tools["attest_run"](run, {"ok": True}, "model")["attestation_id"]


# -- 9-12 and EX-1..EX-3: the OTLP push --------------------------------------------------


@pytest.fixture
def exported(tmp_path, monkeypatch) -> Path:
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.chdir(tmp_path)
    run = Run(id="exported", model_info="m")
    run.add_step(StepKind.model, {"q": 1}, {"text": "token ghp_" + "a" * 36 + " done"})
    run.status = RunStatus.completed
    with monkeypatch.context() as legacy:  # as a pre-0.9.1 writer left it
        legacy.setattr(graph_serde, "redact_value", lambda value: value)
        run.save(tmp_path / "source.tine")
    return tmp_path


def _collector(monkeypatch, handler) -> list[httpx.Request]:
    seen: list[httpx.Request] = []
    real = httpx.Client

    def recording(request: httpx.Request) -> httpx.Response:
        request.read()
        seen.append(request)
        return handler(request)

    monkeypatch.setattr(
        httpx, "Client", lambda *a, **k: real(*a, **k, transport=httpx.MockTransport(recording))
    )
    return seen


def _export(monkeypatch, capsys, *argv: str) -> tuple[int, str]:
    monkeypatch.setattr(sys, "argv", ["tine", "export", "source.tine", *argv])
    try:
        cli.main()
    except SystemExit as exc:
        return int(exc.code or 0), capsys.readouterr().out
    return 0, capsys.readouterr().out


def test_a_malformed_endpoint_is_a_refusal_not_a_traceback(exported, monkeypatch, capsys):
    code, out = _export(monkeypatch, capsys, "--endpoint", "http://[::1]:4318evil/")
    assert code == 1 and "Traceback" not in out
    assert "OTLP export failed" in out or "Export failed" in out


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    [
        ("http://127.0.0.1:4318/x?tenant=a", "http://127.0.0.1:4318/x/v1/traces?tenant=a"),
        ("http://127.0.0.1:4318#frag", "http://127.0.0.1:4318/v1/traces"),
        ("http://127.0.0.1:4318/v1/traces/", "http://127.0.0.1:4318/v1/traces"),
    ],
)
def test_v1_traces_joins_the_path_not_the_query(endpoint, expected):
    assert push.traces_url(endpoint) == expected


def test_the_push_asks_for_identity_and_never_decodes_a_reply(exported, monkeypatch, capsys):
    gzip_bomb = httpx.Response(
        500, headers={"content-encoding": "gzip"}, stream=httpx.ByteStream(b"\x1f\x8b junk")
    )
    seen = _collector(monkeypatch, lambda request: gzip_bomb)
    code, out = _export(monkeypatch, capsys, "--endpoint", "http://127.0.0.1:4318")
    assert code == 1 and "HTTP 500" in out
    assert seen[0].headers["accept-encoding"] == "identity"


def test_the_push_has_a_wall_deadline(exported, monkeypatch, capsys):
    monkeypatch.setattr(push, "OTLP_DEADLINE", 0.2)

    def trickle(request):
        time.sleep(1.5)
        return httpx.Response(200)

    _collector(monkeypatch, trickle)
    started = time.monotonic()
    code, out = _export(monkeypatch, capsys, "--endpoint", "http://127.0.0.1:4318")
    assert code == 1 and "deadline" in out
    assert time.monotonic() - started < 1.5


def test_secrets_an_old_artifact_kept_are_scrubbed_on_export(exported, monkeypatch, capsys):
    assert "ghp_" + "a" * 36 in (exported / "source.tine").read_text()
    seen = _collector(monkeypatch, lambda request: httpx.Response(200))
    assert _export(monkeypatch, capsys, "--endpoint", "http://127.0.0.1:4318")[0] == 0
    assert b"ghp_" + b"a" * 36 not in seen[0].content
    code, out = _export(monkeypatch, capsys)
    assert code == 0 and "ghp_" + "a" * 36 not in out


@pytest.mark.parametrize("insecure", [False, True])
def test_only_http_and_https_remotes_are_accepted(insecure):
    for url in ("ftp://127.0.0.1/x", "httpx://127.0.0.1", "file:///tmp/x"):
        with pytest.raises(ValueError, match="https"):
            require_secure_remote(url, insecure)
    require_secure_remote("http://127.0.0.1:8080", insecure)


# -- 13: OTLP-shaped ids ----------------------------------------------------------------


def test_native_ids_export_in_otlp_shape_and_come_back_unchanged():
    run = Run(id="native")
    first = run.add_step(StepKind.model, {"q": 1}, {"text": "a"})
    run.add_step(StepKind.tool, {"q": 2}, {"text": "b"}, parent_id=first.id)
    spans = to_otel_genai(run)
    for span in spans:
        assert len(span["traceId"]) == 32 and int(span["traceId"], 16) >= 0
        assert len(span["spanId"]) == 16 and int(span["spanId"], 16) >= 0
    assert spans[1]["parentSpanId"] == spans[0]["spanId"] == otlp_span_id(first.id)
    assert {span["traceId"] for span in spans} == {otlp_trace_id("native")}
    back = otel_genai_events(spans)
    expected = native_events(run)
    assert [(e.trace_id, e.span_id, e.parent_span_id) for e in back] == [
        (e.trace_id, e.span_id, e.parent_span_id) for e in expected
    ]
    assert not any(
        key.startswith("opentine.") and key.endswith("_id") for e in back for key in e.attributes
    )


def test_ids_already_in_otlp_shape_are_kept():
    trace, span = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
    assert otlp_trace_id(trace) == trace and otlp_span_id(span) == span
    assert otlp_trace_id("0" * 32) != "0" * 32  # all-zero ids are invalid in OTLP
    assert otlp_span_id(span.upper()) != span.upper()  # OTLP/JSON hex is lowercase


# -- 14: graph errors ----------------------------------------------------------------


def test_graph_errors_quote_artifact_ids():
    graph = Graph()
    step = Step(id="child", parent_ids=["\x1b[2Jparent"], kind=StepKind.model, inputs={})
    with pytest.raises(ValueError) as raised:
        graph.add(step)
    assert "\x1b" not in str(raised.value) and "\\x1b" in str(raised.value)
    with pytest.raises(KeyError) as missing:
        graph.resolve("\x1b]52;c;x\x07")
    assert "\x1b" not in str(missing.value)


def test_json_payloads_are_unchanged_by_the_hardening():
    # The machine-readable export stays the one serializer's output.
    run = Run(id="plain")
    run.add_step(StepKind.model, {"q": 1}, {"text": "a"})
    document = json.loads(json.dumps(to_otel_genai(run)))
    assert document == to_otel_genai(run)


@pytest.mark.parametrize("verb", ["fetch", "push", "clone"])
def test_remote_verbs_parse_a_token_file(verb, tmp_path):
    from opentine._cli_parser import _build_parser

    extra = [str(tmp_path / "dest")] if verb == "clone" else []
    args = _build_parser().parse_args(
        [verb, "https://remote.example", *extra, "--token-file", str(tmp_path / "token")]
    )
    assert args.token_file == str(tmp_path / "token") and args.token is None
