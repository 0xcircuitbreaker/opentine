"""``tine export``: a recorded run leaving for the OpenTelemetry ecosystem.

``tine import`` was the only interop direction that had a command. Everything
here drives ``opentine.cli.main`` in-process — no subprocess, so no binary and
no git-shelling contract — and the central claim is a *round trip*, not a shape
check: the document the command writes is fed back through the very importer
``tine import --format otel-json`` uses, and the events that come out must carry
the structure ``native_events`` produced from the run that went in — every span
id, parent, causal edge, payload, token counter and cost. A shape assertion
would pass on a document that dropped the causal edges, the usage counters, or
the error status; this one cannot. The two edges the mapping is documented to
move rather than keep (cost, and absent token counters) are pinned by their own
test, so the normalization cannot grow to cover a real loss.

The push half is exercised against a real ``httpx`` client wired to a
``MockTransport``, so the URL, the method, the ``Content-Type`` and the body are
the ones httpx would really put on the wire, and a connection failure is a real
``httpx.ConnectError`` raised by the transport rather than a stubbed sentinel.
"""

from __future__ import annotations

import json
import sys
from dataclasses import fields
from pathlib import Path

import httpx
import pytest

from opentine import Run, RunStatus, StepKind, cli
from opentine._cli_export import TRACES_PATH
from opentine.trace.exporters import COST_ATTRIBUTE
from opentine.trace.importers import native_events, otel_genai_events
from opentine.trace.schema import TraceEvent

COMPAT = Path(__file__).parent / "fixtures" / "compat"
ENDPOINT_ENV = "OTEL_EXPORTER_OTLP_ENDPOINT"


def _structure(event) -> dict:
    """Everything the GenAI mapping promises to carry, in a comparable form.

    Two documented edges are *normalized*, never ignored, and the loss test
    below proves they are the only two: ``cost`` has no GenAI convention so it
    rides in ``opentine.cost_usd``, which the importer leaves as an attribute;
    and a span that reported no tokens imports as explicit zero counters.
    """
    recorded = event.cost if event.cost is not None else event.attributes.get(COST_ATTRIBUTE, 0.0)
    return {
        "kind": event.kind,
        "span_id": event.span_id,
        "parent_span_id": event.parent_span_id,
        "causal_span_ids": event.causal_span_ids,
        "actor": event.actor,
        "model": event.model,
        "timestamp": event.timestamp,
        "duration": event.duration,
        "inputs": event.inputs,
        "outputs": event.outputs,
        "usage": {name: count for name, count in event.usage.items() if count},
        "cost": float(recorded),
    }


def _reproduces(document: dict, run: Run) -> bool:
    return [_structure(event) for event in otel_genai_events(document)] == [
        _structure(event) for event in native_events(run)
    ]


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #


def _rich_run(path: Path | None = None) -> Run:
    """A run with every feature the mapping has to carry.

    Branched (so a merge parent lands in the causal links), with a tool step, a
    priced model step with token usage, and a failure — the four shapes that
    take different paths through the exporter.
    """
    run = Run(id="export_source", model_info="mock-model", user_prompt="test prompt")
    think = run.add_step(StepKind.think, {"text": "planning"})
    tool = run.add_step(
        StepKind.tool,
        {"name": "grep", "arguments": {"q": "x"}},
        parent_id=think.id,
        tool_info={"name": "grep"},
    )
    model = run.add_step(
        StepKind.model,
        {"prompt": "answer"},
        outputs={"text": "an answer"},
        parent_id=tool.id,
        model_info="mock-model",
        cost=0.0125,
        usage={"input": 11, "output": 7},
    )
    # Two parents, so the export has to carry a causal edge, not just a tree.
    merge = run.add_step(StepKind.done, {"text": "done"}, parent_ids=[think.id, model.id])
    run.add_step(StepKind.error, {"text": "boom"}, parent_id=merge.id, error={"message": "boom"})
    run.status = RunStatus.completed
    if path is not None:
        run.save(path)
    return run


@pytest.fixture
def workspace(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.delenv(ENDPOINT_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    _rich_run(tmp_path / "source.tine")
    return tmp_path


def _invoke(monkeypatch, capsys, *argv: str) -> tuple[int, str]:
    """Drive ``cli.main()`` exactly as the console script does; return (code, output)."""
    monkeypatch.setattr(sys, "argv", ["tine", *argv])
    code = 0
    try:
        cli.main()
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, capsys.readouterr().out


def _collector(monkeypatch, handler) -> list[httpx.Request]:
    """Route every client the export builds through *handler*; record the requests."""
    seen: list[httpx.Request] = []
    real_client = httpx.Client

    def recording(request: httpx.Request) -> httpx.Response:
        request.read()  # materialize the body before the transport is torn down
        seen.append(request)
        return handler(request)

    def factory(*args, **kwargs):
        return real_client(*args, **kwargs, transport=httpx.MockTransport(recording))

    monkeypatch.setattr(httpx, "Client", factory)
    return seen


# --------------------------------------------------------------------------- #
# (a) the round trip: export -> importer -> the same run
# --------------------------------------------------------------------------- #


def test_exported_document_reimports_to_the_events_the_run_produced(workspace, monkeypatch, capsys):
    run = Run.load(workspace / "source.tine")

    code, out = _invoke(monkeypatch, capsys, "export", "source.tine")

    assert code == 0
    document = json.loads(out)
    assert len(otel_genai_events(document)) == len(run.steps)
    assert _reproduces(document, run), (
        "the OTLP document must re-import to the events the run produced"
    )


def test_the_round_trip_loses_nothing_but_the_two_documented_edges(workspace, monkeypatch, capsys):
    """Pin the loss set, so the normalization above cannot hide a real regression."""
    run = Run.load(workspace / "source.tine")
    _, out = _invoke(monkeypatch, capsys, "export", "source.tine")

    for source, returned in zip(
        native_events(run), otel_genai_events(json.loads(out)), strict=True
    ):
        differing = {
            field.name
            for field in fields(TraceEvent)
            if getattr(source, field.name) != getattr(returned, field.name)
        }
        assert differing <= {"cost", "usage", "attributes"}, differing
        assert returned.attributes[COST_ATTRIBUTE] == str(source.cost), "cost rides in an attribute"
        assert {name: count for name, count in returned.usage.items() if count} == source.usage
        assert source.attributes.items() <= returned.attributes.items(), "attributes only grew"


def test_the_round_trip_carries_structure_costs_and_failure(workspace, monkeypatch, capsys):
    """Named facts, so a regression says which part of the run was dropped."""
    run = Run.load(workspace / "source.tine")

    _, out = _invoke(monkeypatch, capsys, "export", "source.tine")
    events = otel_genai_events(json.loads(out))

    assert [event.kind for event in events] == ["model", "tool", "model", "model", "error"]
    assert [event.span_id for event in events] == [step.id for step in run.steps]
    assert [event.parent_span_id for event in events] == [step.parent_id for step in run.steps]
    merge = events[3]
    assert merge.causal_span_ids == tuple(run.steps[3].parent_ids[:-1]), "merge parent survived"
    priced = events[2]
    assert priced.usage == {"input": 11, "output": 7}
    assert priced.attributes[COST_ATTRIBUTE] == "0.0125", "cost has no GenAI key of its own"
    assert priced.outputs == {"text": "an answer"}


def test_a_second_export_of_the_reimported_document_is_identical(workspace, monkeypatch, capsys):
    """Exporting is idempotent, so a pipeline can re-emit without drifting."""
    _, first = _invoke(monkeypatch, capsys, "export", "source.tine")
    events = otel_genai_events(json.loads(first))

    from opentine.trace.exporters import to_otel_genai_document

    assert otel_genai_events(to_otel_genai_document(events)) == events


def test_the_document_is_a_complete_otlp_envelope(workspace, monkeypatch, capsys):
    _, out = _invoke(monkeypatch, capsys, "export", "source.tine")
    document = json.loads(out)

    scope = document["resourceSpans"][0]["scopeSpans"][0]
    assert scope["scope"]["name"] == "opentine"
    assert len(scope["spans"]) == 5
    resource = document["resourceSpans"][0]["resource"]["attributes"]
    assert resource == [{"key": "service.name", "value": {"stringValue": "opentine"}}]
    assert out.startswith("{\n"), "stdout is the pretty document and nothing else"


def test_service_name_names_the_run_in_the_backend(workspace, monkeypatch, capsys):
    _, out = _invoke(monkeypatch, capsys, "export", "source.tine", "--service-name", "agents")

    resource = json.loads(out)["resourceSpans"][0]["resource"]["attributes"]
    assert resource == [{"key": "service.name", "value": {"stringValue": "agents"}}]


@pytest.mark.parametrize("release", ["v0_3_0", "v0_4_0", "v0_5_0"])
def test_artifacts_from_every_supported_release_still_export(
    workspace, monkeypatch, capsys, release
):
    """The compatibility promise reaches the new verb: 0.3.0 onwards must export."""
    fixture = COMPAT / release / "artifact.tine"
    if not fixture.exists():  # pragma: no cover - fixture set is committed
        pytest.skip(f"no compat fixture for {release}")

    code, out = _invoke(monkeypatch, capsys, "export", str(fixture))

    assert code == 0
    assert _reproduces(json.loads(out), Run.load(fixture))


# --------------------------------------------------------------------------- #
# (b) --output
# --------------------------------------------------------------------------- #


def test_output_writes_the_document_to_the_file(workspace, monkeypatch, capsys):
    code, out = _invoke(monkeypatch, capsys, "export", "source.tine", "--output", "spans.json")

    assert code == 0
    document = json.loads((workspace / "spans.json").read_text(encoding="utf-8"))
    assert _reproduces(document, Run.load(workspace / "source.tine"))
    assert "5 span(s)" in out and "spans.json" in out
    assert "resourceSpans" not in out, "the document went to the file, not to stdout"


def test_output_refuses_to_overwrite_without_force(workspace, monkeypatch, capsys):
    (workspace / "spans.json").write_text("keep me", encoding="utf-8")

    code, out = _invoke(monkeypatch, capsys, "export", "source.tine", "--output", "spans.json")

    assert code == 1 and "Refusing to overwrite" in out
    assert (workspace / "spans.json").read_text(encoding="utf-8") == "keep me"

    code, _ = _invoke(
        monkeypatch, capsys, "export", "source.tine", "--output", "spans.json", "--force"
    )
    assert code == 0
    assert "resourceSpans" in (workspace / "spans.json").read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# (c) the OTLP push
# --------------------------------------------------------------------------- #


def test_push_posts_the_document_to_v1_traces(workspace, monkeypatch, capsys):
    seen = _collector(monkeypatch, lambda request: httpx.Response(200, json={"partialSuccess": {}}))

    code, out = _invoke(
        monkeypatch, capsys, "export", "source.tine", "--endpoint", "https://collector.test:4318"
    )

    assert code == 0, out
    assert len(seen) == 1
    request = seen[0]
    assert request.method == "POST"
    assert str(request.url) == f"https://collector.test:4318{TRACES_PATH}"
    assert request.headers["content-type"] == "application/json"
    posted = json.loads(request.content)
    assert _reproduces(posted, Run.load(workspace / "source.tine"))
    assert "5 span(s)" in out and "collector.test" in out and "200" in out


def test_an_endpoint_that_already_names_v1_traces_is_used_as_is(workspace, monkeypatch, capsys):
    seen = _collector(monkeypatch, lambda request: httpx.Response(202))

    code, out = _invoke(
        monkeypatch,
        capsys,
        "export",
        "source.tine",
        "--endpoint",
        f"https://collector.test{TRACES_PATH}",
        "--format",
        "otlp",
    )

    assert code == 0, out
    assert str(seen[0].url) == f"https://collector.test{TRACES_PATH}"
    assert "202" in out


def test_the_otel_environment_variable_supplies_the_endpoint(workspace, monkeypatch, capsys):
    seen = _collector(monkeypatch, lambda request: httpx.Response(200))
    monkeypatch.setenv(ENDPOINT_ENV, "https://from-env.test/")

    code, out = _invoke(monkeypatch, capsys, "export", "source.tine", "--format", "otlp")

    assert code == 0, out
    assert str(seen[0].url) == f"https://from-env.test{TRACES_PATH}"


def test_otlp_without_any_endpoint_is_a_usage_refusal(workspace, monkeypatch, capsys):
    code, out = _invoke(monkeypatch, capsys, "export", "source.tine", "--format", "otlp")

    assert code == 1
    assert "--endpoint" in out and ENDPOINT_ENV in out


def test_a_loopback_collector_needs_no_insecure_opt_in(workspace, monkeypatch, capsys):
    seen = _collector(monkeypatch, lambda request: httpx.Response(200))

    code, out = _invoke(
        monkeypatch, capsys, "export", "source.tine", "--endpoint", "http://127.0.0.1:4318"
    )

    assert code == 0, out
    assert str(seen[0].url) == f"http://127.0.0.1:4318{TRACES_PATH}"


def test_cleartext_to_a_remote_collector_is_refused_until_opted_in(workspace, monkeypatch, capsys):
    seen = _collector(monkeypatch, lambda request: httpx.Response(200))

    code, out = _invoke(
        monkeypatch, capsys, "export", "source.tine", "--endpoint", "http://collector.test:4318"
    )

    assert code == 1 and seen == [], "nothing may leave before the transport check passes"
    assert "cleartext" in out and "--allow-insecure" in out

    code, out = _invoke(
        monkeypatch,
        capsys,
        "export",
        "source.tine",
        "--endpoint",
        "http://collector.test:4318",
        "--allow-insecure",
    )
    assert code == 0, out
    assert len(seen) == 1


# --------------------------------------------------------------------------- #
# (d) a push that fails must fail the command
# --------------------------------------------------------------------------- #


def test_a_connection_error_exits_non_zero_and_names_the_endpoint(workspace, monkeypatch, capsys):
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    _collector(monkeypatch, refuse)

    code, out = _invoke(
        monkeypatch, capsys, "export", "source.tine", "--endpoint", "https://down.test:4318"
    )

    assert code == 1
    assert "unreachable" in out and f"https://down.test:4318{TRACES_PATH}" in out
    assert "connection refused" in out


@pytest.mark.parametrize("status", [400, 401, 429, 500, 503])
def test_a_non_2xx_reply_exits_non_zero_with_the_status_and_the_reason(
    workspace, monkeypatch, capsys, status
):
    _collector(monkeypatch, lambda request: httpx.Response(status, text="collector said no"))

    code, out = _invoke(
        monkeypatch, capsys, "export", "source.tine", "--endpoint", "https://collector.test"
    )

    assert code == 1
    assert str(status) in out and "collector said no" in out
    assert "rejected" in out


def test_a_refusal_body_cannot_flood_or_style_the_terminal(workspace, monkeypatch, capsys):
    _collector(
        monkeypatch,
        lambda request: httpx.Response(500, text="[red]x[/]\x1b[2J" + "y" * 100_000),
    )

    code, out = _invoke(
        monkeypatch, capsys, "export", "source.tine", "--endpoint", "https://collector.test"
    )

    assert code == 1
    assert "\x1b[2J" not in out and "y" * 1_000 not in out


# --------------------------------------------------------------------------- #
# flags this destination cannot honour, and a run that is not there
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("extra", "flag"),
    [
        (["--endpoint", "https://collector.test", "--output", "spans.json"], "--output"),
        (["--endpoint", "https://collector.test", "--force"], "--force"),
        (["--force"], "--force"),
        (["--allow-insecure"], "--allow-insecure"),
    ],
)
def test_a_flag_the_destination_cannot_honour_is_refused_out_loud(
    workspace, monkeypatch, capsys, extra, flag
):
    _collector(monkeypatch, lambda request: httpx.Response(200))

    code, out = _invoke(monkeypatch, capsys, "export", "source.tine", *extra)

    assert code == 1, out
    assert flag in out and "no effect" in out


def test_a_missing_run_is_a_refusal_not_an_empty_document(workspace, monkeypatch, capsys):
    code, out = _invoke(monkeypatch, capsys, "export", "nope.tine")

    assert code == 1 and "Run not found" in out


def test_an_unreadable_artifact_is_a_refusal_not_a_traceback(workspace, monkeypatch, capsys):
    (workspace / "broken.tine").write_text("{not json", encoding="utf-8")

    code, out = _invoke(monkeypatch, capsys, "export", "broken.tine")

    assert code == 1 and "Export failed" in out


def test_export_is_routed_and_leaves_the_artifact_untouched(workspace, monkeypatch, capsys):
    assert "export" in cli.LEGACY_COMMANDS
    before = (workspace / "source.tine").read_bytes()

    _invoke(monkeypatch, capsys, "export", "source.tine")

    assert (workspace / "source.tine").read_bytes() == before
