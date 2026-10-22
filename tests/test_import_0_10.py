"""0.10 import: inclusive LangChain usage, bounded message strings, provider
aliases, the Claude Code / Codex / Gemini CLI OTel dialects, OTLP logs, and
agent-CLI session transcripts.

Every fixture below is synthetic and built from the producer's documented or
source-defined shape (cited per section); no captured user content is used.
"""

from __future__ import annotations

import json
import os
import time
import tracemalloc
from pathlib import Path

import pytest

from opentine import Repo, cli
from opentine._cli_import_read import detect_and_read
from opentine._pricing_pass import price_events
from opentine.billing import Usage, bill
from opentine.integrations._lc_payloads import token_usage
from opentine.trace import otel_genai_events
from opentine.trace._import_detect import detect_format
from opentine.trace._otel_log_import import otel_log_events
from opentine.trace._transcript_claude import claude_transcript_events
from opentine.trace._transcript_codex import codex_session_events
from opentine.trace._transcript_gemini import gemini_session_events
from opentine.trace._transcript_qwen import qwen_session_events

MODEL = "claude-opus-5-5"


def _attrs(**values):
    out = []
    for key, value in values.items():
        if isinstance(value, bool):
            wrapped = {"boolValue": value}
        elif isinstance(value, int):
            wrapped = {"intValue": str(value)}
        else:
            wrapped = {"stringValue": str(value)}
        out.append({"key": key, "value": wrapped})
    return out


def _span(name, span_id, parent=None, **attributes):
    span = {
        "traceId": "a" * 32,
        "spanId": span_id,
        "name": name,
        "startTimeUnixNano": "1791000000000000000",
        "endTimeUnixNano": "1791000001000000000",
        "attributes": _attrs(**attributes),
    }
    if parent:
        span["parentSpanId"] = parent
    return span


def _document(*spans):
    return {"resourceSpans": [{"scopeSpans": [{"spans": list(spans)}]}]}


def _logs(*records):
    return {"resourceLogs": [{"scopeLogs": [{"logRecords": list(records)}]}]}


def _log(name, offset, **attributes):
    nanos = (1_791_000_000 + offset) * 1_000_000_000  # 2026-10, inside the cards' dates
    return {"timeUnixNano": str(nanos), "attributes": _attrs(**{"event.name": name, **attributes})}


def _priced(events):
    return [event for event in price_events(events) if event.kind == "model"]


# --- E3-1: LangChain usage is inclusive ---------------------------------------


def test_langchain_usage_metadata_subtracts_cached_and_reasoning_from_totals():
    wire = {"input_tokens": 10_000, "cache_read_input_tokens": 90_000, "output_tokens": 2_000}
    metadata = {
        "input_tokens": 100_000,
        "output_tokens": 2_000,
        "total_tokens": 102_000,
        "input_token_details": {"cache_read": 90_000},
    }
    usage = token_usage(metadata)
    assert usage == {"input": 10_000, "output": 2_000, "total": 102_000, "cache_read": 90_000}
    adapter = Usage(input=10_000, output=2_000, cache_read=90_000)
    assert wire["input_tokens"] == usage["input"]
    when = "2026-10-14"
    recorded = bill("anthropic", MODEL, Usage(**usage), effective_at=when).amount_usd
    assert recorded == bill("anthropic", MODEL, adapter, effective_at=when).amount_usd


def test_langchain_ttl_split_and_too_small_totals_are_read_safely():
    split = {
        "input_tokens": 30,
        "output_tokens": 5,
        "input_token_details": {
            "cache_creation": 20,
            "ephemeral_5m_input_tokens": 5,
            "ephemeral_1h_input_tokens": 15,
        },
    }
    assert token_usage(split) == {
        "input": 10,
        "output": 5,
        "cache_write_5m": 5,
        "cache_write_1h": 15,
    }
    # a total smaller than its own sub-counts cannot include them: kept as reported
    odd = {"input_tokens": 3, "output_tokens": 1, "input_token_details": {"cache_read": 9}}
    assert token_usage(odd)["input"] == 3


def test_langchain_handler_records_provider_so_the_run_prices(tmp_path):
    from opentine.integrations.langchain import OpenTineCallbackHandler

    repo = Repo.init(tmp_path / "r")
    handler = OpenTineCallbackHandler(repo)
    handler.on_chat_model_start(
        {"name": "ChatAnthropic"},
        [[{"role": "user", "content": "hi"}]],
        run_id="llm-1",
        metadata={"ls_provider": "anthropic", "ls_model_name": MODEL},
    )
    message = {
        "content": "hello",
        "usage_metadata": {
            "input_tokens": 100,
            "output_tokens": 5,
            "input_token_details": {"cache_read": 90},
        },
    }
    handler.on_llm_end({"generations": [[{"text": "hello", "message": message}]]}, run_id="llm-1")
    run = repo.load_run(handler.run_id)
    step = [step for step in run.steps if step.kind.value == "model"][0]
    assert step.provider == "anthropic"
    assert step.usage["input"] == 10 and step.usage["cache_read"] == 90


# --- E3-3 / kind coercion / provider aliases ----------------------------------


def test_a_message_string_bomb_is_left_undecoded_and_noted():
    bomb = "[" + ",".join(["{}"] * 300_000) + "]"
    span = _span("chat", "b" * 16, **{"gen_ai.input.messages": bomb, "gen_ai.request.model": "m"})
    tracemalloc.start()
    events = otel_genai_events(_document(span))
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert peak < 50 * 1024 * 1024
    attributes = events[0].attributes
    assert attributes["gen_ai.input.messages"] == bomb
    assert any("undecoded" in warning for warning in attributes["opentine.import_warnings"])


def test_one_invalid_explicit_kind_no_longer_fails_the_import():
    good = _span("chat", "c" * 16, **{"gen_ai.request.model": "m"})
    bad = _span("x", "d" * 16, **{"opentine.trace.kind": "think-really-hard"})
    events = otel_genai_events(_document(good, bad))
    assert len(events) == 2
    assert events[1].kind == "model"
    assert any("opentine.trace.kind" in w for w in events[1].attributes["opentine.import_warnings"])


@pytest.mark.parametrize(
    "spelled,expected",
    [
        ("gcp.gemini", "google"),
        ("gcp.vertex_ai", "google"),
        ("x_ai", "xai"),
        ("mistral_ai", "mistral"),
        ("aws.bedrock", "bedrock"),
        ("azure.ai.openai", "foundry"),
        ("anthropic", "anthropic"),
        ("somebody-new", "somebody-new"),
    ],
)
def test_otel_provider_spellings_map_onto_catalog_ids(spelled, expected):
    span = _span("chat", "e" * 16, **{"gen_ai.provider.name": spelled})
    assert otel_genai_events(_document(span))[0].provider == expected


# --- Claude Code spans (code.claude.com/docs/en/monitoring-usage) -------------


def test_a_claude_code_trace_imports_priced():
    spans = [
        _span("claude_code.interaction", "1" * 16, user_prompt="<REDACTED>"),
        _span(
            "claude_code.llm_request",
            "2" * 16,
            "1" * 16,
            model=MODEL,
            **{"gen_ai.system": "anthropic"},
            input_tokens=4,
            output_tokens=120,
            cache_read_tokens=32_145,
            cache_creation_tokens=11_402,
            speed="normal",
        ),
        _span("claude_code.tool", "3" * 16, "1" * 16, tool_name="Bash"),
        _span("claude_code.tool.execution", "4" * 16, "3" * 16, success="true"),
        _span("claude_code.tool.blocked_on_user", "5" * 16, "3" * 16, decision="accept"),
    ]
    events = otel_genai_events(_document(*spans))
    assert [event.kind for event in events] == ["human", "model", "tool", "approval"]
    model = events[1]
    assert model.usage == {
        "input": 4,
        "output": 120,
        "cache_read": 32_145,
        "cache_write_5m": 11_402,
    }
    priced = _priced(events)
    assert priced[0].billing["status"] == "complete" and float(priced[0].cost) > 0


# --- OTLP logs: Claude Code, Codex (session_telemetry.rs), Gemini (telemetry.md) --


def test_otlp_logs_from_three_agent_clis_import_priced():
    document = _logs(
        _log(
            "api_request",
            1,
            model=MODEL,
            input_tokens=10,
            output_tokens=5,
            cache_read_tokens=100,
            cache_creation_tokens=0,
            cost_usd="0.01",
            **{"session.id": "cc"},
        ),
        _log(
            "codex.sse_event",
            2,
            model="gpt-6.1-sol",
            input_token_count=1000,
            cached_token_count=800,
            output_token_count=50,
            reasoning_token_count=20,
            **{"event.kind": "response.completed", "conversation.id": "cx"},
        ),
        _log(
            "gemini_cli.api_response",
            3,
            model="gemini-3.8-flash",
            input_token_count=500,
            cached_content_token_count=100,
            output_token_count=40,
            thoughts_token_count=7,
            **{"session.id": "gm"},
        ),
        _log(
            "gen_ai.client.inference.operation.details",
            4,
            **{
                "gen_ai.request.model": "gemini-3.8-flash",
                "gen_ai.usage.input_tokens": 500,
                "session.id": "gm",
            },
        ),
        _log("gemini_cli.config", 0, model="ignored"),
    )
    events = otel_log_events(document)
    models = {event.trace_id: event for event in events if event.kind == "model"}
    assert set(models) == {"cc", "cx", "gm"}  # the semconv duplicate is not billed twice
    assert models["cx"].usage == {"input": 200, "output": 30, "cache_read": 800, "reasoning": 20}
    assert models["gm"].usage == {"input": 400, "output": 40, "cache_read": 100, "reasoning": 7}
    assert models["cc"].usage == {"input": 10, "output": 5, "cache_read": 100}
    assert all(event.billing["status"] == "complete" for event in _priced(events))


def test_otel_logs_import_through_the_cli_and_auto_detect(tmp_path):
    source = tmp_path / "logs.jsonl"  # the collector file exporter: one document per line
    source.write_text(
        json.dumps(_logs(_log("api_request", 1, model=MODEL, input_tokens=3, output_tokens=2)))
        + "\n"
    )
    assert detect_and_read(str(source), "auto")[0] == "otel-logs"
    assert cli.main(["import", str(source), "--save", str(tmp_path / "out.tine")]) in (0, None)


# --- transcripts ----------------------------------------------------------------


def _claude_lines():
    usage = {
        "input_tokens": 2,
        "output_tokens": 389,
        "cache_read_input_tokens": 25_027,
        "cache_creation_input_tokens": 15_304,
        "cache_creation": {"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 15_304},
        "output_tokens_details": {"thinking_tokens": 178},
    }
    placeholder = {**usage, "output_tokens": 16}
    base = {"sessionId": "s1", "timestamp": "2026-10-14T00:00:00Z"}
    return [
        {**base, "type": "user", "uuid": "u1", "message": {"role": "user", "content": "fix it"}},
        {
            **base,
            "type": "assistant",
            "uuid": "a1",
            "requestId": "r1",
            "message": {
                "id": "msg_1",
                "model": MODEL,
                "role": "assistant",
                "usage": placeholder,
                "content": [{"type": "thinking", "thinking": "..."}],
            },
        },
        {
            **base,
            "type": "assistant",
            "uuid": "a2",
            "requestId": "r1",
            "message": {
                "id": "msg_1",
                "model": MODEL,
                "role": "assistant",
                "usage": usage,
                "content": [
                    {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"cmd": "ls"}}
                ],
            },
        },
        {
            **base,
            "type": "user",
            "uuid": "u2",
            "message": {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "ok"}],
            },
        },
        {**base, "type": "attachment", "uuid": "x1"},
    ]


def test_claude_code_transcript_folds_blocks_and_counts_usage_once(tmp_path):
    path = tmp_path / "s1.jsonl"
    path.write_text("\n".join(json.dumps(line) for line in _claude_lines()) + "\n")
    events = claude_transcript_events(path)
    assert [event.kind for event in events] == ["human", "model", "tool"]
    model = events[1]
    assert model.usage == {
        "input": 2,
        "output": 211,
        "cache_read": 25_027,
        "cache_write_1h": 15_304,
        "reasoning": 178,
    }
    assert model.outputs["tool_calls"][0]["name"] == "Bash"
    assert events[2].actor == "Bash"
    assert detect_format(path.read_text()) == "claude-code-transcript"


def test_codex_rollout_counts_a_call_only_when_the_total_moves():
    usage = {
        "input_tokens": 1000,
        "cached_input_tokens": 900,
        "output_tokens": 60,
        "reasoning_output_tokens": 40,
        "total_tokens": 1060,
    }
    count = {"type": "token_count", "info": {"last_token_usage": usage, "total_token_usage": usage}}
    lines = [
        {
            "timestamp": "t",
            "type": "session_meta",
            "payload": {"id": "cx", "model_provider": "openai"},
        },
        {"timestamp": "t", "type": "turn_context", "payload": {"model": "gpt-6.1-sol"}},
        {
            "timestamp": "t",
            "type": "event_msg",
            "payload": {"type": "user_message", "message": "go"},
        },
        {
            "timestamp": "t",
            "type": "response_item",
            "payload": {
                "type": "function_call",
                "name": "shell",
                "arguments": "{}",
                "call_id": "c1",
            },
        },
        {"timestamp": "t", "type": "event_msg", "payload": count},
        {"timestamp": "t", "type": "event_msg", "payload": count},  # re-emitted, nothing spent
        {
            "timestamp": "t",
            "type": "response_item",
            "payload": {"type": "function_call_output", "call_id": "c1", "output": "done"},
        },
    ]
    events = codex_session_events([json.dumps(line) for line in lines])
    assert [event.kind for event in events] == ["human", "model", "tool"]
    assert events[1].usage == {"input": 100, "output": 20, "cache_read": 900, "reasoning": 40}
    assert events[1].model == "gpt-6.1-sol" and events[1].provider == "openai"
    assert events[2].actor == "shell"


def test_gemini_session_upserts_patches_and_keeps_rewound_calls():
    tokens = {"input": 500, "output": 40, "cached": 100, "thoughts": 7, "tool": 0, "total": 547}
    lines = [
        {"sessionId": "gm", "projectHash": "h", "startTime": "t", "lastUpdated": "t"},
        {"id": "m1", "timestamp": "t", "type": "user", "content": [{"text": "hi"}]},
        {
            "id": "m2",
            "timestamp": "t",
            "type": "gemini",
            "content": [{"text": "..."}],
            "model": "gemini-3.8-flash",
            "tokens": tokens,
            "toolCalls": [
                {"id": "c1", "name": "ls", "args": {}, "status": "success", "timestamp": "t"}
            ],
        },
        {"$patch": {"id": "m2", "toolCalls": [{"id": "c1", "result": [{"text": "a.txt"}]}]}},
        {"$rewindTo": "m2"},
    ]
    events = gemini_session_events([json.dumps(line) for line in lines])
    assert [event.kind for event in events] == ["human", "model", "tool"]
    assert events[1].usage == {"input": 400, "output": 40, "cache_read": 100, "reasoning": 7}
    assert events[2].outputs["result"] == "a.txt"


def test_qwen_session_reads_usage_metadata():
    meta = {
        "promptTokenCount": 20_529,
        "cachedContentTokenCount": 529,
        "candidatesTokenCount": 402,
        "thoughtsTokenCount": 0,
        "totalTokenCount": 20_931,
    }
    lines = [
        {
            "uuid": "1",
            "sessionId": "q",
            "timestamp": "t",
            "type": "user",
            "message": {"role": "user", "parts": [{"text": "hi"}]},
        },
        {
            "uuid": "2",
            "sessionId": "q",
            "timestamp": "t",
            "type": "assistant",
            "model": "qwen3.8-max",
            "usageMetadata": meta,
            "message": {
                "role": "model",
                "parts": [
                    {"text": "thinking", "thought": True},
                    {"text": "hello"},
                    {"functionCall": {"name": "ls", "args": {}}},
                ],
            },
        },
        {
            "uuid": "3",
            "sessionId": "q",
            "timestamp": "t",
            "type": "tool_result",
            "toolCallResult": {"callId": "c", "status": "success"},
            "message": {
                "role": "user",
                "parts": [{"functionResponse": {"name": "ls", "response": {"output": "x"}}}],
            },
        },
    ]
    events = qwen_session_events([json.dumps(line) for line in lines])
    assert [event.kind for event in events] == ["human", "model", "tool"]
    assert events[1].usage == {"input": 20_000, "output": 402, "cache_read": 529}
    assert events[1].outputs["text"] == "hello" and events[1].provider == "qwen"
    assert detect_format("\n".join(json.dumps(line) for line in lines)) == "qwen-session"


def test_transcript_import_marks_capture_and_default_location_resolves_latest(
    tmp_path, monkeypatch, capsys
):
    home = tmp_path / "claude"
    project = home / "projects" / "-work"
    project.mkdir(parents=True)
    older = project / "old.jsonl"
    older.write_text(json.dumps(_claude_lines()[0]) + "\n")
    newest = project / "s1.jsonl"
    newest.write_text("\n".join(json.dumps(line) for line in _claude_lines()) + "\n")
    os.utime(older, (time.time() - 100, time.time() - 100))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home))
    for name in ("CODEX_HOME", "QWEN_HOME", "GEMINI_CLI_HOME"):
        monkeypatch.setenv(name, str(tmp_path / "none"))
    assert cli.main(["import", "--from-default-location"]) in (0, None)
    assert "s1.jsonl" in capsys.readouterr().out
    saved = tmp_path / "run.tine"
    code = cli.main(
        ["import", "latest", "--from-default-location", "--save", str(saved), "--price"]
    )
    assert code in (0, None)
    from opentine import Run

    run = Run.load(saved)
    assert run.metadata["capture"] == {
        "method": "transcript-import",
        "source_format": "claude-code-transcript",
        "agent_writable": True,
    }
    assert any(step.cost for step in run.steps)


def test_an_oversized_transcript_line_is_skipped(tmp_path, monkeypatch):
    from opentine.trace import _transcript_common

    lines = _claude_lines()
    longest = max(len(json.dumps(line)) for line in lines)
    monkeypatch.setattr(_transcript_common, "MAX_LINE_BYTES", longest + 8)
    lines[0]["message"]["content"] = "x" * (longest + 100)
    path = Path(tmp_path / "s.jsonl")
    path.write_text("\n".join(json.dumps(line) for line in lines) + "\n")
    assert [event.kind for event in claude_transcript_events(path)][0] == "model"


# --- re-audit fixes: interleaved tool results, bounded session ids, linear work ---


def test_claude_tool_results_inside_a_streaming_response_do_not_split_it():
    lines = _claude_lines()
    usage = lines[2]["message"]["usage"]
    tail = {
        **lines[2],
        "uuid": "a3",
        "message": {**lines[2]["message"], "content": [{"type": "text", "text": "done"}]},
    }
    # Claude Code ran the tool while msg_1 was still streaming: the tool result
    # sits between two lines of the same response.
    events = claude_transcript_events([lines[0], lines[1], lines[2], lines[3], tail])
    assert [event.kind for event in events] == ["human", "model", "tool"]
    models = [event for event in events if event.kind == "model"]
    assert len(models) == 1 and models[0].usage["cache_read"] == usage["cache_read_input_tokens"]
    assert models[0].outputs["text"] == "done"


def test_an_oversized_session_id_is_not_copied_into_every_event():
    huge = "s" * 100_000
    lines = [{**line, "sessionId": huge} for line in _claude_lines()]
    events = claude_transcript_events(lines)
    assert events and all(len(event.trace_id) <= 128 for event in events)
    assert len({event.trace_id for event in events}) == 1
    assert claude_transcript_events(_claude_lines())[0].trace_id == "s1"  # id-shaped: kept


def test_reused_span_ids_are_numbered_in_linear_time():
    from opentine.trace._transcript_common import Chain

    chain = Chain("s")
    started = time.perf_counter()
    for _ in range(20_000):
        chain.add("tool", None, "tool:same")
    assert time.perf_counter() - started < 10  # quadratic probing took minutes
    ids = [event.span_id for event in chain.events]
    assert len(set(ids)) == len(ids) and ids[:3] == ["tool:same", "tool:same#2", "tool:same#3"]


def test_gemini_patch_merge_is_linear_in_tool_calls():
    calls = [{"id": f"c{i}", "name": "ls", "args": {}} for i in range(20_000)]
    lines = [
        {"id": "m1", "timestamp": "t", "type": "user", "content": [{"text": "hi"}]},
        {
            "id": "m2",
            "timestamp": "t",
            "type": "gemini",
            "model": "gemini-3.8-flash",
            "content": [],
            "toolCalls": calls,
        },
        {"$patch": {"id": "m2", "toolCalls": [{"id": c["id"], "result": "ok"} for c in calls]}},
    ]
    started = time.perf_counter()
    events = gemini_session_events(lines)
    assert time.perf_counter() - started < 10  # the nested loop was 4e8 comparisons
    tools = [event for event in events if event.kind == "tool"]
    assert len(tools) == 20_000 and all(event.outputs["result"] == "ok" for event in tools)


def _growth(build, run, n: int) -> float:
    """time(4n) / time(n), best of three each: ~4 when linear, ~16 when quadratic."""

    def best(size: int) -> float:
        data = build(size)
        timings = []
        for _ in range(3):
            started = time.perf_counter()
            run(data)
            timings.append(time.perf_counter() - started)
        return min(timings)

    return best(4 * n) / max(best(n), 0.01)


def _gemini_updates(size: int) -> list[dict]:
    calls = [{"id": f"c{i}", "name": "ls", "args": {}} for i in range(size)]
    message = {"id": "m", "timestamp": "t", "type": "gemini", "content": [], "toolCalls": calls}
    # Many tiny updates aimed at one message with many calls: the index used to
    # be rebuilt for each of them.
    return [message, {"$patch": {"id": "m", "updates": [{"id": "m"}] * size}}] + [
        {"$patch": {"id": "m", "toolCalls": [{"id": "c0", "result": "ok"}]}}
    ] * size


def test_gemini_patch_updates_cost_linear_time_in_updates_times_calls():
    assert _growth(_gemini_updates, gemini_session_events, 1500) < 8


def test_gemini_result_attaches_to_one_call_when_ids_repeat():
    calls = [{"id": "dup", "name": "ls", "args": {}} for _ in range(50)]
    lines = [
        {"id": "m", "timestamp": "t", "type": "gemini", "content": [], "toolCalls": calls},
        {"$patch": {"id": "m", "toolCalls": [{"id": "dup", "result": "x" * 1000}]}},
    ]
    tools = [event for event in gemini_session_events(lines) if event.kind == "tool"]
    assert len(tools) == 50
    assert sum(json.dumps(event.outputs).count("x" * 1000) for event in tools) == 1


def test_claude_per_record_ids_and_tool_names_are_bounded_on_every_copy():
    huge = "r" * 200_000
    lines = _claude_lines()
    lines[2]["message"]["content"][0]["name"] = "N" * 200_000
    blocks = [{"type": "tool_result", "tool_use_id": "t1", "content": "ok"}] * 40
    lines[3] = {**lines[3], "requestId": huge, "promptId": huge, "agentId": huge}
    lines[3]["message"] = {"role": "user", "content": blocks}
    events = claude_transcript_events(lines)
    tools = [event for event in events if event.kind == "tool"]
    assert len(tools) == 40
    for event in tools:
        assert len(json.dumps(event.attributes)) < 1000
        assert len(event.inputs["name"]) <= 256 and len(event.actor) <= 256
    assert tools[0].attributes["claude_code.requestId"].startswith("requestId-")
    kept = claude_transcript_events(_claude_lines())
    assert any(event.attributes.get("claude_code.requestId") == "r1" for event in kept)


def test_long_span_ids_are_digested_before_reuse_numbering():
    from opentine.trace._transcript_common import Chain

    chain = Chain("s")
    for _ in range(3):
        chain.add("tool", None, "u" * 100_000)
    ids = [event.span_id for event in chain.events]
    assert len(set(ids)) == 3 and all(len(span) < 100 for span in ids)
    assert ids[0].startswith("span-") and ids[1] == ids[0] + "#2"


def test_codex_call_arguments_are_recorded_with_one_output_only():
    big = {"cmd": "x" * 5000}
    lines = [
        {"type": "session_meta", "payload": {"id": "s", "model_provider": "openai"}},
        {
            "type": "response_item",
            "payload": {
                "type": "function_call",
                "call_id": "c1",
                "name": "shell",
                "arguments": big,
            },
        },
    ] + [
        {
            "type": "response_item",
            "payload": {"type": "function_call_output", "call_id": "c1", "output": "ok"},
        }
    ] * 20
    tools = [event for event in codex_session_events(lines) if event.kind == "tool"]
    assert len(tools) == 20
    assert sum(json.dumps(event.inputs).count("x" * 5000) for event in tools) == 1


def test_an_oversized_timestamp_string_is_not_parsed():
    from opentine.trace._import_helpers import timestamp

    assert timestamp("1" * 100_000) == 0.0
    assert timestamp("2026-10-14T00:00:00Z") > 0


# --- final security pass #5/#6/#7 -------------------------------------------


@pytest.mark.parametrize(
    ("model", "provider"),
    [
        ("ft:gpt-4.1-mini-2025-04-14:acme::BxYz12", "openai"),
        ("gpt-oss:120b-cloud", "ollama-cloud"),
        ("gpt-6.1-sol", "openai"),
    ],
)
def test_codex_otel_provider_is_not_guessed_from_a_colon(model, provider):
    document = _logs(
        _log(
            "codex.sse_event",
            1,
            model=model,
            input_token_count=10,
            output_token_count=5,
            **{"event.kind": "response.completed", "conversation.id": "cx"},
        )
    )
    (event,) = otel_log_events(document)
    assert event.provider == provider
    assert _priced([event])[0].billing["status"] != "unmetered"


def test_codex_otel_uses_a_stated_provider():
    document = _logs(
        _log(
            "codex.sse_event",
            1,
            model="qwen3:8b",
            model_provider="lmstudio",
            input_token_count=10,
            **{"event.kind": "response.completed", "conversation.id": "cx"},
        )
    )
    (event,) = otel_log_events(document)
    assert event.provider == "lmstudio"
    assert _priced([event])[0].billing["status"] == "unknown"  # an import is never free


def test_otel_logs_refuse_past_the_event_cap_before_building_chains(monkeypatch):
    import opentine.trace._otel_log_import as logs

    monkeypatch.setattr(logs, "MAX_EVENTS", 50)
    built = []
    monkeypatch.setattr(logs, "Chain", lambda trace_id: built.append(trace_id))
    records = [_log("user_prompt", i, prompt="x", **{"session.id": f"s{i}"}) for i in range(500)]
    with pytest.raises(ValueError, match="maximum event count"):
        otel_log_events(_logs(*records))
    assert built == []  # refused while reading, not after building every chain


def test_otel_logs_drop_semconv_duplicates_once_api_responses_appear():
    details = _log(
        "gen_ai.client.inference.operation.details",
        1,
        **{"gen_ai.request.model": "gemini-3.8-flash", "session.id": "gm"},
    )
    response = _log(
        "gemini_cli.api_response",
        2,
        model="gemini-3.8-flash",
        input_token_count=5,
        **{"session.id": "gm"},
    )
    events = otel_log_events(_logs(details, response, details))
    assert [event.kind for event in events] == ["model"]


def _claude_with(bad):
    good = [
        {"type": "user", "sessionId": "s", "uuid": "u0", "message": {"content": "hi"}},
        {
            "type": "assistant",
            "sessionId": "s",
            "uuid": "u1",
            "message": {
                "id": "a",
                "model": MODEL,
                "content": [{"type": "text", "text": "ok"}],
                "usage": {"input_tokens": 3, "output_tokens": 2},
            },
        },
    ]
    return [json.dumps(line) for line in [*good, bad]]


@pytest.mark.parametrize(
    "bad",
    [
        {"type": "assistant", "sessionId": "s", "uuid": "u2", "message": {"id": "b", "content": 7}},
        {"type": "assistant", "sessionId": "s", "uuid": "u3", "message": {"id": "c", "usage": [1]}},
        {"type": "user", "sessionId": "s", "uuid": "u4", "message": {"content": {"x": 1}}},
    ],
)
def test_a_claude_line_with_odd_field_types_is_skipped_not_fatal(bad):
    events = claude_transcript_events(_claude_with(bad))
    assert any(event.kind == "model" and event.usage for event in events)


def test_gemini_qwen_and_logs_records_with_odd_field_types_are_skipped():
    gemini = [
        json.dumps({"sessionId": "g"}),
        json.dumps({"id": "m", "type": "gemini", "toolCalls": 7, "model": "gemini-3.8-flash"}),
        json.dumps({"$patch": {"id": "m", "toolCalls": [{"id": 1}]}}),
    ]
    assert isinstance(gemini_session_events(gemini), list)
    qwen = [
        json.dumps({"uuid": "u", "sessionId": "s", "type": "assistant", "message": {"parts": 3}}),
        json.dumps(
            {
                "uuid": "v",
                "sessionId": "s",
                "type": "user",
                "message": {"parts": [{"text": "hi"}]},
            }
        ),
    ]
    assert [event.kind for event in qwen_session_events(qwen)][-1] == "human"
    assert otel_log_events({"resourceLogs": [{"scopeLogs": [{"logRecords": 5}]}]}) == []


def test_a_codex_record_with_odd_field_types_is_skipped_and_noted(monkeypatch):
    import opentine.trace._transcript_codex as codex

    original = codex._Builder.feed

    def feed(self, record):
        if record.get("type") == "boom":
            raise TypeError("odd shape")
        return original(self, record)

    monkeypatch.setattr(codex._Builder, "feed", feed)
    lines = [
        json.dumps({"type": "session_meta", "payload": {"id": "c1"}}),
        json.dumps({"type": "event_msg", "payload": {"type": "user_message", "message": "hi"}}),
        json.dumps({"type": "boom", "payload": {}}),
    ]
    events = codex_session_events(lines)
    assert events and "skipped 1 record(s)" in str(events[0].attributes)


# --- final pass 2: an import is never free; tiers; LangChain TTL; subagents ------


def _codex_local_log(tmp_path, **billing):
    record = _log(
        "codex.sse_event",
        1,
        model="gpt-6.1-sol",
        model_provider="ollama",
        input_token_count=5_000_000,
        output_token_count=2_000_000,
        **{"event.kind": "response.completed", "conversation.id": "cx"},
    )
    source = tmp_path / "trace.json"
    source.write_text(json.dumps(_logs(record)))
    return source


def _price_json(capsys, path):
    capsys.readouterr()
    assert cli.main(["price", "--json", str(path)]) in (0, None)
    return json.loads(capsys.readouterr().out)


def test_a_plain_import_naming_a_local_provider_never_reprices_free(tmp_path, capsys):
    saved = tmp_path / "a.tine"
    source = _codex_local_log(tmp_path)
    assert cli.main(["import", str(source), "--save", str(saved)]) in (0, None)
    report = _price_json(capsys, saved)
    assert "unmetered" not in report["status_counts"]
    assert report["status_counts"] == {"unknown": 1}


def test_a_source_claimed_unmetered_verdict_is_not_trusted(tmp_path, capsys):
    record = {
        "kind": "model",
        "timestamp": 1_791_000_001,
        "trace_id": "t",
        "span_id": "s",
        "model": "claude-opus-5-5",
        "provider": "ollama",
        "usage": {"input": 1_000_000, "output": 1_000_000},
        "billing": {"status": "unmetered", "amount_usd": "0"},
    }
    source = tmp_path / "events.jsonl"
    source.write_text(json.dumps(record) + "\n")
    saved = tmp_path / "b.tine"
    assert cli.main(["import", str(source), "--format", "jsonl", "--save", str(saved)]) in (
        0,
        None,
    )
    report = _price_json(capsys, saved)
    assert "unmetered" not in report["status_counts"]


def _claude_call(uuid, message_id, **usage_extra):
    usage = {"input_tokens": 100_000, "output_tokens": 10_000, **usage_extra}
    return {
        "sessionId": "s1",
        "timestamp": "2026-10-14T00:00:00Z",
        "type": "assistant",
        "uuid": uuid,
        "message": {
            "id": message_id,
            "model": MODEL,
            "role": "assistant",
            "usage": usage,
            "content": [{"type": "text", "text": "ok"}],
        },
    }


def test_imported_claude_fast_and_us_only_calls_price_at_their_tier():
    lines = [
        _claude_call("a1", "m1", speed="standard"),
        _claude_call("a2", "m2", speed="fast"),
        _claude_call("a3", "m3", inference_geo="us"),
    ]
    standard, fast, us = _priced(claude_transcript_events(lines))
    assert fast.inputs["service_tier"] == "fast" and us.inputs["service_tier"] == "us"
    assert fast.cost == pytest.approx(standard.cost * 2)
    assert us.cost == pytest.approx(standard.cost * 1.1)


def test_imported_claude_otel_fast_calls_price_at_the_fast_tier():
    document = _logs(
        _log(
            "api_request",
            1,
            model=MODEL,
            input_tokens=100_000,
            output_tokens=10_000,
            speed="normal",
        ),
        _log(
            "api_request", 2, model=MODEL, input_tokens=100_000, output_tokens=10_000, speed="fast"
        ),
    )
    normal, fast = _priced(otel_log_events(document))
    assert fast.cost == pytest.approx(normal.cost * 2)


def test_langchain_raw_anthropic_usage_keeps_the_one_hour_cache_split():
    raw = {
        "input_tokens": 10,
        "output_tokens": 50,
        "cache_creation_input_tokens": 100_000,
        "cache_read_input_tokens": 0,
        "cache_creation": {"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 100_000},
    }
    usage = token_usage(raw)
    assert usage["cache_write_1h"] == 100_000 and "cache_write_5m" not in usage


def _session_with_agent(tmp_path, *, agents=1):
    main = tmp_path / "s1.jsonl"
    spawn = {
        "sessionId": "s1",
        "timestamp": "2026-10-14T00:00:00Z",
        "type": "user",
        "uuid": "u9",
        "toolUseResult": {"agentId": "a0", "status": "completed"},
        "message": {
            "role": "user",
            "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "done"}],
        },
    }
    main.write_text("\n".join(json.dumps(line) for line in [*_claude_lines()[:3], spawn]) + "\n")
    folder = tmp_path / "s1" / "subagents"
    folder.mkdir(parents=True)
    for index in range(agents):
        call = _claude_call(f"sa{index}", f"sub{index}")
        call.update(isSidechain=True, agentId=f"a{index}")
        head = {"type": "fork-context-ref", "agentId": f"a{index}"}
        (folder / f"agent-a{index}.jsonl").write_text(
            json.dumps(head) + "\n" + json.dumps(call) + "\n"
        )
    return main


def test_claude_subagent_transcripts_are_imported_under_their_spawner(tmp_path):
    events = claude_transcript_events(_session_with_agent(tmp_path))
    spawner = next(e for e in events if e.span_id == "tool:t1")
    subagent = [e for e in events if e.span_id.startswith("agent-a0/")]
    # 0.12: a typed subagent edge under the spawning tool call, then its steps.
    assert [e.kind for e in subagent] == ["subagent", "model"]
    assert subagent[0].parent_span_id == spawner.span_id
    assert subagent[1].parent_span_id == subagent[0].span_id
    assert subagent[0].trace_id == events[0].trace_id
    assert len({e.span_id for e in events}) == len(events)


def test_subagent_files_past_the_cap_are_counted_not_silently_dropped(tmp_path, monkeypatch):
    from opentine.trace import _transcript_agents

    monkeypatch.setattr(_transcript_agents, "MAX_AGENT_FILES", 1)
    events = claude_transcript_events(_session_with_agent(tmp_path, agents=3))
    # One imported subagent: its typed edge plus its one model step.
    assert sum(e.span_id.startswith("agent-") for e in events) == 2
    warnings = events[0].attributes["opentine.import_warnings"]
    assert any("2 subagent transcript(s) not imported" in w for w in warnings)


def test_a_symlinked_subagents_folder_is_not_followed(tmp_path):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    session = _session_with_agent(outside)
    target = tmp_path / "work"
    target.mkdir()
    linked = target / "s1.jsonl"
    linked.write_text(session.read_text())
    (target / "s1").mkdir()
    (target / "s1" / "subagents").symlink_to(outside / "s1" / "subagents")
    events = claude_transcript_events(linked)
    assert not any(e.span_id.startswith("agent-") for e in events)


def test_session_listing_counts_subagent_transcripts(tmp_path, monkeypatch):
    from opentine._cli_import_sessions import sessions

    home = tmp_path / "claude"
    project = home / "projects" / "-work"
    project.mkdir(parents=True)
    _session_with_agent(project, agents=2)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home))
    (found,) = sessions("claude-code-transcript")
    assert found.agents == 2


def test_import_billing_guards_cover_exactly_the_priced_kinds():
    from opentine import _import_billing, _pricing_pass

    assert _import_billing._PRICEABLE == _pricing_pass.PRICEABLE_KINDS


# --- final pass 3: imported billing is an allowlist; auto import finds subagents ---

_SOURCE_BILLING = [
    None,
    {},
    {"status": ""},
    {"status": None},
    {"status": 0},
    {"status": "unmetered"},
    {"status": "UNMETERED"},
    {"status": " unmetered"},
    {"status": "complete", "amount_usd": "0", "known_subtotal_usd": "0"},
    {"status": "partial", "amount_usd": "0"},
    {"status": "free"},
    {"note": "x"},
    {"calculation": {}},
    {"status": "", "calculation": {"usage": {}}},
]


@pytest.mark.parametrize("billing", _SOURCE_BILLING)
@pytest.mark.parametrize("provider", ["ollama", "vllm", "lmstudio", "llamacpp", "anthropic"])
@pytest.mark.parametrize("kind", ["model", "error", "done"])
def test_no_source_billing_block_makes_an_imported_call_free(
    tmp_path, capsys, billing, provider, kind
):
    record = {
        "kind": kind,
        "timestamp": 1_791_000_001,
        "trace_id": "t",
        "span_id": "s",
        "model": "claude-opus-5-5",
        "provider": provider,
        "usage": {"input": 1_000_000, "output": 1_000_000},
    }
    if billing is not None:
        record["billing"] = billing
    source = tmp_path / "events.jsonl"
    source.write_text(json.dumps(record) + "\n")
    saved = tmp_path / "b.tine"
    command = ["import", str(source), "--format", "jsonl", "--save", str(saved)]
    assert cli.main(command) in (0, None)
    report = _price_json(capsys, saved)
    assert "unmetered" not in report["status_counts"]
    assert not report.get("by_provider") or provider == "anthropic"


def test_an_unreadable_billing_status_never_reads_as_no_verdict():
    from types import SimpleNamespace

    from opentine._local_providers import unmetered_call
    from opentine._pricing_record import verdict_status

    for billing in ({"status": ""}, {"status": 3}, {"note": "x"}, {"calculation": {}}):
        step = SimpleNamespace(billing=billing)
        assert verdict_status(step) == "unknown"
        assert not unmetered_call("ollama", "qwen3:8b", verdict_status(step))
    assert verdict_status(SimpleNamespace(billing={})) is None  # a harness capture
    assert verdict_status(SimpleNamespace(billing={"status": "unmetered"})) == "unmetered"


def test_auto_import_reads_claude_subagent_transcripts_like_the_explicit_format(tmp_path):
    session = _session_with_agent(tmp_path)
    detected, auto = detect_and_read(str(session), "auto")
    _, explicit = detect_and_read(str(session), "claude-code-transcript")
    assert detected == "claude-code-transcript"
    assert [e.span_id for e in auto] == [e.span_id for e in explicit]
    assert any(e.span_id.startswith("agent-a0/") for e in auto)


def test_import_latest_from_default_location_includes_subagents(tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    project = home / "projects" / "p"
    project.mkdir(parents=True)
    _session_with_agent(project)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home))
    saved = tmp_path / "dl.tine"
    command = ["import", "latest", "--from-default-location", "--save", str(saved), "--json"]
    capsys.readouterr()
    assert cli.main(command) in (0, None)
    explicit = claude_transcript_events(project / "s1.jsonl")
    assert json.loads(capsys.readouterr().out)["events_imported"] == len(explicit)


# --- final pass 4: one API response is billed once per session ------------------


def _session_with_copies(tmp_path, *, fork_copy=True, shared=True):
    """A session whose subagent files repeat the parent's response (and each other's)."""
    parent = _claude_call("p1", "msg_PARENT")
    parent["requestId"] = "req_PARENT"
    main = tmp_path / "s1.jsonl"
    main.write_text(json.dumps(parent) + "\n")
    folder = tmp_path / "s1" / "subagents"
    folder.mkdir(parents=True)
    for agent in ("aaa", "bbb"):
        lines = []
        if fork_copy:
            lines.append({**parent, "isSidechain": True, "agentId": agent})
        if shared:
            lines.append({**_claude_call(f"{agent}1", "msg_SHARED"), "isSidechain": True})
        lines.append({**_claude_call(f"{agent}2", f"msg_{agent}"), "isSidechain": True})
        (folder / f"agent-{agent}.jsonl").write_text(
            "\n".join(json.dumps(line) for line in lines) + "\n"
        )
    return main


def _billed_ids(events):
    return [e.span_id.rsplit("message:", 1)[-1] for e in events if e.kind == "model"]


def test_a_forked_subagent_repeating_the_parent_response_does_not_bill_it_again(tmp_path):
    events = claude_transcript_events(_session_with_copies(tmp_path, shared=False))
    assert sorted(_billed_ids(events)) == ["msg_PARENT", "msg_aaa", "msg_bbb"]
    assert len({e.span_id for e in events}) == len(events)


def test_sibling_subagents_sharing_a_response_bill_it_once(tmp_path):
    events = claude_transcript_events(_session_with_copies(tmp_path))
    ids = _billed_ids(events)
    assert sorted(ids) == ["msg_PARENT", "msg_SHARED", "msg_aaa", "msg_bbb"]
    total = sum(e.usage.get("output", 0) for e in events if e.kind == "model")
    assert total == 4 * 10_000


def test_a_repeated_request_id_alone_is_not_billed_twice(tmp_path):
    first = {**_claude_call("x1", "msg_A"), "requestId": "req_SAME"}
    again = {**_claude_call("x2", "msg_B"), "requestId": "req_SAME"}
    events = claude_transcript_events([first, again])
    assert _billed_ids(events) == ["msg_A"]


def test_deduplicated_session_prices_one_call_once(tmp_path):
    events = claude_transcript_events(_session_with_copies(tmp_path, shared=False))
    priced = _priced(events)
    one = bill("anthropic", MODEL, Usage(input=100_000, output=10_000), effective_at="2026-10-14")
    assert sum(step.cost for step in priced) == pytest.approx(3 * float(one.amount_usd))


# -- final security pass 5: library imports, 0.9.x imports, source costs, linear walk


def _library_run(tmp_path, records):
    from opentine.trace import Recorder, jsonl_events

    source = tmp_path / "lib.jsonl"
    source.write_text("\n".join(json.dumps(record) for record in records) + "\n")
    recorder = Recorder.start(Repo.init(tmp_path / "repo"), ref="heads/main", capture=False)
    recorder.import_events(jsonl_events(source))
    return recorder.repo.load_run(recorder.finalize())


_LOCAL_LABELLED = {
    "kind": "model",
    "timestamp": 1_790_000_000,
    "trace_id": "t1",
    "span_id": "s1",
    "model": "claude-opus-5",
    "provider": "ollama",
    "usage": {"input": 1_000_000, "output": 100_000},
}


@pytest.mark.parametrize("billing", [None, {"status": "unmetered"}, {"status": ""}])
def test_a_library_import_never_reprices_a_local_label_as_free(tmp_path, billing):
    from opentine._pricing_pass import price_run

    record = dict(_LOCAL_LABELLED, **({"billing": billing} if billing is not None else {}))
    run = _library_run(tmp_path, [record])
    assert all(not step.billing for step in run.steps if step.kind.value == "model")
    assert price_run(run, effective_at="2026-10-14").status_counts == {"unknown": 1}


def test_a_run_imported_by_0_9_2_never_reprices_a_local_label_as_free():
    # tests/fixtures/pricing/imported_by_0_9_2.tine: written by 0.9.2's own
    # ``tine import --save`` (no billing on its steps, one labelled ``ollama``).
    from opentine import Run
    from opentine._pricing_pass import price_run

    run = Run.load(Path(__file__).parent / "fixtures/pricing/imported_by_0_9_2.tine")
    counts = price_run(run, effective_at="2026-10-14").status_counts
    assert "unmetered" not in counts
    assert counts.get("unknown") == 1


def test_a_harness_run_without_billing_still_reprices_local_calls_as_unmetered():
    from opentine import Run
    from opentine._pricing_pass import price_run
    from opentine.core import StepKind

    run = Run(id="h", manifest={"kind": "external-harness"}, metadata={"harness": "codex"})
    run.add_step(StepKind.model, {}, usage={"input": 1}, provider="ollama", model_info="qwen3:8b")
    assert price_run(run, effective_at="2026-10-14").status_counts == {"unmetered": 1}


def test_a_library_import_keeps_no_cost_from_the_source(tmp_path):
    record = dict(_LOCAL_LABELLED, provider="anthropic", model="claude-sonnet-5-5", cost=0.0001)
    run = _library_run(tmp_path, [record])
    (step,) = [step for step in run.steps if step.kind.value == "model"]
    assert not step.cost


def test_tine_import_keeps_no_cost_from_the_source(tmp_path, capsys):
    from opentine import Run

    source = tmp_path / "d.jsonl"
    source.write_text(json.dumps(dict(_LOCAL_LABELLED, provider="anthropic", cost=0.0001)) + "\n")
    for flags in ([], ["--price"]):
        saved = tmp_path / f"d{len(flags)}.tine"
        assert cli.main(
            ["import", str(source), "--format", "jsonl", "--save", str(saved), *flags]
        ) in (0, None)
        capsys.readouterr()
        (step,) = [step for step in Run.load(saved).steps if step.kind.value == "model"]
        assert step.cost != 0.0001  # the catalog's figure, or nothing -- never the file's


def _chain(spans: int) -> dict:
    items = [
        {
            "traceId": "t",
            "spanId": f"s{index}",
            **({"parentSpanId": f"s{index - 1}"} if index else {}),
            "name": "chat",
            "attributes": [{"key": "gen_ai.usage.input_tokens", "value": {"intValue": "1"}}],
        }
        for index in range(spans)
    ]
    return {"resourceSpans": [{"scopeSpans": [{"spans": items}]}]}


def test_the_agent_billing_walk_is_linear_in_a_span_chain():
    def elapsed(spans: int) -> float:
        document = _chain(spans)
        best = float("inf")
        for _ in range(3):
            started = time.perf_counter()
            events = otel_genai_events(document)
            assert len(events) == spans
            best = min(best, time.perf_counter() - started)
        return best

    elapsed(200)  # warm
    small, large = elapsed(1500), elapsed(6000)
    assert large < max(small, 0.02) * 8  # 4x spans: linear ~4x, quadratic ~16x


# --- final pass 6: one subagent file on disk is read once; budget charged up front ---


@pytest.mark.skipif(not hasattr(os, "link"), reason="hard links unavailable")
def test_hard_linked_subagent_transcripts_are_read_once(tmp_path, monkeypatch):
    from opentine.trace import _transcript_agents

    main = _session_with_agent(tmp_path)
    folder = tmp_path / "s1" / "subagents"
    for index in range(1, 6):
        os.link(folder / "agent-a0.jsonl", folder / f"agent-a{index}.jsonl")
    parsed = []
    original = _transcript_agents.build

    def counting(source, builder, **kwargs):
        if "subagents" in str(source):
            parsed.append(source)
        return original(source, builder, **kwargs)

    monkeypatch.setattr(_transcript_agents, "build", counting)
    events = claude_transcript_events(main)
    assert len(parsed) == 1
    warnings = events[0].attributes["opentine.import_warnings"]
    assert any("5 duplicate subagent transcript(s) skipped" in w for w in warnings)


def test_a_failing_subagent_file_still_spends_the_session_byte_budget(tmp_path, monkeypatch):
    from opentine.trace import _transcript_agents

    main = _session_with_agent(tmp_path, agents=3)
    folder = tmp_path / "s1" / "subagents"
    sizes = [path.stat().st_size for path in sorted(folder.glob("agent-*.jsonl"))]
    # Room for the session and two subagent files, not three.
    budget = main.stat().st_size + sizes[0] + sizes[1]
    monkeypatch.setattr(_transcript_agents, "MAX_SOURCE_BYTES", budget)
    parsed = []
    original = _transcript_agents.build

    def failing(source, builder, **kwargs):
        skipped = original(source, builder, **kwargs)
        if "subagents" not in str(source):
            return skipped
        parsed.append(source)
        raise ValueError("event cap")  # every subagent file fails after a full parse

    monkeypatch.setattr(_transcript_agents, "build", failing)
    events = claude_transcript_events(main)
    assert len(parsed) == 2  # the third is refused before it is read
    warnings = events[0].attributes["opentine.import_warnings"]
    assert any("3 subagent transcript(s) not imported" in w for w in warnings)


# --- final pass 9 #4: span content coverage is linear --------------------------


def _covered_before(payload, turns):
    """The pre-fix ``_covered``: one substring scan per turn (the oracle)."""
    from opentine.trace import _genai_semconv as semconv

    def dumped(value):
        return json.dumps(value, ensure_ascii=False, default=str)

    try:
        text = dumped(payload)
        for turn in turns:
            content = turn.get("content")
            rendered = content if isinstance(content, str) else dumped(content)
            evidence = [rendered] if rendered else []
            evidence += [
                dumped(turn[field])
                for field in semconv.CARRIED_FIELDS
                if turn.get(field) is not None
            ]
            if not evidence or any(item not in text for item in evidence):
                return False
    except (RecursionError, TypeError, ValueError):
        return False
    return True


def test_span_coverage_matches_the_per_turn_scan_on_random_inputs():
    import random

    from opentine.trace._otel_content import _covered
    from opentine.trace._substrings import all_in

    rng = random.Random(9)
    alphabet = 'abé\U0001f600 "{}'
    for _ in range(3000):
        words = ["".join(rng.choice(alphabet) for _ in range(rng.randint(0, 4))) for _ in range(6)]
        payload = {"messages": [{"role": "user", "content": rng.choice(words)} for _ in range(3)]}
        turns = []
        for _ in range(rng.randint(0, 5)):
            turn = {"role": "user", "content": rng.choice([*words, None, {"k": rng.choice(words)}])}
            if rng.random() < 0.3:
                turn["tool_calls"] = [{"id": rng.choice(words)}]
            turns.append(turn)
        assert _covered(payload, turns) == _covered_before(payload, turns)
        text = "".join(rng.choice(words) for _ in range(8))
        needles = set(rng.sample(words, 3))
        assert all_in(needles, text) == all(needle in text for needle in needles)


def test_the_automaton_path_agrees_with_direct_search():
    from opentine.trace import _substrings

    text = "x" * 50 + "abcabécd" + "y" * 50
    for needles, expected in (
        ({"abc", "bca", "cab", "éc"}, True),
        ({"abc", "zzz"}, False),
        ({"b", "ab", "abcabécd"}, True),
        ({"cd", "dx"}, False),
    ):
        assert _substrings._all_found(set(needles), text) is expected
        assert _substrings.all_in(needles, text) is expected


def test_span_coverage_is_linear_in_turns_times_payload():
    from opentine.trace._otel_content import _covered

    def elapsed(scale: int) -> float:
        # Every turn's evidence is distinct and sits only at the payload's end:
        # the worst case for a per-turn substring scan.
        count = 500 * scale
        tail = "".join(f"<{i}>" for i in range(count))
        payload = {"text": "a" * (40_000 * scale) + tail}
        turns = [{"role": "user", "content": f"<{i}>"} for i in range(count)]
        best = float("inf")
        for _ in range(3):
            started = time.monotonic()
            _covered(payload, turns)
            best = min(best, time.monotonic() - started)
        return best

    small, large = elapsed(1), elapsed(4)
    # 4x turns and 4x payload: linear grows ~4x, the old per-turn scan ~16x.
    assert large < max(small, 0.02) * 8
