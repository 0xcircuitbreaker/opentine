"""Final security pass 10: #6 span-coverage memory, #7 MCP control characters,
#8 Unicode-digit token counts, #9 inline reasoning kept beside structured.
"""

from __future__ import annotations

import json
import random
import time
import tracemalloc

from opentine import Run
from opentine._mcp_safety import visible
from opentine.graph import StepKind
from opentine.trace._substrings import all_in
from opentine.trace._transcript_claude import claude_transcript_events
from opentine.trace._transcript_usage import count
from tests.test_security_0_10_cli_mcp import _FakeServer, _v3

# --- #6: bounded memory and time ---------------------------------------------


def test_coverage_search_agrees_with_direct_search_on_random_inputs():
    rng = random.Random(10)
    alphabet = "abcé😀 "
    for _ in range(4000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 60)))
        needles = {
            "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 5)))
            for _ in range(rng.randint(0, 8))
        }
        assert all_in(needles, text) == all(needle in text for needle in needles)


def _adversarial(scale: int) -> tuple[set[str], str]:
    # Distinct needles, all present, far past the direct-search budget.
    needles = {f"<{index:07d}>" for index in range(20_000 * scale)}
    return needles, "".join(sorted(needles))


def test_coverage_search_memory_stays_a_small_multiple_of_its_input():
    needles, text = _adversarial(4)
    size = len(text) + sum(map(len, needles))
    tracemalloc.start()
    try:
        all_in(needles, text)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 10 * size, (peak, size)


def test_coverage_search_time_grows_linearly():
    def elapsed(scale: int) -> float:
        needles, text = _adversarial(scale)
        best = float("inf")
        for _ in range(2):
            started = time.perf_counter()
            all_in(needles, text)
            best = min(best, time.perf_counter() - started)
        return best

    small, large = elapsed(1), elapsed(4)
    assert large < max(small, 0.01) * 8


def test_an_unproven_coverage_keeps_the_structured_conversation():
    # Past the budget the answer is "not covered": the attribute is kept, never dropped.
    needles, text = _adversarial(2)
    assert all_in(needles, text) is False
    assert all_in(set(list(needles)[:5]), text) is True


# --- #7: control characters never reach an MCP client -------------------------

CONTROLS = "".join(chr(code) for code in (*range(0x20), 0x7F, *range(0x80, 0xA0)))


def _controls(value) -> list[str]:
    found: list[str] = []
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            found += [hex(ord(char)) for char in item if char in CONTROLS and char not in "\n\t"]
        elif isinstance(item, dict):
            stack += list(item.keys()) + list(item.values())
        elif isinstance(item, (list, tuple)):
            stack += list(item)
    return sorted(set(found))


def test_visible_strips_controls_but_keeps_newline_and_tab():
    value = {f"k{CONTROLS}": [f"a{CONTROLS}b", {"deep": "\x1b]52;c;eA==\x07x\x9bq"}]}
    cleaned = visible(value)
    assert _controls(cleaned) == []
    assert cleaned == {"k\t\n": ["a\t\nb", {"deep": "]52;c;eA==xq"}]}
    assert visible({"plain": "ok"}) == {"plain": "ok"}


def test_visible_is_iterative_on_deep_values():
    value: list = ["\x1bx"]
    for _ in range(5000):
        value = [value]
    cleaned = visible(json.loads(json.dumps(value)))
    for _ in range(5000):
        cleaned = cleaned[0]
    assert cleaned == ["x"]


def test_no_mcp_tool_or_resource_returns_a_control_character(tmp_path, monkeypatch):
    import opentine.mcp_server as mcp_server

    payload = f"\x1b[2J\x1b]52;c;eA==\x07{chr(0x7F)}{chr(0x9B)}31m{chr(0x85)}"
    _, v3_run, event, _ = _v3(tmp_path, text=f"answer{payload}", model=f"gpt{payload}")
    runs = tmp_path / "runs"
    runs.mkdir()
    run = Run(run_id=f"r{payload}", model_info=f"m{payload}")
    run.add_step(StepKind.think, {"text": f"t{payload}"})
    run.add_step(StepKind.done, {"text": f"d{payload}"})
    run.save(runs / "plain.tine")
    monkeypatch.setattr(mcp_server, "server_class", lambda: _FakeServer)
    server = mcp_server.create_server(runs, tmp_path)
    calls = {
        "list_runs": (),
        "show_run": ("plain",),
        "fork_run": ("plain", 0),
        "diff_runs": ("plain", "plain"),
        "resource:run://{run_id}": ("plain",),
        "search_runs": (),
        "inspect_object": (event,),
        "context_slice": (event,),
        "semantic_diff": (v3_run, v3_run),
        "resource:tine-object://{object_id}": (event,),
    }
    assert set(calls) <= set(server.tools)
    for name, args in calls.items():
        result = server.tools[name](*args)
        assert _controls(result) == [], name


# --- #8: only ASCII digits are token counts ------------------------------------


def test_token_counts_accept_ascii_digits_only():
    assert count("12") == 12 and count(" 7 ") == 7 and count(5) == 5
    for bad in ("²", "١٢", "１２", "1²", "", "-1", "9" * 40):
        assert count(bad) is None, bad


def test_a_unicode_digit_token_count_skips_the_record_not_the_session():
    lines = [
        {"type": "user", "sessionId": "s", "uuid": "u0", "message": {"content": "hi"}},
        {
            "type": "assistant",
            "sessionId": "s",
            "uuid": "u1",
            "message": {
                "id": "a",
                "model": "claude-opus-5-5",
                "content": [{"type": "text", "text": "ok"}],
                "usage": {"input_tokens": "²", "output_tokens": "³"},
            },
        },
        {
            "type": "assistant",
            "sessionId": "s",
            "uuid": "u2",
            "message": {
                "id": "b",
                "model": "claude-opus-5-5",
                "content": [{"type": "text", "text": "fine"}],
                "usage": {"input_tokens": 3, "output_tokens": 2},
            },
        },
    ]
    events = claude_transcript_events([json.dumps(line) for line in lines])
    assert any(event.kind == "model" and event.usage for event in events)


# --- #9: inline reasoning is never dropped -------------------------------------


def test_inline_think_is_kept_beside_structured_reasoning():
    from opentine.models._stream_content import chat_content

    message = {
        "content": "<think>inline plan</think>The answer.",
        "reasoning_content": "structured plan",
    }
    result = chat_content(message)
    assert result["text"] == "The answer."
    assert "structured plan" in result["reasoning_content"]
    assert "inline plan" in result["reasoning_content"]


def test_inline_think_alone_still_becomes_reasoning():
    from opentine.models._stream_content import chat_content

    result = chat_content({"content": "<think>only inline</think>Done."})
    assert result["text"] == "Done." and result["reasoning_content"] == "only inline"
