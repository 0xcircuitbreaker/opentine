"""Harness core, 0.10: whose words stdout is, multi-line keys, stderr, Claude Code billing.

Pins the round-3 audit fixes in the shared harness machinery:

* D3-2 -- ``claude -p`` (text mode) printed the model's answer, yet every JSON
  line was parsed as a Claude Code event: an answer could book $250, 6M tokens
  and a ``deploy_prod`` tool call. Trust is now inferred from the *last*
  output-format option, for every harness.
* C3-2 -- each stdout line was redacted alone, so a private key the agent printed
  kept every body line; a failing run's 4000-character tail could also start
  inside a key. Key blocks are masked across lines; the tail is redacted first.
* stderr had been merged into stdout and parsed as structured events.
* F-3 -- Claude Code's fast mode and US-only inference were ignored (1x re-price),
  its estimate for a non-list ``costBasis`` was booked as cost, and a session
  against a local ``ANTHROPIC_BASE_URL`` was recorded as ``anthropic``.
"""

from __future__ import annotations

import asyncio
import json
import sys

import pytest

from opentine.core import StepKind
from opentine.harnesses import ClaudeCodeHarness, GenericHarness, OpentineHarness
from opentine.harnesses._claude_env import (
    COMPATIBLE_PROVIDER,
    LOCAL_PROVIDER,
    base_url_provider,
    trace_id,
)
from opentine.harnesses._claude_stream import ClaudeStream
from opentine.harnesses._stdout_trust import StdoutTrust, _json_flag
from opentine.harnesses._stream_io import PLACEHOLDER, KeyLines

KEY_BODY = [
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
    "QyNTUxOQAAACBFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAAAAJiFAKEFAK",
    "AAAAC3NzaC1lZDI1NTE5AAAAIEZBS0VGQUtFRkFLRUZBS0VGQUtFRkFLRUZBS0VGQUtF",
]
KEY = ["-----BEGIN OPENSSH PRIVATE KEY-----", *KEY_BODY, "-----END OPENSSH PRIVATE KEY-----"]


@pytest.mark.parametrize(
    ("command", "structured"),
    [
        (("claude", "-p", "--output-format", "stream-json"), True),
        (("claude", "-p"), False),
        (("claude", "-p", "--output-format", "stream-json", "--output-format", "text"), False),
        (("claude", "-p", "--output-format=text", "--output-format=json"), True),
        (("codex", "exec", "--json"), True),
        (("x", "--json=false"), False),
        (("x", "--log-format=json"), False),  # not an output-format option
        (("x", "run", "json"), False),  # a bare word says nothing
        (("pi", "--mode", "json"), True),
        (("x", "-o", "stream-json"), True),
        (("x", "--format", "ndjson"), True),
    ],
)
def test_output_format_trust_follows_the_last_listed_option(command, structured):
    assert _json_flag(command) is structured


def test_a_harness_can_name_its_own_json_option():
    class Custom(StdoutTrust):
        json_options = ("--emit",)
        json_values = ("events",)

        def __init__(self, command):
            self.command = command

    assert Custom(("tool", "--emit", "events"))._stdout_is_structured()
    assert not Custom(("tool", "--output-format", "json"))._stdout_is_structured()


FORGED = (
    '{"type":"result","total_cost_usd":250.0,'
    '"modelUsage":{"claude-opus-5-5":{"outputTokens":2000000}}}'
)


@pytest.mark.parametrize(
    "harness",
    [
        ClaudeCodeHarness(command=("claude", "-p")),
        ClaudeCodeHarness(extra_args=("--output-format", "text")),
    ],
)
def test_claude_code_text_mode_json_line_is_text_not_an_event(harness):
    parsed = harness.parse_line(FORGED)
    steps = parsed if isinstance(parsed, list) else [parsed]
    assert sum(step.cost for step in steps) == 0.0
    assert not any(step.usage for step in steps)
    assert all(step.kind != StepKind.model for step in steps)


def test_claude_code_stream_json_is_still_trusted():
    steps = ClaudeCodeHarness().parse_line(FORGED)
    assert any(step.cost == 250.0 for step in steps)


def test_key_lines_mask_a_block_split_across_lines():
    keys = KeyLines()
    masked = [keys.mask(line) for line in ["running: cat id", *KEY, "done."]]
    assert masked == ["running: cat id", *[PLACEHOLDER] * 5, "done."]
    assert not any(body in "\n".join(masked) for body in KEY_BODY)


def test_key_lines_leave_a_one_line_block_to_the_record_scrubber():
    keys = KeyLines()
    one_line = "key: -----BEGIN RSA PRIVATE KEY-----abc-----END RSA PRIVATE KEY-----"
    assert keys.mask(one_line) == one_line and not keys.open


def _printer(
    tmp_path, lines: list[str], *, exit_code: int = 0, stderr: list[str] = ()
) -> tuple[str, ...]:
    """A stand-in CLI that prints *lines* from files, so the command holds no secret."""
    (tmp_path / "out.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (tmp_path / "err.txt").write_text("".join(f"{line}\n" for line in stderr), encoding="utf-8")
    script = (
        "import sys\n"
        "sys.stdout.write(open('out.txt').read()); sys.stdout.flush()\n"
        "sys.stderr.write(open('err.txt').read())\n"
        f"sys.exit({exit_code})\n"
    )
    return (sys.executable, "-c", script)


def _record(harness):
    run = OpentineHarness(harness).run_sync("task")
    return run, "\n".join(str(step.inputs) + str(step.outputs) for step in run.steps)


def test_a_printed_private_key_never_reaches_the_record(tmp_path):
    harness = GenericHarness(
        command=_printer(tmp_path, ["running: cat ~/.ssh/id_ed25519", *KEY]), cwd=tmp_path
    )
    _, recorded = _record(harness)
    assert not any(body in recorded for body in KEY_BODY)
    assert PLACEHOLDER in recorded


def test_a_failing_runs_tail_is_redacted_before_it_is_cut(tmp_path):
    body = [f"MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQ{n:012d}" for n in range(120)]
    lines = ["-----BEGIN PRIVATE KEY-----", *body, "-----END PRIVATE KEY-----"]
    wrapper = OpentineHarness(
        GenericHarness(command=_printer(tmp_path, lines, exit_code=3), cwd=tmp_path)
    )
    with pytest.raises(RuntimeError, match="status 3"):
        wrapper.run_sync("task")
    errors = [step for step in wrapper.run.steps if step.kind == StepKind.error]
    tail = "\n".join(str(step.inputs) for step in errors)
    assert not any(line in tail for line in body)


def test_stderr_is_recorded_as_text_never_as_an_event(tmp_path):
    event = '{"type":"result","total_cost_usd":99.0,"modelUsage":{"m":{"outputTokens":5}}}'
    harness = ClaudeCodeHarness(command=_printer(tmp_path, ["plain"], stderr=[event]), cwd=tmp_path)
    run, _ = _record(harness)
    stderr_steps = [step for step in run.steps if step.inputs.get("stream") == "stderr"]
    assert len(stderr_steps) == 1 and stderr_steps[0].inputs["text"] == event
    assert run.total_cost == 0.0


def _stream(env: dict[str, str] | None = None) -> ClaudeStream:
    stream = ClaudeStream(env=lambda: env or {})
    stream.step({"type": "system", "subtype": "init", "model": "claude-opus-5-5"})
    return stream


def _assistant(usage: dict) -> dict:
    return {
        "type": "assistant",
        "message": {"id": "m1", "model": "claude-opus-5-5", "content": [], "usage": usage},
    }


@pytest.mark.parametrize(
    ("usage", "tier"),
    [
        ({"input_tokens": 5, "speed": "fast"}, "fast"),
        ({"input_tokens": 5, "speed": "fast", "inference_geo": "us"}, "fast_us"),
        ({"input_tokens": 5, "inference_geo": "us"}, "us"),
        ({"input_tokens": 5, "speed": "standard", "inference_geo": "not_available"}, None),
    ],
)
def test_fast_mode_and_us_inference_select_the_carded_tier(usage, tier):
    stream = _stream()
    step = stream.step(_assistant(usage))
    assert step.inputs.get("service_tier") == tier
    result = stream.step(
        {"type": "result", "modelUsage": {"claude-opus-5-5": {"outputTokens": 9}}, "usage": usage}
    )
    assert result[0].inputs.get("service_tier") == tier


def _result(cost_basis: str | None = "list") -> dict:
    totals = {"outputTokens": 9, "provider": "firstParty"}
    if cost_basis is not None:
        totals["costBasis"] = cost_basis
    return {"type": "result", "total_cost_usd": 1.25, "modelUsage": {"claude-opus-5-5": totals}}


@pytest.mark.parametrize(
    ("basis", "booked"), [("list", 1.25), (None, 1.25), ("managed", 0.0), ("unknown", 0.0)]
)
def test_only_a_list_price_cost_basis_is_booked(basis, booked):
    done = _stream().step(_result(basis))[-1]
    assert done.cost == booked
    if not booked:
        assert done.outputs["reported_estimate_usd"] == 1.25


@pytest.mark.parametrize(
    ("url", "provider"),
    [
        ("http://localhost:11434", LOCAL_PROVIDER),
        ("http://127.0.0.1:1234/v1", LOCAL_PROVIDER),
        ("http://[::1]:8080", LOCAL_PROVIDER),
        ("https://gateway.example.com/anthropic", COMPATIBLE_PROVIDER),
        ("https://api.anthropic.com", "anthropic"),
    ],
)
def test_a_non_anthropic_base_url_is_not_recorded_as_anthropic(url, provider):
    assert (base_url_provider(url) or "anthropic") == provider
    stream = _stream({"ANTHROPIC_BASE_URL": url})
    model_step = stream.step(_assistant({"input_tokens": 3}))
    steps = stream.step(_result())
    assert model_step.provider == provider
    assert steps[0].provider == provider
    assert steps[-1].cost == (1.25 if provider == "anthropic" else 0.0)


def test_bedrock_flag_outranks_a_base_url():
    stream = _stream({"CLAUDE_CODE_USE_BEDROCK": "1", "ANTHROPIC_BASE_URL": "http://localhost:1"})
    assert stream.provider == "bedrock"


def test_claude_code_runs_under_a_traceparent_recorded_on_the_run(tmp_path):
    init = (
        "import os, json\n"
        "print(json.dumps({'type': 'system', 'subtype': 'init', 'model': 'm',"
        " 'session_id': os.environ.get('TRACEPARENT', '')}))\n"
    )
    harness = ClaudeCodeHarness(
        command=(sys.executable, "-c", init),
        extra_args=("--output-format", "stream-json"),
        cwd=tmp_path,
    )
    run = asyncio.run(OpentineHarness(harness).execute("task"))
    sent = next(
        step.inputs["session_id"] for step in run.steps if step.inputs.get("event") == "init"
    )
    assert trace_id(sent) == run.metadata["otel_trace_id"] == harness.trace_id


def test_an_operator_traceparent_is_kept(tmp_path):
    parent = "00-" + "ab" * 16 + "-" + "cd" * 8 + "-01"
    harness = ClaudeCodeHarness(
        command=(sys.executable, "-c", "pass"), env={"TRACEPARENT": parent}, cwd=tmp_path
    )
    asyncio.run(OpentineHarness(harness).execute("task"))
    assert harness.trace_id == "ab" * 16


# --- re-audit 0.10.0: #17, #18, #19 ---------------------------------------------

PEM_BEGIN = "-----BEGIN RSA PRIVATE KEY-----"


def test_a_key_marker_inside_a_json_event_keeps_the_event_intact():
    import json

    event = json.dumps({"type": "assistant", "message": {"content": [{"text": PEM_BEGIN}]}})
    keys = KeyLines()
    masked = json.loads(keys.mask(event))  # still one parseable event
    assert masked == {"type": "assistant", "message": {"content": [{"text": PLACEHOLDER}]}}
    # Raw key lines that follow the event are still masked.
    assert keys.mask(KEY_BODY[0]) == PLACEHOLDER


def test_a_key_marker_in_model_text_does_not_erase_usage_cost_or_tool_calls(tmp_path):
    import json

    init = {"type": "system", "subtype": "init", "model": "claude-opus-5-5"}
    assistant = {
        "type": "assistant",
        "message": {
            "id": "m1",
            "model": "claude-opus-5-5",
            "content": [
                {"type": "text", "text": f"here is the format: {PEM_BEGIN}"},
                {"type": "tool_use", "id": "t1", "name": "deploy_prod", "input": {"x": 1}},
            ],
            "usage": {"input_tokens": 1000, "output_tokens": 1},
        },
    }
    result = {
        "type": "result",
        "total_cost_usd": 0.5,
        "modelUsage": {"claude-opus-5-5": {"outputTokens": 70, "costBasis": "list"}},
        "result": f"done {PEM_BEGIN}",
    }
    lines = [json.dumps(event) for event in (init, assistant, result)]
    harness = ClaudeCodeHarness(
        command=_printer(tmp_path, lines),
        extra_args=("--output-format", "stream-json"),
        cwd=tmp_path,
    )
    run, _ = _record(harness)
    models = [step for step in run.steps if step.kind == StepKind.model]
    assert any((step.usage or {}).get("input") == 1000 for step in models)
    assert any((step.usage or {}).get("output") == 70 for step in models)
    calls = [call for step in models for call in (step.outputs or {}).get("tool_calls") or []]
    assert [call["name"] for call in calls] == ["deploy_prod"]
    assert run.total_cost == pytest.approx(0.5)


@pytest.mark.parametrize(
    "prefix",
    [
        lambda n: f"{n:6d}\t",  # cat -n
        lambda n: f"{n}: ",  # nl -s ': '
        lambda n: f"id_rsa:{n}:",  # grep -n
        lambda n: "> ",  # markdown quote
        lambda n: "- ",  # bullet
        lambda n: "    ",  # indented
    ],
)
def test_prefixed_key_bodies_are_masked(prefix):
    lines = [prefix(n) + line for n, line in enumerate(KEY, start=1)]
    keys = KeyLines()
    masked = [keys.mask(line) for line in [*lines, "done."]]
    assert not any(body in "\n".join(masked) for body in KEY_BODY)
    assert masked[-1] == "done."


def test_a_prefixed_key_never_reaches_the_record(tmp_path):
    lines = [f"{n:6d}\t{line}" for n, line in enumerate(KEY, start=1)]
    harness = GenericHarness(command=_printer(tmp_path, ["$ cat -n id", *lines]), cwd=tmp_path)
    _, recorded = _record(harness)
    assert not any(body in recorded for body in KEY_BODY)


@pytest.mark.parametrize(
    ("command", "structured"),
    [
        (("codex", "exec", "--json", "-o", "last.txt"), True),
        (("codex", "exec", "-o", "json"), False),
        (("codex", "exec", "--output-last-message", "json"), False),
        (("codex", "exec"), False),
    ],
)
def test_codex_o_is_a_file_not_an_output_format(command, structured):
    from opentine.harnesses import CodexCLIHarness

    assert CodexCLIHarness(command=command)._stdout_is_structured() is structured


# --------------------------------------------------------------------------- #
# Re-audit round 2, #8: a key inside a JSON event is masked before any sink
# --------------------------------------------------------------------------- #

_UNTERMINATED = {
    "plain": "\n".join(KEY[:-1]),
    "numbered": "\n".join(f"{n:6d}\t{line}" for n, line in enumerate(KEY[:-1], start=1)),
    "terminated-numbered": "\n".join(f"{n:6d}\t{line}" for n, line in enumerate(KEY, start=1)),
}


def _key_event_lines(text: str) -> list[str]:
    import json

    init = {"type": "system", "subtype": "init", "model": "claude-opus-5-5"}
    assistant = {
        "type": "assistant",
        "message": {
            "id": "m1",
            "model": "claude-opus-5-5",
            "content": [{"type": "text", "text": f"the key is:\n{text}\nanything else?"}],
            "usage": {"input_tokens": 1000, "output_tokens": 1},
        },
    }
    return [json.dumps(init), json.dumps(assistant)]


@pytest.mark.parametrize("shape", sorted(_UNTERMINATED))
def test_a_key_inside_a_json_event_never_reaches_the_record(tmp_path, shape):
    lines = _key_event_lines(_UNTERMINATED[shape])
    harness = ClaudeCodeHarness(
        command=_printer(tmp_path, lines),
        extra_args=("--output-format", "stream-json"),
        cwd=tmp_path,
    )
    run, recorded = _record(harness)  # every step, the done step's raw output included
    assert not any(body in recorded for body in KEY_BODY)
    assert PLACEHOLDER in recorded
    models = [step for step in run.steps if step.kind == StepKind.model]
    assert any((step.usage or {}).get("input") == 1000 for step in models)  # event intact


@pytest.mark.parametrize("shape", sorted(_UNTERMINATED))
def test_a_key_inside_a_json_event_never_reaches_the_error_step(tmp_path, shape):
    lines = _key_event_lines(_UNTERMINATED[shape])
    wrapper = OpentineHarness(
        ClaudeCodeHarness(
            command=_printer(tmp_path, lines, exit_code=3),
            extra_args=("--output-format", "stream-json"),
            cwd=tmp_path,
        )
    )
    with pytest.raises(RuntimeError, match="status 3"):
        wrapper.run_sync("task")
    recorded = "\n".join(str(step.inputs) + str(step.outputs) for step in wrapper.run.steps)
    assert any(step.kind == StepKind.error for step in wrapper.run.steps)
    assert not any(body in recorded for body in KEY_BODY)


def test_masking_a_json_event_keeps_unrelated_text_and_is_not_recursive():
    import json

    deep: object = "-----BEGIN PRIVATE KEY-----\n" + KEY_BODY[0]
    for _ in range(500):
        deep = [deep]
    line = json.dumps({"keep": "ordinary text", "deep": deep})
    masked = KeyLines().mask(line)
    assert KEY_BODY[0] not in masked and "ordinary text" in masked


# Re-audit round 3: a deep event never kills the run; the last open marker decides.

BEGIN = "-----BEGIN PRIVATE KEY-----"
END = "-----END PRIVATE KEY-----"


def _deep_event(depth: int) -> str:
    return '{"a":' * depth + '"' + BEGIN + "\\nAAAAAAAAAAAAAAAA" + '"' + "}" * depth


@pytest.mark.parametrize("depth", [500, 900, 990, 2000])
def test_a_deep_event_with_a_key_marker_never_raises(depth):
    # 3.11's budget made json.dumps raise past ~940 levels where json.loads did
    # not; a lowered limit reproduces that band on every Python.
    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(max(200, min(limit, 600)))
    try:
        masked = KeyLines().mask(_deep_event(depth))
    finally:
        sys.setrecursionlimit(limit)
    assert "AAAAAAAAAAAAAAAA" not in masked


def test_an_event_past_the_depth_bound_is_masked_as_text():
    keys = KeyLines()
    masked = keys.mask(_deep_event(600))
    assert masked.endswith(PLACEHOLDER) and keys.open


@pytest.mark.parametrize(
    "line",
    [
        f"{BEGIN} x {END} {BEGIN}",
        f"{BEGIN} x {END} y {BEGIN} z",
        f"{BEGIN} {BEGIN}",
        f"pre {BEGIN} a {END} {BEGIN} b {END} {BEGIN}",
    ],
)
def test_the_last_unterminated_marker_on_a_line_opens_the_block(line):
    keys = KeyLines()
    out = keys.mask(line)
    assert keys.open and out.endswith(PLACEHOLDER)
    assert keys.mask(KEY_BODY[0]) == PLACEHOLDER
    assert keys.mask("  1\t" + KEY_BODY[1]) == PLACEHOLDER


@pytest.mark.parametrize("prefix", ["", "     2\t"])
def test_a_second_unterminated_marker_inside_a_json_event_is_masked(prefix):
    body = "\n".join(prefix + part for part in KEY_BODY)
    text = f"{BEGIN} x {END} {BEGIN}\n{body}"
    line = json.dumps({"item": {"text": text}})
    masked = KeyLines().mask(line)
    assert json.loads(masked)
    assert not any(part in masked for part in KEY_BODY)


@pytest.mark.parametrize(
    "line",
    [f"{BEGIN} x {END}", f"a {BEGIN} x {END} b {BEGIN} y {END}", "no marker at all"],
)
def test_complete_blocks_on_one_line_leave_the_block_closed(line):
    keys = KeyLines()
    assert keys.mask(line) == line and not keys.open


# Re-audit round 4, #5: a key block used as an object key was left verbatim.
def test_a_key_block_used_as_a_json_object_key_is_masked():
    body = "\n".join(KEY_BODY)
    line = json.dumps({"item": {f"{BEGIN}\n{body}": 1, "text": "ok"}, "usage": {"input": 7}})
    masked = KeyLines().mask(line)
    event = json.loads(masked)
    assert not any(part in masked for part in KEY_BODY)
    assert event["usage"] == {"input": 7} and event["item"]["text"] == "ok"


# --------------------------------------------------------------------------- #
# Final pass, #9: masking never records less than the scrubber would
# --------------------------------------------------------------------------- #

_ARMORS = ["RSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY"]
_PGP = "PGP PRIVATE KEY BLOCK"


def _key_shapes(armor: str) -> dict[str, str]:
    begin, end = f"-----BEGIN {armor}-----", f"-----END {armor}-----"
    head = [begin, "Version: test", ""] if armor == _PGP else [begin]
    block = [*head, *KEY_BODY, end]
    return {
        "plain": "\n".join(block),
        "unterminated": "\n".join(block[:-1]),
        "cat-A": "\n".join(line + "$" for line in block),
        "git-diff": "diff --git a/k b/k\n--- a/k\n+++ /dev/null\n@@ -1,5 +0,0 @@\n"
        + "\n".join("-" + line for line in block),
        "js-concat": "const k =\n" + " +\n".join(f'  "{line}\\n"' for line in block) + ";",
        "cat-n": "\n".join(f"{n:6d}\t{line}" for n, line in enumerate(block, start=1)),
        "cat-n-unterminated": "\n".join(
            f"{n:6d}\t{line}" for n, line in enumerate(block[:-1], start=1)
        ),
    }


_SHAPES = [(armor, shape) for armor in [*_ARMORS, _PGP] for shape in _key_shapes(_ARMORS[0])]


def _stored_bytes(run, tmp_path) -> bytes:
    from opentine.repository import Repo

    saved = tmp_path / "run.tine"
    run.save(saved)
    repo = Repo.init(tmp_path / "repo")
    repo.put_run(run)
    blobs = [saved.read_bytes()]
    blobs += [path.read_bytes() for path in (tmp_path / "repo").rglob("*") if path.is_file()]
    return b"\n".join(blobs)


def _assert_no_key(stored: bytes) -> None:
    for body in KEY_BODY:
        assert body.encode() not in stored
        assert body.encode().hex().encode() not in stored


@pytest.mark.parametrize(("armor", "shape"), _SHAPES)
def test_a_key_in_a_structured_tool_result_never_reaches_disk(tmp_path, armor, shape):
    text = _key_shapes(armor)[shape]
    tool_result = {
        "type": "user",
        "message": {"content": [{"type": "tool_result", "tool_use_id": "t1", "content": text}]},
    }
    lines = [*_key_event_lines("ok"), json.dumps(tool_result)]
    harness = ClaudeCodeHarness(
        command=_printer(tmp_path, lines),
        extra_args=("--output-format", "stream-json"),
        cwd=tmp_path,
    )
    run, recorded = _record(harness)
    assert not any(body in recorded for body in KEY_BODY)
    _assert_no_key(_stored_bytes(run, tmp_path))


@pytest.mark.parametrize(("armor", "shape"), _SHAPES)
def test_a_key_printed_as_raw_text_never_reaches_disk(tmp_path, armor, shape):
    text = _key_shapes(armor)[shape]
    harness = GenericHarness(command=_printer(tmp_path, text.split("\n")), cwd=tmp_path)
    run, recorded = _record(harness)
    assert not any(body in recorded for body in KEY_BODY)
    _assert_no_key(_stored_bytes(run, tmp_path))


def test_masking_replaces_whole_spans_and_keeps_the_text_around_them():
    from opentine.harnesses._key_mask import masked_text

    begin, end = "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"
    text = f"before {begin}\n-{KEY_BODY[0]}$\n{end} middle {begin}\n{KEY_BODY[1]}"
    assert masked_text(text) == f"before {PLACEHOLDER} middle {PLACEHOLDER}"
    assert masked_text("no key here") == "no key here"


def test_a_pretty_printed_member_line_stays_valid_json():
    keys = KeyLines()
    document = json.dumps({"final": f"see {BEGIN}\n{KEY_BODY[0]}", "costUsd": 1.5}, indent=2)
    masked = [keys.mask(line) for line in document.splitlines()]
    event = json.loads("\n".join(masked))
    assert event == {"final": f"see {PLACEHOLDER}", "costUsd": 1.5}
