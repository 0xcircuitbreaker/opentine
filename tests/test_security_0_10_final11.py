"""Final pass 11: a PuTTY key whose comment holds a quote, and OTel log records
with out-of-range or non-numeric timestamps and counters."""

from __future__ import annotations

import json
import random

import pytest

from opentine import Run
from opentine.graph import StepKind
from opentine.redaction import redact_blob, redact_text
from opentine.repository import Repo
from opentine.trace._otel_log_import import otel_log_events

_SECRET = "AAAAIPRIVATEKEYBYTESSECRET1234"


def _ppk(version: int, comment: str, mac: bool) -> list[str]:
    lines = [
        f"PuTTY-User-Key-File-{version}: ssh-ed25519",
        "Encryption: none",
        f"Comment: {comment}",
        "Public-Lines: 1",
        "AAAAC3NzaC1lZDI1NTE5AAAAIPUB",
        "Private-Lines: 1",
        _SECRET,
    ]
    return lines + (["Private-MAC: 0123456789abcdef"] if mac else [])


@pytest.mark.parametrize("version", [2, 3])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize("mac", [True, False])
@pytest.mark.parametrize("comment", ['my "work" key', 'it\'s "x" \\ y', '"'])
def test_a_quote_in_a_ppk_comment_never_cuts_the_file_short(version, newline, mac, comment):
    text = newline.join(_ppk(version, comment, mac)) + newline + "an ordinary prose line"
    out = redact_text(text)
    assert _SECRET not in out
    assert "an ordinary prose line" in out


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize("mac", [True, False])
def test_the_same_ppk_inside_a_json_string_is_redacted_and_stays_valid(newline, mac):
    text = newline.join(_ppk(3, 'my "work" key', mac)) + newline
    for document in ({"output": text}, {"outer": json.dumps({"output": text})}):
        out = redact_blob(json.dumps(document).encode())
        json.loads(out)
        assert _SECRET.encode() not in out


def test_a_quoted_comment_ppk_never_reaches_a_saved_run(tmp_path):
    text = "\n".join(_ppk(3, '"work laptop"', True)) + "\n"
    run = Run(id="ppk-quote")
    run.add_step(StepKind.tool, {"command": "cat work.ppk"}, outputs={"output": text})
    path = tmp_path / "ppk.tine"
    run.save(path)
    assert _SECRET not in path.read_text()
    repo = Repo.init(tmp_path / "repo")
    repo.put_run(run)
    for blob in (tmp_path / "repo").rglob("*"):
        if blob.is_file():
            assert _SECRET.encode() not in blob.read_bytes()


# --- OTel logs: hostile numeric fields ----------------------------------------


def _value(value):
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    return {"stringValue": str(value)}


def _record(nanos, **attributes):
    attributes = {
        "event.name": "api_request",
        "model": "claude-opus-5-5",
        "input_tokens": 3,
        "output_tokens": 2,
        "session.id": "s",
        **attributes,
    }
    record = {"attributes": [{"key": k, "value": _value(v)} for k, v in attributes.items()]}
    if nanos is not None:
        record["timeUnixNano"] = nanos
    return record


def _document(*records):
    return {"resourceLogs": [{"scopeLogs": [{"logRecords": list(records)}]}]}


_GOOD = str(1_791_000_000 * 1_000_000_000)


@pytest.mark.parametrize(
    "nanos",
    ["9" * 400, 10**400, -5, "-5", "abc", "1e400", 1.5e300, True, [1], {"a": 1}, 2**63],
)
def test_one_bad_log_timestamp_never_aborts_the_import(nanos):
    events = otel_log_events(_document(_record(_GOOD), _record(nanos)))
    assert len(events) == 2
    warnings = events[0].attributes.get("opentine.import_warnings") or []
    if nanos not in (True,) and not isinstance(nanos, (list, dict, float)):
        assert any("timestamp" in warning for warning in warnings)


def test_hostile_numeric_fields_never_abort_an_otel_logs_import():
    rng = random.Random(11)
    hostile = [10**400, -(10**400), "9" * 500, "NaN", "Infinity", "-1", "1e999", 1e308, -1, ""]
    fields = ("input_tokens", "output_tokens", "cache_read_tokens", "cache_creation_tokens")
    for _ in range(300):
        record = _record(
            rng.choice([_GOOD, *hostile]),
            **{name: rng.choice(hostile + [5]) for name in fields},
            cost_usd=rng.choice(hostile + ["0.01"]),
            duration_ms=rng.choice(hostile + [10]),
        )
        events = otel_log_events(_document(_record(_GOOD), record))
        assert events, "the good record still imports"
