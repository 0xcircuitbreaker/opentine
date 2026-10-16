"""Final-pass-7 redaction regression: a secret one JSON-string level deeper.

A JSON string holding a JSON string literal (``jq -Rs`` output, a ``json.dumps``'d
log line, MCP text content) keeps its inner line breaks as a doubly escaped
``\\\\n``. The byte scan's unquoted value ran across that escape and ate the next
line's credential name, and the escaped-string check decoded only one level, so
``DB_PASSWORD='secret'`` on the following line was written out (0.9.2 redacted it
for the newer names, such as ``AZURE_STORAGE_KEY``). The check now compares
against the original string's full redaction, every nested level decoded.
"""

from __future__ import annotations

import json
import time

import pytest

from opentine import Run
from opentine.core import RunStatus
from opentine.graph import StepKind
from opentine.redaction import redact_blob, redact_value
from opentine.repository import Repo

SECRET = "Hunter2SecretValue"

TEXTS = [
    f"AZURE_STORAGE_KEY=abc\nDB_PASSWORD='{SECRET}'",
    f"NAME=x\nAPI_KEY='{SECRET}'",
    f"--token x\n--password '{SECRET}'\nnext",
    f"MYSQL_PWD=x\nmysql -p'{SECRET}'",
    f"MYSQL_PWD=x\n--password '{SECRET}'\nnext",
    f"DB_PASSWORD=devpass\nAPI_KEY='{SECRET}'",
    f'client-key-data: x\nDB_PASSWORD="{SECRET}"',
]


def _nested(text: str, level: int) -> str:
    for _ in range(level - 1):
        text = json.dumps(text)
    return text


@pytest.mark.parametrize("level", [1, 2, 3, 4])
@pytest.mark.parametrize("text", TEXTS)
def test_a_value_behind_a_nested_escaped_newline_is_redacted(text, level):
    blob = json.dumps({"stdout": _nested(text, level), "exit_code": 0}).encode()
    out = redact_blob(blob)
    assert SECRET.encode() not in out, out
    assert json.loads(out)["exit_code"] == 0


@pytest.mark.parametrize("level", [2, 3])
def test_redact_value_covers_nested_levels(level):
    value = {"arguments": {"stdout": _nested(TEXTS[0], level)}}
    assert SECRET not in json.dumps(redact_value(value))


@pytest.mark.parametrize("level", [2, 3])
def test_nested_values_never_reach_disk(tmp_path, level):
    output = json.dumps({"exit_code": 0, "stdout": _nested(TEXTS[0], level)})
    run = Run(run_id=f"nested-{level}")
    run.add_step(StepKind.tool, {"command": "cat .env | jq -Rs ."}, outputs={"output": output})
    run.status = RunStatus.completed
    path = tmp_path / "run.tine"
    run.save(path)
    assert SECRET not in path.read_text(encoding="utf-8")
    repo = Repo.init(tmp_path / "repo")
    repo.put_run(run)
    for blob in (tmp_path / "repo").rglob("*"):
        if blob.is_file():
            assert SECRET.encode() not in blob.read_bytes(), blob


def test_clean_nested_strings_stay_byte_identical():
    blob = json.dumps({"stdout": _nested("line one\nline two\nall fine here", 3)}).encode()
    assert redact_blob(blob) == blob


def test_nested_check_stays_linear():
    def elapsed(n: int) -> float:
        lines = "\n".join(f"AZURE_STORAGE_KEY=a{i}\nDB_PASSWORD='{SECRET}{i}'" for i in range(n))
        blob = json.dumps({"stdout": _nested(lines, 2)}).encode()
        best = float("inf")
        for _ in range(2):
            started = time.monotonic()
            out = redact_blob(blob)
            best = min(best, time.monotonic() - started)
        assert SECRET.encode() not in out
        return best

    small, large = elapsed(150), elapsed(600)
    assert large < max(small, 0.02) * 8  # 4x input: linear ~4x, quadratic ~16x
