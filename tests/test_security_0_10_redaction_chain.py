"""0.10 final pass 4: chained assignments and linear tail extension in redaction."""

from __future__ import annotations

import json
import time

import pytest

from opentine.redaction import redact_blob, redact_text

SECRET = "hunter2Secret"

CHAINED = [
    f'docker run -e AZURE_STORAGE_KEY=abc -e DB_PASSWORD="{SECRET}" img',
    f"docker run -e AZURE_STORAGE_KEY=abc -e DB_PASSWORD='{SECRET}' img",
    f'x GITHUB_TOKEN=abc DB_PASSWORD="{SECRET}" tail',
    f"x GITHUB_TOKEN=abc DB_PASSWORD='{SECRET}'",
    f'k client-key-data: xyz api_key="{SECRET}" tail',
    f"env STORAGE_KEY=one API_KEY={SECRET} more",
    f"cmd --api-key=one --password={SECRET}",
]


@pytest.mark.parametrize("text", CHAINED)
def test_a_second_assignment_on_the_line_is_still_redacted(text):
    assert SECRET not in redact_text(text)


@pytest.mark.parametrize("text", CHAINED)
def test_a_second_assignment_inside_json_is_redacted_and_json_stays_valid(text):
    out = redact_blob(json.dumps({"command": text, "n": 1}).encode())
    assert SECRET.encode() not in out
    json.loads(out)


def test_a_multi_word_value_is_still_redacted_whole():
    out = redact_text("the password: correct horse battery staple")
    assert "horse" not in out and "staple" not in out


def _ratio(unit: bytes, small: int) -> float:
    def elapsed(size: int) -> float:
        blob = b"log: " + unit * (size // len(unit))
        best = float("inf")
        for _ in range(3):
            started = time.monotonic()
            redact_blob(blob)
            best = min(best, time.monotonic() - started)
        return best

    a, b = elapsed(small), elapsed(small * 4)
    return b / max(a, 0.02)


@pytest.mark.parametrize(
    "unit",
    [
        b"/MYSQL_PWD=" + b"a" * 510,
        b"/--user=u:" + b"a" * 510,
        b"/cookie: " + b"a" * 4096,
    ],
    ids=["pwd", "curl", "cookie"],
)
def test_capped_form_tails_stay_linear_when_heads_repeat(unit):
    # Each tail used to scan to the end of the run, not to the next match:
    # O(matches x n). Linear work grows ~4x for 4x input; quadratic ~16x.
    assert _ratio(unit, 50_000) < 8
