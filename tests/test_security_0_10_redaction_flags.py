"""Final security pass 6 #1: a quoted value after a space-separated credential flag.

``--password "x"``, ``--token 'x'``, ``--client-secret "x"`` were written out
verbatim -- in plain text, inside JSON, and through ``redact_value`` -- because the
flag rule only took a bare value. And a bare value was cut at 512 bytes, leaving
the tail of a long token behind.
"""

from __future__ import annotations

import json
import time

import pytest

from opentine.redaction import redact_blob, redact_value

SECRET = "Hunter2Secret9"
FLAGS = (
    "--password",
    "--passwd",
    "--pass",
    "--token",
    "--api-key",
    "--api_key",
    "--apikey",
    "--secret",
    "--client-secret",
    "--client_secret",
    "--auth-token",
    "--access-token",
)
STYLES = ('"{s}"', "'{s}'", "{s}")


def _command(flag: str, style: str) -> str:
    return f"tool login -u bob {flag} {style.format(s=SECRET)} --verbose"


@pytest.mark.parametrize("flag", FLAGS)
@pytest.mark.parametrize("style", STYLES)
def test_every_credential_flag_and_quote_style_is_redacted(flag, style):
    command = _command(flag, style)
    plain = redact_blob(command.encode())
    document = redact_blob(json.dumps({"command": command}).encode())
    value = redact_value({"arguments": {"command": command}})
    for output in (plain, document, json.dumps(value).encode()):
        assert SECRET.encode() not in output, output
    assert b"--verbose" in plain  # only the value goes
    assert json.loads(document)["command"].endswith("--verbose")


@pytest.mark.parametrize("quote", ['"', "'"])
def test_the_quotes_stay_and_json_stays_json(quote):
    command = f"psql {FLAGS[0]} {quote}{SECRET}{quote}"
    assert redact_blob(command.encode()) == f"psql --password {quote}[REDACTED]{quote}".encode()
    document = json.dumps({"command": command, "next": 1}).encode()
    assert json.loads(redact_blob(document)) == {
        "command": f"psql --password {quote}[REDACTED]{quote}",
        "next": 1,
    }


def test_an_escaped_quote_inside_a_quoted_value_does_not_end_it():
    command = 'x --password "ab\\"' + SECRET + '" tail'
    assert SECRET.encode() not in redact_blob(command.encode())
    document = redact_blob(json.dumps({"c": command}).encode())
    assert SECRET.encode() not in document
    json.loads(document)


def test_an_unclosed_quoted_value_is_still_redacted():
    assert SECRET.encode() not in redact_blob(f'x --token "{SECRET}'.encode())
    document = redact_blob(json.dumps({"c": f'x --token "{SECRET}'}).encode())
    assert SECRET.encode() not in document
    json.loads(document)


def test_a_long_token_after_a_flag_is_removed_whole():
    jwt = "eyJ" + "a" * 900 + ".eyJ" + "b" * 400 + ".sig" + "c" * 40
    for style in STYLES:
        command = f"curl {FLAGS[11]} {style.format(s=jwt)} https://example.test"
        plain = redact_blob(command.encode())
        assert b"aaaa" not in plain and b"bbbb" not in plain and b"cccc" not in plain, plain
        document = redact_blob(json.dumps({"c": command}).encode())
        assert b"bbbb" not in document and b"cccc" not in document
        json.loads(document)


def test_a_dash_value_and_the_assignment_form_are_unchanged():
    assert redact_blob(b"tool --token --verbose") == b"tool --token --verbose"
    assert redact_blob(b"tool --password=abc123secret") == b"tool --password=[REDACTED]"


def test_flag_redaction_stays_linear():
    def elapsed(count: int) -> float:
        unit = '--password "a\\"b c" --token x '
        blob = (unit * count).encode()
        best = float("inf")
        for _ in range(3):
            started = time.monotonic()
            redact_blob(blob)
            best = min(best, time.monotonic() - started)
        return best

    small, large = elapsed(1000), elapsed(4000)
    assert large < max(small, 0.02) * 8


@pytest.mark.parametrize("quote", ['"', "'"])
def test_a_quoted_flag_value_inside_json_inside_json_is_redacted(quote):
    command = f"helm repo add r https://x --client-secret {quote}{SECRET}{quote} && ls"
    document = json.dumps({"out": json.dumps({"command": command})}).encode()
    redacted = redact_blob(document)
    assert SECRET.encode() not in redacted
    inner = json.loads(json.loads(redacted)["out"])
    assert (
        inner["command"]
        == f"helm repo add r https://x --client-secret {quote}[REDACTED]{quote} && ls"
    )


def test_backslash_runs_never_break_json():
    import random

    rng = random.Random(7)
    for _ in range(2000):
        pieces = [
            rng.choice(["\\", '"', "'", "x", " ", "--token ", "--password "]) for _ in range(12)
        ]
        text = "".join(pieces)
        for document in (json.dumps({"c": text}), json.dumps({"o": json.dumps({"c": text})})):
            json.loads(redact_blob(document.encode()))
