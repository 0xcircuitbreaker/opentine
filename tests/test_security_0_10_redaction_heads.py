"""Final-pass-5 redaction regressions: value heads and escaped credential fields.

1. An unquoted multi-word value stopped at *any* later word followed by ``=`` or
   ``:``, so base64 padding (``Basic dXNl…=``) or a ``user:pass`` word ended it and
   the encoded credential was written out. Only a real credential-name head ends a
   value now.
2. A JSON-escaped field (``\\"password\\":\\"x\\"``) inside other text -- ``curl -d``,
   ``echo``, a logged payload -- matched neither the field rule nor the assignment
   rule, so the value was kept.
"""

from __future__ import annotations

import json
import time

import pytest

from opentine.redaction import redact_blob

SECRET = "Zq9secretVALUE77"


@pytest.mark.parametrize(
    "text, tail",
    [
        ("using credentials: Basic dXNlcjpwYXNzd29yZA== for proxy", "dXNlcjpwYXNzd29yZA=="),
        ("proxy credentials: Basic dXNlcjpwYXNzd29yZDE= ok", "dXNlcjpwYXNzd29yZDE="),
        ("api_key: Key abcDEF123ghi== tail", "abcDEF123ghi=="),
        (
            "DEBUG http.client: sending with credentials: Basic dXNlcjpodW50ZXIyU2VjcmV0OTk=",
            "dXNlcjpodW50ZXIyU2VjcmV0OTk=",
        ),
        ("x password: hunter2 user:pass more", "user:pass"),
        ("x secret: alpha beta== gamma", "beta=="),
    ],
)
def test_padding_and_colon_words_stay_inside_the_value(text, tail):
    for blob in (text.encode(), json.dumps({"msg": text}).encode()):
        out = redact_blob(blob)
        assert tail.encode() not in out, out
        if blob.startswith(b"{"):
            json.loads(out)


@pytest.mark.parametrize(
    "text, secrets",
    [
        ('-e AZURE_STORAGE_KEY=x1secret -e DB_PASSWORD="y2secret"', ["x1secret", "y2secret"]),
        ("run GITHUB_TOKEN=x1secret DB_PASSWORD='y2secret'", ["x1secret", "y2secret"]),
        ('run client-key-data: x1secret api_key="y2secret"', ["x1secret", "y2secret"]),
    ],
)
def test_chained_credential_assignments_still_split(text, secrets):
    out = redact_blob(text.encode())
    for secret in secrets:
        assert secret.encode() not in out, out


@pytest.mark.parametrize(
    "text",
    [
        'curl -d "{\\"password\\":\\"' + SECRET + '\\",\\"user\\":\\"bob\\"}" https://x',
        'echo {\\"api_key\\": \\"' + SECRET + '\\"}',
        'INFO payload={\\"token\\":\\"' + SECRET + '\\"} sent',
        'INFO {\\"client_secret\\" : \\"' + SECRET + '\\"}',
        "lit \\'password\\':\\'" + SECRET + "\\' end",
    ],
)
def test_escaped_credential_fields_are_redacted(text):
    for blob in (text.encode(), json.dumps({"cmd": text}).encode()):
        out = redact_blob(blob)
        assert SECRET.encode() not in out, out
        if blob.startswith(b"{"):
            json.loads(out)


def test_escaped_field_keeps_neighbours_and_structure():
    out = redact_blob(b'x {\\"password\\":\\"' + SECRET.encode() + b'\\",\\"user\\":\\"bob\\"} y')
    assert out == b'x {\\"password\\":\\"[REDACTED]\\",\\"user\\":\\"bob\\"} y'


def test_escaped_value_with_a_literal_quote_is_redacted_whole():
    blob = b'lit \\"password\\":\\"a\\\\\\"b ' + SECRET.encode() + b'\\" end'
    assert SECRET.encode() not in redact_blob(blob)


def test_unescaped_quote_ends_an_escaped_value_inside_json():
    # Raw JSON bytes: the holder string ends before the escaped value closes.
    doc = json.dumps({"a": 'x \\"password\\":\\"' + SECRET, "b": 1}).encode()
    out = redact_blob(doc)
    assert SECRET.encode() not in out
    assert json.loads(out)["b"] == 1


def _seconds(blob: bytes) -> float:
    best = float("inf")
    for _ in range(2):
        started = time.monotonic()
        redact_blob(blob)
        best = min(best, time.monotonic() - started)
    return best


@pytest.mark.parametrize(
    "unit",
    [
        b"password: a b c d e f g h ",
        b"x secret: aa== bb== cc== ",
        b'{\\"password\\":\\"aaaa',
        b"-e DB_PASSWORD=x ",
    ],
)
def test_heads_and_escaped_fields_stay_linear(unit):
    small = _seconds(unit * 2000)
    large = _seconds(unit * 8000)
    assert large < max(small, 0.02) * 8
