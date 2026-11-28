"""0.88.1: credential shapes the field walk stored in clear (pre-existing on main).

``_canon_redact._redact`` read every string as one ``label=value`` pair, and the
callers that run only that walk (event attributes, usage, billing, fork
overrides) kept a secret anywhere else in the text. Each case is fixed text and
is checked through the walk alone, the full v3 guard and the byte scanner.
"""

from __future__ import annotations

import base64

import pytest

from opentine._canon_redact import _redact
from opentine._v3_guards import guarded_redaction
from opentine.redaction import redact_text

B64 = base64.b64encode(bytes(range(40, 70)) + b"x").decode()  # ends "==", holds "/"
SLASHED = "2/B08l2qiCXjkPoADhtPjw=="
PEM = (
    "-----BEGIN {0}-----\nMIIEowIBAAKCAQEAsecretbodyline0123456789abcdef\n"
    "ZmFrZWtleQ==\n-----END {0}-----"
)

CASES = [
    # (1) a later line of a multi-line .env / shell file
    (f"DB_HOST=x\nPASSWORD={B64}", B64, "DB_HOST=x\nPASSWORD="),
    (f"DB_HOST=x\nDB_USER=app\nexport DB_PASSWORD={B64}", B64, "export DB_PASSWORD="),
    # (2) URL query strings
    (f"see https://h.example/x?a=1&token={B64}", B64, "&token="),
    ("https://h.example/p?b=2&access_token=abc123secretval", "abc123secretval", "access_token="),
    ("https://h.example/p?b=2&sig=Zm9vYmFyYmF6cXV4", "Zm9vYmFyYmF6cXV4", "&sig="),
    ("https://h.example/p?b=2&key=abcdefsecret", "abcdefsecret", "&key="),
    ("https://h.example/p?b=2&api_key=hunter2xx", "hunter2xx", "api_key="),
    # (3) URL userinfo: scheme, user and host kept
    ("postgres://bob:hunter2@db.example.com:5432/app", "hunter2", "postgres://bob:"),
    ("mysql://root:hunter2@db/app", "hunter2", "mysql://root:"),
    ("redis://:hunter2@cache:6379/0", "hunter2", "@cache:6379"),
    ("amqp://guest:hunter2@mq/vhost", "hunter2", "amqp://guest:"),
    ("mongodb+srv://bob:hunter2@c.mongodb.net/x", "hunter2", "mongodb+srv://bob:"),
    ("https://bob:hunter2@git.example.com/repo.git", "hunter2", "@git.example.com"),
    (f"postgres://bob:{SLASHED}@db/app", SLASHED, "postgres://bob:"),
    # (4) PEM and PGP private-key bodies
    *((PEM.format(kind), "secretbodyline", "PRIVATE KEY")
      for kind in ("PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY",
                   "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY")),
    ("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQOYBF0secretbodyline0123456789\n=abcd\n"
     "-----END PGP PRIVATE KEY BLOCK-----", "secretbodyline", "PRIVATE KEY"),
    # (5) an assignment on the line after a base64 line
    (f"{B64}\npassword=hunter2", "hunter2", "password="),
    (f"root\n{B64}\nAPI_KEY=hunter2", "hunter2", "API_KEY="),
    # (6) all-capital run-together names
    ("MYSQLROOTPASSWORDPRODUCTION= hunter2", "hunter2", "MYSQLROOTPASSWORDPRODUCTION="),
    ("note\nPRODDBSECRETVALUE=hunter2", "hunter2", "PRODDBSECRETVALUE="),
]  # fmt: skip


@pytest.mark.parametrize(("text", "secret", "kept"), CASES)
def test_the_field_walk_alone_redacts_the_secret(text, secret, kept):
    out = _redact({"v": text})["v"]
    assert secret not in out and "REDACTED" in out and kept in out


@pytest.mark.parametrize(("text", "secret", "kept"), CASES)
def test_the_v3_guard_redacts_the_secret(text, secret, kept):
    out = guarded_redaction({"v": text}, where="t")["v"]
    assert secret not in out and "REDACTED" in out and kept in out


@pytest.mark.parametrize(("text", "secret", "kept"), CASES)
def test_the_byte_scanner_redacts_the_secret(text, secret, kept):
    out = redact_text(text)
    assert secret not in out and "REDACTED" in out and kept in out


def test_a_caps_name_as_a_dict_key_is_redacted():
    assert _redact({"MYSQLROOTPASSWORDPRODUCTION": "hunter2"}) == {
        "MYSQLROOTPASSWORDPRODUCTION": "[REDACTED]"
    }


@pytest.mark.parametrize(
    "text",
    ["https://registry.example:8080/@scope/pkg", "https://h.example/p?page=2&q=hello",
     f"{B64}\nnext line", "PUBLIC_KEY_ID=abc",
     "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"],
)  # fmt: skip
def test_benign_text_is_kept(text):
    assert _redact({"v": text})["v"] == text
    assert guarded_redaction({"v": text}, where="t")["v"] == text


# Token formats and JSON held in one string: the scanner caught them, the walk did not.
_T = "Zq9XkW7pLm3"
TOKENS = [
    '{"db": {"password": "' + _T + '"}}',
    "tok ghp_" + "a" * 26 + _T,
    "github_pat_11AAAA_" + _T * 6,
    "key sk-" + _T * 4,
    "sk-ant-api03-" + _T * 6,
    "xoxb-1234-5678-" + _T,
    "id AKIAIOSFODNN7" + _T[:7].upper(),
    "AIzaSyA" + "b" * 24 + _T,
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0." + _T * 3,
]


@pytest.mark.parametrize("text", TOKENS)
def test_a_token_in_a_walked_string_is_redacted(text):
    secret = _T[:7].upper() if "AKIA" in text else _T
    assert secret not in str(_redact({"attrs": {"v": text}}))
    assert secret not in str(guarded_redaction({"v": text}, where="t"))


@pytest.mark.parametrize(
    "text",
    ["sha256:" + "ab" * 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
     "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYI\n-----END PUBLIC KEY-----",
     '{"page": 2, "sort": "asc"}', "task-runner ask-me sk-"],
)  # fmt: skip
def test_digests_public_keys_and_plain_json_are_kept(text):
    assert _redact({"v": text})["v"] == text
