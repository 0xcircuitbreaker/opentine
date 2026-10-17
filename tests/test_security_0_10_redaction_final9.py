"""Final-pass-9 redaction regressions.

* An unterminated private-key edit ended *after* the line break, so the next line
  lost its line start once private keys moved to the front of the scan, and the
  line-anchored rules (``DB_PASSWORD=…`` to end of line, ``Authorization: …``) no
  longer matched it: most of the credential was written out (0.9.2 redacted it).
* The quoted-field rule resumed past a non-secret field's value quote, which may
  open the next field's name: ``"a": "password": "v"`` kept ``v``.
* PuTTY (``.ppk``) and RFC 4716 ``---- BEGIN SSH2 … PRIVATE KEY ----`` keys carry
  no PEM marker and were saved whole.
* The JSON path rescanned every escaped string twice plus a per-step pass, and
  each nesting level doubled the work.
"""

from __future__ import annotations

import json
import time

import pytest

from opentine import Run
from opentine.core import RunStatus
from opentine.graph import StepKind
from opentine.redaction import _scan, redact_blob, redact_text
from opentine.repository import Repo

SECRET = "Charlie7Secret"
BODY = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW"
MARKERS = [
    f"-----BEGIN OPENSSH PRIVATE KEY-----\n{BODY}\n",
    "-----BEGIN RSA PRIVATE KEY-----\n",
    f"-----BEGIN PRIVATE KEY-----\n{BODY}\n{BODY}\n",
]
LINES = [
    f"DB_PASSWORD=Alpha,{SECRET}\n",
    f'Authorization: Basic "{SECRET}"\n',
    f'Cookie: x; y="{SECRET}"\n',
]


def _on_disk(tmp_path, output: str) -> list[bytes]:
    run = Run(run_id="final9")
    run.add_step(StepKind.tool, {"command": "cat deploy.txt"}, outputs={"output": output})
    run.status = RunStatus.completed
    path = tmp_path / "run.tine"
    run.save(path)
    repo = Repo.init(tmp_path / "repo")
    repo.put_run(run)
    blobs = [path.read_bytes()]
    blobs += [p.read_bytes() for p in (tmp_path / "repo").rglob("*") if p.is_file()]
    return blobs


@pytest.mark.parametrize("crlf", [False, True])
@pytest.mark.parametrize("line", LINES)
@pytest.mark.parametrize("marker", MARKERS)
def test_the_line_after_an_unterminated_key_keeps_its_line_start(marker, line, crlf):
    text = marker + line
    if crlf:
        text = text.replace("\n", "\r\n")
    out = redact_text(text)
    assert SECRET not in out, out
    assert out.startswith("[REDACTED PRIVATE KEY]\r\n" if crlf else "[REDACTED PRIVATE KEY]\n")


@pytest.mark.parametrize("line", LINES)
def test_the_line_after_an_unterminated_key_never_reaches_disk(tmp_path, line):
    output = "==> deploy.txt: 2 lines\n" + MARKERS[0] + line
    for blob in _on_disk(tmp_path, output):
        assert SECRET.encode() not in blob


@pytest.mark.parametrize(
    "text",
    [
        b'"a": "password": "Hunter2Secret"',
        b"'db': 'api_key': 'Hunter2Secret'",
        b'"label": "client_secret": "Hunter2Secret"',
        b'"MYSQL_PWD":"client_secret": "Hunter2Secret"',
        b'config error at "database": "password": "Hunter2Secret"',
        b'\\"a\\": \\"password\\": \\"Hunter2Secret\\"',
    ],
)
def test_a_field_name_opened_by_a_value_quote_is_still_a_field(text):
    assert b"Hunter2Secret" not in redact_blob(text)


def test_ordinary_fields_are_untouched():
    blob = json.dumps({"a": "b", "c": "d", "list": ["x", "y"]}).encode()
    assert redact_blob(blob) == blob


def _ppk(mac: bool = True) -> str:
    lines = [f"AAAAB3NzaC1yc2EAAAABJQAAAQEAk{i:02d}{'x' * 34}" for i in range(5)]
    text = (
        "PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nComment: rsa-key-20261016\n"
        "Public-Lines: 2\n" + "\n".join(lines[:2]) + "\nPrivate-Lines: 3\n" + "\n".join(lines[2:])
    )
    return text + ("\nPrivate-MAC: 0123456789abcdef" if mac else "")


def _ssh2(end: bool = True) -> str:
    lines = [f"P2/56wAAAi4AAAA3aWYtbW9kbntzaWdue{i:02d}{'y' * 30}" for i in range(4)]
    text = '---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nComment: "rsa-key"\n' + "\n".join(lines)
    return text + ("\n---- END SSH2 ENCRYPTED PRIVATE KEY ----" if end else "")


def _body_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if len(line) >= 40]


@pytest.mark.parametrize("key", [_ppk(), _ppk(mac=False), _ssh2(), _ssh2(end=False)])
@pytest.mark.parametrize("wrap", ["plain", "json", "nested"])
def test_ppk_and_ssh2_private_keys_are_redacted_whole(key, wrap):
    text = key + "\nnext line kept\n"
    if wrap == "plain":
        out = redact_text(text)
    else:
        inner = json.dumps(text) if wrap == "nested" else text
        blob = redact_blob(json.dumps({"stdout": inner}).encode())
        json.loads(blob)  # still JSON
        out = blob.decode()
    for line in _body_lines(key):
        assert line not in out, line
    assert "[REDACTED PRIVATE KEY]" in out
    assert "next line kept" in out


def test_ppk_keys_never_reach_disk(tmp_path):
    for blob in _on_disk(tmp_path, "$ cat id_rsa.ppk\n" + _ppk() + "\n"):
        for line in _body_lines(_ppk()):
            assert line.encode() not in blob


def test_a_line_after_a_truncated_ppk_is_kept():
    out = redact_text("PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nerror: truncated\n")
    assert out == "[REDACTED PRIVATE KEY]\nerror: truncated\n"


def _best(fn, blob: bytes) -> float:
    best = float("inf")
    for _ in range(3):
        started = time.monotonic()
        fn(blob)
        best = min(best, time.monotonic() - started)
    return best


@pytest.mark.parametrize(
    "doc",
    [
        json.dumps(["\n"] * 20000),
        json.dumps({f"\n{i}": 0 for i in range(8000)}),
        json.dumps([f"2026-10-16 INFO request ok\nline two {i}" for i in range(2000)]),
    ],
    # Short ids: the document as an id overflows Windows' 32767-char env var
    # limit when pytest sets PYTEST_CURRENT_TEST.
    ids=["newlines", "escaped-keys", "log-lines"],
)
def test_json_redaction_stays_close_to_the_byte_scan(doc):
    blob = doc.encode()
    assert _best(redact_blob, blob) < max(_best(_scan, blob), 0.02) * 6


def test_nesting_depth_costs_linear_not_exponential_work():
    base = "\n".join(f"machine h login u password p{i}" for i in range(300))

    def at(depth: int) -> float:
        text = base
        for _ in range(depth):
            text = json.dumps(text)
        return _best(redact_blob, json.dumps({"o": text}).encode())

    one, four = at(1), at(4)
    assert four < max(one, 0.02) * 8  # linear in depth ~4x; doubling per level ~16x
