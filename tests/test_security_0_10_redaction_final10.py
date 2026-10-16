"""Final pass 10: decorated PPK files, armored or numbered truncated keys,
``--flag=value`` credentials, and CLI passwords after a literal ``\\n`` escape."""

from __future__ import annotations

import json
import time

import pytest

from opentine import Run
from opentine.graph import StepKind
from opentine.redaction import redact_blob, redact_text
from opentine.repository import Repo

_PPK = [
    "PuTTY-User-Key-File-3: ssh-ed25519",
    "Encryption: none",
    "Comment: ed25519-key-20260101",
    "Public-Lines: 2",
    "AAAAC3NzaC1lZDI1NTE5AAAAIPubLineOneZulu9",
    "AAAAPubLineTwoZulu9xyz",
    "Private-Lines: 1",
    "AAAAIGPrivBodyZulu9XYZabcdefghijklmnop",
    "Private-MAC: 0123456789abcdef0123456789abcdef",
]
_DECORATIONS = {
    "read-tool": lambda i: f"{i + 1:6d}→",
    "cat-n": lambda i: f"{i + 1:6d}\t",
    "spaces-number": lambda i: f"{i + 1:6d}  ",
    "diff": lambda i: "+",
    "quote": lambda i: "> ",
    "indent": lambda i: "    ",
    "none": lambda i: "",
}
_SECRETS = ("PrivBodyZulu9", "PubLineOneZulu9", "0123456789abcdef0123")


def _ppk(decorate, trailing: str = "") -> str:
    return "".join(decorate(i) + line + trailing + "\n" for i, line in enumerate(_PPK))


def _clean(text: str) -> bool:
    return not any(secret in text for secret in _SECRETS)


@pytest.mark.parametrize("name", sorted(_DECORATIONS))
@pytest.mark.parametrize("trailing", ["", "  "])
def test_a_decorated_ppk_file_is_redacted_whole(name, trailing):
    text = _ppk(_DECORATIONS[name], trailing) + "after the key\n"
    out = redact_text(text)
    assert _clean(out) and "after the key" in out
    blob = redact_blob(json.dumps({"output": text}).encode()).decode()
    assert _clean(blob) and json.loads(blob)


def test_a_truncated_decorated_ppk_file_is_walked_by_its_counts():
    lines = _PPK[:-1]  # no Private-MAC: the file was cut short
    text = "".join(f"{i + 1:6d}→{line}\n" for i, line in enumerate(lines))
    out = redact_text(text + "     9→an ordinary prose line\n")
    assert _clean(out) and "an ordinary prose line" in out


def test_a_decorated_ppk_never_reaches_a_saved_run(tmp_path):
    numbered = _ppk(_DECORATIONS["read-tool"])
    run = Run(id="ppk")
    run.add_step(StepKind.tool, {"name": "read"}, outputs={"output": numbered})
    path = tmp_path / "ppk.tine"
    run.save(path)
    assert _clean(path.read_text())
    repo = Repo.init(tmp_path / "repo")
    repo.put_run(run)
    for blob in (tmp_path / "repo").rglob("*"):
        if blob.is_file():
            assert b"PrivBodyZulu9" not in blob.read_bytes()


def test_ppk_redaction_stays_linear_in_headers():
    def elapsed(count: int) -> float:
        text = "PuTTY-User-Key-File-3: x\n" * count
        started = time.perf_counter()
        redact_text(text)
        return time.perf_counter() - started

    small, large = elapsed(2000), elapsed(8000)
    assert large < max(small, 0.02) * 8


_BODY = [f"MIIE{i:02d}" + "A" * 58 for i in range(3)]


@pytest.mark.parametrize("header", ["Version: GnuPG v2", "Hash: SHA256", "Charset: UTF-8"])
def test_a_truncated_pgp_block_with_armor_headers_keeps_no_body(header):
    body = "\n".join(_BODY)
    text = f"-----BEGIN PGP PRIVATE KEY BLOCK-----\n{header}\n\n{body}\n"
    assert "MIIE0" not in redact_text(text)
    blob = redact_blob(json.dumps({"a": text}).encode()).decode()
    assert "MIIE0" not in blob and json.loads(blob)
    nested = redact_blob(json.dumps({"a": json.dumps({"b": text})}).encode()).decode()
    assert "MIIE0" not in nested


@pytest.mark.parametrize("name", ["read-tool", "cat-n", "quote", "indent"])
def test_a_numbered_truncated_rsa_block_keeps_no_body(name):
    decorate = _DECORATIONS[name]
    lines = ["-----BEGIN RSA PRIVATE KEY-----", *_BODY]
    out = redact_text("".join(decorate(i) + line + "\n" for i, line in enumerate(lines)))
    assert "MIIE0" not in out


def test_a_diagnostic_after_a_truncated_marker_is_kept():
    text = "-----BEGIN RSA PRIVATE KEY-----\nerror: parser failed here\n\nnext line"
    out = redact_text(text)
    assert "error: parser failed here" in out and "next line" in out


@pytest.mark.parametrize(
    "command",
    [
        "gh auth login --token=Zq1234567Kxx",
        "nomad job run -token=Zq1234567Kxx job.hcl",
        "x --pass=Zq1234567Kxx",
        "openssl enc -pass Zq1234567Kxx",
        "tool --api-key='Zq1234567Kxx'",
        'tool --access-token="Zq1234567Kxx" --next',
        "consul acl -token Zq1234567Kxx",
    ],
)
def test_a_credential_flag_with_equals_or_one_dash_is_redacted(command):
    assert "Zq1234567Kxx" not in redact_text(command)
    blob = redact_blob(json.dumps({"command": command}).encode()).decode()
    assert "Zq1234567Kxx" not in blob and json.loads(blob)


def test_a_token_counter_is_still_kept():
    assert redact_text("token=12 tokens: 40 --tokens 5") == "token=12 tokens: 40 --tokens 5"


@pytest.mark.parametrize(
    "text",
    [
        repr({"script": "set -e\nmysql -uroot -pS3cretPw1x appdb"}),
        repr(["set -e\nredis-cli -h r -a S3cretPw1x ping"]),
        "cmd='cd /srv\\ndocker login -u ci -p S3cretPw1x reg.io'",
        "log: step\\tmysqldump -uroot -pS3cretPw1x db",
        "cmd: x\\n--password S3cretPw1x next",
    ],
)
def test_cli_passwords_after_a_literal_escape_are_redacted(text):
    assert "S3cretPw1x" not in redact_text(text)
    prefixed = b"INFO payload=" + json.dumps({"log": text}).encode()
    assert b"S3cretPw1x" not in redact_blob(prefixed)


def test_cli_password_after_an_escape_never_reaches_a_saved_run(tmp_path):
    output = repr({"script": "set -e\nmysql -uroot -pS3cretPw1x appdb"})
    run = Run(id="cli")
    run.add_step(StepKind.tool, {"name": "plan"}, outputs={"output": output})
    path = tmp_path / "cli.tine"
    run.save(path)
    assert "S3cretPw1x" not in path.read_text()
