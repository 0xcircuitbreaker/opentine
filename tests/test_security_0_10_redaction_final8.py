"""Final security pass 8: wrapped keys after a value rule, long field names, signed URLs."""

from __future__ import annotations

import base64
import json
import time

import pytest

from opentine import Run
from opentine.graph import StepKind
from opentine.redaction import redact_blob
from opentine.repository import Repo
from opentine.tools._env_scrub import _sensitive

PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEAFAKEKEYBODYzz9QmFrZUtleUJvZHlMaW5lVHdvFAKE\n"
    "SECONDLINEBODYxyzw\n"
    "-----END RSA PRIVATE KEY-----\n"
)


def _wrapped(width: int = 76) -> str:
    encoded = base64.b64encode(PEM.encode()).decode()
    return "\n".join(encoded[i : i + width] for i in range(0, len(encoded), width))


def _body_lines(wrapped: str) -> list[bytes]:
    return [line.encode() for line in wrapped.split("\n")[1:] if len(line) >= 16]


PREFIXES = (
    "SSH_PRIVATE_KEY=",
    'PRIVATE_KEY="',
    "client-key-data: ",
    "password: x ",
    "export SSH_PRIVATE_KEY=",
)


@pytest.mark.parametrize("prefix", PREFIXES)
@pytest.mark.parametrize("width", (64, 76))
@pytest.mark.parametrize("as_json", (False, True))
def test_a_wrapped_key_after_a_value_rule_is_removed_whole(prefix, width, as_json):
    wrapped = _wrapped(width)
    text = "DB_HOST=localhost\n" + prefix + wrapped + "\nOTHER=1\n"
    blob = json.dumps({"stdout": text}).encode() if as_json else text.encode()
    out = redact_blob(blob)
    if as_json:
        json.loads(out)
    for line in _body_lines(wrapped):
        assert line not in out
    assert b"FAKEKEYBODY" not in out


def test_a_wrapped_key_after_a_credential_name_never_reaches_disk(tmp_path):
    wrapped = _wrapped()
    output = "DB_HOST=localhost\nSSH_PRIVATE_KEY=" + wrapped + "\nOTHER=1\n"
    run = Run(id="final8")
    run.add_step(StepKind.tool, {"name": "shell"}, outputs={"output": output})
    path = tmp_path / "run.tine"
    run.save(path)
    repo = Repo.init(tmp_path / "repo")
    repo.put_run(run)
    files = [p for p in (tmp_path / "repo").rglob("*") if p.is_file()]
    stored = [path.read_bytes()] + [p.read_bytes() for p in files]
    for line in _body_lines(wrapped):
        assert not any(line in data for data in stored)


@pytest.mark.parametrize("length", (129, 300, 5000))
def test_a_long_secret_field_name_is_still_redacted(length):
    name = "a" * length + "_password"
    for blob in (
        json.dumps({name: "hunter2secretvalue"}).encode(),
        ('curl -d "{\\"' + name + '\\": \\"hunter2secretvalue\\"}"').encode(),
    ):
        assert b"hunter2secretvalue" not in redact_blob(blob)


def test_long_field_names_stay_linear():
    def elapsed(n: int) -> float:
        blob = ('"' + "a" * 2000 + '": "v", ') * n
        best = float("inf")
        for _ in range(3):
            started = time.monotonic()
            redact_blob(blob.encode())
            best = min(best, time.monotonic() - started)
        return best

    small, large = elapsed(50), elapsed(200)
    assert large < max(small, 0.02) * 8


@pytest.mark.parametrize(
    "value",
    (
        "https://acct.blob.core.windows.net/c/f?se=2026-10-17&sp=r&sv=2024&sig=abcdEFGH1234",
        "se=2026-10-17&sp=r&sig=abcdEFGH1234",
        "https://b.s3.amazonaws.com/o?X-Amz-Credential=AKIDEXAMPLE%2F2026&X-Amz-Signature=abcdef1234567",
        "https://storage.googleapis.com/b/o?X-Goog-Credential=svc%40p&X-Goog-Signature=abcdef12345678",
        "https://api.example.com/hook?token=abcdef1234567890",
    ),
)
def test_signed_url_credentials_are_scrubbed_from_tool_environments(value):
    assert _sensitive("ARTIFACT_URL", value)


@pytest.mark.parametrize(
    "value", ("https://example.com/?page=2", "/usr/local/bin", "en_US.UTF-8", "sig=short")
)
def test_ordinary_values_are_kept_in_tool_environments(value):
    assert not _sensitive("ARTIFACT_URL", value)
