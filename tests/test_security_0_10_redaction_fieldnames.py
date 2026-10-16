"""Quoted fields use the record walk's secret-name predicate (``_redact_names``).

``"MYSQL_PWD": "…"``, ``"X_PW": "…"``, ``"app.db.pwd": "…"`` and the other names the
dict walk redacts were kept verbatim by the text rule, whose name list was older, so
the same object leaked as text (tool output, a curl body, JSON inside a string) and
not as a dict. One predicate now decides both.
"""

from __future__ import annotations

import json
import time

import pytest

from opentine import Repo, Run
from opentine._canon_redact import _field_name, _secret_field
from opentine._redact_names import CREDENTIAL_NAMES, SECRET_SUFFIXES, secret_name
from opentine.graph import StepKind
from opentine.redaction import redact_blob, redact_text, redact_value

SECRET = "Zq9SeKrEtValue77"
NAMES = (
    "X_PW",
    "MYSQL_PWD",
    "app.db.pwd",
    "spring.datasource.pwd",
    "LDAP_BIND_PW",
    "AZURE_STORAGE_KEY",
    "client-key-data",
    "key_data",
    "dbPassword",
    "next_page_token",
    "ConnectionString",
    "webhook_url",
)


def _nest(text: str, level: int) -> str:
    for _ in range(level):
        text = json.dumps({"stdout": text})
    return text


@pytest.mark.parametrize("name", NAMES)
def test_the_text_rule_agrees_with_the_record_walk(name):
    assert secret_name(name) is _secret_field(
        _field_name(name), set(CREDENTIAL_NAMES), SECRET_SUFFIXES
    )
    assert secret_name(name)


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("level", [0, 1, 2, 3])
def test_a_secret_named_field_is_redacted_at_every_nesting_level(name, level):
    blob = _nest(json.dumps({name: SECRET, "other": "kept"}), level).encode()
    out = redact_blob(blob)
    assert SECRET.encode() not in out
    json.loads(out)
    assert b"kept" in out


@pytest.mark.parametrize("name", NAMES)
def test_the_escaped_spelling_in_command_text_is_redacted(name):
    body = json.dumps({name: SECRET}).replace('"', '\\"')
    for text in (f'curl -d "{body}" https://x', f"echo {body}", f"INFO payload={body}"):
        out = redact_text(text)
        assert SECRET not in out, text
        assert out.count('\\"') == text.count('\\"'), "quotes are kept"


def test_counters_and_ordinary_fields_are_kept():
    doc = json.dumps(
        {"input_tokens": "123", "max_tokens": "4096", "model": "m", "session_id": "s-1"}
    )
    assert redact_blob(doc.encode()) == doc.encode()


def test_a_field_saved_with_a_run_never_reaches_disk(tmp_path):
    output = json.dumps({"exit_code": 0, "stdout": json.dumps({"MYSQL_PWD": SECRET})})
    run = Run(id="fields")
    run.add_step(StepKind.tool, {"name": "shell"}, outputs={"output": output})
    path = tmp_path / "run.tine"
    run.save(path)
    assert SECRET.encode() not in path.read_bytes()
    repo = Repo.init(tmp_path / "repo")
    repo.put_run(run)
    for blob in (tmp_path / "repo" / ".tine" / "objects").rglob("*"):
        if blob.is_file():
            assert SECRET.encode() not in blob.read_bytes()
    assert SECRET not in json.dumps(redact_value({"note": output}))


def test_the_field_rule_stays_linear():
    def cost(count: int) -> float:
        unit = '{"field_%d": "value", "app.db.pwd": "x"} '
        blob = "".join(unit % i for i in range(count)).encode()
        best = float("inf")
        for _ in range(2):
            started = time.perf_counter()
            redact_blob(blob)
            best = min(best, time.perf_counter() - started)
        return best

    small, large = cost(2000), cost(8000)
    assert large < max(small, 0.02) * 6
