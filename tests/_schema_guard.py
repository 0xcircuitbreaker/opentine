"""0.45 acceptance: every ``--json`` output validates against its published schema.

Loaded by ``conftest.py`` for the whole suite. Every document the CLI writes
through :func:`opentine._cli_json.serialize` -- so every ``--json`` object any
test drives -- is checked against the ``tine-cli-envelope-1`` envelope and,
when one is published, its command's own schema. A mismatch fails the test
that produced it, so a schema cannot drift from real output unnoticed.

A document that names no ``command``, carries no ``error`` and no published
tag is not a CLI envelope (an export body such as an Agent Trace record) and
is left to the tests of its own format.
"""

from __future__ import annotations

import json

import pytest

from opentine import _cli_json, _schemas


def _is_envelope(document: object) -> bool:
    if not isinstance(document, dict):
        return False
    if "command" in document or "error" in document:
        return True
    try:
        _schemas.detect(document)
    except _schemas.SchemaError:
        return False
    return True


@pytest.fixture(autouse=True)
def _every_json_output_meets_its_schema(monkeypatch):
    original = _cli_json.serialize
    failures: list[str] = []

    def checked(payload, **kwargs):
        text = original(payload, **kwargs)
        document = json.loads(text)
        if _is_envelope(document):
            errors = _schemas.validate_output(document)
            if errors:
                failures.append(f"{document.get('command')!r}: {errors[:3]}")
        return text

    monkeypatch.setattr(_cli_json, "serialize", checked)
    yield
    assert not failures, f"--json output does not meet its published schema: {failures}"
