"""The audit anchor outlasts a transient Windows sharing violation."""

from __future__ import annotations

import os

import pytest

from opentine.remote import _audit
from opentine.repository import _winretry

KEY = b"k" * 32


def _flaky(monkeypatch, name, failures):
    real = getattr(os, name)
    left = [failures]

    def fake(*args, **kwargs):
        if left[0]:
            left[0] -= 1
            raise PermissionError(13, "sharing violation")
        return real(*args, **kwargs)

    monkeypatch.setattr(os, name, fake)


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(_winretry, "WINDOWS", True)
    monkeypatch.setattr(_winretry, "_sleep", lambda _s: None)


def test_write_anchor_retries_a_blocked_replace(tmp_path, monkeypatch, windows):
    path = tmp_path / "audit.sqlite3.audit-head"
    _audit.write_anchor(path, "a" * 64, KEY)
    _flaky(monkeypatch, "replace", 3)
    _audit.write_anchor(path, "b" * 64, KEY)
    assert _audit.read_anchor(path, KEY) == "b" * 64
    assert [p.name for p in tmp_path.iterdir()] == [path.name]


def test_read_anchor_retries_a_blocked_open(tmp_path, monkeypatch, windows):
    path = tmp_path / "audit.sqlite3.audit-head"
    _audit.write_anchor(path, "c" * 64, KEY)
    _flaky(monkeypatch, "open", 3)
    assert _audit.read_anchor(path, KEY) == "c" * 64


def test_posix_does_not_retry(tmp_path, monkeypatch):
    monkeypatch.setattr(_winretry, "WINDOWS", False)
    path = tmp_path / "audit.sqlite3.audit-head"
    _flaky(monkeypatch, "replace", 1)
    with pytest.raises(PermissionError):
        _audit.write_anchor(path, "d" * 64, KEY)
