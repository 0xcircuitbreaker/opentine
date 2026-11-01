"""Two ``tine run --parallel`` members saving one content-addressed run (0.19.1).

Both replace the same ``.tine_runs/<id>.tine`` at once. On Windows the loser of
that race briefly gets ``PermissionError`` from ``os.replace``; the artifact and
index writers now retry it like the repository's control files do.
"""

from __future__ import annotations

import os

from opentine import _canon, _codec_io
from opentine.repository import _winretry


def _flaky_replace(monkeypatch, failures: int) -> list[int]:
    calls = [0]
    real = os.replace

    def replace(source, target):
        calls[0] += 1
        if calls[0] <= failures:
            raise PermissionError(32, "The process cannot access the file")
        real(source, target)

    monkeypatch.setattr(_winretry, "WINDOWS", True)
    monkeypatch.setattr(_winretry, "_sleep", lambda _s: None)
    monkeypatch.setattr(_winretry.os, "replace", replace)
    return calls


def test_a_text_save_survives_a_transient_sharing_violation(monkeypatch, tmp_path):
    calls = _flaky_replace(monkeypatch, 3)
    target = tmp_path / "index.json"
    _canon.atomic_write_text(target, "{}")
    assert target.read_text() == "{}" and calls[0] == 4
    assert [p.name for p in tmp_path.iterdir()] == ["index.json"]  # no temp left behind


def test_a_binary_save_survives_a_transient_sharing_violation(monkeypatch, tmp_path):
    calls = _flaky_replace(monkeypatch, 2)
    target = tmp_path / "run.tine"
    target.write_bytes(b"old")
    _codec_io.atomic_write_bytes(target, b"new")
    assert target.read_bytes() == b"new" and calls[0] == 3


def test_a_persistent_denial_still_fails_closed(monkeypatch, tmp_path):
    _flaky_replace(monkeypatch, 10_000)
    target = tmp_path / "run.tine"
    try:
        _codec_io.atomic_write_bytes(target, b"x")
    except PermissionError:
        pass
    else:
        raise AssertionError("a lasting denial must surface")
    assert not target.exists() and list(tmp_path.iterdir()) == []
