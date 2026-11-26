"""0.84 end to end: capture, seal, audit, provenance, query and the oversight queue.

The acceptance criteria, through the CLI where a user would type them:

* ``tine ingest`` batches are sealed into a segment whose root is signed once
  by a pinned ``runner`` key; ``tine ingest audit`` signs a sampling verdict
  by a pinned ``auditor`` key with the stated guarantee and its bound;
* a tampered export of the segment fails its audit, ``tine ingest segments``
  exits 1, and the failure opens an ``ingest`` item in the oversight queue;
* ``tine provenance embed`` ties a PNG to the run that made it and ``tine
  provenance verify`` passes, then reports a modified file;
* segments, audits and provenance records are ``tine query`` rows whose
  per-row ``--verify`` is ``verified`` for the pinned roles, and an index row
  edited by hand fails.

Counts and ordering only; no timing.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing

import pytest

from opentine import _containment_records, _ingest_batch, _oversight_queue
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.provenance_fixture import png
from tests.test_077_live_ingest_e2e import _pin_oversight
from tests.test_084_rl_capture import T0, _advance, _episodes, _key, _tine, make_repo

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


@pytest.fixture
def repo(tmp_path, monkeypatch):
    return make_repo(tmp_path, monkeypatch)


def _query(capsys, root: str, sql: str, *extra: str) -> tuple[int, dict]:
    return _tine(capsys, "query", sql, "--verify", "--refresh", *extra, "--repo", root, "--json")


def _tampered(repo, segment: str) -> bytes:
    """The segment's stored lines with every episode changed: any sample catches it."""
    from opentine import _rl_segment

    claim = _rl_segment.read(repo, segment)["claim"]
    found = _rl_segment.episodes(repo, claim["stream"], claim["batches"])
    lines = []
    for index in found["indexes"]:
        lines.append(json.dumps({"e": "x", "i": index, "k": "episode"}).encode())
    return b"\n".join(lines) + b"\n"


def test_capture_audit_provenance_query_and_oversight(repo, tmp_path, capsys):
    root = str(repo.path)
    for i in range(2):
        _ingest_batch.append(repo, "rl", _episodes(100, 100 * i), _key("runner"), at_ms=T0 + i)
    code, out = _tine(capsys, "ingest", "seal", "--stream", "rl", "--key", "runner.key",
                      "--repo", root, "--json")  # fmt: skip
    assert code == 0, out
    segment = out["segment"]["id"] if "segment" in out else out["id"]
    _advance(repo)
    guarantee = ("--confidence", "0.99", "--max-bad", "0.005")
    code, out = _tine(capsys, "ingest", "audit", segment, "--key", "auditor.key", *guarantee,
                      "--repo", root, "--json")  # fmt: skip
    assert code == 0, out
    code, report = _tine(capsys, "ingest", "segments", "rl", "--repo", root, "--json")
    assert code == 0, report
    _pin_oversight(repo)
    assert not [i for i in _oversight_queue.queue(repo)["items"] if i["source"] == "ingest"]

    code, out = _query(capsys, root, "SELECT oid, episodes, signed FROM ingest_segments")
    assert code == 0 and [r["episodes"] for r in out["rows"]] == [200]
    assert [c["status"] for c in out["verification"]["rows"]] == ["verified"]
    code, out = _query(capsys, root, "SELECT oid, segment, verdict, checked, confidence,"
                       " max_bad FROM ingest_audits")  # fmt: skip
    assert code == 0 and [r["verdict"] for r in out["rows"]] == ["pass"]
    row = out["rows"][0]
    assert row["segment"] == segment and (row["confidence"], row["max_bad"]) == ("0.99", "0.005")
    assert 0 < row["checked"] <= 200
    assert [c["status"] for c in out["verification"]["rows"]] == ["verified"]

    # A trainer's export with every episode altered fails its signed audit.
    export = tmp_path / "export.jsonl"
    export.write_bytes(_tampered(repo, segment))
    code, out = _tine(capsys, "ingest", "audit", segment, "--key", "auditor.key",
                      "--episodes", str(export), "--repo", root, "--json")  # fmt: skip
    code, report = _tine(capsys, "ingest", "segments", "rl", "--repo", root, "--json")
    assert code == 1
    items = [i for i in _oversight_queue.queue(repo)["items"] if i["source"] == "ingest"]
    assert [i["item"] for i in items] == [f"ingest:{segment}"]
    code, out = _query(capsys, root, "SELECT oid, verdict FROM ingest_audits ORDER BY verdict")
    assert sorted(r["verdict"] for r in out["rows"]) == ["fail", "pass"]

    # Provenance: a PNG made by a run, embedded, verified, queried, then modified.
    run = _containment_records.anchor(repo, "produce", "made an image")
    image = tmp_path / "out.png"
    image.write_bytes(png())
    code, out = _tine(capsys, "provenance", "embed", str(image), "--run", run, "--key",
                      "runner.key", "--repo", root, "--json")  # fmt: skip
    assert code == 0, out
    code, out = _tine(capsys, "provenance", "verify", str(image), "--repo", root, "--json")
    assert code == 0 and out["ok"] and out["verification"] == "verified"
    code, out = _query(capsys, root, "SELECT oid, target, media, pointer FROM artifact_provenance")
    assert code == 0 and [(r["target"], r["pointer"]) for r in out["rows"]] == [(run, "png-text")]
    assert [c["status"] for c in out["verification"]["rows"]] == ["verified"]
    image.write_bytes(image.read_bytes() + b"\x00")
    code, out = _tine(capsys, "provenance", "verify", str(image), "--repo", root, "--json")
    assert code == 1 and not out["ok"]

    # An index row edited by hand fails its per-row verify.
    with closing(sqlite3.connect(repo.path / "query" / "index.sqlite")) as db:
        db.execute("UPDATE ingest_audits SET verdict = 'pass'")
        db.commit()
    code, out = _tine(capsys, "query", "SELECT oid, verdict FROM ingest_audits", "--verify",
                      "--repo", root, "--json")  # fmt: skip
    assert code == 1
    assert sorted(c["status"] for c in out["verification"]["rows"]) == ["failed", "verified"]
