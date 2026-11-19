"""0.64: the Inspect log reader is bounded against hostile input, and fuzzed."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from opentine import _fuzz, _fuzz_corpus
from opentine import _inspect_log as reader
from opentine._fuzz_targets import TARGETS
from opentine._inspect_log import InspectLogError, parse_log

ROOT = Path(__file__).resolve().parents[1]
HEAD = {"version": 2, "status": "success", "eval": {"task": "t"}}


def _zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0)), data,
                             compress_type=zipfile.ZIP_DEFLATED)  # fmt: skip
    return buffer.getvalue()


def test_a_minimal_log_reads():
    log = parse_log(json.dumps({**HEAD, "samples": [{"id": 1, "scores": {}}]}).encode())
    assert log["samples"][0]["id"] == 1 and log["samples"][0]["epoch"] == 1


@pytest.mark.parametrize(
    "doc",
    [
        b"[]",
        b"\xff\xfe",
        json.dumps({"eval": {}}).encode(),
        json.dumps({**HEAD, "samples": {}}).encode(),
        json.dumps({**HEAD, "samples": [{"id": True}]}).encode(),
        json.dumps({**HEAD, "samples": [{"id": 1, "epoch": 0}]}).encode(),
        json.dumps({**HEAD, "samples": [{"id": 1}, {"id": 1}]}).encode(),
        json.dumps({**HEAD, "samples": [{"id": 1, "scores": []}]}).encode(),
        json.dumps({**HEAD, "version": "2"}).encode(),
    ],
)
def test_malformed_logs_are_refused(doc):
    with pytest.raises(InspectLogError):
        parse_log(doc)


def test_string_and_integer_ids_are_different_samples():
    doc = {**HEAD, "samples": [{"id": 1}, {"id": "1"}]}
    assert [s["id"] for s in parse_log(json.dumps(doc).encode())["samples"]] == [1, "1"]


def test_deep_nesting_is_refused():
    deep = "[" * 100_000 + "]" * 100_000
    with pytest.raises(InspectLogError):
        parse_log(f'{{"eval": {{"task": "t"}}, "x": {deep}}}'.encode())
    nested = {"task": "t"}
    for _ in range(reader.MAX_DEPTH + 2):
        nested = {"a": nested}
    with pytest.raises(InspectLogError, match="deeper"):
        parse_log(json.dumps({**HEAD, "metadata": nested}).encode())


def test_an_oversized_log_is_refused_before_parsing(monkeypatch):
    monkeypatch.setattr(reader, "MAX_LOG_BYTES", 64)
    with pytest.raises(InspectLogError, match="larger"):
        parse_log(b"{" + b" " * 100 + b"}")


def test_a_zip_bomb_member_is_refused():
    bomb = _zip({"header.json": json.dumps(HEAD).encode(), "samples/x.json": b" " * (4 << 20)})
    with pytest.raises(InspectLogError, match="ratio"):
        parse_log(bomb)


def test_a_zip_without_a_header_or_with_too_many_members_is_refused(monkeypatch):
    with pytest.raises(InspectLogError, match="header"):
        parse_log(_zip({"samples/1.json": b"{}"}))
    with pytest.raises(InspectLogError):
        parse_log(reader.ZIP_MAGIC + b"\0" * 64)
    monkeypatch.setattr(reader, "MAX_MEMBERS", 2)
    many = _zip({f"m{i}": b"" for i in range(3)} | {"header.json": json.dumps(HEAD).encode()})
    with pytest.raises(InspectLogError, match="members"):
        parse_log(many)


def test_the_fuzz_target_seeds_from_the_committed_fixtures_and_finds_no_crash():
    seeds = _fuzz_corpus.seeds("inspect", ROOT)
    assert len(seeds) >= 5  # the five fixtures, then any triaged regressions
    spec = TARGETS["inspect"]
    assert all(_fuzz.check(spec.run, (), parts) is None for parts in seeds[:5])
    report = _fuzz.fuzz("inspect", seeds, seed=64, iterations=400)
    assert report.crashes == [], report.crashes[0]["trace"]
