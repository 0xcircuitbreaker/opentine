"""0.84 acceptance: 1% silently dropped or altered episodes are caught at the stated confidence.

Ten sealed segments of 1,000 episodes each (ten audit seeds, each from the op
log tree after its seal) and ten tamper seeds per segment: 100 trials. Every
trial drops 5 and alters 5 episodes (1%) of an exported copy of the segment and
audits the copy for "99% confidence that at most 0.5% are tampered or missing".
The guarantee says each trial is caught with probability >= 99%, so at least
99 of 100 must be; counts only, no timing.
"""

from __future__ import annotations

import hashlib
import json
import random

import pytest

from opentine import _ingest_batch, _rl_audit, _rl_segment, _rl_verify
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_084_rl_capture import T0, _advance, _episodes, _key, make_repo

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


@pytest.fixture
def repo(tmp_path, monkeypatch):
    return make_repo(tmp_path, monkeypatch)


SEGMENTS, TAMPER_SEEDS, PER_SEGMENT = 10, 10, 1000


def _lines(repo, segment: dict) -> list[bytes]:
    return [line.encode() for oid in segment["batches"]
            for line in repo.get(oid).payload()["value"]["events"].splitlines()]  # fmt: skip


def _tampered(lines: list[bytes], seed: int) -> tuple[bytes, set[int]]:
    rng = random.Random(seed)
    picked = rng.sample(range(len(lines)), len(lines) // 100)
    dropped, altered = set(picked[: len(picked) // 2]), set(picked[len(picked) // 2 :])
    out = []
    for position, line in enumerate(lines):
        if position in dropped:
            continue
        if position in altered:
            row = json.loads(line)
            row["e"]["r"] = row["e"]["r"] + 100
            line = json.dumps(row).encode()
        out.append(line)
    rng.shuffle(out)  # order is not evidence: lookups go by index
    return b"\n".join(out) + b"\n", dropped | altered


def test_one_percent_tampering_is_caught_in_at_least_99_of_100_seeds(repo):
    caught = trials = 0
    for s in range(SEGMENTS):
        _ingest_batch.append(repo, "rl", _episodes(PER_SEGMENT, PER_SEGMENT * s), _key("runner"),
                             at_ms=T0 + s)  # fmt: skip
        segment = _rl_segment.seal(repo, "rl", _key("runner"), at_ms=T0 + s)
        _advance(repo)
        lines = _lines(repo, segment)
        clean = _rl_audit.evaluate(repo, segment["id"], confidence="0.99", max_bad="0.005",
                                   source=b"\n".join(lines), key=_key("auditor"))  # fmt: skip
        assert clean["verdict"] == "pass" and clean["bound"]["tolerated"] == 5
        for t in range(TAMPER_SEEDS):
            seed = int.from_bytes(hashlib.sha256(f"{s}:{t}".encode()).digest()[:8], "big")
            data, bad = _tampered(lines, seed)
            row = _rl_audit.evaluate(repo, segment["id"], confidence="0.99", max_bad="0.005",
                                     source=data, key=_key("auditor"))  # fmt: skip
            hits = {f["position"] for f in row["failures"]}
            assert hits <= bad and row["missing"] + row["altered"] == len(hits)
            trials += 1
            caught += row["verdict"] == "fail"
    assert trials == 100 and caught >= 99, caught


def test_a_signed_failing_audit_blocks_segments_verify(repo, tmp_path):
    _ingest_batch.append(repo, "rl", _episodes(PER_SEGMENT), _key("runner"), at_ms=T0)
    segment = _rl_segment.seal(repo, "rl", _key("runner"), at_ms=T0)
    _advance(repo)
    data, _ = _tampered(_lines(repo, segment), 7)
    row = _rl_audit.run(repo, segment["id"], _key("auditor"), confidence="0.99",
                        max_bad="0.005", at_ms=T0, source=data)  # fmt: skip
    assert row["verdict"] == "fail" and row["source"]["kind"] == "file"
    report = _rl_verify.verify(repo, "rl")
    assert not report["ok"]
    assert {f["code"] for f in report["findings"]} == {"ingest.audit-failed"}
