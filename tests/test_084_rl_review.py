"""0.84: forged segments and audits fail ``tine ingest segments`` with their own codes."""

from __future__ import annotations

import pytest

from opentine import (
    _ingest_batch,
    _ingest_holds,
    _ingest_policy,
    _rl_audit,
    _rl_segment,
    _rl_verify,
)
from opentine.repository._holds import INGEST_AUDIT, INGEST_SEGMENT
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.test_084_rl_capture import T0, _advance, _episodes, _key, make_repo

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


@pytest.fixture
def repo(tmp_path, monkeypatch):
    return make_repo(tmp_path, monkeypatch)


def _codes(repo) -> set[str]:
    return {f["code"] for f in _rl_verify.verify(repo, "rl")["findings"] if f["level"] == "fail"}


def _forge_segment(repo, segment: dict, signer: str, **change) -> str:
    claim = {k: v for k, v in segment.items() if k != "id"} | change
    target = _ingest_policy.anchor_id("rl")
    oid = _ingest_holds.write(repo, target, claim, _key(signer), previous=claim["previous"],
                              signed_at=claim["sealed_at"])  # fmt: skip
    _ingest_holds.move_head(repo, "rl", segment["id"], oid, prefix=INGEST_SEGMENT)
    return oid


def _sealed(repo) -> dict:
    _ingest_batch.append(repo, "rl", _episodes(200), _key("runner"), at_ms=T0)
    return _rl_segment.seal(repo, "rl", _key("runner"), at_ms=T0)


def test_a_segment_with_a_wrong_root_fails(repo):
    segment = _sealed(repo)
    _forge_segment(repo, segment, "runner", root="sha256:" + "0" * 64)
    assert "ingest.segment-root" in _codes(repo)


def test_a_segment_whose_log_entry_commits_to_something_else_fails(repo):
    segment = _sealed(repo)
    _advance(repo)
    later = segment["log"]["index"] + 1  # the _advance entry: no seal note
    _forge_segment(repo, segment, "runner", log={**segment["log"], "index": later})
    assert _codes(repo) == {"ingest.segment-log"}


def test_an_optimizer_signed_segment_fails(repo):
    segment = _sealed(repo)
    _forge_segment(repo, segment, "optimizer")
    assert "ingest.segment-optimizer-key" in _codes(repo)


def test_a_segment_that_skips_batches_fails(repo):
    _sealed(repo)
    nxt = _ingest_batch.append(repo, "rl", _episodes(10, 200), _key("runner"), at_ms=T0)
    _ingest_batch.append(repo, "rl", _episodes(10, 210), _key("runner"), at_ms=T0)
    second = _rl_segment.seal(repo, "rl", _key("runner"), at_ms=T0)
    _forge_segment(repo, second, "runner", batches=second["batches"][1:])
    assert nxt["id"] in second["batches"]
    assert "ingest.segment-batches" in _codes(repo)


def test_an_audit_with_a_chosen_seed_fails_to_recompute(repo):
    segment = _sealed(repo)
    _advance(repo)
    honest = _rl_audit.evaluate(repo, segment["id"], confidence="0.99", max_bad="0.005")
    forged = {**honest, "seed": "11" * 32, "at": "2027-01-15T08:00:00Z"}
    oid = _ingest_holds.write(repo, segment["id"], forged, _key("auditor"), previous=None,
                              signed_at=forged["at"])  # fmt: skip
    _ingest_holds.hold(repo, INGEST_AUDIT + segment["id"], oid)
    assert _codes(repo) == {"ingest.audit-recompute"}


def test_an_audit_claiming_a_smaller_sample_fails(repo):
    segment = _sealed(repo)
    _advance(repo)
    honest = _rl_audit.evaluate(repo, segment["id"], confidence="0.99", max_bad="0.005")
    forged = {**honest, "checked": 3, "ok": 3, "at": "2027-01-15T08:00:00Z",
              "bound": {**honest["bound"], "sample": 3}}  # fmt: skip
    oid = _ingest_holds.write(repo, segment["id"], forged, _key("auditor"), previous=None,
                              signed_at=forged["at"])  # fmt: skip
    _ingest_holds.hold(repo, INGEST_AUDIT + segment["id"], oid)
    assert "ingest.audit-recompute" in _codes(repo)


def test_an_audit_signed_by_the_optimizer_fails(repo):
    segment = _sealed(repo)
    _advance(repo)
    honest = _rl_audit.evaluate(repo, segment["id"], confidence="0.99", max_bad="0.005")
    honest["at"] = "2027-01-15T08:00:00Z"
    oid = _ingest_holds.write(repo, segment["id"], honest, _key("optimizer"), previous=None,
                              signed_at=honest["at"])  # fmt: skip
    _ingest_holds.hold(repo, INGEST_AUDIT + segment["id"], oid)
    assert _codes(repo) == {"ingest.audit-optimizer-key"}


def test_unsealed_batches_are_advisory_only(repo):
    _sealed(repo)
    _ingest_batch.append(repo, "rl", _episodes(5, 200), _key("runner"), at_ms=T0)
    report = _rl_verify.verify(repo, "rl")
    assert report["ok"]
    assert {f["code"] for f in report["findings"]} == {"ingest.segment-unaudited",
                                                        "ingest.segment-pending"}  # fmt: skip
