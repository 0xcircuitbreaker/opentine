"""0.84 red-team review: sample seeds a runner or trainer cannot grind, bounded guarantees."""

from __future__ import annotations

import hashlib

import pytest

from opentine import _rl_audit, _rl_merkle, _rl_segment, _rl_verify
from opentine._ingest_policy import IngestError
from opentine.repository import _oplog, _tlog, _tlog_note
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.test_084_rl_capture import T0, _advance, _fill, _key, make_repo

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


@pytest.fixture
def repo(tmp_path, monkeypatch):
    return make_repo(tmp_path, monkeypatch)


def _sealed(repo) -> dict:
    _fill(repo)
    segment = _rl_segment.seal(repo, "rl", _key("runner"), at_ms=T0 + 10)
    _advance(repo)
    return segment


def _public_seed(repo, segment: dict) -> str:
    """The seed anyone holding the op log could compute (and grind) before the audit."""
    entries = _tlog_note.verify_log(_oplog.log_root(repo.path), _oplog.ORIGIN)
    size = segment["log"]["index"] + 2
    root = _tlog.merkle_root([_tlog.leaf_hash(e) for e in entries[:size]])
    raw = _rl_audit.CONVENTION.encode() + b"\x00" + segment["id"].encode() + b"\x00"
    return hashlib.sha256(raw + root).hexdigest()


def test_the_seed_is_not_computable_from_the_op_log_alone(repo):
    # A runner writes the entry after its seal; with a public seed it grinds that
    # entry offline until the sample misses its tampering. The auditor's reveal stops it.
    segment = _sealed(repo)
    row = _rl_audit.run(repo, segment["id"], _key("auditor"), confidence="0.99",
                        max_bad="0.005", at_ms=T0 + 20)  # fmt: skip
    assert row["seed"] != _public_seed(repo, segment)
    assert _rl_verify.verify(repo, "rl")["ok"]


def test_a_reveal_not_made_by_the_audit_signer_does_not_recompute(repo):
    segment = _sealed(repo)
    row = _rl_audit.run(repo, segment["id"], _key("auditor"), confidence="0.99",
                        max_bad="0.005", at_ms=T0 + 20)  # fmt: skip
    forged = _key("runner").sign(b"anything").hex()
    with pytest.raises(IngestError, match="reveal"):
        _rl_audit.evaluate(
            repo,
            segment["id"],
            confidence="0.99",
            max_bad="0.005",
            reveal=(forged, _key("auditor").public_key().public_bytes_raw()),
        )
    pub = _key("auditor").public_key().public_bytes_raw()
    again = _rl_audit.evaluate(repo, segment["id"], confidence="0.99", max_bad="0.005",
                               reveal=(row["reveal"], pub))  # fmt: skip
    assert again["seed"] == row["seed"]


def test_an_episode_file_gets_its_own_seed_so_it_cannot_be_fitted_to_a_known_sample(repo):
    segment = _sealed(repo)
    first = _rl_audit.run(repo, segment["id"], _key("auditor"), confidence="0.99",
                          max_bad="0.005", at_ms=T0 + 20)  # fmt: skip
    second = _rl_audit.run(repo, segment["id"], _key("auditor"), confidence="0.99",
                           max_bad="0.005", at_ms=T0 + 21, source=b"")  # fmt: skip
    assert first["seed"] != second["seed"]
    assert second["verdict"] == "fail" and second["missing"] == second["checked"]


@pytest.mark.parametrize(
    "text", ["Infinity", "-Infinity", "sNaN", "1e-999999999", "0." + "1" * 400]
)
def test_guarantee_numbers_that_are_infinite_or_unbounded_are_refused(text):
    with pytest.raises(ValueError):
        _rl_merkle.fraction(text, "confidence", low_open=True)
