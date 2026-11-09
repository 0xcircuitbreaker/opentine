"""0.48 review hardening: option injection, cross-review findings, symlinks in the code map."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _code_graph, _review_finding, _review_run

SEED = "11" * 32


def _signed(review_id: str) -> dict:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED))
    return _review_finding.sign(
        _review_finding.build(review_id, "rf-1", "high", "m", reviewer="fake-0"), key
    )


def _hex() -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED))
    return key.public_key().public_bytes_raw().hex()


def test_a_base_that_looks_like_an_option_never_reaches_git(tmp_path):
    with pytest.raises(ValueError, match="not an option"):
        _review_run.context(tmp_path, f"--output={(tmp_path / 'x').as_posix()}", None)
    assert not (tmp_path / "x").exists()


def test_a_finding_signed_for_another_review_fails_under_this_one():
    record = _signed("billing")
    rows = _review_run.verify_all([record, "junk"], [_hex()], "auth")
    assert rows[0]["state"] == "failed" and rows[0]["code"] == "review-finding.wrong-review"
    assert rows[1]["state"] == "failed" and rows[1]["finding_id"] is None
    assert _review_run.verify_all([record], [_hex()], "billing")[0]["state"] == "verified"


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_the_code_map_never_follows_a_symlink_out_of_the_tree(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("def leaked_name():\n    pass\n", "utf-8")
    root = tmp_path / "w"
    root.mkdir()
    (root / "ok.py").write_text("def fine():\n    pass\n", "utf-8")
    os.symlink(outside / "secret.py", root / "link.py")
    found = _code_graph.build(Path(root))
    names = {s["name"] for f in found["files"] for s in f["symbols"]}
    assert "fine" in names and "leaked_name" not in names
