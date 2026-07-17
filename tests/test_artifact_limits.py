"""Resource-limit regressions for portable compatibility artifacts."""

from pathlib import Path

import pytest

from opentine import Run, _artifact_io


def test_portable_artifact_reads_are_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    artifact = tmp_path / "oversized.tine"
    artifact.write_bytes(b"{" + b" " * 64 + b"}")
    monkeypatch.setattr(_artifact_io, "MAX_TINE_ARTIFACT_BYTES", 32)

    with pytest.raises(ValueError, match="size limit"):
        Run.load(artifact)
    assert not Run.verify_integrity(artifact).ok
    assert "size limit" in Run.verify_integrity(artifact).reason
    signature = Run.verify_signature(artifact, trust_embedded=True)
    assert not signature.ok
    assert "size limit" in signature.reason
