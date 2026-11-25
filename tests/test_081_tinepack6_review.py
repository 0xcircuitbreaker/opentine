"""0.81 review: holes found attacking TINEPACK6 integrity and compatibility.

Each test failed before its fix on ``feat/hec-packs-review-integrity``.
"""

from __future__ import annotations

import re

import pytest

from opentine import _codec, _hec, _redacted_derive
from opentine.repository import Repo
from tests.test_046_redacted_public import KEY, _run

pytestmark = pytest.mark.skipif(not _codec.available("zstd"), reason="TINEPACK6 needs zstd")


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "off")


def test_a_redacted_public_bundle_never_silently_drops_the_asked_pack_format(tmp_path):
    # `bundle create --redacted-public` now accepts --pack-format TINEPACK6, and the
    # signed record names the pack's sha256: it must refuse, not write TINEPACK3.
    repo = Repo.init(tmp_path / "s")
    run = _run(repo)
    with pytest.raises(ValueError, match="TINEPACK6"):
        _redacted_derive.public_bundle(
            repo, "heads/main", run, KEY, algorithm="hmac-sha256", pack_format="TINEPACK6"
        )
    data = _redacted_derive.public_bundle(
        repo, "heads/main", run, KEY, algorithm="hmac-sha256", pack_format="TINEPACK5"
    )
    assert b"TINEPACK5\0" in data


_LOCAL = re.compile(rb"/tmp/claude|scratchpad|/home/user|venv0\d")


@pytest.mark.parametrize("chunk", range(4))
def test_the_shipped_hec_vectors_carry_no_local_paths_or_working_labels(chunk):
    # Three accepted vectors decoded to blobs holding a build machine's temporary
    # paths, and vector names carried working labels; vectors ship neutral data.
    from tests.test_081_hec_vectors import MANIFEST, ROOT, VECTORS, _limits, _want

    leaked = []
    for vector in VECTORS[chunk::4]:
        assert re.fullmatch(r"(accept|reject-[a-z-]+)-\d{4}", vector["name"]), vector["name"]
        if not vector["expect"]["ok"]:
            continue
        pack = (ROOT / vector["pack"]).read_bytes()
        limits = _limits(MANIFEST["limits"][vector["limits"]])
        for o in _hec.decode(pack, _hec.OPENTINE, _want(vector["want"]), limits).objects:
            if _LOCAL.search(o.body):
                leaked.append(vector["name"])
    assert leaked == []
