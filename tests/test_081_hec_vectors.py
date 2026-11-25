"""0.81: the HEC1 decoder answers every shipped vector exactly.

``tests/vectors/tinepack6`` holds the ``opentine-1`` decode vectors: each names
a pack, a want-set and limits, and expects either the sha256 of the decoded
output or one reason code. The reason codes must be the published list.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from opentine import _hec
from opentine._hec._backend import zstd_available
from opentine._hec._core import uv

ROOT = Path(__file__).resolve().parent / "vectors" / "tinepack6"
MANIFEST = json.loads((ROOT / "manifest.json").read_text("utf-8"))
VECTORS = MANIFEST["vectors"]


def _limits(values: dict) -> _hec.Limits:
    limits = _hec.Limits()
    for key, value in values.items():
        assert hasattr(limits, key), key
        setattr(limits, key, value)
    return limits


def _want(spec: dict):
    table = MANIFEST["wants"][spec["ids"]]
    ids = (
        {x.encode("ascii") for x in table["ascii"]}
        if "ascii" in table
        else {bytes.fromhex(x) for x in table["hex"]}
    )
    return _hec.Closure(ids) if spec["kind"] == "closure" else ids


def run(vector: dict) -> dict:
    pack = (ROOT / vector["pack"]).read_bytes()
    limits = _limits(MANIFEST["limits"][vector["limits"]])
    try:
        decoded = _hec.decode(pack, _hec.OPENTINE, _want(vector["want"]), limits)
    except _hec.HecError as exc:
        return {"code": exc.code, "ok": False}
    out = []
    for o in decoded.objects:
        for part in (o.id, o.type.desc, o.body):
            out += [uv(len(part)), part]
    out += [uv(len(decoded.aux)), decoded.aux]
    return {"ok": True, "sha256": hashlib.sha256(b"".join(out)).hexdigest()}


def test_the_manifest_is_modest_and_names_only_published_codes():
    assert MANIFEST["grammar"] == "opentine-1" and MANIFEST["body"] == "HEC1"
    assert MANIFEST["counts"]["vectors"] == len(VECTORS) >= 600
    assert set(MANIFEST["reject_codes"]) <= set(_hec.REASON_CODES)
    size = sum(p.stat().st_size for p in ROOT.rglob("*") if p.is_file())
    assert size < 5 * 1024 * 1024
    packs = {v["pack"] for v in VECTORS}
    assert packs == {f"packs/{p.name}" for p in (ROOT / "packs").glob("*.hec")}
    for name in packs:  # named by content: a vector cannot drift silently
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == name[6:-4]


@pytest.mark.skipif(not zstd_available(), reason="most vectors carry zstd streams")
@pytest.mark.parametrize("chunk", range(8))
def test_every_vector_decodes_to_its_expected_answer(chunk):
    wrong = []
    for index in range(chunk, len(VECTORS), 8):
        vector = VECTORS[index]
        got = run(vector)
        if got != vector["expect"]:
            wrong.append(f"{index} {vector['name']}: {got} != {vector['expect']}")
    assert wrong == []


def test_both_verdicts_and_every_reason_code_family_are_exercised():
    codes = {v["expect"].get("code") for v in VECTORS} - {None}
    assert {"budget", "size-mismatch", "want-mismatch", "derive", "truncated"} <= codes
    assert sum(v["expect"]["ok"] for v in VECTORS) >= 300
