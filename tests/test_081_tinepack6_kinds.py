"""0.81: every object kind the repository can hold survives v3 -> TINEPACK6 -> objects.

The object sources are the ones the suite already has: the golden compat
repositories of every release since 0.9 (old stored forms, legacy step ids),
the conformance vector packs, a repository holding every record kind a loop
writes, and binary and sealed-looking blobs. Every pack round-trips byte- and
id-identical through each TINEPACK6 candidate (all-HEC, split, plain).
"""

from __future__ import annotations

import base64
import json
import shutil
from pathlib import Path

import pytest

from opentine import _codec
from opentine.kernel import KernelError
from opentine.repository import Repo, _pack6_build
from opentine.repository._packs import oid_of
from opentine.repository.pack import create_pack, inspect_pack

pytestmark = pytest.mark.skipif(not _codec.available("zstd"), reason="TINEPACK6 needs zstd")
ROOT = Path(__file__).resolve().parents[1]
COMPAT = sorted(p for p in (ROOT / "tests" / "fixtures" / "compat").glob("v*/repo") if p.is_dir())


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "off")


def _round_trip(objects: list[tuple[str, bytes]], shallow: list[str]) -> set[str]:
    kinds = set()
    for name, data in _pack6_build.candidates(objects, shallow).items():
        _, got, boundary = inspect_pack(data)
        assert got == sorted(objects), name
        assert boundary == sorted(shallow), name
        assert all(oid_of(raw) == oid for oid, raw in got), name
    for oid, raw in objects:
        kinds.add(oid.split(":", 1)[0])
        kinds.add(raw.split(b"\n", 1)[0].decode())
    return kinds


@pytest.mark.parametrize("fixture", COMPAT, ids=[p.parent.name for p in COMPAT])
def test_every_golden_compat_repository_round_trips(fixture, tmp_path):
    shutil.copytree(fixture, tmp_path / "repo")
    try:
        repo = Repo.open(tmp_path / "repo")
        oids = repo.iter_oids()
    except (KernelError, ValueError) as exc:  # a layout this release only migrates
        pytest.skip(f"not openable in place: {exc}")
    assert oids
    data = create_pack(repo, oids)
    _, objects, shallow = inspect_pack(data)
    assert _round_trip(objects, shallow)


def test_enough_compat_releases_are_covered():
    assert len(COMPAT) >= 20


def _vector_packs() -> list[bytes]:
    out = []
    for path in sorted((ROOT / "docs" / "conformance" / "vectors").glob("*.json")):
        for case in json.loads(path.read_text("utf-8")).get("cases", []):
            given = case.get("input") or {}
            if case.get("op") not in ("pack.inspect", "pack.install"):
                continue
            if "bytes_b64" in given:
                out.append(base64.b64decode(given["bytes_b64"]))
            elif "blob" in given:
                out.append((ROOT / "docs" / "conformance" / given["blob"]).read_bytes())
    return out


def test_every_readable_conformance_pack_round_trips():
    done = 0
    for data in _vector_packs():
        try:
            _, objects, shallow = inspect_pack(data)
        except (KernelError, ValueError):
            continue
        if objects:
            _round_trip(objects, shallow)
            done += 1
    assert done >= 8


def test_every_record_kind_a_loop_writes_round_trips(tmp_path):
    from tests import verify_everywhere_fixture

    built = verify_everywhere_fixture.build(tmp_path)
    repo: Repo = built["repo"]
    repo.put("blob", bytes(range(256)) * 64, redact=False)
    repo.put("blob", b"TINEAES6" + bytes(range(200)), redact=False)
    _, objects, shallow = inspect_pack(create_pack(repo, repo.iter_oids()))
    kinds = _round_trip(objects, shallow)
    assert {"blob", "event", "run", "attestation", "annotation"} <= kinds
