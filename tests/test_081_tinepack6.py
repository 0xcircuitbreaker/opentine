"""0.81 TINEPACK6: the HEC transfer pack, its negotiation, budgets and bundles."""

from __future__ import annotations

import hashlib
import json
import os
import random

import pytest

from opentine import _bundle, _codec
from opentine.kernel import KernelError, canonical_json
from opentine.repository import Repo, _pack4, _pack5, _pack6, _pack6_build, _pack_peer
from opentine.repository import client as repository_client
from opentine.repository.pack import inspect_pack
from tests.test_037_tinepack5 import _record, _repo
from tests.test_remote_0_12 import URL, _remote

pytestmark = pytest.mark.skipif(not _codec.available("zstd"), reason="TINEPACK6 needs zstd")


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "home" / ".config"))
    monkeypatch.setenv("OPENTINE_AUTO_PACK", "off")
    monkeypatch.delenv(_pack6.OPT_IN_ENV, raising=False)


def _mixed(tmp_path) -> Repo:
    """Runs plus binary and sealed-looking blobs, which HEC cannot see into."""
    repo = _repo(tmp_path, runs=2)
    rng = random.Random(81)
    for index in range(4):
        repo.put("blob", bytes(rng.randrange(256) for _ in range(20_000)), redact=False)
        repo.put("blob", b"TINEAES6" + os.urandom(2_000) + b"%d" % index, redact=False)
    return repo


def _payload(header: dict, rest: bytes) -> bytes:
    raw = canonical_json(header)
    payload = _codec._uvarint(len(raw)) + raw + rest
    return _pack6.MAGIC6 + hashlib.sha256(payload).digest() + payload


def test_v6_carries_the_same_objects_as_v3_and_installs(tmp_path):
    repo = _mixed(tmp_path)
    v3 = repo.pack()
    v6 = _pack6_build.from_v3(v3)
    assert v6.startswith(_pack6.MAGIC6)
    old, new = inspect_pack(v3), inspect_pack(v6)
    assert old[1] == new[1] and old[2] == new[2]
    assert new[0] == "sha256:" + hashlib.sha256(v6[42:]).hexdigest()
    clone = Repo.init(tmp_path / "clone")
    clone.import_pack(v6)
    assert clone.fsck().ok and all(clone.has(oid) for oid, _ in new[1])


def test_every_candidate_decodes_and_the_smallest_is_kept(tmp_path):
    repo = _mixed(tmp_path)
    _, objects, shallow = inspect_pack(repo.pack())
    found = _pack6_build.candidates(objects, shallow)
    assert set(found) == {"hec", "split", "plain"}
    for data in found.values():
        assert inspect_pack(data)[1] == sorted(objects)
    assert _pack6_build.build(objects, shallow) == min(found.values(), key=len)
    assert len(found["split"]) < len(found["hec"])  # binary bodies go to zstd
    sealed = [raw for _, raw in objects if b"\nTINEAES6" in raw]
    assert sealed and all(_pack6_build.opaque(raw) for raw in sealed)


@pytest.mark.parametrize("runs", [1, 3])
def test_v6_is_never_larger_than_v5_by_more_than_its_frame(tmp_path, runs):
    repo = _repo(tmp_path, runs=runs)
    _, objects, shallow = inspect_pack(repo.pack())
    v5, v6 = _pack5.build(objects, shallow), _pack6_build.build(objects, shallow)
    assert len(v6) <= len(v5) + 256
    binary = _mixed(tmp_path / "b")
    _, objects, shallow = inspect_pack(binary.pack())
    assert len(_pack6_build.build(objects, shallow)) <= len(_pack5.build(objects, shallow)) + 256


def test_text_runs_come_out_far_smaller_than_v5(tmp_path):
    repo = _repo(tmp_path, runs=4)
    _, objects, shallow = inspect_pack(repo.pack())
    assert len(_pack6_build.build(objects, shallow)) * 2 < len(_pack5.build(objects, shallow))


def test_tampered_or_inconsistent_v6_packs_are_refused(tmp_path):
    v6 = _pack6_build.from_v3(_repo(tmp_path, runs=1).pack())
    with pytest.raises(KernelError, match="checksum"):
        inspect_pack(v6[:-1] + bytes([v6[-1] ^ 1]))
    length, start = _codec._read_uvarint(v6[42:], 0)
    header = json.loads(v6[42 + start : 42 + start + length])
    body = v6[42 + start + length :]
    for change in ({"hec": "HECS"}, {"grammar": "git-sha1"}, {"version": 2}, {"extra": 1}):
        with pytest.raises(KernelError):
            inspect_pack(_payload(header | change, body))
    with pytest.raises(KernelError, match="does not match"):
        inspect_pack(_payload(header | {"hec_bytes": header["hec_bytes"] - 1}, body))
    from opentine.repository._packs import oid_of

    for at in range(0, header["hec_bytes"], max(1, header["hec_bytes"] // 64)):
        hec = bytearray(body)
        hec[at] ^= 0x10
        try:  # pack bytes are malleable: a flip is refused, or every id is still recomputed
            got = inspect_pack(_payload(header, bytes(hec)))[1]
        except KernelError:
            continue
        assert all(oid == oid_of(raw) for oid, raw in got)


def test_hec_refusals_carry_their_reason_code(tmp_path):
    v6 = _pack6_build.from_v3(_repo(tmp_path, runs=1).pack())
    with pytest.raises(_pack6.Pack6Error) as info:
        inspect_pack(v6, max_body=100)
    assert info.value.code == "budget" and "budget" in str(info.value)


def test_the_server_decodes_with_its_own_smaller_budget(tmp_path, monkeypatch):
    v6 = _pack6_build.from_v3(_repo(tmp_path, runs=1).pack())
    inspect_pack(v6)  # the CLI budget (256 MiB) takes it
    monkeypatch.setattr(_pack6, "SERVE_MAX_OUTPUT", 1000)
    with pytest.raises(_pack6.Pack6Error) as info:
        inspect_pack(v6, serve=True)
    assert info.value.code == "budget"
    assert _pack6.SERVE_DECODES == 2 and _pack6._SERVE_SLOTS._value == 2  # slots released


def test_a_plain_section_over_the_budget_is_refused_before_inflating(tmp_path):
    repo = _mixed(tmp_path)
    _, objects, shallow = inspect_pack(repo.pack())
    split = _pack6_build.candidates(objects, shallow)["split"]
    with pytest.raises(_pack6.Pack6Error) as info:
        inspect_pack(split, max_body=50_000)
    assert info.value.code == "budget"


# --- negotiation ------------------------------------------------------------ #


def test_v6_is_listed_and_chosen_only_when_opted_in_on_both_ends(monkeypatch):
    assert "TINEPACK6" not in _pack_peer.local_formats()
    offered = ["TINEPACK6", "TINEPACK5", "TINEPACK4", "TINEPACK3"]
    assert _pack_peer.choose(offered, ["zstd"]) == (_pack5.V5, None)  # not opted in here
    monkeypatch.setenv(_pack6.OPT_IN_ENV, "1")
    assert _pack_peer.local_formats()[0] == "TINEPACK6"
    assert _pack_peer.choose(offered, ["zstd"]) == (_pack6.V6, None)
    assert _pack_peer.choose(offered[1:], ["zstd"]) == (_pack5.V5, None)  # peer did not list it


def test_opted_in_client_and_server_round_trip_in_v6(tmp_path, monkeypatch):
    monkeypatch.setenv(_pack6.OPT_IN_ENV, "1")
    service, _, seen = _remote(tmp_path, monkeypatch)
    assert service.capabilities()["pack_formats"][0] == "TINEPACK6"
    origin = _repo(tmp_path)
    repository_client.push(origin, URL, ref="heads/r1")
    assert any(r.content.startswith(_pack6.MAGIC6) for r in seen)  # the pushed pack
    clone = Repo.init(tmp_path / "clone")
    repository_client.fetch(clone, URL, ref="heads/r1")
    assert clone.has(origin.read_ref("heads/r1")) and clone.fsck().ok


def test_without_opt_in_the_wire_stays_v5(tmp_path, monkeypatch):
    service, _, seen = _remote(tmp_path, monkeypatch)
    assert "TINEPACK6" not in service.capabilities()["pack_formats"]
    origin = _repo(tmp_path, runs=1)
    _record(origin, "heads/extra", steps=2)
    repository_client.push(origin, URL, ref="heads/r0")
    assert not any(r.content.startswith(_pack6.MAGIC6) for r in seen)


# --- bundles ---------------------------------------------------------------- #


def test_bundles_stay_v3_and_carry_v6_only_when_asked(tmp_path):
    repo = _mixed(tmp_path)
    default = _bundle.verify(_bundle.create(repo, ["heads/r0"]))
    v6 = _bundle.verify(_bundle.create(repo, ["heads/r0"], pack_format="TINEPACK6"))
    assert v6.pack.startswith(_pack6.MAGIC6) and v6.objects == default.objects
    assert len(v6.pack) < len(default.pack)
    clone = Repo.init(tmp_path / "clone")
    _bundle.unbundle(clone, _bundle.create(repo, ["heads/r0"], pack_format="TINEPACK6"), "b")
    assert clone.fsck().ok
    assert _pack4.V3 == "TINEPACK3"


# --- the TS verifier's refusal (parity fixture) ------------------------------ #


def test_the_ts_refusal_fixture_is_a_v6_pack_and_bundle_python_reads():
    """The fixture is written by ``scripts/gen_tinepack6_ts_fixture.py``."""
    root = os.path.join(os.path.dirname(__file__), "vectors", "tinepack6", "ts-refusal.json")
    with open(root, encoding="utf-8") as handle:
        fixture = json.load(handle)
    pack, bundle = bytes.fromhex(fixture["pack_hex"]), bytes.fromhex(fixture["bundle_hex"])
    assert pack.startswith(_pack6.MAGIC6)
    pack_id, objects, _ = inspect_pack(pack)
    assert pack_id == fixture["python"]["pack_id"]
    assert [oid for oid, _ in objects] == fixture["python"]["objects"]
    assert _bundle.verify(bundle).pack == pack
    message = "unsupported pack format TINEPACK6"
    assert fixture["ts"]["pack"] == {"code": "pack.version-unsupported", "message": message}
    assert fixture["ts"]["bundle"]["code"] == "bundle.pack-invalid:pack.version-unsupported"
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "..", "ts", "verifier", "src", "pack.ts"), encoding="utf-8") as f:
        source = f.read()
    assert f'fail("{message}", "pack.version-unsupported")' in source
