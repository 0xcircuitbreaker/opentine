"""0.46: ``tine bundle create --redacted-public`` and the two record families in every verifier."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from opentine import _bundle, _redacted_copy, _redacted_derive, _schemas, _tombstone, cli
from opentine._cli_errors import VERIFICATION_FAILED
from opentine._pyz import _records
from opentine._pyz_build import build_bytes
from opentine._signed_record import RecordError
from opentine.graph import Run, StepKind
from opentine.policies import PolicySet
from opentine.redaction import redact_blob
from opentine.repository import Repo
from opentine.repository._purge import purge
from opentine.repository.pack import inspect_pack, reachable

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "docs" / "conformance" / "vectors"
KEY = b"ab" * 32
MARK = "internal-codename-zebra"


def _run(store: Repo) -> str:
    run = Run(id="r", model_info="m", user_prompt="p", policies=PolicySet().to_dict())
    run.add_step(StepKind.done, {"text": f"the plan for {MARK} is ready"})
    return store.put_run(run, ref="heads/main").run_id


@pytest.fixture
def stricter(monkeypatch):
    """A ruleset that learned one more secret shape after the run was stored."""

    def redact(body: bytes) -> bytes:
        return redact_blob(body).replace(MARK.encode(), b"[REDACTED]")

    monkeypatch.setattr(_redacted_derive, "redact_blob", redact)


@pytest.fixture
def store(tmp_path):
    repo = Repo.init(tmp_path / "s")
    return repo, _run(repo)


def _tine(capsys, *argv: str) -> tuple[int, str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 1
    return code, capsys.readouterr().out


def test_the_public_copy_holds_only_redacted_objects_and_a_signed_link(store, stricter, tmp_path):
    repo, run = store
    data = _redacted_derive.public_bundle(repo, "heads/main", run, KEY, algorithm="hmac-sha256")
    checked = _bundle.verify(data)
    record = checked.redacted_public
    public = checked.refs["heads/main"]
    assert record["source_run"] == run and record["public_run"] == public != run
    assert record["redacted"] > 0 and record["objects"] == checked.objects
    assert MARK.encode() not in checked.pack  # TINEPACK3 is zlib: check the objects
    _, objects, _ = inspect_pack(checked.pack)
    assert all(MARK.encode() not in raw for _, raw in objects)
    private = set(reachable(repo, [run], include_associated=True))
    assert run not in {oid for oid, _ in objects} and not private & {
        o for o, _ in objects if o.startswith("run:")
    }
    found = _redacted_copy.check(record, hmac_key=KEY, pack=record["pack"])
    assert found["state"] == "verified" and found["public_run"] == public
    target = Repo.init(tmp_path / "pub")
    _bundle.unbundle(target, data, "public")
    assert target.fsck().ok and target.load_run(public) is not None
    assert not target.has(run)


def test_no_annotation_or_attestation_reaches_the_public_copy(store, stricter):
    from opentine.repository._annotations import write_run_annotation

    repo, run = store
    note = write_run_annotation(repo, run, {"label": "private review"}, [])
    data = _redacted_derive.public_bundle(repo, "heads/main", run, KEY, algorithm="hmac-sha256")
    _, objects, _ = inspect_pack(_bundle.verify(data).pack)
    assert note not in {oid for oid, _ in objects}
    assert not any(oid.startswith(("annotation:", "attestation:")) for oid, _ in objects)


def test_nothing_to_redact_gives_the_same_run(store):
    repo, run = store
    data = _redacted_derive.public_bundle(repo, "heads/main", run, KEY, algorithm="hmac-sha256")
    record = _bundle.verify(data).redacted_public
    assert record["public_run"] == run and record["redacted"] == 0


def test_a_purged_blob_stays_a_boundary_with_its_tombstone(store, stricter):
    repo, run = store
    blob = next(oid for oid in reachable(repo, [run], include_associated=False)
                if oid.startswith("blob:") and MARK.encode() in repo.get(oid).body)  # fmt: skip
    tomb = _tombstone.sign(_tombstone.build(blob, "erasure", "alice"), KEY,
                           algorithm="hmac-sha256")  # fmt: skip
    purge(repo, tomb)
    data = _redacted_derive.public_bundle(repo, "heads/main", run, KEY, algorithm="hmac-sha256")
    checked = _bundle.verify(data)
    assert [record["oid"] for record in checked.tombstones] == [blob]


def test_a_record_moved_onto_another_pack_is_refused(store, stricter):
    repo, run = store
    data = _redacted_derive.public_bundle(repo, "heads/main", run, KEY, algorithm="hmac-sha256")
    checked = _bundle.verify(data)
    other = _bundle.create(repo, ["heads/main"])
    pack = _bundle.verify(other).pack
    forged = _bundle.assemble(
        pack, {"heads/main": run}, {"redacted_public": checked.redacted_public}
    )
    with pytest.raises(_bundle.BundleError, match="another pack"):
        _bundle.verify(forged)
    with pytest.raises(RecordError) as caught:
        _redacted_copy.check(checked.redacted_public, hmac_key=KEY, pack="sha256:" + "0" * 64)
    assert caught.value.code == "redacted-copy.pack-mismatch"


def test_cli_redacted_public_round_trip(store, stricter, tmp_path, capsys):
    repo, run = store
    key = tmp_path / "k"
    key.write_text(KEY.decode(), encoding="utf-8")
    out = tmp_path / "public.bundle"
    code, _ = _tine(capsys, "bundle", "create", str(out), "heads/main", "--redacted-public",
                    "--repo", str(repo.path))  # fmt: skip
    assert code != 0  # the record is signed: no key, no copy
    code, _ = _tine(capsys, "bundle", "create", str(out), "heads/main", "--redacted-public",
                    "--key-file", str(key), "--repo", str(repo.path))  # fmt: skip
    assert code == 0
    code, printed = _tine(capsys, "bundle", "verify", str(out), "--key-file", str(key))
    report = json.loads(printed)
    assert code == 0 and report["redacted_public"]["state"] == "verified"
    assert report["redacted_public"]["source_run"] == run
    code, printed = _tine(capsys, "bundle", "verify", str(out))
    assert code == 0 and json.loads(printed)["redacted_public"]["state"] == "unchecked"
    other = tmp_path / "other"
    other.write_text("cd" * 32, encoding="utf-8")
    code, printed = _tine(capsys, "bundle", "verify", str(out), "--key-file", str(other))
    assert code == VERIFICATION_FAILED
    assert json.loads(printed)["redacted_public"]["reason"] == "redacted-copy.bad-signature"
    code, _ = _tine(capsys, "bundle", "create", str(out), "--all", "--redacted-public",
                    "--key-file", str(key), "--repo", str(repo.path))  # fmt: skip
    assert code != 0  # exactly one run


# --- the two conformance families in Python and the pyz ---------------------- #


def _cases(name: str) -> list[dict]:
    return json.loads((VECTORS / name).read_text("utf-8"))["cases"]


def _keys(value: dict) -> dict:
    hmac, public = value.get("hmac_key_hex"), value.get("public_key")
    return {
        "hmac_key": bytes.fromhex(hmac) if hmac else None,
        "public_key": bytes.fromhex(public) if public else None,
    }


FAMILIES = (("61-tombstone.json", 23), ("62-redacted-copy.json", 16))


def _closure(run_closure):
    def run(value: dict) -> dict:
        import base64

        objects = {row["id"]: base64.b64decode(row["data_b64"]) for row in value["objects"]}
        return run_closure(value["run"], objects, value["tombstones"])

    return run


def _runner(verifier: str, op: str):
    """``(call(value), refusal type)`` for one conformance op in one verifier."""
    from opentine._tombstone_closure import closure

    if op == "tombstone.closure":
        found = _records.closure if verifier == "pyz" else closure
        return _closure(found), _records.Refused if verifier == "pyz" else RecordError
    field = "tombstone" if op == "tombstone.verify" else "record"
    check = _tombstone.check if field == "tombstone" else _redacted_copy.check
    found = _records.verify if verifier == "pyz" else check

    def run(value: dict) -> dict:
        keys = _keys(value)
        if field == "record":
            keys["pack"] = value.get("pack")
        return found(value[field], **keys)

    return run, _records.Refused if verifier == "pyz" else RecordError


@pytest.mark.parametrize("verifier", ["python", "pyz"])
@pytest.mark.parametrize(("family", "count"), FAMILIES)
def test_the_61_and_62_families_agree_in_python_and_the_pyz(verifier, family, count):
    """0.46 acceptance: a purged blob verifies as content-unavailable in each verifier
    (the TS verifier runs the same families in ``ts/verifier``'s conformance test)."""
    from tests.conformance import tagged

    cases = _cases(family)
    assert len(cases) == count
    for case in cases:
        value = tagged.decode(case["input"]["value"])
        run, refused = _runner(verifier, case["op"])
        if case["expect"] == "accept":
            assert run(value) == case["output"], case["id"]
        else:
            with pytest.raises(refused) as caught:
                run(value)
            assert caught.value.code == case["reason"], case["id"]
    if family.startswith("61"):
        purged = next(case for case in cases if case["id"] == "tombstone.closure.purged")
        assert purged["output"]["state"] == "content-unavailable"


def test_the_built_pyz_verifies_a_tombstone_file_offline(tmp_path):
    record = _tombstone.sign(_tombstone.build("blob:sha256:" + "1" * 64, "erasure", "alice"), KEY,
                             algorithm="hmac-sha256")  # fmt: skip
    path = tmp_path / "tombstone.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    key = tmp_path / "k"
    key.write_text(KEY.decode(), encoding="utf-8")
    pyz = tmp_path / "tine-verify.pyz"
    pyz.write_bytes(build_bytes())
    argv = [sys.executable, "-I", "-S", pyz.as_posix(), path.as_posix(), "--key-file",
            key.as_posix()]  # fmt: skip
    done = subprocess.run(argv, capture_output=True, text=True, timeout=300, cwd=tmp_path)
    result = json.loads(done.stdout)
    assert done.returncode == 0 and result["mode"] == "tombstone", done.stderr
    assert result["checks"][0]["reason"] == "tombstone.verified"
    path.write_text(json.dumps({**record, "reason": "routine"}), encoding="utf-8")
    done = subprocess.run(argv, capture_output=True, text=True, timeout=300, cwd=tmp_path)
    assert done.returncode == 1
    assert json.loads(done.stdout)["checks"][0]["reason"] == "tombstone.bad-signature"


def test_the_record_schemas_hold_the_vectors_and_detect_them():
    for name, field in (("61-tombstone.json", "tombstone"), ("62-redacted-copy.json", "record")):
        from tests.conformance import tagged

        for case in _cases(name):
            if case["expect"] != "accept" or case["op"] == "tombstone.closure":
                continue
            record = tagged.decode(case["input"]["value"])[field]
            stem, errors = _schemas.validate(record)
            assert errors == [] and stem in {"opentine-tombstone-1", "opentine-redacted-copy-1"}
