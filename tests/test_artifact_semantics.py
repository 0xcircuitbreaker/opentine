"""Adversarial regressions for portable v1/v2 artifact semantics."""

from __future__ import annotations

import hashlib
import json
import zlib
from pathlib import Path

import pytest

import opentine.signing as signing
from opentine import Run, StepKind
from opentine._canon import _integrity_digest
from opentine.kernel import KernelError, ObjectEnvelope, verify_object
from opentine.repository import Repo
from opentine.repository.pack import MAGIC, inspect_pack


def _artifact(path: Path) -> dict:
    run = Run(id="artifact-shapes")
    run.add_step(StepKind.think, {"index": 1})
    run.add_step(StepKind.think, {"index": 2})
    run.save(path)
    return json.loads(path.read_text(encoding="utf-8"))


def _write_valid_digest(path: Path, data: dict) -> None:
    data["metadata"]["integrity"]["digest"] = _integrity_digest(data)
    path.write_text(json.dumps(data), encoding="utf-8")


@pytest.mark.parametrize("version", [True, 2.0])
def test_artifact_version_requires_an_exact_integer(tmp_path: Path, version: object):
    path = tmp_path / "bad-version.tine"
    data = _artifact(path)
    data["format_version"] = version
    _write_valid_digest(path, data)

    assert not Run.verify_integrity(path).ok
    with pytest.raises(ValueError, match="Unsupported .tine format_version"):
        Run.load(path)
    with pytest.raises(ValueError, match="requires a .tine v2 source"):
        Repo.init(tmp_path / "repo").migrate_v2(path)


def test_artifact_graph_order_cannot_silently_omit_steps(tmp_path: Path):
    path = tmp_path / "missing-order-entry.tine"
    data = _artifact(path)
    data["graph"]["order"].pop()
    _write_valid_digest(path, data)

    assert Run.verify_integrity(path).ok
    with pytest.raises(ValueError, match="contain every stored step exactly once"):
        Run.load(path)
    with pytest.raises(ValueError, match="contain every stored step exactly once"):
        Repo.init(tmp_path / "repo").migrate_v2(path)


def test_artifact_graph_rejects_mismatched_ids_and_parent_shapes(tmp_path: Path):
    path = tmp_path / "bad-step.tine"
    data = _artifact(path)
    step_id = data["graph"]["order"][0]
    data["graph"]["steps"][step_id]["id"] = "0" * 64
    _write_valid_digest(path, data)
    with pytest.raises(ValueError, match="key and embedded ID differ"):
        Run.load(path)

    data = _artifact(path)
    step_id = data["graph"]["order"][0]
    data["graph"]["steps"][step_id]["parent_ids"] = step_id
    _write_valid_digest(path, data)
    with pytest.raises(ValueError, match="parent_ids must be a list of strings"):
        Run.load(path)


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("manifest", [["model", {"name": "x"}]], "manifest must be an object"),
        ("refs", [["main", "missing"]], "refs must be an object"),
        ("transcript", {"role": "user"}, "transcript must be a list"),
    ],
)
def test_artifact_top_level_collections_are_not_reinterpreted(
    tmp_path: Path, field: str, value: object, reason: str
):
    path = tmp_path / "bad-shape.tine"
    data = _artifact(path)
    data[field] = value
    _write_valid_digest(path, data)
    with pytest.raises(ValueError, match=reason):
        Run.load(path)


def test_artifact_refs_cannot_silently_disappear_during_v3_migration(tmp_path: Path):
    path = tmp_path / "dangling-ref.tine"
    data = _artifact(path)
    data["refs"]["experiment"] = "f" * 64
    _write_valid_digest(path, data)

    with pytest.raises(ValueError, match="refs must point to stored graph steps"):
        Run.load(path)
    with pytest.raises(ValueError, match="refs must point to stored graph steps"):
        Repo.init(tmp_path / "repo").migrate_v2(path)


def test_artifact_rejects_nonfinite_timestamp_strings_and_metadata(tmp_path: Path):
    path = tmp_path / "nonfinite.tine"
    data = _artifact(path)
    step_id = data["graph"]["order"][0]
    data["graph"]["steps"][step_id]["timestamp"] = "NaN"
    _write_valid_digest(path, data)
    with pytest.raises(ValueError, match="timestamp must be a finite number"):
        Run.load(path)

    run = Run(id="metadata-nan", metadata={"measurement": float("nan")})
    with pytest.raises(ValueError, match="Out of range float values"):
        run.save(tmp_path / "metadata-nan.tine")


def test_artifact_load_rejects_non_object_root_cleanly(tmp_path: Path):
    path = tmp_path / "array.tine"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="artifact root must be an object"):
        Run.load(path)


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (
            b'{"format_version":2,"graph":{"steps":{},"steps":{}}}',
            "duplicate .tine object key",
        ),
        (b'{"format_version":2,"measurement":NaN}', "non-finite number"),
        (b'{"format_version":2,"measurement":Infinity}', "non-finite number"),
        (b'{"format_version":2,"measurement":1e10000}', "non-finite number"),
        (b'{"format_version":2,"measurement":-1e10000}', "non-finite number"),
    ],
)
def test_all_artifact_entry_points_reject_parser_differentials(
    tmp_path: Path, raw: bytes, reason: str
):
    path = tmp_path / "ambiguous.tine"
    path.write_bytes(raw)

    with pytest.raises(ValueError, match=reason):
        Run.load(path)
    integrity = Run.verify_integrity(path)
    signature = Run.verify_signature(path, trust_embedded=True)
    assert not integrity.ok and reason in integrity.reason
    assert not signature.ok and signature.state == "error" and reason in signature.reason
    with pytest.raises(ValueError, match=reason):
        Repo.init(tmp_path / "repo").migrate_v2(path)


def test_deep_artifact_nesting_has_a_stable_fail_closed_error(tmp_path: Path):
    path = tmp_path / "deep.tine"
    path.write_text("[" * 20_000 + "]" * 20_000, encoding="ascii")
    with pytest.raises(ValueError, match="nesting exceeds the parser limit"):
        Run.load(path)
    result = Run.verify_integrity(path)
    assert not result.ok and "nesting exceeds the parser limit" in result.reason


def test_portable_artifacts_refuse_non_utf8_json_encodings(tmp_path: Path):
    path = tmp_path / "utf16.tine"
    path.write_bytes('{"format_version":2}'.encode("utf-16le"))
    with pytest.raises(ValueError, match="must use UTF-8 JSON"):
        Run.load(path)


def test_artifact_integer_parsing_has_a_cross_version_digit_bound(tmp_path: Path):
    path = tmp_path / "huge-int.tine"
    path.write_bytes(b'{"format_version":2,"value":' + b"1" * 5_000 + b"}")
    with pytest.raises(ValueError, match="integer.*exceeds the parser limit"):
        Run.load(path)


def test_kernel_verification_never_skips_a_supplied_empty_oid():
    stored = ObjectEnvelope.create("annotation", {"value": "x"}).encode()
    with pytest.raises(KernelError, match="object id mismatch"):
        verify_object(stored, "")


@pytest.mark.parametrize(
    "body",
    [
        b'{"objects":[],"shallow":[],"version":' + b"1" * 10_000 + b"}",
        b'{"objects":[],"shallow":[],"version":"\xff"}',
    ],
)
def test_pack_manifest_parser_errors_are_kernel_errors(body: bytes):
    packed = MAGIC + hashlib.sha256(body).digest() + zlib.compress(body)
    with pytest.raises(KernelError, match="invalid pack manifest"):
        inspect_pack(packed)


def test_signature_lengths_are_checked_before_hex_conversion(monkeypatch):
    data = {
        "metadata": {
            "integrity": {
                "signature": {
                    "alg": "hmac-sha256",
                    "scheme": signing.SCHEME,
                    "value": "a" * 1_000_000,
                }
            }
        }
    }

    def guarded_hex(value: object) -> bool:
        assert isinstance(value, str) and len(value) <= 128
        return True

    monkeypatch.setattr(signing, "_is_hex", guarded_hex)
    result = signing.verify_artifact(data, hmac_key=b"x" * 32)
    assert not result.ok and result.state == "error"


def test_v3_compatibility_loader_does_not_collapse_ambiguous_json_blobs(tmp_path: Path):
    repo = Repo.init(tmp_path / "repo")
    ambiguous = repo.put("blob", b'{"value":1,"value":2}', redact=False)
    event = repo.put(
        "event",
        {
            "causal_ids": [],
            "input_blob": ambiguous,
            "output_blob": ambiguous,
            "parent_ids": [],
        },
    )
    run_id = repo.put(
        "run",
        {"events": [event], "manifests": {}, "roots": [event], "tips": [event]},
    )

    with pytest.raises(ValueError, match="must be a canonical object"):
        repo.load_run(run_id)
