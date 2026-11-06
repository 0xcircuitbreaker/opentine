"""0.40.0: ``.tine`` v5, text blobs as JSON strings (SPEC Part 10).

v5 re-spells a v4 document; it never re-addresses one. Every fixture written as
v4 and re-spelled as v5 reads back to the same canonical v4 bytes, so its root,
every oid and every ``tine-sig/3`` block are unchanged. v4 stays the default
writer; v5 is written only under ``--format 5`` / ``OPENTINE_FORMAT=5``.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind
from opentine._artifact_io import parse_artifact_json, read_artifact_bytes
from opentine._artifact_v4 import _entry, _envelope, write_v4
from opentine._artifact_v4_read import read_v4, verify_v4
from opentine._artifact_v4_repo import install_v4
from opentine._evidence_export import archival_bytes
from opentine._format_v4 import FORMAT_ENV, format_arg, write_format, writer_format
from opentine._graph_serde import verify_integrity
from opentine._pyz_build import build_bytes
from opentine._signing_v4 import append_signature, verify_artifact_v4
from opentine._tine_v5 import ARTIFACT_V5_KIND, is_v5_artifact, to_v4, to_v5
from opentine.kernel import ObjectEnvelope, canonical_json

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = sorted((ROOT / "tests" / "fixtures").rglob("*.tine"))
KEY = b"k" * 32
AT = "2026-11-01T00:00:00Z"


def _v5_bytes(v4: bytes) -> bytes:
    return canonical_json(to_v5(json.loads(v4)))


def _run(name: str = "v5") -> Run:
    run = Run(id=name, model_info="mock-model", user_prompt="p")
    run.add_step(StepKind.think, {"text": "line one\r\nline two\n" * 40})
    run.add_step(StepKind.done, {"text": "done é\U0001f600"})
    run.status = RunStatus.completed
    return run


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: str(p.relative_to(ROOT / "tests")))
def test_every_fixture_round_trips_through_v5_with_identical_bytes(path):
    v4 = write_v4(Run.load(path))
    v5 = _v5_bytes(v4)
    document = json.loads(v5)
    assert is_v5_artifact(document) and len(v5) <= len(v4)
    assert canonical_json(parse_artifact_json(v5)) == v4  # the very same v4 document
    assert set(document["objects"]) == set(json.loads(v4)["objects"])
    assert read_v4(v5)._v4_origin["root"] == json.loads(v4)["root"]
    assert verify_v4(document).ok


def test_signatures_carry_over_unchanged_and_still_verify():
    v4 = json.loads(write_v4(_run()))
    signed = json.loads(append_signature(v4, KEY, key_id="k", signer="ci", signed_at=AT))
    v5 = to_v5(signed)
    assert v5["signatures"] == signed["signatures"] and v5["root"] == signed["root"]
    result = verify_artifact_v4(v5, hmac_key=KEY)
    assert result.ok and result.state == "verified"
    assert verify_artifact_v4(parse_artifact_json(canonical_json(v5)), hmac_key=KEY).ok


def test_format_5_writes_v5_and_the_default_is_still_v4(tmp_path, monkeypatch):
    monkeypatch.delenv(FORMAT_ENV, raising=False)
    assert writer_format() == 4 and format_arg("5") == 5
    run = _run()
    run.save(tmp_path / "default.tine")
    assert json.loads(read_artifact_bytes(tmp_path / "default.tine"))["kind"] == "tine-artifact/4"
    with write_format(5):
        run.save(tmp_path / "flag.tine", sign_key=KEY, key_id="k", signed_at=AT)
    monkeypatch.setenv(FORMAT_ENV, "5")
    run.save(tmp_path / "env.tine")
    for name in ("flag", "env"):
        raw = read_artifact_bytes(tmp_path / f"{name}.tine")
        assert json.loads(raw)["kind"] == ARTIFACT_V5_KIND
        assert verify_integrity(tmp_path / f"{name}.tine").ok
    monkeypatch.delenv(FORMAT_ENV)
    run.save(tmp_path / "plain.tine", sign_key=KEY, key_id="k", signed_at=AT)
    flag = json.loads(read_artifact_bytes(tmp_path / "flag.tine"))
    plain = json.loads(read_artifact_bytes(tmp_path / "plain.tine"))
    assert flag["root"] == plain["root"] and flag["signatures"] == plain["signatures"]
    assert canonical_json(to_v4(flag)) == canonical_json(plain)
    loaded = Run.load(tmp_path / "flag.tine")
    assert [s.inputs for s in loaded.steps] == [
        s.inputs for s in Run.load(tmp_path / "plain.tine").steps
    ]


@pytest.mark.parametrize(
    ("body", "text"),
    [
        (b"", True),
        (b"plain ascii", True),
        (b"crlf\r\nand lf\nand cr\r", True),
        (b"nul\x00inside", True),
        ("﻿bom   \U0001f600 é".encode(), True),
        (b"\xff\xfe not utf-8", False),
        (b"\xed\xa0\x80 encoded lone surrogate", False),
        (b"\xc0\xaf overlong slash", False),
        (b"\xf4\x90\x80\x80 beyond U+10FFFF", False),
        (b"truncated \xe2\x82", False),
    ],
)
def test_text_and_binary_blobs_keep_their_oid(body, text):
    envelope = ObjectEnvelope.create("blob", body, 1)
    v4_entry = _entry(envelope)
    doc = {"format_version": 4, "kind": "tine-artifact/4", "objects": {envelope.oid: v4_entry}}
    v5_entry = to_v5(doc)["objects"][envelope.oid]
    assert v5_entry["encoding"] == ("text" if text else "raw")
    if text:
        assert set(v5_entry) == {"encoding", "schema", "text", "type"}
        assert v5_entry["text"].encode("utf-8") == body
    wire = parse_artifact_json(canonical_json(to_v5(doc)))  # through the real parser
    rebuilt = _envelope(wire["objects"][envelope.oid], envelope.oid, "blob")
    assert rebuilt.oid == envelope.oid and rebuilt.body == body


def _v5_doc(**objects) -> dict:
    return {"format_version": 5, "kind": ARTIFACT_V5_KIND, "objects": objects}


@pytest.mark.parametrize(
    "entry",
    [
        {"encoding": "raw", "schema": 1, "type": "blob", "data": base64.b64encode(b"hi").decode()},
        {"encoding": "text", "schema": 1, "type": "event", "text": "{}"},
        {"encoding": "text", "schema": 1, "type": "blob", "text": "x", "data": "eA=="},
        {"encoding": "text", "schema": 1, "type": "blob", "text": 7},
        {"encoding": "text", "schema": 1, "type": "blob", "text": "lone \ud800"},
    ],
    ids=["utf8-as-base64", "text-event", "extra-key", "not-a-string", "lone-surrogate"],
)
def test_non_v5_spellings_are_refused(entry):
    with pytest.raises(ValueError):
        to_v4(_v5_doc(**{"blob:sha256:" + "0" * 64: entry}))


def test_a_lone_surrogate_escape_is_refused_by_the_parser():
    raw = b'{"format_version":5,"kind":"tine-artifact/5","objects":{"b":{"encoding":"text",'
    raw += b'"schema":1,"text":"\\ud800","type":"blob"}}}'
    with pytest.raises(ValueError):
        parse_artifact_json(raw)


def _first_text(document: dict) -> str:
    return next(o for o, e in document["objects"].items() if e["encoding"] == "text")


def test_tampering_with_a_text_blob_is_detected(tmp_path):
    v4 = json.loads(write_v4(_run()))
    signed = to_v5(json.loads(append_signature(v4, KEY, key_id="k", signed_at=AT)))
    oid = _first_text(signed)
    entry = signed["objects"][oid]
    edited = {
        **signed,
        "objects": {**signed["objects"], oid: {**entry, "text": entry["text"] + " "}},
    }
    assert not verify_v4(edited).ok
    assert verify_artifact_v4(edited, hmac_key=KEY).state == "mismatch"
    (tmp_path / "t.tine").write_bytes(canonical_json(edited))
    assert not verify_integrity(tmp_path / "t.tine").ok
    respelled = {**entry, "encoding": "raw", "data": base64.b64encode(b"x").decode()}
    respelled.pop("text")
    bad = {**signed, "objects": {**signed["objects"], oid: respelled}}
    (tmp_path / "r.tine").write_bytes(canonical_json(bad))
    assert not verify_integrity(tmp_path / "r.tine").ok
    stamped = {**signed, "format_version": 4}  # a v5 body under a v4 version is not v4
    assert not verify_v4(stamped).ok


def test_a_v5_file_installs_into_a_repository(tmp_path):
    from opentine.repo import Repo

    v5 = _v5_bytes(write_v4(_run()))
    repo = Repo.init(tmp_path / "repo")
    result = install_v4(repo, parse_artifact_json(v5), ref="heads/main")
    assert result["root"] == json.loads(v5)["root"]
    assert repo.load_run("heads/main").steps[-1].inputs == {"text": "done é\U0001f600"}


def test_the_offline_pyz_verifies_a_v5_file(tmp_path):
    (tmp_path / "tine-verify.pyz").write_bytes(build_bytes())
    good = _v5_bytes(write_v4(_run()))
    document = json.loads(good)
    oid = _first_text(document)
    entry = document["objects"][oid]
    document["objects"][oid] = {**entry, "text": entry["text"] + "!"}
    (tmp_path / "good.tine").write_bytes(archival_bytes(good))
    (tmp_path / "bad.tine").write_bytes(archival_bytes(canonical_json(document)))
    verdicts = {}
    for name in ("good", "bad"):
        done = subprocess.run(
            [sys.executable, "-I", "-S", "tine-verify.pyz", f"{name}.tine"],
            capture_output=True, text=True, timeout=60, cwd=tmp_path,
        )  # fmt: skip
        verdicts[name] = json.loads(done.stdout)
    assert verdicts["good"]["verdict"] == "pass"
    assert verdicts["good"]["checks"][0]["detail"] == f"root {json.loads(good)['root']}"
    assert verdicts["bad"]["verdict"] == "fail"
