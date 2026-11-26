"""0.84: signed provenance sidecars and in-file pointers for produced artifacts.

1. ``tine provenance embed`` writes the pointer each format allows (PNG text
   chunk, JPEG comment, PDF /Info update; none for other files) and a signed
   sidecar; ``verify`` passes and the digest ignores the pointer.
2. Strip, modify and repoint are each detected with their own code.
3. The sidecar is signed by the key it names, verified only for a pinned runner
   that is not an optimizer key, and held (with the run) so it cannot be released.
4. The run must exist and verify here; a dataset version must be held.
"""

from __future__ import annotations

import json

import pytest

from opentine import _artifact_trailer as trailer
from opentine.repository._holds import HoldError, holds_path, read_holds, release
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401
from tests.provenance_fixture import _room, codes, embed, jpeg, pdf, png, tine, verify  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

FILES = {"a.png": (png, "png-text"), "a.jpg": (jpeg, "jpeg-comment"),
         "a.pdf": (pdf, "pdf-info"), "a.bin": (lambda: b"model card text\n", None)}  # fmt: skip


@pytest.mark.parametrize("name", sorted(FILES))
def test_embed_then_verify_each_format(capsys, room, name):
    make, slot = FILES[name]
    path = room["tmp"] / name
    path.write_bytes(make())
    before = trailer.digest(make())
    code, body = embed(capsys, room, path)
    assert code == 0 and body["pointer"] == slot and body["digest"] == before
    assert body["record"].startswith("attestation:")
    assert (path.read_bytes() != make()) is (slot is not None)
    assert trailer.split(path.read_bytes())[1] == ([room["run"]] if slot else [])
    code, body = verify(capsys, room, path)
    assert (code, body["ok"], body["findings"]) == (0, True, [])
    assert body["verification"] == "verified" and body["held"] is True
    assert body["digest"] == before and body["c2pa"] == "absent"


def test_embedding_twice_keeps_one_pointer_and_the_same_digest(capsys, room):
    path = room["tmp"] / "a.png"
    path.write_bytes(png())
    embed(capsys, room, path)
    once = path.read_bytes()
    code, _ = embed(capsys, room, path)
    assert code == 0 and path.read_bytes() == once
    assert trailer.split(once)[1] == [room["run"]]


@pytest.mark.parametrize("name", ["a.png", "a.jpg", "a.pdf"])
def test_a_stripped_pointer_is_detected(capsys, room, name):
    path = room["tmp"] / name
    path.write_bytes(FILES[name][0]())
    embed(capsys, room, path)
    path.write_bytes(trailer.split(path.read_bytes())[0])
    code, body = verify(capsys, room, path)
    assert code == 1 and codes(body) == ["artifact.pointer-stripped"]


@pytest.mark.parametrize("name", ["a.png", "a.jpg", "a.pdf"])
def test_a_repointed_pointer_is_detected(capsys, room, name):
    path = room["tmp"] / name
    path.write_bytes(FILES[name][0]())
    embed(capsys, room, path)
    path.write_bytes(trailer.embed(path.read_bytes(), room["other"])[0])
    code, body = verify(capsys, room, path)
    assert code == 1 and codes(body) == ["artifact.pointer-repointed"]


def test_a_modified_artifact_is_detected(capsys, room):
    for name in ("a.png", "a.bin"):
        path = room["tmp"] / name
        path.write_bytes(FILES[name][0]())
        embed(capsys, room, path)
        if name == "a.png":  # a different pixel under the same pointer
            path.write_bytes(trailer.embed(png(pixel=7), room["run"])[0])
        else:
            path.write_bytes(path.read_bytes() + b"!")
        code, body = verify(capsys, room, path)
        assert code == 1 and codes(body) == ["artifact.digest-mismatch"], name


def test_a_tampered_or_missing_sidecar_fails(capsys, room):
    path = room["tmp"] / "a.png"
    path.write_bytes(png())
    code, body = embed(capsys, room, path)
    sidecar = room["tmp"] / "a.png.provenance.json"
    doc = json.loads(sidecar.read_bytes())
    doc["subject"] = "dataset"
    sidecar.write_bytes(json.dumps(doc).encode("utf-8"))
    code, body = verify(capsys, room, path)
    assert code == 1 and codes(body) == ["artifact.bad-signature"]
    sidecar.write_bytes(b"[" * 500)
    assert codes(verify(capsys, room, path)[1]) == ["artifact.sidecar-invalid"]
    sidecar.unlink()
    assert codes(verify(capsys, room, path)[1]) == ["artifact.sidecar-missing"]


@pytest.mark.parametrize("signer", ["optimizer", "stranger"])
def test_only_a_pinned_non_optimizer_runner_verifies(capsys, room, signer):
    path = room["tmp"] / "a.png"
    path.write_bytes(png())
    assert embed(capsys, room, path, key_name=signer)[0] == 0
    code, body = verify(capsys, room, path)
    assert code == 1 and codes(body) == ["artifact.signer-unverified"]
    assert body["verification"].startswith("unverified: ")


def test_the_record_and_run_are_held_and_never_released(capsys, room):
    path = room["tmp"] / "a.png"
    path.write_bytes(png())
    embed(capsys, room, path)
    rows = [r for r in read_holds(holds_path(room["repo"]))
            if r["target"].startswith("custody:provenance:")]  # fmt: skip
    assert len(rows) == 2 and room["run"] in {r["oid"] for r in rows}
    for row in rows:
        with pytest.raises(HoldError):
            release(room["repo"], row["target"])


def test_the_run_must_exist_and_verify_here(capsys, room, tmp_path):
    from opentine.repository import Repo

    path = room["tmp"] / "a.png"
    path.write_bytes(png())
    embed(capsys, room, path)
    elsewhere = Repo.init(tmp_path / "elsewhere")
    code, body = tine(capsys, "provenance", "verify", path.as_posix(), "--repo",
                      elsewhere.path.parent.as_posix(), "--json")  # fmt: skip
    assert code == 1 and "artifact.run-missing" in codes(body)
    code, body = tine(capsys, "provenance", "embed", path.as_posix(), "--run",
                      "run:sha256:" + "0" * 64, "--key", room["keys"]["runner"].as_posix(),
                      "--repo", room["where"], "--json")  # fmt: skip
    assert code != 0 and "error" in body


def test_an_unknown_dataset_version_is_refused(capsys, room):
    path = room["tmp"] / "d.jsonl"
    path.write_bytes(b'{"x": 1}\n')
    code, body = embed(capsys, room, path, "--subject", "dataset", "--dataset-version",
                       "attestation:sha256:" + "1" * 64)  # fmt: skip
    assert code != 0 and "dataset version" in json.dumps(body)


def test_a_pdf_without_a_classic_trailer_gets_the_sidecar_only(capsys, room):
    path = room["tmp"] / "x.pdf"
    path.write_bytes(b"%PDF-1.7\n1 0 obj\n<< /Type /XRef >>\nendobj\nstartxref\n9\n%%EOF\n")
    code, body = embed(capsys, room, path)
    assert code == 0 and body["pointer"] is None
    assert verify(capsys, room, path)[0] == 0


def test_malformed_png_is_refused_not_guessed(capsys, room):
    path = room["tmp"] / "bad.png"
    path.write_bytes(png()[:-3])
    code, body = embed(capsys, room, path)
    assert code != 0 and "malformed PNG" in json.dumps(body)
