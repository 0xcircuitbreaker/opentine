"""Shared fixtures for the 0.84 artifact provenance tests: a pinned repo and tiny files."""

from __future__ import annotations

import json
import struct
import zlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import opentine.cli as cli
from opentine import _containment_records as records
from opentine import _schemas
from opentine._signing_pins import key_fingerprint
from opentine.repository import Repo
from tests.key_roles_helpers import pin_roles

SEEDS = {"runner": 0x81, "optimizer": 0x82, "stranger": 0x83}


def key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([SEEDS[name]]) * 32)


def fpr(name: str) -> str:
    return key_fingerprint(key(name).public_key().public_bytes_raw())


def chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload))
    )


def png(pixel: int = 0) -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(bytes([0, pixel]))) + chunk(b"IEND", b""))  # fmt: skip


def jpeg() -> bytes:
    app0 = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    seg = b"\xff\xe0" + struct.pack(">H", len(app0) + 2) + app0
    sos = b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"
    return b"\xff\xd8" + seg + sos + b"\x12\x34\x56" + b"\xff\xd9"


def pdf() -> bytes:
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [] /Count 0 >>"]
    out, offsets = b"%PDF-1.4\n", []
    for n, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{n} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 3\n0000000000 65535 f \n" + b"".join(
        f"{o:010d} 00000 n \n".encode() for o in offsets
    )
    return out + f"trailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()


@pytest.fixture(name="room")
def _room(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    repo = Repo.init(tmp_path / "r")
    roles = {"runner": [fpr("runner"), fpr("optimizer")], "optimizer": [fpr("optimizer")]}
    text = "version = 1\n[roles]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in roles.items())
    (repo.path / "key-roles.toml").write_bytes(text.encode("utf-8"))
    pin_roles(repo.path)
    keys = {}
    for name in SEEDS:
        keys[name] = tmp_path / f"{name}.hex"
        keys[name].write_bytes(key(name).private_bytes_raw().hex().encode("ascii"))
    run = records.anchor(repo, "produce", "made an image")
    other = records.anchor(repo, "produce", "made another")
    return {"repo": repo, "where": repo.path.parent.as_posix(), "keys": keys, "run": run,
            "other": other, "tmp": tmp_path}  # fmt: skip


def tine(capsys, *argv: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = exc.code or 0
    body = json.loads(capsys.readouterr().out)
    assert _schemas.validate_output(body) == [] or "error" in body
    return code, body


def embed(capsys, room, path, *extra: str, key_name: str = "runner") -> tuple[int, dict]:
    return tine(capsys, "provenance", "embed", path.as_posix(), "--run", room["run"], "--key",
                room["keys"][key_name].as_posix(), "--repo", room["where"], "--json",
                *extra)  # fmt: skip


def verify(capsys, room, path, *extra: str) -> tuple[int, dict]:
    return tine(capsys, "provenance", "verify", path.as_posix(), "--repo", room["where"],
                "--json", *extra)  # fmt: skip


def codes(body: dict) -> list[str]:
    return [f["code"] for f in body["findings"]]
