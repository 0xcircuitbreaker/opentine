"""Pre-parse limits for compressed and persistent JSON container amplification."""

from __future__ import annotations

import base64
import hashlib
import io
import zlib

import pytest

from opentine._artifact_io import parse_artifact_json
from opentine.kernel import KernelError, ObjectEnvelope, canonical_json, validate_json_shape
from opentine.remote.app import RemoteApp
from opentine.repository import Repo
from opentine.repository import pack as pack_module
from opentine.repository.pack import MAGIC, inspect_pack


def _empty_objects(count: int) -> bytes:
    return b",".join([b"{}"] * count)


def test_kernel_rejects_structural_object_bomb_before_json_materialization():
    body = b'{"causal_ids":[],"padding":[' + _empty_objects(70_000) + b'],"parent_ids":[]}'
    header = canonical_json({"encoding": "json", "schema": 1, "type": "event"})
    with pytest.raises(KernelError, match="semantic parser limits"):
        ObjectEnvelope.decode(header + b"\n" + body)


def test_repository_refuses_to_persist_an_object_it_cannot_read(tmp_path):
    repo = Repo.init(tmp_path)
    payload = {"causal_ids": [], "padding": [{} for _ in range(70_000)], "parent_ids": []}
    with pytest.raises(KernelError, match="semantic parser limits"):
        repo.put("event", payload)
    assert repo.iter_oids() == []


def test_pack_rejects_structural_manifest_bomb_before_json_materialization():
    body = b'{"objects":[' + _empty_objects(70_000) + b'],"shallow":[],"version":1}'
    packed = MAGIC + hashlib.sha256(body).digest() + zlib.compress(body, level=9)
    assert len(packed) < 2_000
    with pytest.raises(KernelError, match="semantic parser limits"):
        inspect_pack(packed)


def test_pack_rejects_oversized_embedded_envelope_header_before_parsing():
    raw = b'{"padding":"' + b"a" * (1024 * 1024) + b'"}\nbody'
    body = canonical_json(
        {
            "objects": [{"data": base64.b64encode(raw).decode(), "id": "blob:sha256:" + "0" * 64}],
            "shallow": [],
            "version": 1,
        }
    )
    packed = MAGIC + hashlib.sha256(body).digest() + zlib.compress(body, level=9)
    assert len(packed) < 4_000
    with pytest.raises(KernelError, match="invalid packed object"):
        inspect_pack(packed)


def test_pack_decompression_uses_fixed_output_chunks(monkeypatch):
    raw_factory = zlib.decompressobj
    requested: list[int] = []

    class Decompressor:
        def __init__(self):
            self._value = raw_factory()

        def decompress(self, data, max_length=0):
            requested.append(max_length)
            return self._value.decompress(data, max_length)

        def __getattr__(self, name):
            return getattr(self._value, name)

    monkeypatch.setattr(pack_module.zlib, "decompressobj", Decompressor)
    body = canonical_json({"objects": [], "shallow": [], "version": 1})
    packed = MAGIC + hashlib.sha256(body).digest() + zlib.compress(body)
    inspect_pack(packed)
    assert requested and max(requested) <= 64 * 1024


def test_artifact_rejects_excessive_flat_structure_and_ignores_tokens_in_strings():
    raw = b'{"ignored":[' + _empty_objects(170_000) + b"]}"
    with pytest.raises(ValueError, match="structure is excessive"):
        parse_artifact_json(raw)

    text = '{}[],:\\"' * 40_000
    validate_json_shape(canonical_json({"text": text}))


def test_remote_json_rejects_structural_padding_and_unknown_fields():
    app = object.__new__(RemoteApp)
    body = b'{"padding":[' + _empty_objects(34_000) + b"]}"
    app.max_request_bytes = len(body)
    environ = {"CONTENT_LENGTH": str(len(body)), "wsgi.input": io.BytesIO(body)}
    with pytest.raises(ValueError, match="invalid request JSON"):
        app._json(environ, "wants")

    body = b'{"padding":"ignored","wants":[]}'
    app.max_request_bytes = len(body)
    environ = {"CONTENT_LENGTH": str(len(body)), "wsgi.input": io.BytesIO(body)}
    with pytest.raises(ValueError, match="must be an object"):
        app._json(environ, "wants")
