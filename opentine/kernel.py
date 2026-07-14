from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Protocol

OBJECT_TYPES = frozenset({"blob", "event", "run", "attestation", "annotation"})
OID_RE = re.compile(r"^(blob|event|run|attestation|annotation):sha256:([0-9a-f]{64})$")


class KernelError(ValueError):
    pass


def _number(value: int | float) -> str:
    if isinstance(value, int):
        if abs(value) > 9_007_199_254_740_991:
            raise KernelError("canonical JSON integer exceeds 2**53-1; encode big ints as strings")
        return str(value)
    if not math.isfinite(value):
        raise KernelError("canonical JSON forbids NaN and infinity")
    if value == 0:
        return "0"
    raw = repr(value).lower()
    absolute = abs(value)
    if 1e-6 <= absolute < 1e21:
        if "e" in raw:
            raw = format(Decimal(raw), "f")
        if "." in raw:
            raw = raw.rstrip("0").rstrip(".")
        return raw
    if "e" not in raw:
        raw = format(value, ".15e")
    coefficient, exponent = raw.split("e")
    coefficient = coefficient.rstrip("0").rstrip(".")
    exponent_number = int(exponent)
    sign = "+" if exponent_number >= 0 else ""
    return f"{coefficient}e{sign}{exponent_number}"


def _parse_int(value: str) -> int | float:
    integer = int(value)
    return integer if abs(integer) <= 9_007_199_254_740_991 else float(value)


def _string(value: str) -> str:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise KernelError("canonical JSON forbids lone Unicode surrogates") from exc
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _sort_key(value: str) -> bytes:
    return value.encode("utf-16be")


def _encode(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_encode(item) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise KernelError("canonical JSON object keys must be strings")
        pairs = (_string(key) + ":" + _encode(value[key]) for key in sorted(value, key=_sort_key))
        return "{" + ",".join(pairs) + "}"
    raise KernelError(f"unsupported canonical JSON type: {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    return _encode(value).encode("utf-8")


def parse_oid(oid: str) -> tuple[str, str]:
    match = OID_RE.fullmatch(oid) if isinstance(oid, str) else None
    if not match:
        raise KernelError(f"invalid typed object id: {oid!r}")
    return match.group(1), match.group(2)


def object_id(object_type: str, schema: int, stored: bytes) -> str:
    if object_type not in OBJECT_TYPES or type(schema) is not int or not 1 <= schema < 2**53:
        raise KernelError("invalid object type or schema")
    framed = object_type.encode() + b"\0" + str(schema).encode() + b"\0" + stored
    return f"{object_type}:sha256:{hashlib.sha256(framed).hexdigest()}"


@dataclass(frozen=True)
class ObjectEnvelope:
    object_type: str
    schema: int
    body: bytes
    encoding: str

    @classmethod
    def create(cls, object_type: str, payload: Any, schema: int = 1) -> ObjectEnvelope:
        if object_type == "blob":
            if not isinstance(payload, bytes):
                raise KernelError("blob payload must be bytes")
            return cls(object_type, schema, payload, "raw")
        if object_type not in OBJECT_TYPES:
            raise KernelError(f"unknown object type: {object_type}")
        return cls(object_type, schema, canonical_json(payload), "json")

    @property
    def oid(self) -> str:
        return object_id(self.object_type, self.schema, self.body)

    def payload(self) -> Any:
        return self.body if self.encoding == "raw" else json.loads(self.body, parse_int=_parse_int)

    def encode(self) -> bytes:
        header = canonical_json(
            {"encoding": self.encoding, "schema": self.schema, "type": self.object_type}
        )
        return header + b"\n" + self.body

    @classmethod
    def decode(cls, stored: bytes, expected_oid: str | None = None) -> ObjectEnvelope:
        try:
            raw_header, body = stored.split(b"\n", 1)
            header = json.loads(raw_header)
        except (ValueError, json.JSONDecodeError) as exc:
            raise KernelError("malformed object envelope") from exc
        if not isinstance(header, dict) or len(header) != 3 or canonical_json(header) != raw_header:
            raise KernelError("non-canonical object header")
        schema = header.get("schema")
        if type(schema) is not int or schema < 1:
            raise KernelError("invalid object schema")
        envelope = cls(str(header.get("type")), schema, body, str(header.get("encoding")))
        if envelope.object_type not in OBJECT_TYPES:
            raise KernelError("unknown object type")
        if envelope.encoding != ("raw" if envelope.object_type == "blob" else "json"):
            raise KernelError("object encoding/type mismatch")
        if envelope.encoding == "json":
            try:
                parsed = json.loads(body, parse_int=_parse_int)
            except json.JSONDecodeError as exc:
                raise KernelError("malformed object JSON") from exc
            if canonical_json(parsed) != body:
                raise KernelError("non-canonical object body")
        if expected_oid and envelope.oid != expected_oid:
            raise KernelError("object id mismatch")
        return envelope


def _links(payload: dict[str, Any], object_type: str) -> list[str]:
    if object_type == "event":
        values = [*(payload.get("parent_ids") or []), *(payload.get("causal_ids") or [])]
        for key in ("input_blob", "output_blob", "artifact_blob"):
            if payload.get(key):
                values.append(payload[key])
        return values
    if object_type == "run":
        values = [
            *(payload.get("roots") or []),
            *(payload.get("tips") or []),
            *(payload.get("events") or []),
            *(payload.get("manifests") or {}).values(),
        ]
        values.extend(value for key, value in payload.items() if key.endswith("_blob") and value)
        return values
    if object_type in {"attestation", "annotation"}:
        values = [payload["target_id"]] if payload.get("target_id") else []
        if object_type == "annotation" and payload.get("previous_id"):
            values.append(payload["previous_id"])
        values.extend(payload.get("evidence_ids") or [])
        return values
    return []


def validate_links(
    envelope: ObjectEnvelope,
    exists: Callable[[str], bool] | None = None,
) -> tuple[str, ...]:
    def event_ids(ids: Any) -> bool:
        return isinstance(ids, list) and all(parse_oid(oid)[0] == "event" for oid in ids)

    if envelope.encoding == "raw":
        return ()
    payload = envelope.payload()
    if not isinstance(payload, dict):
        raise KernelError(f"{envelope.object_type} payload must be an object")
    if envelope.object_type == "run" and not isinstance(payload.get("manifests") or {}, dict):
        raise KernelError("manifests must be an object")
    links = _links(payload, envelope.object_type)
    if envelope.object_type == "event":
        for field in ("parent_ids", "causal_ids"):
            values = payload.get(field) or []
            if not event_ids(values):
                raise KernelError(f"{field} must contain event ids")
            if len(set(values)) != len(values):
                raise KernelError(f"duplicate {field} link")
        for field in ("input_blob", "output_blob", "artifact_blob"):
            if payload.get(field) and parse_oid(payload[field])[0] != "blob":
                raise KernelError(f"{field} must contain a blob id")
    if envelope.object_type == "run":
        event_values = payload.get("events") or []
        if not event_ids(event_values):
            raise KernelError("events must contain event ids")
        events = set(event_values)
        for field in ("roots", "tips"):
            values = payload.get(field) or []
            if not event_ids(values):
                raise KernelError(f"{field} must contain event ids")
            if not set(values) <= events:
                raise KernelError(f"{field} must be a subset of events")
        manifest_map = payload.get("manifests") or {}
        if any(parse_oid(value)[0] != "blob" for value in manifest_map.values()):
            raise KernelError("manifests must contain blob ids")
        blob_values = [value for key, value in payload.items() if key.endswith("_blob") and value]
        if any(parse_oid(value)[0] != "blob" for value in blob_values):
            raise KernelError("run blob fields must contain blob ids")
    if envelope.object_type == "annotation" and payload.get("previous_id"):
        if parse_oid(payload["previous_id"])[0] != "annotation":
            raise KernelError("previous_id must contain an annotation id")
    for link in links:
        parse_oid(link)
        if link == envelope.oid:
            raise KernelError("object cannot link to itself")
        if exists is not None and not exists(link):
            raise KernelError(f"missing linked object: {link}")
    return tuple(links)


def verify_object(stored: bytes, oid: str, exists: Callable[[str], bool] | None = None) -> bool:
    envelope = ObjectEnvelope.decode(stored, oid)
    validate_links(envelope, exists)
    return True


class RepoProtocol(Protocol):
    def put(self, object_type: str, payload: Any, schema: int = 1) -> str: ...
    def get(self, oid: str) -> ObjectEnvelope: ...
    def update_ref(self, name: str, new_oid: str, expected_old: str | None = None) -> None: ...
