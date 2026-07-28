from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Protocol

OBJECT_TYPES = frozenset({"blob", "event", "run", "attestation", "annotation"})
OID_RE = re.compile(r"^(blob|event|run|attestation|annotation):sha256:([0-9a-f]{64})$")


class KernelError(ValueError):
    pass


def validate_json_shape(raw: bytes | str, *, max_tokens: int = 200_000) -> None:
    depth = tokens = 0
    in_string = escaped = False
    for token in raw if isinstance(raw, bytes | bytearray) else map(ord, raw):
        if in_string:
            if escaped:
                escaped = False
            else:
                escaped = token == 0x5C
                in_string = token != 0x22
            continue
        if token == 0x22:
            in_string = True
        elif token in (0x5B, 0x7B):
            depth += 1
            tokens += 1
        elif token in (0x2C, 0x3A, 0x5D, 0x7D):
            tokens += 1
            depth -= token in (0x5D, 0x7D)
        if depth > 512 or tokens > max_tokens:
            raise KernelError("JSON structure exceeds semantic parser limits")


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
    if 1e-6 <= abs(value) < 1e21:
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
    return f"{coefficient}e{'+' if exponent_number >= 0 else ''}{exponent_number}"


def _parse_int(value: str) -> int | float:
    try:
        integer = int(value)
    except ValueError as exc:
        raise KernelError("canonical JSON integer literal is too large") from exc
    return integer if abs(integer) <= 9_007_199_254_740_991 else float(value)


def _string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _encode(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_encode(item) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise KernelError("canonical JSON object keys must be strings")
        keys = sorted(value, key=lambda item: item.encode("utf-16be"))
        return "{" + ",".join(_string(key) + ":" + _encode(value[key]) for key in keys) + "}"
    raise KernelError(f"unsupported canonical JSON type: {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    try:
        return _encode(value).encode("utf-8")
    except (RecursionError, UnicodeEncodeError) as exc:
        raise KernelError("canonical JSON nesting or Unicode key is invalid") from exc


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
        if object_type not in OBJECT_TYPES:
            raise KernelError(f"unknown object type: {object_type}")
        if object_type == "blob":
            if not isinstance(payload, bytes):
                raise KernelError("blob payload must be bytes")
            return cls(object_type, schema, payload, "raw")
        body = canonical_json(payload)
        validate_json_shape(body)
        return cls(object_type, schema, body, "json")

    @property
    def oid(self) -> str:
        return object_id(self.object_type, self.schema, self.body)

    def payload(self) -> Any:
        return self.body if self.encoding == "raw" else json.loads(self.body, parse_int=_parse_int)

    def encode(self) -> bytes:
        header = {"encoding": self.encoding, "schema": self.schema, "type": self.object_type}
        return canonical_json(header) + b"\n" + self.body

    @classmethod
    def decode(cls, stored: bytes, expected_oid: str | None = None) -> ObjectEnvelope:
        try:
            raw_header, body = stored.split(b"\n", 1)
            if len(raw_header) > 256:
                raise ValueError("object header exceeds its size limit")
            header = json.loads(raw_header)
        except (ValueError, RecursionError) as exc:
            raise KernelError("malformed object envelope") from exc
        if not isinstance(header, dict) or len(header) != 3 or canonical_json(header) != raw_header:
            raise KernelError("non-canonical object header")
        schema = header.get("schema")
        if type(schema) is not int or not 1 <= schema < 2**53:
            raise KernelError("invalid object schema")
        envelope = cls(str(header.get("type")), schema, body, str(header.get("encoding")))
        expected_encoding = "raw" if envelope.object_type == "blob" else "json"
        if envelope.object_type not in OBJECT_TYPES or envelope.encoding != expected_encoding:
            raise KernelError("unknown object type or encoding/type mismatch")
        if envelope.encoding == "json":
            try:
                validate_json_shape(body)
                parsed = json.loads(body, parse_int=_parse_int)
            except (json.JSONDecodeError, RecursionError, UnicodeDecodeError) as exc:
                raise KernelError("malformed object JSON") from exc
            if canonical_json(parsed) != body:
                raise KernelError("non-canonical object body")
        if expected_oid is not None and envelope.oid != expected_oid:
            raise KernelError("object id mismatch")
        return envelope


def validate_links(envelope: ObjectEnvelope, exists=None) -> tuple[str, ...]:
    def event_ids(ids: Any) -> bool:
        return isinstance(ids, list) and all(parse_oid(oid)[0] == "event" for oid in ids)

    if envelope.encoding == "raw":
        return ()
    payload = envelope.payload()
    if not isinstance(payload, dict):
        raise KernelError(f"{envelope.object_type} payload must be an object")
    links: list[str] = []
    if envelope.object_type == "event":
        for field in ("parent_ids", "causal_ids"):
            values = payload.get(field, [])
            if not event_ids(values) or len(set(values)) != len(values):
                raise KernelError(f"{field} must contain event ids; unique event ids are required")
            links.extend(values)
        for field in ("input_blob", "output_blob", "artifact_blob"):
            if payload.get(field) and parse_oid(payload[field])[0] != "blob":
                raise KernelError(f"{field} must contain a blob id")
            if payload.get(field):
                links.append(payload[field])
    if envelope.object_type == "run":
        if not isinstance(payload.get("manifests", {}), dict):
            raise KernelError("manifests must be an object")
        event_values = payload.get("events", [])
        if not event_ids(event_values) or len(set(event_values)) != len(event_values):
            raise KernelError("events must contain unique event ids")
        events = set(event_values)
        field_values: list[str] = []
        for field in ("roots", "tips"):
            values = payload.get(field, [])
            if not event_ids(values) or len(set(values)) != len(values):
                raise KernelError(f"{field} must contain unique events from the run")
            if not set(values) <= events:
                raise KernelError(f"{field} must be a subset of events")
            field_values.extend(values)
        blobs = [
            *payload.get("manifests", {}).values(),
            *(value for key, value in payload.items() if key.endswith("_blob") and value),
        ]
        if any(parse_oid(value)[0] != "blob" for value in blobs):
            raise KernelError("run blob fields must contain blob ids")
        links = [*field_values, *event_values, *blobs]
    if envelope.object_type in {"annotation", "attestation"}:
        links = [payload["target_id"]] if payload.get("target_id") else []
        if envelope.object_type == "annotation" and payload.get("previous_id"):
            if parse_oid(payload["previous_id"])[0] != "annotation":
                raise KernelError("previous_id must contain an annotation id")
            links.append(payload["previous_id"])
        evidence = payload.get("evidence_ids", [])
        links.extend(evidence if isinstance(evidence, list) else [None])
        if envelope.object_type == "attestation":
            if parse_oid(payload.get("target_id", ""))[0] != "run":
                raise KernelError("attestation target_id must contain a run id")
    envelope_oid = envelope.oid
    for link in links:
        parse_oid(link)
        if link == envelope_oid:
            raise KernelError("object cannot link to itself")
        if exists is not None and not exists(link):
            raise KernelError(f"missing linked object: {link}")
    return tuple(links)


def verify_object(stored: bytes, oid: str, exists=None) -> bool:
    return validate_links(ObjectEnvelope.decode(stored, oid), exists) is not None


class RepoProtocol(Protocol):
    def put(self, object_type: str, payload: Any, schema: int = 1) -> str: ...
    def get(self, oid: str) -> ObjectEnvelope: ...
    def update_ref(self, name: str, new_oid: str, expected_old: str | None = None) -> None: ...
