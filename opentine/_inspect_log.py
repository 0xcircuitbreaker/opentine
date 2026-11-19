"""Bounded reader for Inspect AI evaluation logs (``.eval`` zip and ``.json``), 0.64.

Pure parsing: ``inspect_ai`` is never imported. A ``.json`` log is one
``EvalLog`` object (``version``, ``eval``, ``results``, ``samples``...); a
``.eval`` log is a zip holding ``header.json`` (the log without samples; older
writers only ``_journal/start.json``) and one ``samples/<id>_epoch_<n>.json``
per sample. Both read into the same normalized dict::

    {"version": int, "status": str, "eval": {...}, "results": {...} | None,
     "samples": [{"id": str | int, "epoch": int, "input": ..., "target": ...,
                  "messages": [...], "output": {...}, "scores": {...},
                  "metadata": {...}}, ...]}

Every input is hostile until proven otherwise: the log, each zip member and the
whole zip are size-capped, the zip's member count and compression ratio are
capped, JSON nesting is depth-capped, and sample/message counts are capped.
Every refusal is an :class:`InspectLogError` (a ``ValueError``).
"""

from __future__ import annotations

import io
import json
import zipfile
import zlib
from pathlib import Path
from typing import Any

MAX_LOG_BYTES = 256 << 20
MAX_MEMBER_BYTES = 64 << 20
MAX_TOTAL_BYTES = 512 << 20
MAX_MEMBERS = 100_000
MAX_RATIO = 200
MAX_DEPTH = 64
MAX_SAMPLES = 100_000
MAX_MESSAGES = 10_000
ZIP_MAGIC = b"PK\x03\x04"


class InspectLogError(ValueError):
    """An Inspect log this reader refuses (malformed, oversized, or hostile)."""


def _depth_ok(value: Any) -> None:
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise InspectLogError(f"JSON nesting deeper than {MAX_DEPTH}")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)


def _no_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


def _finite(text: str) -> float:
    value = float(text)
    if value in (float("inf"), float("-inf")):
        raise ValueError("number out of range")
    return value


def _json(raw: bytes, where: str) -> Any:
    try:  # ValueError: NaN/Infinity, overflowing floats, ints past the digit limit
        value = json.loads(raw.decode("utf-8"), parse_constant=_no_constant, parse_float=_finite)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise InspectLogError(f"{where}: not JSON ({type(exc).__name__})") from exc
    _depth_ok(value)
    return value


def _object(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InspectLogError(f"{where}: expected a JSON object")
    return value


def _sample(value: Any, where: str) -> dict[str, Any]:
    sample = _object(value, where)
    ident = sample.get("id")
    if isinstance(ident, bool) or not isinstance(ident, (str, int)):
        raise InspectLogError(f"{where}: sample id must be a string or an integer")
    if isinstance(ident, str) and not 0 < len(ident) <= 1024:
        raise InspectLogError(f"{where}: sample id must be 1..1024 characters")
    epoch = sample.get("epoch", 1)
    if isinstance(epoch, bool) or not isinstance(epoch, int) or not 0 < epoch < 1 << 20:
        raise InspectLogError(f"{where}: epoch must be a positive integer")
    messages = sample.get("messages")
    messages = [] if messages is None else messages
    if not isinstance(messages, list) or len(messages) > MAX_MESSAGES:
        raise InspectLogError(f"{where}: messages must be a list of at most {MAX_MESSAGES}")
    for field in ("scores", "metadata", "output"):
        if sample.get(field) is not None and not isinstance(sample[field], dict):
            raise InspectLogError(f"{where}: {field} must be an object")
    return {
        "id": ident,
        "epoch": epoch,
        "input": sample.get("input", ""),
        "target": sample.get("target", ""),
        "messages": [_object(m, f"{where}: message") for m in messages],
        "output": sample.get("output") or {},
        "scores": sample.get("scores") or {},
        "metadata": sample.get("metadata") or {},
    }


def _normalize(log: dict[str, Any], samples: list[Any]) -> dict[str, Any]:
    head = _object(log.get("eval"), "eval")
    if not isinstance(head.get("task"), str) or not head["task"]:
        raise InspectLogError("eval.task must be a non-empty string")
    if len(samples) > MAX_SAMPLES:
        raise InspectLogError(f"more than {MAX_SAMPLES} samples")
    out = [_sample(item, f"sample {index}") for index, item in enumerate(samples)]
    seen = set()
    for item in out:
        key = (type(item["id"]).__name__, item["id"], item["epoch"])
        if key in seen:
            raise InspectLogError(f"duplicate sample {item['id']!r} epoch {item['epoch']}")
        seen.add(key)
    results = log.get("results")
    version = log.get("version", 2)
    if isinstance(version, bool) or not isinstance(version, int):
        raise InspectLogError("version must be an integer")
    status = log.get("status", "success")
    if not isinstance(status, str):
        raise InspectLogError("status must be a string")
    return {"version": version, "status": status, "eval": head,
            "results": results if isinstance(results, dict) else None, "samples": out}  # fmt: skip


def _read_zip(data: bytes) -> dict[str, Any]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, EOFError, ValueError,
            RuntimeError) as exc:  # RuntimeError: an unsupported zip version  # fmt: skip
        raise InspectLogError(f"not a readable .eval zip ({exc})") from exc
    if len(infos) > MAX_MEMBERS:
        raise InspectLogError(f"more than {MAX_MEMBERS} zip members")
    total = 0
    seen: set[str] = set()
    members: dict[str, bytes] = {}
    for info in infos:
        if info.file_size > MAX_MEMBER_BYTES:
            raise InspectLogError(f"{info.filename}: member larger than {MAX_MEMBER_BYTES} bytes")
        if info.file_size > MAX_RATIO * max(info.compress_size, 1) + 4096:
            raise InspectLogError(f"{info.filename}: compression ratio over {MAX_RATIO}")
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            raise InspectLogError(f"zip expands past {MAX_TOTAL_BYTES} bytes")
        name = info.filename
        if name in seen:
            raise InspectLogError(f"{name}: zip member name appears twice")
        seen.add(name)
        if name == "header.json" or name == "_journal/start.json" or name.startswith("samples/"):
            try:
                with archive.open(info) as handle:
                    raw = handle.read(MAX_MEMBER_BYTES + 1)
            except (zipfile.BadZipFile, zlib.error, OSError, EOFError, ValueError,
                    RuntimeError) as exc:  # RuntimeError: encrypted or unsupported  # fmt: skip
                raise InspectLogError(f"{name}: unreadable member ({exc})") from exc
            if len(raw) > info.file_size or len(raw) > MAX_MEMBER_BYTES:
                raise InspectLogError(f"{name}: member larger than it declares")
            members[name] = raw
    head_raw = members.get("header.json") or members.get("_journal/start.json")
    if head_raw is None:
        raise InspectLogError(".eval zip has no header.json")
    log = _object(_json(head_raw, "header.json"), "header.json")
    names = sorted(n for n in members if n.startswith("samples/") and n.endswith(".json"))
    samples = [_json(members[n], n) for n in names]
    return _normalize(log, samples)


def parse_log(data: bytes) -> dict[str, Any]:
    """The normalized log for *data* (``.eval`` zip or ``.json`` bytes)."""
    if not isinstance(data, bytes):
        raise InspectLogError("log bytes expected")
    if len(data) > MAX_LOG_BYTES:
        raise InspectLogError(f"log larger than {MAX_LOG_BYTES} bytes")
    if data.startswith(ZIP_MAGIC):
        return _read_zip(data)
    log = _object(_json(data, "log"), "log")
    samples = log.get("samples")
    samples = [] if samples is None else samples
    if not isinstance(samples, list):
        raise InspectLogError("samples must be a list")
    return _normalize(log, samples)


def read_log(path: str | Path) -> dict[str, Any]:
    """Read and normalize the log at *path* (bounded before it is read whole)."""
    path = Path(path)
    with open(path, "rb") as handle:
        data = handle.read(MAX_LOG_BYTES + 1)
    return parse_log(data)


__all__ = ["MAX_DEPTH", "MAX_LOG_BYTES", "InspectLogError", "parse_log", "read_log"]
