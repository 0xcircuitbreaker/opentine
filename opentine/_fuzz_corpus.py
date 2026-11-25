"""Seed corpora for the fuzz targets, taken from the conformance vectors (0.53).

``seeds(target, root)`` reads ``docs/conformance/vectors`` (and the ``.tine``
fixtures under ``tests/fixtures``) in a checkout at *root*, adds seeds built
here (TINEPACK4/5/6 re-spellings of the vector packs, v5 and TINEZ1 forms of the
v4 artifacts, a freshly signed DSSE envelope) and the triaged regression
inputs in ``tests/fuzz_regressions/<target>/``. Every seed is a tuple of parts.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from opentine._fuzz import Parts, unframe

VECTORS = Path("docs") / "conformance" / "vectors"
REGRESSIONS = Path("tests") / "fuzz_regressions"


def _cases(root: Path, *ops: str) -> Iterator[dict[str, Any]]:
    for path in sorted((root / VECTORS).glob("*.json")):
        for case in json.loads(path.read_text(encoding="utf-8")).get("cases", []):
            if not ops or case.get("op") in ops:
                yield case


def _input_bytes(root: Path, case: dict[str, Any]) -> bytes | None:
    given = case.get("input") or {}
    if "bytes_b64" in given:
        return base64.b64decode(given["bytes_b64"])
    if "blob" in given:
        path = root / "docs" / "conformance" / given["blob"]
        return path.read_bytes() if path.is_file() else None
    return None


def _envelopes(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        if "payloadType" in value and "signatures" in value:
            yield value
        for item in value.values():
            yield from _envelopes(item)
    elif isinstance(value, list):
        for item in value:
            yield from _envelopes(item)


def _otlp(route: str) -> list[Parts]:
    from opentine import _otlp_fuzz

    return [(data,) for name, data in _otlp_fuzz.seeds() if name == route]


def _tine(root: Path) -> list[Parts]:
    from opentine import _codec
    from opentine._artifact_io import parse_artifact_json
    from opentine._format_v4 import is_v4_artifact
    from opentine._tine_v5 import to_v5
    from opentine.kernel import canonical_json

    out: list[Parts] = []
    for path in sorted((root / "tests" / "fixtures").rglob("*.tine")):
        if not path.is_file() or path.stat().st_size > 1 << 20:
            continue
        raw = path.read_bytes()
        try:
            data = parse_artifact_json(raw)
        except (ValueError, RecursionError):
            continue
        if is_v4_artifact(data):
            out += [(raw,), (canonical_json(to_v5(data)),)]
            if _codec.available("zlib"):
                out.append((_codec.wrap(raw, "zlib"),))
    for case in _cases(root, "artifact.parse", "integrity.verify"):
        raw = _input_bytes(root, case)
        if raw is not None:
            out.append((raw,))
    return out


def _pack(root: Path) -> list[Parts]:
    from opentine.repository import _pack4, _pack5
    from opentine.repository.pack import inspect_pack

    out: list[Parts] = []
    for case in _cases(root, "pack.inspect", "pack.install"):
        raw = _input_bytes(root, case)
        if raw is None:
            continue
        out.append((raw,))
        try:
            inspect_pack(raw)
        except ValueError:
            continue
        out.append((_pack4.from_v3(raw, "zlib"),))
        if _pack5.available():
            from opentine.repository import _pack6_build

            out += [(_pack5.from_v3(raw),), (_pack6_build.from_v3(raw),)]
    return out


def _localpack(root: Path) -> list[Parts]:
    out: list[Parts] = []
    for case in _cases(root, "localpack.read"):
        raw, args = _input_bytes(root, case), case.get("args") or {}
        if raw is None or "pack_b64" not in args:
            continue
        dicts = json.dumps(args.get("dicts_b64") or {}, sort_keys=True).encode()
        out.append((raw, base64.b64decode(args["pack_b64"]), dicts))
    return out


def _dsse(root: Path) -> list[Parts]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from opentine import intoto
    from opentine._fuzz_targets import DSSE_SEED_KEY

    out: list[Parts] = []
    for case in _cases(root):
        for envelope in _envelopes(case.get("input")):
            out.append((json.dumps(envelope, sort_keys=True).encode(),))
    statement = {
        "_type": intoto.STATEMENT_TYPE,
        "predicateType": intoto.PREDICATE_TYPE,
        "subject": [{"name": "run.tine", "digest": {"sha256": "ab" * 32}}],
        "predicate": {"run": {"id": "r"}},
    }
    key = Ed25519PrivateKey.from_private_bytes(DSSE_SEED_KEY)
    out.append((json.dumps(intoto.sign_statement(statement, key)).encode(),))
    out.append((json.dumps(_replay_envelope(key)).encode(),))
    return out


def _replay_envelope(key: Any) -> dict[str, Any]:
    """A ``replay/v1`` envelope that verifies, so the fuzzer gets past its signature."""
    from opentine import _intoto_replay as replay

    result = dict.fromkeys(replay._RESULT_BOOLS, True)
    predicate = {
        "verifier": {"id": "https://opentine.dev/tine", "version": "0"},
        "mode": "cache",
        "replay": {"replay_id": "r2", "second_id": None, "fork_point": None},
        "result": {**result, "slice_ok": None, "structural_drift": [], "accounting_drift": []},
        "fidelity": {},
        "verified_at": "2026-01-01T00:00:00Z",
    }
    statement = {
        "_type": replay.STATEMENT_TYPE,
        "subject": [{"name": "r", "digest": {"sha256": "ab" * 32}}],
        "predicateType": replay.PREDICATE_TYPE,
        "predicate": predicate,
    }
    return replay.sign_statement(statement, key)


INSPECT = "tests/fixtures/inspect"  # 0.64: the committed Inspect log fixtures
HEC_SEEDS = "tests/vectors/tinepack6/packs"  # 0.81: the HEC1 decode vectors


def regressions(target: str, root: Path) -> list[Parts]:
    """The triaged crash inputs kept for *target* (each must now read or refuse)."""
    folder = root / REGRESSIONS / target
    return [unframe(p.read_bytes()) for p in sorted(folder.glob("*.bin"))]


def seeds(target: str, root: Path) -> list[Parts]:
    """Every seed for *target* in the checkout at *root*."""
    built = {
        "otlp-spans": lambda: _otlp("add_spans"),
        "otlp-logs": lambda: _otlp("add_logs"),
        "tine": lambda: _tine(root),
        "pack": lambda: _pack(root),
        "localpack": lambda: _localpack(root),
        "dsse": lambda: _dsse(root),
        "hec": lambda: [(p.read_bytes(),) for p in sorted((root / HEC_SEEDS).glob("*.hec"))],
        "inspect": lambda: [
            (p.read_bytes(),)
            for p in sorted((root / INSPECT).glob("*.*"))
            if p.suffix in (".eval", ".json") and p.name != "MANIFEST.json"
        ],
    }[target]()
    return built + regressions(target, root)


__all__ = ["REGRESSIONS", "VECTORS", "regressions", "seeds"]
