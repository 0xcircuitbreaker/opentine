"""Experiment manifests (0.67): the ``opentine.experiment-manifest/1`` claim convention.

A manifest is one signed JSON document stating what an experiment was and what
it found::

    {"convention": "opentine.experiment-manifest/1", "experiment": NAME,
     "hypothesis": TEXT, "code_digest": "sha256:..", "container_digest": "sha256:.."|null,
     "model": {"id": TEXT, "version": TEXT}, "sampling": {NAME: scalar},
     "seeds": [INT], "data": [{"name": TEXT, "commitment": "sha256:.."}],
     "compute": {"usd": NUM|null, "gpu_hours": NUM|null, "tokens": INT|null},
     "results": [{"id": TEXT, "verdict": "sha256:..", "path": POSIX, "score": "0".."1",
                  "passed": BOOL, "input": ANY}],
     "conclusion": TEXT, "created_at": TIME, "signer": "sha256:..",
     "signature": {tine-sig/3 block}}

Each result row references a signed ``tine-eval-verdict/1`` by digest and by
path (relative to the manifest). ``tine experiment check`` judges the claim
(:mod:`opentine._experiment_check`). No object kind and no ``tine verify`` code
is added: the manifest is a file convention (docs/EXPERIMENTS.md).
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opentine import _signed_doc
from opentine.kernel import canonical_json

CONVENTION = "opentine.experiment-manifest/1"
DOMAIN = b"opentine.experiment-manifest.v1:"
FIELDS = (
    "convention", "experiment", "hypothesis", "code_digest", "container_digest", "model",
    "sampling", "seeds", "data", "compute", "results", "conclusion", "created_at", "signer",
)  # fmt: skip
ROW_FIELDS = ("id", "verdict", "path", "score", "passed")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
NAME_RE = re.compile(r"[A-Za-z0-9_.:/@+-]{1,128}")
SCORE_RE = re.compile(r"0|1|0\.[0-9]{0,5}[1-9]")
TIME_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
MAX_ROWS = 100_000


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _num(value: Any) -> bool:
    return value is None or (isinstance(value, int | float) and not isinstance(value, bool))


def _rows(results: Any) -> list[str]:
    if not isinstance(results, list) or len(results) > MAX_ROWS:
        return [f"results is a list of at most {MAX_ROWS} rows"]
    seen: set[str] = set()
    for row in results:
        if not isinstance(row, dict) or set(ROW_FIELDS) - set(row):
            return ["a result row has id, verdict, path, score and passed"]
        if set(row) - {*ROW_FIELDS, "input"}:
            return [f"result row {row.get('id')!r} has unknown fields"]
        if not isinstance(row["id"], str) or not NAME_RE.fullmatch(row["id"]):
            return ["a result row id is 1..128 safe characters"]
        if row["id"] in seen:
            return [f"result row {row['id']} is listed twice"]
        seen.add(row["id"])
        if not isinstance(row["verdict"], str) or not DIGEST_RE.fullmatch(row["verdict"]):
            return [f"result row {row['id']}: verdict is a sha256: digest"]
        path = row["path"]
        if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path \
                or ".." in path.split("/"):  # fmt: skip
            return [f"result row {row['id']}: path is a relative POSIX path"]
        if not isinstance(row["score"], str) or not SCORE_RE.fullmatch(row["score"]):
            return [f"result row {row['id']}: score is a decimal string in 0..1"]
        if not isinstance(row["passed"], bool):
            return [f"result row {row['id']}: passed is a boolean"]
    return []


def problems(doc: Any) -> list[str]:
    """What is wrong with *doc*'s fields (signature not checked); none: well formed."""
    if not isinstance(doc, dict) or doc.get("convention") != CONVENTION:
        return ["not an opentine.experiment-manifest/1 document"]
    missing = [f for f in FIELDS if f not in doc and f != "signer"]
    if missing:
        return [f"missing {', '.join(missing)}"]
    extra = set(doc) - {*FIELDS, "signature"}
    if extra:
        return [f"unknown fields {sorted(extra)}"]
    if not isinstance(doc["experiment"], str) or not NAME_RE.fullmatch(doc["experiment"]):
        return ["experiment is 1..128 safe characters"]
    for name in ("hypothesis", "conclusion"):
        if not isinstance(doc[name], str) or not doc[name].strip():
            return [f"{name} is non-empty text"]
    if not isinstance(doc["code_digest"], str) or not DIGEST_RE.fullmatch(doc["code_digest"]):
        return ["code_digest is a sha256: digest"]
    box = doc["container_digest"]
    if box is not None and not (isinstance(box, str) and DIGEST_RE.fullmatch(box)):
        return ["container_digest is a sha256: digest or null"]
    model = doc["model"]
    if not isinstance(model, dict) or set(model) != {"id", "version"} \
            or not all(isinstance(v, str) and v for v in model.values()):  # fmt: skip
        return ["model is {id, version} (non-empty text)"]
    sampling = doc["sampling"]
    if not isinstance(sampling, dict) or not all(
        isinstance(v, str | int | float | bool) or v is None for v in sampling.values()
    ):
        return ["sampling maps names to scalars"]
    seeds = doc["seeds"]
    if not isinstance(seeds, list) or not all(
        isinstance(s, int) and not isinstance(s, bool) for s in seeds
    ):
        return ["seeds is a list of integers"]
    data = doc["data"]
    if not isinstance(data, list) or not all(
        isinstance(d, dict) and set(d) == {"name", "commitment"} and isinstance(d["name"], str)
        and isinstance(d["commitment"], str) and DIGEST_RE.fullmatch(d["commitment"])
        for d in data
    ):  # fmt: skip
        return ["data lists {name, commitment: sha256:..}"]
    compute = doc["compute"]
    if not isinstance(compute, dict) or set(compute) != {"usd", "gpu_hours", "tokens"} \
            or not all(_num(v) for v in compute.values()):  # fmt: skip
        return ["compute is {usd, gpu_hours, tokens} (numbers or null)"]
    if not isinstance(doc["created_at"], str) or not TIME_RE.fullmatch(doc["created_at"]):
        return ["created_at is YYYY-MM-DDTHH:MM:SSZ"]
    return _rows(doc["results"])


def body(doc: dict[str, Any]) -> dict[str, Any]:
    return {name: doc.get(name) for name in FIELDS}


def sign(doc: dict[str, Any], private_key: Any, *, at: str | None = None) -> dict[str, Any]:
    """*doc* signed (``signer``, ``created_at`` and ``signature`` set); raises if malformed."""
    from opentine._signing_keys import load_ed25519_private
    from opentine._signing_pins import key_fingerprint

    private = load_ed25519_private(private_key)
    out = {k: v for k, v in doc.items() if k != "signature"}
    out["created_at"] = at or out.get("created_at") or now()
    out["signer"] = key_fingerprint(private.public_key().public_bytes_raw())
    found = problems(out)
    if found:
        raise ValueError(f"not a valid experiment manifest: {found[0]}")
    out["signature"] = _signed_doc.sign(DOMAIN, body(out), private, signer=out["signer"],
                                        signed_at=out["created_at"])  # fmt: skip
    return out


def verify(doc: dict[str, Any], domain: bytes = DOMAIN, fields: tuple = FIELDS) -> str | None:
    """None when *doc*'s embedded signature is by its ``signer``; else the reason."""
    from opentine._signing_pins import key_fingerprint

    block = doc.get("signature")
    if not isinstance(block, dict):
        return "unsigned"
    try:
        raw = bytes.fromhex(str(block.get("public_key", "")))
    except ValueError:
        raw = b""
    if len(raw) != 32 or key_fingerprint(raw) != doc.get("signer"):
        return "the signing key is not the named signer"
    result = _signed_doc.verify(domain, {n: doc.get(n) for n in fields}, block, public_key=raw)
    return None if result.ok else f"signature {result.state}: {result.reason}"


def digest(doc: dict[str, Any], domain: bytes = DOMAIN) -> str:
    """``sha256:`` over the domain and JCS of the whole document, signature included."""
    return "sha256:" + hashlib.sha256(domain + canonical_json(doc)).hexdigest()


def load(path: str | Path) -> dict[str, Any]:
    doc = json.loads(Path(path).read_bytes())
    if not isinstance(doc, dict):
        raise ValueError(f"{path}: not a JSON object")
    return doc


def dump(doc: dict[str, Any]) -> bytes:
    return (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


__all__ = ["CONVENTION", "DOMAIN", "FIELDS", "body", "digest", "dump", "load", "now",
           "problems", "sign", "verify"]  # fmt: skip
