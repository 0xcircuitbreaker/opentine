"""A small signed lineage (root, promoted child) and dataset versions for the 0.78 BOM tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from opentine._lineage import record
from opentine.attest_signing import sign_attestation
from tests.lineage_helpers import RECORDER, art, key, promoted
from tests.promote_helpers import AT, EVALER, RUN_A, RUN_B, fingerprint

SCHEMAS = Path(__file__).parent / "data" / "aibom"
TRAIN = "sha256:" + hashlib.sha256(b"train-v1").hexdigest()
FILTER = {"exclude": ["integrity-tainted", "monitor-flagged"], "excluded_runs": 3}


def lineage(base: Path) -> tuple[Path, str, str]:
    """``(lineage folder, root variant, child variant)``; the child cites a signed eval."""
    decision, cand = promoted(base)
    store = base / "lineage"
    root = record(key(RECORDER), run=RUN_A, artifacts=art(0), store=store, at=AT)
    child = record(key(RECORDER), run=RUN_B, artifacts={**art(1), "weights": TRAIN},
                   store=store, parents=[root["variant"]], evals=[cand], decision=decision,
                   selector="tournament", at=AT)  # fmt: skip
    return store, root["variant"], child["variant"]


def dataset_version(
    path: Path,
    digest: str = TRAIN,
    *,
    signer: str = EVALER,
    taint: dict | None = FILTER,
    licence: str | None = "CC-BY-4.0",
) -> Path:
    """A signed dataset version: a claim convention on an existing attestation."""
    claim = {"convention": "opentine.dataset-version/1", "dataset": digest, "name": "train-v1",
             "taint_filter": taint}  # fmt: skip
    if licence:
        claim["licence"] = licence
    payload = {"claim": claim, "evidence_ids": [], "signer": fingerprint(signer),
               "target_id": RUN_A}  # fmt: skip
    payload["signature"] = sign_attestation(payload, key(signer), algorithm="ed25519",
                                            signed_at=AT)  # fmt: skip
    path.write_bytes((json.dumps(payload, indent=2, sort_keys=True) + "\n").encode())
    return path


def validator(name: str):
    """A jsonschema validator for a vendored, digest-pinned official schema."""
    import pytest

    jsonschema = pytest.importorskip("jsonschema", reason="schema validation needs jsonschema")
    referencing = pytest.importorskip("referencing", reason="schema refs need referencing")
    docs = {p.name: json.loads(p.read_bytes()) for p in SCHEMAS.glob("*.json")}
    resources = []
    for doc in docs.values():
        if "$id" in doc:
            spec = referencing.jsonschema.specification_with(
                doc.get("$schema", "https://json-schema.org/draft/2020-12/schema")
            )
            resources.append((doc["$id"], spec.create_resource(doc)))
    registry = referencing.Registry().with_resources(resources)
    schema = docs[name]
    cls = jsonschema.validators.validator_for(schema)
    return cls(schema, registry=registry, format_checker=cls.FORMAT_CHECKER)
