"""Shared fixtures for the 0.58 eval statistics and promotion tests (deterministic)."""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine._eval_run import run_eval
from opentine._eval_scorers import parse
from opentine._signing_pins import key_fingerprint

AT = "2026-11-01T12:00:00Z"
EVALER, PROMOTER, APPROVER = "5a" * 32, "6b" * 32, "7c" * 32
RUN_A = "run:sha256:" + "a" * 64
RUN_B = "run:sha256:" + "b" * 64
RUN_C = "run:sha256:" + "c" * 64


def key(seed: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))


def fingerprint(seed: str) -> str:
    return key_fingerprint(key(seed).public_key().public_bytes_raw())


def write_key(path: Path, seed: str) -> Path:
    path.write_text(seed, encoding="utf-8")
    return path


def make_eval(out: Path, run: str, passing, *, n: int = 40, dataset: str = "main",
              signer: str = EVALER, keep=None, threshold: float = 1.0) -> Path:  # fmt: skip
    """An exact-scored eval of *n* items; item i passes when ``passing(i)``."""
    items = [{"id": f"{dataset}-{i:03d}", "input": f"{dataset} {i}", "expected": "yes"}
             for i in range(n) if keep is None or keep(i)]  # fmt: skip
    outputs = {row["id"]: {"output": "yes" if passing(i) else "no", "run": run}
               for row in items for i in [int(row["id"].rsplit("-", 1)[1])]}  # fmt: skip
    run_eval(
        items, parse("exact"), key(signer), out, outputs=outputs, created_at=AT, threshold=threshold
    )
    return out


def policy(base: Path, **overrides) -> Path:
    """A promotion policy and its label admission policy, written under *base*."""
    admission = {"kind": "opentine.admission-policy", "version": 1, "refs": ["labels/*"],
                 "subjects": [fingerprint(PROMOTER)], "levels": ["OPENTINE_PROMOTED"]}  # fmt: skip
    (base / "labels.json").write_bytes(json.dumps(admission).encode())
    values = {
        "label_policy": "labels.json",
        "test": "paired-bootstrap",
        "alpha": "0.05",
        "seed": 7,
        "resamples": 500,
        "min_n": 30,
        "metric": "pass_rate",
        "budget_usd": "10",
        "approvers": [fingerprint(APPROVER)],
        "min_approvals": 1,
        "require_holdout": True,
        "eval_signers": [fingerprint(EVALER)],
        **overrides,
    }
    lines = ["[promote]"] + [f"{k} = {json.dumps(v)}" for k, v in values.items()]
    path = base / "promote.toml"
    path.write_bytes(("\n".join(lines) + "\n").encode())
    return path
