"""Build ``tests/data/dataset_version.json``: shared dataset-version vectors (0.75).

Each case is one ``opentine.dataset-version/1`` attestation payload and the
offline verdict :func:`opentine._dataset_claims.offline` gives it. The TS
verifier (``ts/verifier/test/datasetversion.test.ts``) answers the same file
field for field. Keys, run ids and times are fixed, so the file is
byte-stable: ``python -c "from tests.dataset_vectors import write; write()"``
regenerates it.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _dataset_claims as dc
from opentine._signing_pins import key_fingerprint
from opentine.attest_signing import sign_attestation

PATH = Path(__file__).resolve().parent / "data" / "dataset_version.json"
AT = "2026-11-21T00:00:00Z"
CURATOR = Ed25519PrivateKey.from_private_bytes(b"\x81" * 32)
OTHER = Ed25519PrivateKey.from_private_bytes(b"\x82" * 32)
OUT = ("ok", "signature", "problems", "members", "excluded")


def _id(kind: str, n: int) -> str:
    return f"{kind}:sha256:" + hashlib.sha256(f"{kind}{n}".encode()).hexdigest()


def _fp(key: Any) -> str:
    return key_fingerprint(key.public_key().public_bytes_raw())


def _claim(**change: Any) -> dict[str, Any]:
    runs = sorted(_id("run", n) for n in range(6))
    members = [{"run": r, "content": _id("x", i).split(":", 1)[1]} for i, r in enumerate(runs[:3])]
    claim = {"convention": dc.VERSION, "name": "train", "version": 1, "previous": None,
             "selection": "failures:sha256:" + "a" * 64, "members": members,
             "members_digest": dc.members_digest(members),
             "dedup": {"chunking": dict(dc.CHUNKING), "candidates": 4,
                       "dropped": [{"run": runs[3], "same_as": runs[0]}]},
             "taint_filter": {"mode": "default", "sources": list(dc.SOURCES),
                              "excluded": [runs[4]], "included_tainted": [],
                              "justification": None},
             "withdrawn": [runs[5]], "curator": _fp(CURATOR), "created_at": AT}  # fmt: skip
    claim.update(change)
    return claim


def _sign(claim: dict[str, Any], key: Any = CURATOR, signer: str | None = None) -> dict[str, Any]:
    payload = {"claim": claim, "evidence_ids": [], "signer": signer or _fp(key),
               "target_id": _id("run", 99)}  # fmt: skip
    payload["signature"] = sign_attestation(payload, key, algorithm="ed25519", signed_at=AT)
    return payload


def _cases() -> list[tuple[str, dict[str, Any]]]:
    good = _claim()
    runs = [m["run"] for m in good["members"]]
    tainted = copy.deepcopy(good)
    tainted["taint_filter"].update(mode="include-tainted", included_tainted=[runs[1]],
                                   justification=_id("attestation", 1))  # fmt: skip
    tampered = _sign(good)
    tampered["claim"] = copy.deepcopy(good)
    tampered["claim"]["members"] = tampered["claim"]["members"][:2]
    overlap = copy.deepcopy(good)
    overlap["taint_filter"]["excluded"] = sorted([*overlap["taint_filter"]["excluded"], runs[0]])
    dup = copy.deepcopy(good)
    dup["members"][1]["content"] = dup["members"][0]["content"]
    dup["members_digest"] = dc.members_digest(dup["members"])
    unjustified = copy.deepcopy(good)
    unjustified["taint_filter"]["mode"] = "include-tainted"
    later = _claim(version=2, previous=_id("attestation", 7))
    orphan = _claim(version=2)
    unsigned = {k: v for k, v in _sign(good).items() if k != "signature"}
    return [
        ("good-default", _sign(good)),
        ("good-include-tainted", _sign(tainted)),
        ("good-second-version", _sign(later)),
        ("tampered-members", tampered),
        ("excluded-member", _sign(overlap)),
        ("duplicate-content", _sign(dup)),
        ("include-tainted-without-justification", _sign(unjustified)),
        ("second-version-without-previous", _sign(orphan)),
        ("signer-names-another-key", _sign(good, CURATOR, _fp(OTHER))),
        ("curator-is-not-the-signer", _sign(good, OTHER)),
        ("unsigned", unsigned),
        # Blank is ASCII whitespace only, on both sides (no Unicode separators).
        ("selection-ascii-blank", _sign(_claim(selection=" \t\n\v\f\r"))),
        ("selection-info-separators", _sign(_claim(selection="\x1c\x1d\x1e\x1f"))),
        ("selection-next-line", _sign(_claim(selection="\x85"))),
        ("selection-byte-order-mark", _sign(_claim(selection="\ufeff"))),
    ]


def build() -> dict[str, Any]:
    cases = []
    for name, payload in _cases():
        found = dc.offline(payload)
        cases.append({"id": name, "payload": payload, "expect": {k: found[k] for k in OUT}})
    return {"format": "opentine-dataset-version-vectors/1", "convention": dc.VERSION,
            "cases": cases}  # fmt: skip


def text() -> bytes:
    return (json.dumps(build(), indent=1, sort_keys=True) + "\n").encode("utf-8")


def write() -> None:
    PATH.write_bytes(text())


__all__ = ["OUT", "PATH", "build", "text", "write"]
