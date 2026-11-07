"""SPEC 8.10-8.11 (0.44): RFC 9162 inclusion and consistency, cosignature quorums.

Every case is a verdict: the ops answer ``ok`` (and a class or the cosigner
names) and never raise, so a consumer reports a bad proof as ``ok: false``.
The tree is the 13 leaves ``SHA-256(0x00 || "leaf <i>")``; the checkpoint
and cosignatures come from fixed Ed25519 seeds with fixed timestamps (Ed25519
is deterministic), so regeneration is byte-identical.
"""

from __future__ import annotations

import base64
import hashlib
import shutil
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine.repository import _tlog, _tlog_cosign, _tlog_note, _tlog_proof
from tests.conformance.cases import VERDICT, Case, Family, V

ORIGIN = "conformance.example/log"
ENTRIES = [f"leaf {i}".encode() for i in range(13)]
LEAVES = [_tlog.leaf_hash(e) for e in ENTRIES]
_b64 = lambda raw: base64.b64encode(raw).decode()  # noqa: E731


def _key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def _hashes() -> _tlog_proof.Hashes:
    root = Path(tempfile.mkdtemp(prefix="tine-conformance-tlog-"))
    _tlog.write_tiles(root, ENTRIES, 0)
    tiles = {}
    for path in root.rglob("*"):
        if path.is_file():
            tiles[path.relative_to(root).as_posix()] = path.read_bytes()
    shutil.rmtree(root)
    return _tlog_proof.Hashes(len(ENTRIES), tiles.__getitem__)


HASHES = _hashes()
ROOT = {n: _tlog.merkle_root(LEAVES[:n]) for n in range(1, 14)}


def _inclusion(index: int, size: int) -> dict:
    proof = _tlog_proof.inclusion_proof(HASHES, index, size)
    return {"entry_b64": _b64(ENTRIES[index]), "index": index, "size": size,
            "path": _tlog_proof.encode(proof), "root_b64": _b64(ROOT[size])}  # fmt: skip


def _consistency(old: int, new: int) -> dict:
    proof = _tlog_proof.consistency_proof(HASHES, old, new)
    return {"old_size": old, "new_size": new, "old_root_b64": _b64(ROOT[old]),
            "new_root_b64": _b64(ROOT[new]), "proof": _tlog_proof.encode(proof)}  # fmt: skip


LOG_KEY = _key("conformance log")
WITNESSES = [(f"w{i}.conformance.example", _key(f"witness {i}")) for i in range(3)]
WITNESS_VKEYS = [
    _tlog_cosign.witness_vkey(n, k.public_key().public_bytes_raw()) for n, k in WITNESSES
]
CHECKPOINT = _tlog_note.sign_checkpoint(LOG_KEY, ORIGIN, 13, ROOT[13])
FORK = _tlog_note.sign_checkpoint(LOG_KEY, ORIGIN, 13, ROOT[12])  # same size, other root


def _cosigned(note: bytes, which: tuple[int, ...]) -> str:
    for i in which:
        name, key = WITNESSES[i]
        note = _tlog_cosign.cosign(note, key, name, timestamp=1_760_000_000 + i)
    return note.decode()


def _quorum(note: str, need: int, total: int = 3, vkeys: list | None = None) -> dict:
    return {"checkpoint": note, "need": need, "total": total,
            "witnesses": WITNESS_VKEYS if vkeys is None else vkeys}  # fmt: skip


def _case(cid, op, intent, value, requires=()) -> Case:
    return Case(id=cid, section="8.10" if op != "tlog.quorum" else "8.11", checklist=(8,),
                op=op, profile="verifier", expect=VERDICT, intent=intent, input=V(value),
                requires=requires)  # fmt: skip


def _flip(text: str) -> str:
    raw = bytearray(base64.b64decode(text))
    raw[0] ^= 1
    return _b64(bytes(raw))


GOOD = _inclusion(5, 13)
STEP = _consistency(7, 13)
ED = ("ed25519",)

TLOG = Family(
    "57-tlog.json",
    "8.10",
    "tlog",
    (
        _case("tlog.inclusion.middle", "tlog.inclusion", "leaf 5 of 13 proves to the root", GOOD),
        _case(
            "tlog.inclusion.last",
            "tlog.inclusion",
            "the last leaf of an unbalanced tree",
            _inclusion(12, 13),
        ),  # fmt: skip
        _case(
            "tlog.inclusion.single",
            "tlog.inclusion",
            "a one-leaf tree has an empty path",
            _inclusion(0, 1),
        ),  # fmt: skip
        _case(
            "tlog.inclusion.wrong-entry",
            "tlog.inclusion",
            "another entry under leaf 5's path",
            {**GOOD, "entry_b64": _b64(ENTRIES[6])},
        ),  # fmt: skip
        _case(
            "tlog.inclusion.wrong-index",
            "tlog.inclusion",
            "the right path at the wrong index",
            {**GOOD, "index": 4},
        ),  # fmt: skip
        _case(
            "tlog.inclusion.short-path",
            "tlog.inclusion",
            "a path missing its last hash",
            {**GOOD, "path": GOOD["path"][:-1]},
        ),  # fmt: skip
        _case(
            "tlog.inclusion.flipped-hash",
            "tlog.inclusion",
            "one bit of one path hash flipped",
            {**GOOD, "path": [_flip(GOOD["path"][0]), *GOOD["path"][1:]]},
        ),  # fmt: skip
        _case(
            "tlog.consistency.extends", "tlog.consistency", "7 -> 13: a consistent extension", STEP
        ),  # fmt: skip
        _case(
            "tlog.consistency.power-of-two",
            "tlog.consistency",
            "8 -> 13: old size a power of two",
            _consistency(8, 13),
        ),  # fmt: skip
        _case(
            "tlog.consistency.same-size",
            "tlog.consistency",
            "13 -> 13 with the same root",
            _consistency(13, 13),
        ),  # fmt: skip
        _case(
            "tlog.consistency.fork",
            "tlog.consistency",
            "a different old root is a fork",
            {**STEP, "old_root_b64": _b64(ROOT[6])},
        ),  # fmt: skip
        _case(
            "tlog.consistency.same-size-fork",
            "tlog.consistency",
            "two roots for one size are a fork",
            {**_consistency(13, 13), "old_root_b64": _b64(ROOT[12])},
        ),  # fmt: skip
        _case(
            "tlog.consistency.rollback",
            "tlog.consistency",
            "13 -> 7: the tree shrank",
            {
                **STEP,
                "old_size": 13,
                "new_size": 7,
                "old_root_b64": STEP["new_root_b64"],
                "new_root_b64": STEP["old_root_b64"],
            },
        ),  # fmt: skip
        _case(
            "tlog.quorum.two-of-three",
            "tlog.quorum",
            "w0 and w1 cosigned: 2-of-3 holds",
            _quorum(_cosigned(CHECKPOINT, (0, 1)), 2),
            ED,
        ),  # fmt: skip
        _case(
            "tlog.quorum.one-of-three",
            "tlog.quorum",
            "one cosignature is not 2-of-3",
            _quorum(_cosigned(CHECKPOINT, (0,)), 2),
            ED,
        ),  # fmt: skip
        _case(
            "tlog.quorum.split-view",
            "tlog.quorum",
            "a fork cosigned by one colluding witness fails 2-of-3",
            _quorum(_cosigned(FORK, (2,)), 2),
            ED,
        ),  # fmt: skip
        _case(
            "tlog.quorum.cosigned-other-body",
            "tlog.quorum",
            "cosignatures moved onto another checkpoint body do not count",
            _quorum(
                FORK.decode() + _cosigned(CHECKPOINT, (0, 1)).split("\n\n", 1)[1].split("\n", 1)[1],
                2,
            ),
            ED,
        ),  # fmt: skip
        _case(
            "tlog.quorum.unpinned-witness",
            "tlog.quorum",
            "a cosigner outside the pinned set does not count",
            _quorum(
                _cosigned(CHECKPOINT, (0, 1)),
                2,
                total=2,
                vkeys=[WITNESS_VKEYS[0], WITNESS_VKEYS[2]],
            ),
            ED,
        ),  # fmt: skip
    ),
)

FAMILIES = (TLOG,)
