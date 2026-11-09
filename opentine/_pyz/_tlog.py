"""Transparency-log proofs and witness quorums for ``tine-verify.pyz`` (SPEC 8.10-8.11).

A stdlib port of ``opentine.repository._tlog_proof`` (RFC 9162 inclusion and
consistency verification) and ``_tlog_cosign.cosigners`` (C2SP
``cosignature/v1``). Each op returns the same verdict shape as the reference
adapter: a proof that does not hold is ``ok: false``, never an exception.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Any

from . import _ed25519

MAX_PROOF_HASHES = 64
COSIGNATURE_TYPE = 0x04
DASH = "— "
MAX_NOTE_BYTES = 1 << 16
MAX_SIGNATURE_LINES = 100


class LogError(ValueError):
    pass


def leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _b64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise LogError("not base64")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise LogError("not base64") from None


def _proof(value: Any) -> list[bytes]:
    if not isinstance(value, list) or len(value) > MAX_PROOF_HASHES:
        raise LogError("proof is not a list of base64 hashes")
    hashes = [_b64(item) for item in value]
    if any(len(h) != 32 for h in hashes):
        raise LogError("proof is not a list of SHA-256 hashes")
    return hashes


def _size(value: Any) -> int:
    if type(value) is not int or value < 0:
        raise LogError("not a tree size")
    return value


def root_from_inclusion(leaf: bytes, index: int, size: int, proof: list[bytes]) -> bytes:
    if not 0 <= index < size:
        raise LogError("inclusion proof index is out of range")
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            raise LogError("inclusion proof is too long")
        if fn & 1 or fn == sn:
            r = _node(p, r)
            while not fn & 1 and fn:
                fn, sn = fn >> 1, sn >> 1
        else:
            r = _node(r, p)
        fn, sn = fn >> 1, sn >> 1
    if sn != 0:
        raise LogError("inclusion proof is too short")
    return r


def consistency(old: int, new: int, old_root: bytes, new_root: bytes, proof: list) -> None:
    if old > new:
        raise LogError("rollback")
    if old == new:
        if proof or old_root != new_root:
            raise LogError("fork")
        return
    if old == 0:
        if proof:
            raise LogError("proof from the empty tree must be empty")
        return
    if old & (old - 1) == 0:
        proof = [old_root, *proof]
    if not proof:
        raise LogError("consistency proof is empty")
    fn, sn = old - 1, new - 1
    while fn & 1:
        fn, sn = fn >> 1, sn >> 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            raise LogError("consistency proof is too long")
        if fn & 1 or fn == sn:
            fr, sr = _node(c, fr), _node(c, sr)
            while not fn & 1 and fn:
                fn, sn = fn >> 1, sn >> 1
        else:
            sr = _node(sr, c)
        fn, sn = fn >> 1, sn >> 1
    if sn != 0 or fr != old_root or sr != new_root:
        raise LogError("fork")


def inclusion(value: Any) -> dict[str, Any]:
    try:
        leaf = leaf_hash(_b64(value["entry_b64"]))
        root = _b64(value["root_b64"])
        proof = _proof(value["path"])
        ok = root_from_inclusion(leaf, _size(value["index"]), _size(value["size"]), proof) == root
    except (KeyError, TypeError, LogError):
        return {"ok": False}
    return {"ok": ok}


def consistency_verdict(value: Any) -> dict[str, Any]:
    try:
        old, new = _b64(value["old_root_b64"]), _b64(value["new_root_b64"])
        proof = _proof(value["proof"])
        consistency(_size(value["old_size"]), _size(value["new_size"]), old, new, proof)
    except (KeyError, TypeError, LogError) as exc:
        text = str(exc)
        return {"ok": False, "class": "rollback" if "rollback" in text else
                "fork" if "fork" in text else "invalid"}  # fmt: skip
    return {"ok": True, "class": "consistent"}


def _key_id(name: str, public: bytes) -> bytes:
    return hashlib.sha256(name.encode() + b"\n" + bytes([COSIGNATURE_TYPE]) + public).digest()[:4]


def _vkey(vkey: Any) -> tuple[str, bytes]:
    try:
        name, hint, encoded = str(vkey).strip().split("+", 2)
    except ValueError:
        raise LogError("witness key is not name+hash+key") from None
    raw = _b64(encoded)
    if not name or any(c in name for c in " +\n") or len(raw) != 33:
        raise LogError("witness key is malformed")
    if raw[0] != COSIGNATURE_TYPE or _key_id(name, raw[1:]).hex() != hint:
        raise LogError("witness key is not an Ed25519 cosignature/v1 key")
    return name, raw[1:]


def cosigners(note: bytes, vkeys: list) -> dict[str, int]:
    if len(note) > MAX_NOTE_BYTES:
        raise LogError("checkpoint note is too large")
    try:
        text = note.decode("utf-8")
    except UnicodeDecodeError:
        raise LogError("checkpoint note is not UTF-8") from None
    body, sep, signatures = text.partition("\n\n")
    lines = [line for line in signatures.split("\n") if line]
    if not sep or len(lines) > MAX_SIGNATURE_LINES:
        raise LogError("checkpoint is not a signed note")
    body += "\n"
    keys = {}
    for vkey in vkeys:
        name, public = _vkey(vkey)
        keys[(name, _key_id(name, public))] = public
    found: dict[str, int] = {}
    for line in lines:
        if not line.startswith(DASH):
            continue
        name, _, encoded = line[len(DASH) :].partition(" ")
        try:
            raw = _b64(encoded)
        except LogError:
            continue
        public = keys.get((name, raw[:4]))
        if public is None or len(raw) != 76:
            continue
        stamp = int.from_bytes(raw[4:12], "big")
        signed = f"cosignature/v1\ntime {stamp}\n{body}".encode()
        if _ed25519.verify(public, signed, raw[12:]):
            found[name] = stamp
    return found


def quorum(value: Any) -> dict[str, Any]:
    try:
        found = cosigners(str(value["checkpoint"]).encode("utf-8"), list(value["witnesses"]))
    except (KeyError, TypeError, LogError):
        return {"ok": False, "cosigners": []}
    ok = len(value["witnesses"]) == value["total"] and len(found) >= value["need"]
    return {"ok": ok, "cosigners": sorted(found)}


__all__ = ["consistency_verdict", "cosigners", "inclusion", "quorum"]
