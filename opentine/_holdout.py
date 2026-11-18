"""Sealed holdouts (0.61): a Merkle-root commitment and TINEAES-sealed items.

``tine dataset seal ITEMS.jsonl --out DIR`` writes a folder that holds no item
in clear::

    DIR/commitment.json   signed attestation, claim opentine.holdout.commitment/1
    DIR/leaves.json       the salted leaf hashes, in item order (checked against root)
    DIR/items/NNNNNN.sealed  one TINEAES3 ciphertext per item
    DIR/access/NNNNNN.json   signed access records (tine dataset unseal)
    DIR/canaries/*.json      signed canary registrations

A leaf is ``sha256(b"opentine.holdout.leaf.v1\\0" + salt + JCS(item))`` with a
random 16-byte salt per item, so a leaf reveals nothing about a short item.
The root is the RFC 6962 Merkle tree hash over the leaves. Each ciphertext is
``TINEAES3`` (:mod:`opentine.remote._sealed`, purpose ``holdout-item``, tenant
the holdout name, context ``ROOT:INDEX``), so it opens only in its slot. The
seal key is a 32-byte file kept outside the folder.

The commitment claim (an existing attestation, signed by a ``dataset``-role key
from the owner-pinned trust bundle) is::

    {"schema": "opentine.holdout.commitment/1", "holdout": NAME, "root": HEX,
     "items": N, "generation": G, "previous": HEX|null,
     "previous_commitment_sha256": HEX|null,
     "budget": {"max_unseals": U, "max_items": I}}

Rotation (``--rotate-from OLD``) seals a new generation whose ``previous`` names
the old root and the sha256 of the old commitment's bytes: a commitment chain.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

COMMITMENT = "opentine.holdout.commitment/1"
PURPOSE = "holdout-item"
LEAF_DOMAIN = b"opentine.holdout.leaf.v1\0"
NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")


class HoldoutError(ValueError):
    """A sealed holdout that cannot be used; ``code`` names the reason."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


def _jcs(value: Any) -> bytes:
    from opentine.kernel import canonical_json

    return canonical_json(value)


def leaf(salt: bytes, item: dict[str, Any]) -> bytes:
    return hashlib.sha256(LEAF_DOMAIN + salt + _jcs(item)).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    """RFC 6962 Merkle tree hash over *leaves* (empty tree: sha256 of nothing)."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    level = [hashlib.sha256(b"\x00" + item).digest() for item in leaves]
    while len(level) > 1:
        nxt = [hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest()
               for i in range(0, len(level) - 1, 2)]  # fmt: skip
        level = nxt + ([level[-1]] if len(level) % 2 else [])
    return level[0]


def seal_key(path: Path, *, create: bool) -> bytes:
    """The 32-byte seal key at *path*; created (random, mode 0600) when asked."""
    path = Path(path)
    if create and not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(os.urandom(32))
    data = path.read_bytes()
    if len(data) != 32:
        raise HoldoutError("holdout.seal-key", f"{path} is not a 32-byte seal key")
    return data


def signer(doc: Any) -> str | None:
    """The Ed25519 fingerprint that signed *doc*, when it verifies."""
    from opentine._promote_pins import _who

    try:
        return _who(doc) if isinstance(doc, dict) else None
    except Exception:  # noqa: BLE001 - a malformed attestation has no signer
        return None


def sign(key: Any, claim: dict[str, Any], target: str, at: str) -> dict[str, Any]:
    from opentine._signing_pins import key_fingerprint
    from opentine.attest_signing import sign_attestation

    payload = {"claim": claim, "evidence_ids": [], "target_id": target,
               "signer": key_fingerprint(key.public_key().public_bytes_raw())}  # fmt: skip
    return {**payload, "signature": sign_attestation(payload, key, algorithm="ed25519",
                                                      signed_at=at)}  # fmt: skip


def dump(path: Path, document: Any) -> bytes:
    data = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data


def require_role(repo: Path | None, who: str | None, role: str) -> None:
    """Refuse unless *who* holds *role* in the owner-pinned key roles (never an optimizer)."""
    from opentine._key_roles import KeyRoleError
    from opentine._promote_pins import role_state

    try:
        found = role_state(repo)
    except KeyRoleError as exc:
        raise HoldoutError("holdout.role", f"key roles: {exc}") from exc
    if found["status"] != "pinned":
        raise HoldoutError("holdout.role", f"the {role} role must come from an owner-pinned "
                           "trust bundle (tine trust bundle create --key-roles)")  # fmt: skip
    roles = found["roles"]
    if who is None or who not in roles.get(role, []) or who in roles.get("optimizer", []):
        raise HoldoutError("holdout.role", f"{who} is not a {role}-role key in the pinned "
                           "key roles (an optimizer key never is)")  # fmt: skip


def load(folder: Path) -> dict[str, Any]:
    """The verified commitment of a sealed folder: claim, signer, leaves, sha256."""
    folder = Path(folder)
    try:
        raw = (folder / "commitment.json").read_bytes()
        doc = json.loads(raw.decode("utf-8"))
        leaves = [bytes.fromhex(h) for h in json.loads((folder / "leaves.json").read_bytes())]
    except (OSError, ValueError, TypeError) as exc:
        raise HoldoutError("holdout.unreadable", f"{folder}: {exc}") from exc
    claim = doc.get("claim") if isinstance(doc, dict) else None
    who = signer(doc)
    if not isinstance(claim, dict) or claim.get("schema") != COMMITMENT or who is None:
        raise HoldoutError("holdout.commitment", f"{folder}: no signed {COMMITMENT}")
    if merkle_root(leaves).hex() != claim.get("root") or len(leaves) != claim.get("items"):
        raise HoldoutError("holdout.commitment", f"{folder}: leaves do not match the root")
    return {"claim": claim, "signer": who, "leaves": leaves,
            "sha256": hashlib.sha256(raw).hexdigest()}  # fmt: skip


def seal(items: list[dict[str, Any]], out: Path, *, name: str, key: Any, master: bytes,
         budget: dict[str, int], at: str, previous: dict | None = None) -> dict:  # fmt: skip
    """Seal *items* into *out*; *previous* is the loaded commitment this one rotates."""
    from opentine.remote._sealed import seal_with

    if not NAME_RE.fullmatch(name):
        raise HoldoutError("holdout.name", f"{name!r}: use [a-z0-9][a-z0-9._-]{{0,63}}")
    out = Path(out)
    if (out / "commitment.json").exists():
        raise HoldoutError("holdout.exists", f"{out} already holds a sealed holdout")
    salts = [os.urandom(16) for _ in items]
    leaves = [leaf(salt, item) for salt, item in zip(salts, items, strict=True)]
    root = merkle_root(leaves).hex()
    for index, (salt, item) in enumerate(zip(salts, items, strict=True)):
        body = _jcs({"salt": salt.hex(), "item": item})
        blob = seal_with(master, PURPOSE, name, f"{root}:{index}", body)
        (out / "items").mkdir(parents=True, exist_ok=True)
        (out / "items" / f"{index:06d}.sealed").write_bytes(blob)
    dump(out / "leaves.json", [h.hex() for h in leaves])
    prev = previous["claim"] if previous else None
    claim = {"schema": COMMITMENT, "holdout": name, "root": root, "items": len(items),
             "generation": prev["generation"] + 1 if prev else 1,
             "previous": prev["root"] if prev else None,
             "previous_commitment_sha256": previous["sha256"] if previous else None,
             "budget": budget}  # fmt: skip
    dump(out / "commitment.json", sign(key, claim, f"sha256:{root}", at))
    return claim


def open_items(folder: Path, master: bytes, indices: list[int]) -> list[dict[str, Any]]:
    """Decrypt *indices* and check each against its committed leaf."""
    from opentine.remote._sealed import unseal_with

    found = load(folder)
    claim = found["claim"]
    out = []
    for index in indices:
        blob = (Path(folder) / "items" / f"{index:06d}.sealed").read_bytes()
        try:
            body = unseal_with(master, PURPOSE, claim["holdout"], f"{claim['root']}:{index}", blob)
        except Exception as exc:  # noqa: BLE001 - wrong key or a moved ciphertext
            raise HoldoutError("holdout.unseal", f"item {index} does not open") from exc
        doc = json.loads(body.decode("utf-8"))
        if leaf(bytes.fromhex(doc["salt"]), doc["item"]) != found["leaves"][index]:
            raise HoldoutError("holdout.commitment", f"item {index} does not match its leaf")
        out.append(doc["item"])
    return out


def chain(folders: list[Path]) -> list[dict[str, Any]]:
    """Check a rotation chain, oldest first; each link names its predecessor."""
    links = [load(folder) for folder in folders]
    for older, newer in zip(links, links[1:], strict=False):
        claim = newer["claim"]
        want = (older["claim"]["root"], older["sha256"], older["claim"]["generation"] + 1)
        got = (claim["previous"], claim["previous_commitment_sha256"], claim["generation"])
        if want != got:
            raise HoldoutError("holdout.chain", f"generation {claim['generation']} does not "
                               "name the commitment before it")  # fmt: skip
    return [{"generation": x["claim"]["generation"], "root": x["claim"]["root"],
             "commitment_sha256": x["sha256"]} for x in links]  # fmt: skip


__all__ = ["COMMITMENT", "HoldoutError", "chain", "load", "merkle_root", "open_items",
           "require_role", "seal", "seal_key", "sign", "signer"]  # fmt: skip
