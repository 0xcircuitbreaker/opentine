"""Single-file, self-verifying bundles of runs: ``tine bundle create|verify|unbundle``.

Layout (all integers big-endian)::

    b"TINEBUNDLE1\\n" | sha256(body) (32 bytes) | body
    body = len(manifest) (4 bytes) | manifest (canonical JSON) | pack

The manifest is ``{"format", "pack", "pack_bytes", "refs"}``: the pack's sha256,
its length and ``ref name -> object id``. The pack is an ordinary transfer pack
(``create_pack``), so it carries each run's associations -- annotations and
attestations -- as a fetch would. A bundle is untrusted input: every size is
capped, every ref name passes :func:`normalize_ref`, every digest is checked and
every ref target must be inside the pack before anything is written.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from opentine._cli_git_sync import is_ancestor
from opentine.kernel import KernelError, canonical_json, parse_oid, validate_json_shape
from opentine.repo import Repo
from opentine.repository._pack_fit import fitted_pack
from opentine.repository._refs import normalize_ref, validate_ref_oid
from opentine.repository.pack import MAX_PACK_BYTES, inspect_pack

MAGIC = b"TINEBUNDLE1\n"
FORMAT = "opentine-bundle/1"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_REFS = 10_000
MAX_BUNDLE_BYTES = len(MAGIC) + 32 + 4 + MAX_MANIFEST_BYTES + MAX_PACK_BYTES
_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")


class BundleError(ValueError):
    """The bundle is malformed, tampered with, oversized or unsafe to import."""


@dataclass(frozen=True)
class Verified:
    digest: str
    refs: dict[str, str]
    pack: bytes
    pack_id: str
    objects: int


def create(repo: Repo, refs: list[str] | None = None) -> bytes:
    """Bundle *refs* (default: every local ref outside ``remotes/``) and their objects."""
    local = repo.list_refs()
    if refs:
        chosen = {}
        for name in refs:
            normalized = normalize_ref(name if "/" in name else f"heads/{name}")
            if normalized not in local:
                raise KeyError(f"no such ref: {name}")
            chosen[normalized] = local[normalized]
    else:
        chosen = {k: v for k, v in local.items() if not k.startswith("remotes/")}
    if not chosen:
        raise ValueError("nothing to bundle: name refs or pass --all in a repository with refs")
    pack, _ = fitted_pack(repo, sorted(set(chosen.values())), [])
    manifest = canonical_json(
        {
            "format": FORMAT,
            "pack": "sha256:" + hashlib.sha256(pack).hexdigest(),
            "pack_bytes": len(pack),
            "refs": dict(sorted(chosen.items())),
        }
    )
    body = len(manifest).to_bytes(4, "big") + manifest + pack
    return MAGIC + hashlib.sha256(body).digest() + body


def read_file(path: str | Path, limit: int = MAX_BUNDLE_BYTES) -> bytes:
    """Read a bundle file in binary mode, refusing anything over *limit* bytes."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise BundleError("bundle is not a regular file")
        if info.st_size > limit:
            raise BundleError("bundle exceeds the maximum size")
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise BundleError("bundle exceeds the maximum size")
    return data


def _manifest(raw: bytes) -> dict:
    try:
        validate_json_shape(raw)
        payload = json.loads(raw)
        if canonical_json(payload) != raw:
            raise BundleError("bundle manifest is not canonical")
    except (KernelError, ValueError, RecursionError, UnicodeDecodeError) as exc:
        raise BundleError(f"invalid bundle manifest: {exc}") from None
    if not isinstance(payload, dict) or set(payload) != {"format", "pack", "pack_bytes", "refs"}:
        raise BundleError("invalid bundle manifest shape")
    if payload["format"] != FORMAT:
        raise BundleError(f"unsupported bundle format: {str(payload['format'])[:40]!r}")
    if not isinstance(payload["refs"], dict) or len(payload["refs"]) > MAX_REFS:
        raise BundleError("invalid or excessive bundle refs")
    return payload


def verify(data: bytes) -> Verified:
    """Check a bundle completely without touching any repository."""
    if len(data) > MAX_BUNDLE_BYTES:
        raise BundleError("bundle exceeds the maximum size")
    if not data.startswith(MAGIC) or len(data) < len(MAGIC) + 36:
        raise BundleError("not an opentine bundle (bad magic or truncated)")
    expected, body = data[len(MAGIC) : len(MAGIC) + 32], data[len(MAGIC) + 32 :]
    if hashlib.sha256(body).digest() != expected:
        raise BundleError("bundle checksum mismatch (truncated or tampered)")
    size = int.from_bytes(body[:4], "big")
    if size > MAX_MANIFEST_BYTES or 4 + size > len(body):
        raise BundleError("bundle manifest length is invalid")
    manifest = _manifest(body[4 : 4 + size])
    pack = body[4 + size :]
    if manifest["pack_bytes"] != len(pack):
        raise BundleError("bundle pack length mismatch")
    if manifest["pack"] != "sha256:" + hashlib.sha256(pack).hexdigest():
        raise BundleError("bundle pack digest mismatch")
    try:
        pack_id, objects, _ = inspect_pack(pack)
    except KernelError as exc:
        raise BundleError(f"bundle pack is invalid: {exc}") from None
    present = {oid for oid, _ in objects}
    refs: dict[str, str] = {}
    for name, oid in manifest["refs"].items():
        try:
            normalized = normalize_ref(name)
            if normalized != name or name.startswith("remotes/") or not isinstance(oid, str):
                raise ValueError(f"invalid ref name: {name!r}")
            parse_oid(oid)
            validate_ref_oid(name, oid)
        except (KernelError, ValueError) as exc:
            raise BundleError(f"unsafe bundle ref: {exc}") from None
        if oid not in present:
            raise BundleError(f"bundle ref {name} points outside the bundle")
        refs[name] = oid
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    return Verified(digest, refs, pack, pack_id, len(objects))


def namespace(value: str) -> str:
    """A tracking namespace from a user name, a file stem or a remote URL."""
    stem = re.sub(r"\.(tine|bundle|git)$", "", value.rstrip("/\\").replace("\\", "/"))
    stem = re.sub(r"[^a-z0-9._-]+", "-", stem.rsplit("/", 1)[-1].casefold()).strip("-.")
    if not _NAME.fullmatch(stem or ""):
        raise BundleError(f"cannot derive a ref namespace from {value[:80]!r}; pass --as NAME")
    normalize_ref(f"remotes/{stem}/x")
    return stem


def tracking_ref(name: str, ref: str) -> str:
    return normalize_ref(f"remotes/{name}/{ref.removeprefix('heads/')}")


def unbundle(repo: Repo, data: bytes, name: str, *, force: bool = False) -> dict:
    """Import a verified bundle; refs land under ``remotes/<name>/``. All or nothing."""
    checked = verify(data)
    if not _NAME.fullmatch(name):
        raise BundleError(f"invalid bundle namespace: {name!r}")
    result = repo.import_pack(checked.pack)
    local = repo.list_refs()
    rows: list[tuple[str, str, str | None]] = []
    unchanged = []
    for ref, oid in sorted(checked.refs.items()):
        target = tracking_ref(name, ref)
        old = local.get(target)
        if old == oid:
            unchanged.append(target)
            continue
        if old is not None and not force and not is_ancestor(repo, old, oid):
            raise BundleError(f"{target} would not fast-forward ({old} -> {oid}); use --force")
        rows.append((target, oid, old))
    if rows:
        repo.update_refs(rows, actor="bundle")
    return {
        "bundle": checked.digest,
        "pack": result.pack_id,
        "objects": len(result.objects),
        "updated": {ref: oid for ref, oid, _ in rows},
        "unchanged": unchanged,
    }


__all__ = [
    "MAX_BUNDLE_BYTES",
    "BundleError",
    "Verified",
    "create",
    "namespace",
    "read_file",
    "tracking_ref",
    "unbundle",
    "verify",
]
