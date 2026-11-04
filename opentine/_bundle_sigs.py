"""``tine-sig/3`` sidecar blocks inside a bundle manifest (SPEC 9.10).

A detached ``tine-sig/3`` block signs a run's root and annotation head; it is
not an object, so a pack cannot carry it. A bundle carries it in its manifest
instead, under the optional key ``signatures``:

    {"<run oid>": [{"annotations_head": <oid|null>, "block": {...}}, ...], ...}

The key is written only when a bundled run has sidecar blocks, so every other
bundle is byte-for-byte what 0.25 wrote and reads there unchanged; a 0.25 reader
refuses a bundle that carries the key (its manifest shape is fixed), rather than
silently dropping the signatures. Pack formats are unchanged.
"""

from __future__ import annotations

from typing import Any

from opentine.kernel import KernelError, canonical_json, parse_oid
from opentine.repository._paths import internal_path
from opentine.repository._sig_sidecar import MAX_SIDECAR_ENTRIES, add_signatures, entries_for

SCHEME = "tine-sig/3"


def collect(repo: Any, carried: list[str]) -> dict[str, list[dict[str, Any]]]:
    """The sidecar entries of every run root the bundle's pack carries."""
    directory = internal_path(repo.path, "signatures", "v4")
    if not directory.is_dir():
        return {}
    roots = {oid for oid in carried if oid.startswith("run:")}
    found: dict[str, list[dict[str, Any]]] = {}
    for path in sorted(directory.glob("*.json")):
        root = f"run:sha256:{path.stem}"
        if root in roots:
            entries = entries_for(repo, root)
            if entries:
                found[root] = entries
    return found


MAX_BLOCK_BYTES = 16 * 1024  # an ed25519/sigstore block is far smaller


def _bad(message: str) -> ValueError:
    from opentine._bundle import BundleError

    return BundleError(f"invalid bundle signatures: {message}")


def _check_entry(entry: Any) -> None:
    if not isinstance(entry, dict) or set(entry) != {"annotations_head", "block"}:
        raise _bad("an entry is not {annotations_head, block}")
    head, block = entry["annotations_head"], entry["block"]
    if head is not None:
        if not isinstance(head, str) or parse_oid(head)[0] != "annotation":
            raise _bad("annotations_head is not an annotation oid")
    if not isinstance(block, dict) or block.get("scheme") != SCHEME:
        raise _bad(f"a block is not {SCHEME}")
    from opentine._signing_verify import _BLOCK_KEYS

    if set(block) - _BLOCK_KEYS:
        raise _bad("a block has unknown keys")
    if len(canonical_json(block)) > MAX_BLOCK_BYTES:
        raise _bad(f"a block exceeds {MAX_BLOCK_BYTES} bytes")


def check(value: Any, present: set[str]) -> dict[str, list[dict[str, Any]]]:
    """Shape-check a manifest's ``signatures``; every root must be in the pack."""
    if not isinstance(value, dict):
        raise _bad("not an object")
    for root, entries in value.items():
        try:
            if not isinstance(root, str) or parse_oid(root)[0] != "run":
                raise _bad("a key is not a run oid")
            if root not in present:
                raise _bad(f"{root} is not in the bundle")
            if not isinstance(entries, list) or not 0 < len(entries) <= MAX_SIDECAR_ENTRIES:
                raise _bad(f"{root} must hold 1..{MAX_SIDECAR_ENTRIES} entries")
            for entry in entries:
                _check_entry(entry)
        except KernelError as exc:
            raise _bad(str(exc)) from None
    return value


def install(repo: Any, signatures: dict[str, list[dict[str, Any]]]) -> int:
    """Merge the bundle's blocks into the local sidecars; returns how many are new."""
    added = 0
    for root, entries in sorted(signatures.items()):
        heads: dict[str | None, list[Any]] = {}
        for entry in entries:
            heads.setdefault(entry["annotations_head"], []).append(entry["block"])
        for head, blocks in heads.items():
            added += add_signatures(repo, root, head, blocks)
    return added


__all__ = ["check", "collect", "install"]
