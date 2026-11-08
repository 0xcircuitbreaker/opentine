"""The 0.46 optional bundle manifest keys, and bundle ref namespaces.

``tombstones`` (a list) holds the signed ``opentine.tombstone`` of each purged
blob the pack leaves as a shallow boundary, sorted by oid, so the receiver
learns why the bytes are missing; each must name one of the pack's shallow
boundaries, once. ``redacted_public`` holds the ``opentine.redacted-copy``
record of a ``--redacted-public`` bundle: its ``pack`` must be the bundle's
pack digest and its ``public_run`` a bundled ref target. Both keys are written
only when they have content, so every other bundle is byte-for-byte what 0.45
wrote; a reader before 0.46 refuses a bundle carrying them (the manifest shape
is fixed) rather than dropping them. Signatures are checked by ``tine bundle
verify --key-file/--pubkey``; here only the shape and the bindings.
"""

from __future__ import annotations

import re
from typing import Any

from opentine._signed_record import RecordError
from opentine.repository._refs import normalize_ref

MAX_TOMBSTONES = 10_000
NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")


def _bad(message: str) -> ValueError:
    from opentine._bundle import BundleError

    return BundleError(f"invalid bundle {message}")


def tombstones_for(repo: Any, pack: bytes) -> list[dict[str, Any]]:
    from opentine.repository import _tombstones
    from opentine.repository._tombstone_sync import boundaries

    return _tombstones.carried(repo, boundaries(pack))


def check(manifest: dict, shallow: list[str], refs: dict[str, str]) -> tuple[list, dict | None]:
    """``(tombstones, redacted_public)`` after their shape and binding rules."""
    from opentine import _redacted_copy, _tombstone

    records = manifest.get("tombstones", [])
    if not isinstance(records, list) or len(records) > MAX_TOMBSTONES:
        raise _bad("tombstones: not a list of at most 10000 records")
    seen: set[str] = set()
    try:
        for record in records:
            _tombstone.well_formed(record)
            if record["oid"] not in shallow or record["oid"] in seen:
                raise _bad(f"tombstones: {record['oid']} is not a boundary of the pack, once")
            seen.add(record["oid"])
        copy = manifest.get("redacted_public")
        if copy is not None:
            found = _redacted_copy.body(copy)
            if not isinstance(copy.get("signature"), dict):
                raise _bad("redacted_public: the record is unsigned")
            _redacted_copy.consistent(found)
            if found["pack"] != manifest["pack"]:
                raise _bad("redacted_public: the record names another pack")
            if found["public_run"] not in refs.values():
                raise _bad("redacted_public: the public run is not a bundled ref")
    except RecordError as exc:
        raise _bad(f"0.46 record: {exc.code}: {exc}") from None
    return records, copy


def install(repo: Any, records: list) -> int:
    from opentine.repository import _tombstones

    return _tombstones.install(repo, records) if records else 0


def namespace(value: str) -> str:
    """A tracking namespace from a user name, a file stem or a remote URL."""
    stem = re.sub(r"\.(tine|bundle|git)$", "", value.rstrip("/\\").replace("\\", "/"))
    stem = re.sub(r"[^a-z0-9._-]+", "-", stem.rsplit("/", 1)[-1].casefold()).strip("-.")
    if not NAME.fullmatch(stem or ""):
        from opentine._bundle import BundleError

        raise BundleError(f"cannot derive a ref namespace from {value[:80]!r}; pass --as NAME")
    normalize_ref(f"remotes/{stem}/x")
    return stem


def tracking_ref(name: str, ref: str) -> str:
    return normalize_ref(f"remotes/{name}/{ref.removeprefix('heads/')}")


__all__ = ["check", "install", "namespace", "tombstones_for", "tracking_ref"]
