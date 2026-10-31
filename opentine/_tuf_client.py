"""A minimal TUF 1.0 client that refreshes Sigstore's ``trusted_root.json``.

Workflow (TUF specification 1.0, section 5), run only by ``tine trust root
update`` -- never implicitly:

1. Start from the stored ``root.json`` (or, on first use, the one the user
   passes with ``--root``; it must be signed by a threshold of its own keys).
2. Walk ``N+1.root.json`` until absent: each new root needs a threshold of
   signatures from the *old* root's root keys and from its *own*, and exactly
   version ``N+1``. The final root must be unexpired. If it rotated the
   timestamp or snapshot keys, stored timestamp/snapshot are discarded
   (fast-forward recovery).
3. ``timestamp.json`` (threshold of timestamp keys, unexpired, no version
   rollback, nor a rollback of the snapshot version it names).
4. Snapshot and targets: length/hashes as listed by their parent, threshold,
   the exact listed version, unexpired; snapshot never lowers a version.
5. Target ``trusted_root.json`` (top-level targets only; delegations are not
   followed): length and hashes are required and checked, then the file must
   parse as a Sigstore trusted root before it replaces the installed one.

Trusted metadata is persisted under ``<sigstore dir>/tuf/`` only after a whole
update succeeds; stored metadata is re-verified on load, so rollback state is
the highest version this client ever accepted.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from opentine._tuf_fetch import fetch
from opentine._tuf_meta import TUFError, check_expiry, check_hashes, parse, verify_role

DEFAULT_REPO_URL = "https://tuf-repo-cdn.sigstore.dev"
TARGET = "trusted_root.json"
MAX_ROOT_ROTATIONS = 256
LIMITS = {"root": 512 * 1024, "timestamp": 16 * 1024, "snapshot": 2 << 20, "targets": 5 << 20}
MAX_TARGET = 1 << 20

__all__ = ["DEFAULT_REPO_URL", "TUFError", "update"]


def _write(path: Path, data: bytes) -> None:
    from opentine._export_write import write_private

    write_private(path, data)


def _stored(tuf: Path, role: str, root: dict) -> dict | None:
    """A stored *role* that still verifies under *root*, else ``None`` (expiry ignored)."""
    try:
        meta = parse((tuf / f"{role}.json").read_bytes()[: LIMITS[role] + 1], role)
        verify_role(meta, root, role)
    except (OSError, TUFError):
        return None
    return meta


def _get(url: str, limit: int, what: str) -> bytes:
    data = fetch(url, limit)
    if data is None:
        raise TUFError(f"{what} is missing from the repository")
    return data


def _walk_roots(repo: str, root: dict, now: datetime) -> tuple[dict, list[bytes]]:
    """The newest root reachable from *root*, and the raw roots accepted on the way."""
    accepted: list[bytes] = []
    for _ in range(MAX_ROOT_ROTATIONS):
        version = root["signed"]["version"] + 1
        raw = fetch(f"{repo}/{version}.root.json", LIMITS["root"])
        if raw is None:
            break
        new = parse(raw, "root")
        verify_role(new, root["signed"], "root")
        verify_role(new, new["signed"], "root")
        if new["signed"]["version"] != version:
            raise TUFError(f"{version}.root.json carries version {new['signed']['version']}")
        root = new
        accepted.append(raw)
    check_expiry(root, now)
    return root, accepted


def _rotated(old: dict, new: dict, role: str) -> bool:
    def keys(root: dict) -> tuple:
        spec = root["signed"]["roles"].get(role) or {}
        return tuple(sorted(spec.get("keyids", []))), spec.get("threshold")

    return keys(old) != keys(new)


def _meta(parent: dict, name: str) -> dict:
    info = (parent["signed"].get("meta") or {}).get(name)
    version = info.get("version") if isinstance(info, dict) else None
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise TUFError(f"{parent['signed']['_type']} lists no valid version for {name}")
    return info


def _versioned(repo: str, root: dict, parent: dict, role: str) -> tuple[dict, bytes]:
    info = _meta(parent, f"{role}.json")
    prefix = f"{info['version']}." if root["signed"].get("consistent_snapshot") else ""
    limit = info["length"] if isinstance(info.get("length"), int) else LIMITS[role]
    raw = _get(f"{repo}/{prefix}{role}.json", min(limit, LIMITS[role]), f"{role}.json")
    check_hashes(raw, info, f"{role}.json")
    meta = parse(raw, role)
    verify_role(meta, root["signed"], role)
    if meta["signed"]["version"] != info["version"]:
        raise TUFError(f"{role}.json version does not match {parent['signed']['_type']}")
    return meta, raw


def _timestamp(repo: str, root: dict, old: dict | None, now: datetime) -> tuple[dict, bytes]:
    raw = _get(f"{repo}/timestamp.json", LIMITS["timestamp"], "timestamp.json")
    new = parse(raw, "timestamp")
    verify_role(new, root["signed"], "timestamp")
    if old is not None:
        if new["signed"]["version"] < old["signed"]["version"]:
            raise TUFError("timestamp version rolled back")
        if _meta(new, "snapshot.json")["version"] < _meta(old, "snapshot.json")["version"]:
            raise TUFError("snapshot version rolled back in timestamp")
    check_expiry(new, now)
    return new, raw


def _snapshot(repo: str, root: dict, ts: dict, old: dict | None, now: datetime):
    new, raw = _versioned(repo, root, ts, "snapshot")
    if old is not None:
        new_meta = new["signed"].get("meta") or {}
        for name, info in (old["signed"].get("meta") or {}).items():
            if name not in new_meta:
                raise TUFError(f"snapshot dropped {name}")
            if _meta(new, name)["version"] < (info or {}).get("version", 0):
                raise TUFError(f"{name} version rolled back in snapshot")
    check_expiry(new, now)
    return new, raw


def _target(repo: str, root: dict, targets: dict) -> bytes:
    info = (targets["signed"].get("targets") or {}).get(TARGET)
    if not isinstance(info, dict):
        raise TUFError(f"top-level targets do not list {TARGET} (delegations are not followed)")
    length = info.get("length")
    if not isinstance(length, int) or isinstance(length, bool) or not 0 < length <= MAX_TARGET:
        raise TUFError(f"{TARGET} length is missing or over {MAX_TARGET} bytes")
    sha = (info.get("hashes") or {}).get("sha256")
    consistent = root["signed"].get("consistent_snapshot") and isinstance(sha, str)
    name = f"{sha}.{TARGET}" if consistent else TARGET
    raw = _get(f"{repo}/targets/{name}", length, TARGET)
    check_hashes(raw, info, TARGET, required=True)
    return raw


def update(base: Path, *, repo_url: str | None = None, initial_root: bytes | None = None,
           now: datetime | None = None) -> dict:  # fmt: skip
    """Refresh ``trusted_root.json`` into *base*; returns a summary of versions."""
    from opentine._trusted_root import FILE_NAME, parse_trusted_root

    now = now or datetime.now(UTC)
    tuf = base / "tuf"
    state_path = tuf / "state.json"
    try:
        state = json.loads(state_path.read_text("utf-8")) if state_path.is_file() else {}
        stored_root = (tuf / "root.json").read_bytes() if (tuf / "root.json").is_file() else None
    except (OSError, ValueError) as exc:
        raise TUFError(f"cannot read TUF state in {tuf}: {exc}") from None
    if initial_root is not None and stored_root is not None:
        raise TUFError(f"already initialised; remove {tuf} to start again from --root")
    raw_root = initial_root if initial_root is not None else stored_root
    if raw_root is None:
        raise TUFError("no trusted TUF root yet: pass --root FILE (an initial root.json)")
    root = parse(raw_root, "root")
    verify_role(root, root["signed"], "root")
    repo = (repo_url or state.get("repo_url") or DEFAULT_REPO_URL).rstrip("/")
    old_ts = _stored(tuf, "timestamp", root["signed"])
    old_snap = _stored(tuf, "snapshot", root["signed"])
    start = root
    root, accepted = _walk_roots(repo, root, now)
    if _rotated(start, root, "timestamp") or _rotated(start, root, "snapshot"):
        old_ts = old_snap = None
    ts, ts_raw = _timestamp(repo, root, old_ts, now)
    snap, snap_raw = _snapshot(repo, root, ts, old_snap, now)
    targets, targets_raw = _versioned(repo, root, snap, "targets")
    check_expiry(targets, now)
    payload = _target(repo, root, targets)
    try:
        parse_trusted_root(payload)
    except ValueError as exc:
        raise TUFError(f"{TARGET} from the repository is invalid: {exc}") from None
    final_root = accepted[-1] if accepted else raw_root
    for name, data in (("root", final_root), ("timestamp", ts_raw), ("snapshot", snap_raw),
                       ("targets", targets_raw)):  # fmt: skip
        _write(tuf / f"{name}.json", data)
    _write(base / FILE_NAME, payload)
    _write(state_path, json.dumps({"repo_url": repo}, sort_keys=True).encode("utf-8"))
    return {
        "root": root["signed"]["version"],
        "timestamp": ts["signed"]["version"],
        "snapshot": snap["signed"]["version"],
        "targets": targets["signed"]["version"],
        "trusted_root": str(base / FILE_NAME),
        "repo_url": repo,
    }
