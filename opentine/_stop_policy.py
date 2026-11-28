"""The stop policy: which fleet a repository's runs belong to and where its stop channel is.

``.tine/stop-policy.json`` (written by ``tine stop init``)::

    {"convention": "opentine.stop-policy/1", "fleet": FLEET, "channel": DIR,
     "vkey": CHANNEL_VKEY, "window_s": 300, "skew_s": 30, "watchdog_s": 10}

With no policy nothing changes (D12). With one, every run and loop under the
repository must hold a fresh continue proof before each step and halts when it
cannot (:mod:`opentine._stop_guard`). The policy file is also held, never
released, under ``stop-policy:<fleet>``, so deleting it does not lift the
requirement: a held policy whose file is missing, unreadable, or differs from
every held version fails closed. A rewritten policy can only make runs halt:
continue proofs are bound to the channel key and fleet they were signed for, and
the window used is the smaller of the policy's and the proof's. The file also
falls under the ``policy-files`` integrity surface (``.tine/*policy*.json``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

CONVENTION = "opentine.stop-policy/1"
FILE_NAME = "stop-policy.json"
DEFAULT_WINDOW_S = 300
DEFAULT_SKEW_S = 30
DEFAULT_WATCHDOG_S = 10
MAX_BYTES = 64 * 1024
_KEYS = {"convention", "fleet", "channel", "vkey", "window_s", "skew_s", "watchdog_s"}


class StopPolicyError(ValueError):
    """A stop policy is in force but cannot be used: callers fail closed."""


def path(repo: Any) -> Path:
    return Path(repo.path) / FILE_NAME


def _int(value: Any, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def parse(data: bytes) -> dict[str, Any]:
    from opentine import _json_shallow
    from opentine._stop_channel import FLEET_ID

    try:
        doc = _json_shallow.loads(data) if len(data) <= MAX_BYTES else None
    except ValueError as exc:
        raise StopPolicyError(f"stop policy is not JSON: {exc}") from exc
    if not isinstance(doc, dict) or set(doc) != _KEYS or doc.get("convention") != CONVENTION:
        raise StopPolicyError(f"stop policy needs exactly {sorted(_KEYS)} ({CONVENTION})")
    if not isinstance(doc["fleet"], str) or not FLEET_ID.fullmatch(doc["fleet"]):
        raise StopPolicyError("stop policy fleet is not a fleet id")
    if not isinstance(doc["channel"], str) or not doc["channel"]:
        raise StopPolicyError("stop policy channel is not a path")
    if not isinstance(doc["vkey"], str):
        raise StopPolicyError("stop policy vkey is not a verifier key")
    if not (_int(doc["window_s"], 1, 86400) and _int(doc["skew_s"], 0, 3600)
            and _int(doc["watchdog_s"], 1, 3600)):  # fmt: skip
        raise StopPolicyError("stop policy window_s, skew_s or watchdog_s is out of range")
    return doc


def make(fleet: str, channel: str, vkey: str, *, window_s: int = DEFAULT_WINDOW_S,
         skew_s: int = DEFAULT_SKEW_S, watchdog_s: int = DEFAULT_WATCHDOG_S) -> dict:  # fmt: skip
    from opentine.kernel import canonical_json

    doc = {"convention": CONVENTION, "fleet": fleet, "channel": channel, "vkey": vkey,
           "window_s": window_s, "skew_s": skew_s, "watchdog_s": watchdog_s}  # fmt: skip
    return parse(canonical_json(doc))


def _held(repo: Any) -> list[str]:
    from opentine.repository._holds import STOP_POLICY, holds_path, read_holds

    return sorted({r["oid"] for r in read_holds(holds_path(repo))
                   if r["target"].startswith(STOP_POLICY)})  # fmt: skip


def install(repo: Any, doc: dict[str, Any]) -> str:
    """Write the policy and hold it; the held blob id."""
    from opentine.kernel import canonical_json
    from opentine.repository._holds import STOP_POLICY, hold_row
    from opentine.repository._paths import atomic_bytes

    data = canonical_json(parse(canonical_json(doc))) + b"\n"
    oid = repo.put("blob", data, redact=False)
    hold_row(repo, oid, STOP_POLICY + doc["fleet"])
    atomic_bytes(path(repo), data)
    return oid


def load(repo: Any) -> dict[str, Any] | None:
    """The policy in force, ``None`` when none was ever installed; fails closed otherwise."""
    held = _held(repo)
    try:
        data = path(repo).read_bytes()
    except FileNotFoundError:
        if held:
            raise StopPolicyError("a stop policy was installed here (held) but its file is "
                                  "missing: runs halt until it is restored") from None  # fmt: skip
        return None
    except OSError as exc:
        raise StopPolicyError(f"stop policy unreadable: {exc}") from exc
    doc = parse(data)
    if held:
        versions = set()
        for oid in held:
            try:
                versions.add(bytes(repo.get(oid).payload()))
            except Exception:  # noqa: BLE001 - an unreadable held version matches nothing
                continue
        if data not in versions:
            raise StopPolicyError("the stop policy file differs from every installed version "
                                  "(edit it with tine stop init)")  # fmt: skip
    return doc


def discover(start: Path | str | None) -> Any:
    """The repository *start* (default: the current directory) belongs to, or ``None``.

    0.91 review: every parent is searched, as ``tine`` itself does, so a command run
    from a subdirectory of a repository is under that repository's stop policy.
    """
    from opentine.repo import Repo

    base = Path(start or ".")
    while not base.exists() and base != base.parent:  # a --save path not written yet
        base = base.parent
    try:
        return Repo.open(base)
    except (OSError, ValueError):
        return None


__all__ = ["CONVENTION", "DEFAULT_SKEW_S", "DEFAULT_WATCHDOG_S", "DEFAULT_WINDOW_S",
           "FILE_NAME", "StopPolicyError", "discover", "install", "load", "make", "parse",
           "path"]  # fmt: skip
