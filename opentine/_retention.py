"""0.39 retention policy: how long an unreachable object is kept before gc deletes it.

``.tine/retention.toml`` (the repository's ``retention.toml``)::

    keep_days = 30                   # default window, never below prune's floor
    legal_hold = ["<oid>", ...]      # kept forever, like ``tine hold``

    [refs]                           # ref namespace (fnmatch) -> keep days
    "heads/release/*" = 365
    [status]                         # run status -> keep days
    failed = 7
    [tier]                           # assurance tier -> keep days
    high = 3650

An object's window is the *longest* that applies to it (the default plus every
matching rule), so adding a rule can only keep more. Facts come from the object
itself: a ``run`` payload's ``status``, ``ref`` and ``assurance_tier`` (top level
or under ``metadata``); objects with no such facts get the default. Held objects
(``tine hold``) and ``legal_hold`` oids are never deleted, whatever their age.

:class:`RetentionPolicy` implements :class:`opentine.remote.RetentionHook`, so a
remote backend can take the same file.
"""

from __future__ import annotations

import datetime
import fnmatch
import time
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any

FILE_NAME = "retention.toml"
DEFAULT_KEEP_DAYS = 14.0
_DAY = 86400.0

Facts = dict[str, str]


class RetentionError(ValueError):
    """The policy file is unreadable or malformed."""


def _days(value: Any, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
        raise RetentionError(f"{where}: keep days must be a number >= 0")
    return float(value)


def _table(data: dict, name: str) -> dict[str, float]:
    table = data.get(name, {})
    if not isinstance(table, dict):
        raise RetentionError(f"[{name}] must be a table")
    return {str(k): _days(v, f"{name}.{k}") for k, v in sorted(table.items())}


class RetentionPolicy:
    def __init__(
        self,
        keep_days: float = DEFAULT_KEEP_DAYS,
        *,
        refs: dict[str, float] | None = None,
        status: dict[str, float] | None = None,
        tier: dict[str, float] | None = None,
        legal_hold: list[str] | None = None,
        source: str = "default",
    ):
        self.keep_days = keep_days
        self.refs = dict(refs or {})
        self.status = dict(status or {})
        self.tier = dict(tier or {})
        self.legal_hold = sorted(set(legal_hold or []))
        self.source = source
        #: ``(tenant, oid) -> last-written epoch seconds | None``; set by :meth:`bind`.
        self.written: Callable[[str, str], float | None] = lambda _t, _o: None
        self.facts: Callable[[str, str], Facts] = lambda _t, _o: {}
        self.held: Callable[[str], set[str]] = lambda _t: set()

    @classmethod
    def loads(cls, text: str, source: str = "<string>") -> RetentionPolicy:
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise RetentionError(f"{source}: {exc}") from exc
        unknown = sorted(set(data) - {"keep_days", "legal_hold", "refs", "status", "tier"})
        if unknown:
            raise RetentionError(f"{source}: unknown key(s): {', '.join(unknown)}")
        holds = data.get("legal_hold", [])
        if not isinstance(holds, list) or not all(isinstance(h, str) for h in holds):
            raise RetentionError(f"{source}: legal_hold must be a list of object ids")
        return cls(
            _days(data.get("keep_days", DEFAULT_KEEP_DAYS), "keep_days"),
            refs=_table(data, "refs"),
            status=_table(data, "status"),
            tier=_table(data, "tier"),
            legal_hold=holds,
            source=source,
        )

    @classmethod
    def for_repo(cls, repo) -> RetentionPolicy:
        """The repository's policy (built-in default when it has no file), bound to it."""
        path = Path(repo.path) / FILE_NAME
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            policy = cls()
        except (OSError, UnicodeDecodeError) as exc:
            raise RetentionError(f"cannot read {path}: {exc}") from exc
        else:
            policy = cls.loads(text, str(path))
        return policy.bind(repo)

    def bind(self, repo) -> RetentionPolicy:
        from opentine.repository._gc_prune import _ages
        from opentine.repository._holds import held

        ages: dict[str, float] | None = None

        def written(_tenant: str, oid: str) -> float | None:
            nonlocal ages
            if ages is None:
                ages = _ages(repo)[0]
            return ages.get(oid)

        self.written = written
        self.facts = lambda _t, oid: object_facts(repo, oid)
        self.held = lambda _t: held(repo)
        return self

    def window_days(self, facts: Facts) -> float:
        days = [self.keep_days]
        ref = facts.get("ref")
        if ref:
            days += [d for pattern, d in self.refs.items() if fnmatch.fnmatchcase(ref, pattern)]
        days += [self.status[facts["status"]]] if facts.get("status") in self.status else []
        days += [self.tier[facts["tier"]]] if facts.get("tier") in self.tier else []
        return max(days)

    def is_held(self, tenant: str, oid: str) -> bool:
        return oid in self.legal_hold or oid in self.held(tenant)

    def expires(self, tenant: str, oid: str) -> float | None:
        """Epoch second the window ends; ``inf`` when held; None when age is unknown."""
        if self.is_held(tenant, oid):
            return float("inf")
        written = self.written(tenant, oid)
        if written is None:
            return None
        return written + self.window_days(self.facts(tenant, oid)) * _DAY

    # RetentionHook
    def retain_until(self, tenant: str, oid: str) -> str | None:
        until = self.expires(tenant, oid)
        if until is None:
            return None
        if until == float("inf"):
            return "hold"
        return datetime.datetime.fromtimestamp(until, datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    def before_delete(self, tenant: str, oid: str) -> None:
        until = self.expires(tenant, oid)
        if until is not None and until > time.time():
            raise PermissionError(f"{oid} is retained until {self.retain_until(tenant, oid)}")

    def retained(self, oid: str, now: float | None = None) -> bool:
        """True when gc must keep *oid* (held, or still inside its window)."""
        until = self.expires("", oid)
        return until is None or until > (time.time() if now is None else now)

    def describe(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "keep_days": self.keep_days,
            "refs": self.refs,
            "status": self.status,
            "tier": self.tier,
            "legal_hold": self.legal_hold,
        }


def object_facts(repo, oid: str) -> Facts:
    """``ref``/``status``/``tier`` read from a run object; ``{}`` for anything else."""
    try:
        envelope = repo.get(oid)
        if envelope.object_type != "run":
            return {}
        payload = envelope.payload()
    except (OSError, ValueError, KeyError):
        return {}
    if not isinstance(payload, dict):
        return {}
    meta = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    facts: Facts = {}
    for key, names in (("ref", ("ref",)), ("status", ("status",)), ("tier", ("assurance_tier",))):
        for name in names:
            value = payload.get(name, meta.get(name))
            if isinstance(value, str) and value:
                facts[key] = value
    return facts


__all__ = ["DEFAULT_KEEP_DAYS", "FILE_NAME", "RetentionError", "RetentionPolicy", "object_facts"]
