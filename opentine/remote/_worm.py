"""Write-once (WORM) retention for object-storage backends (0.49).

S3 Object Lock and Azure immutable blobs share one model, so the store
(``_worm_store``) talks to a small ``BlobClient`` and each cloud has an
adapter (``_worm_s3``, ``_worm_azure``):

* **governance**: a retention date that an operator holding the bypass
  permission (``s3:BypassGovernanceRetention``, or an unlocked Azure policy)
  can shorten or override. OpenTine's ``delete`` never bypasses it on its own.
* **compliance**: a retention date nobody can shorten, the root account
  included (an Azure *locked* time-based policy).
* **legal hold**: no date; the object cannot be deleted until the hold is
  cleared. OpenTine holds (``tine hold``, ``tine-holds/1``) map onto it.

The store refuses a delete inside retention or under a hold *before* it asks
the cloud, and the cloud refuses it again. Either refusal is a
``RetentionLocked`` (a ``PermissionError``).
"""

from __future__ import annotations

import datetime
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Protocol

GOVERNANCE = "governance"
COMPLIANCE = "compliance"
MODES = (GOVERNANCE, COMPLIANCE)
MAX_DAYS = 36_500


class RetentionLocked(PermissionError):
    """A delete was refused: the object is inside retention or under a legal hold."""


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


@dataclass(frozen=True)
class WormPolicy:
    """What every new object is written with: a mode and a retention period."""

    mode: str | None = None
    days: int = 0

    def __post_init__(self) -> None:
        if self.mode is not None and self.mode not in MODES:
            raise ValueError(f"retention mode must be one of {', '.join(MODES)}")
        if not isinstance(self.days, int) or not 0 <= self.days <= MAX_DAYS:
            raise ValueError(f"retention days must be an integer from 0 to {MAX_DAYS}")
        if (self.mode is None) != (self.days == 0):
            raise ValueError("a retention mode needs a positive number of days, and back")

    def until(self, now: datetime.datetime | None = None) -> datetime.datetime | None:
        if self.mode is None:
            return None
        return (now or utcnow()) + datetime.timedelta(days=self.days)


@dataclass(frozen=True)
class BlobRetention:
    """An object's retention as the cloud reports it."""

    mode: str | None = None
    until: datetime.datetime | None = None
    legal_hold: bool = False

    def locked(self, now: datetime.datetime | None = None) -> bool:
        return self.legal_hold or (self.until is not None and self.until > (now or utcnow()))

    def describe(self) -> str:
        if self.legal_hold:
            return "under legal hold"
        stamp = self.until.strftime("%Y-%m-%dT%H:%M:%SZ") if self.until else "?"
        return f"retained ({self.mode}) until {stamp}"


class BlobClient(Protocol):
    """The calls a WORM store needs from S3 or Azure (keys are ``/``-joined)."""

    def put(
        self,
        key: str,
        data: bytes,
        *,
        mode: str | None,
        until: datetime.datetime | None,
        legal_hold: bool,
    ) -> None: ...
    def get(self, key: str) -> bytes: ...  # KeyError when missing
    def exists(self, key: str) -> bool: ...
    def keys(self, prefix: str) -> Iterator[str]: ...
    def delete(self, key: str) -> None: ...  # RetentionLocked when the cloud refuses
    def retention(self, key: str) -> BlobRetention: ...
    def set_legal_hold(self, key: str, on: bool) -> None: ...
    def extend(self, key: str, mode: str, until: datetime.datetime) -> None: ...


def stronger(current: BlobRetention, policy_mode: str, until: datetime.datetime) -> str | None:
    """The mode to re-lock *current* with so it lasts until *until*, or None if it does.

    A reused chunk must stay retained as long as the newest object that uses it,
    so its date only ever moves later and governance only ever becomes compliance.
    """
    mode = COMPLIANCE if COMPLIANCE in (current.mode, policy_mode) else policy_mode
    if current.until is not None and current.until >= until and current.mode == mode:
        return None
    return mode
