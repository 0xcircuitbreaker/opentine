"""Default admission policy for the reference remote service."""

from __future__ import annotations

from typing import Any

from opentine.remote.interfaces import Identity


class AllowAdmission:
    def admit(self, identity: Identity, operation: str, facts: dict[str, Any]) -> None:
        return None
