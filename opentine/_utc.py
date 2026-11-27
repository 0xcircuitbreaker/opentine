"""One spelling of an RFC 3339 UTC timestamp with second precision: ``2026-01-02T03:04:05Z``."""

from __future__ import annotations

from datetime import UTC, datetime

FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def rfc3339_utc(seconds: float | None = None) -> str:
    """*seconds* since the epoch (now when ``None``) as ``YYYY-MM-DDTHH:MM:SSZ``."""
    when = datetime.now(UTC) if seconds is None else datetime.fromtimestamp(seconds, UTC)
    return when.strftime(FORMAT)


__all__ = ["FORMAT", "rfc3339_utc"]
