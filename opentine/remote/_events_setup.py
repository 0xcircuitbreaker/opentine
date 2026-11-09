"""Give a reference remote its event hub, webhook registry and delivery thread (0.45.1)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentine.remote._events import EventHub
from opentine.remote._shares import ShareStore
from opentine.remote._webhook_delivery import attach
from opentine.remote._webhooks import Webhooks


def attach_events(service: Any, state: str | Path, *, allow_private: bool = False) -> EventHub:
    hub = EventHub()
    hooks = Webhooks(state, allow_private=allow_private)
    attach(hub, hooks)
    service.events, service.webhooks = hub, hooks
    service.shares = ShareStore(Path(state) / "shares.json")  # 0.46: caps.share
    return hub


__all__ = ["attach_events"]
