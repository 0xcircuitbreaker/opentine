"""What ``GET /v1/capabilities`` advertises (moved out of ``service`` in 0.52)."""

from __future__ import annotations

from typing import Any

from opentine._version import __version__
from opentine.remote._events import capabilities as event_capabilities
from opentine.remote._hosted_http import capabilities as hosted_capabilities
from opentine.remote._ref_txn import supported as ref_txn_supported
from opentine.repository import _pack4, _pack_peer


def service_capabilities(service: Any) -> dict[str, Any]:
    return {
        "authentication": ["bearer", "oidc"],
        "filters": ["depth", "run", "object_type"],
        "heads_fast_forward": bool(getattr(service, "fast_forward_heads", False)),
        "negotiation": ["haves", "tips"],  # 0.37: fetch may send ref tips (_tips)
        "object_format": "opentine-v3",
        "pack_codecs": _pack4.local_codecs(),
        "pack_format": "TINEPACK3",  # what 0.11 clients read; newer ones use pack_formats
        "pack_formats": _pack_peer.local_formats(),
        "protocol": "opentine-remote/1",
        "ref_txn": ref_txn_supported(service.index),  # 0.43: POST ref-txn (_ref_txn)
        "resumable_upload": True,
        "tombstones": callable(getattr(service.objects, "tombstoned", None)),  # 0.46
        "roles": ["reader", "writer", "admin"],
        "version": __version__,  # 0.37: lets a client pick codec v2 frames (X13)
        **event_capabilities(service),  # 0.45.1: events_sse, webhooks
        **hosted_capabilities(service),  # 0.46: object_read_http, run_closure, list, ...
        **getattr(service, "auth_caps", {}),  # 0.52: scoped_tokens, limits, oidc_exchange
        **getattr(service, "auth_caps", {}),  # 0.52: scoped_tokens, limits, oidc_exchange
    }
