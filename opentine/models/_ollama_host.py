"""Where an Ollama adapter connects, and whether that is Ollama Cloud.

``OLLAMA_HOST`` is documented in the forms the *server* binds -- ``0.0.0.0``,
``127.0.0.1:11434``, ``example.com`` -- and Ollama's own client reads it the same
way: no scheme means ``http`` on port 11434. Used verbatim, those made httpx fail
with "Request URL is missing an 'http://' or 'https://' protocol" (audit round 3).

Ollama also serves hosted "cloud" models: a ``:cloud`` / ``-cloud`` tag proxied
through the local daemon (whose response names ``remote_model``/``remote_host``),
or ``https://ollama.com`` called directly with ``OLLAMA_API_KEY``. Those bill per
token, so they are recorded under ``ollama-cloud`` and never as unmetered.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

DEFAULT_HOST = "http://localhost:11434"
CLOUD_PROVIDER = "ollama-cloud"


def normalize_host(raw: str | None) -> str:
    host = (raw or "").strip() or DEFAULT_HOST
    scheme, separator, rest = host.partition("://")
    if not separator:
        rest, scheme = host, "http"
        authority = rest.split("/", 1)[0]
        if ":" not in authority.rsplit("]", 1)[-1]:
            rest = rest.replace(authority, f"{authority}:11434", 1)
    if scheme.lower() not in ("http", "https"):
        # Only the scheme is named: the value may carry ``user:password@``.
        shown = scheme if scheme.isalpha() and len(scheme) <= 16 else "an unrecognised"
        raise ValueError(f"OLLAMA_HOST must be an http(s) address, got {shown} scheme")
    return f"{scheme.lower()}://{rest}".rstrip("/")


def cloud_host(host: str) -> bool:
    name = (urlsplit(host).hostname or "").lower()
    return name == "ollama.com" or name.endswith(".ollama.com")


def cloud_model(model: str) -> bool:
    tag = model.rsplit(":", 1)[-1].lower() if ":" in model else ""
    return tag == "cloud" or tag.endswith("-cloud")


def served_by_cloud(host: str, model: str, data: dict[str, Any]) -> bool:
    return (
        cloud_host(host)
        or cloud_model(model)
        or bool(data.get("remote_model") or data.get("remote_host"))
    )


__all__ = ["CLOUD_PROVIDER", "cloud_host", "cloud_model", "normalize_host", "served_by_cloud"]
