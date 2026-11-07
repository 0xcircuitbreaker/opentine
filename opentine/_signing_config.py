"""Sigstore ``SigningConfig`` (TUF target ``signing_config.v0.2.json``; 0.44, X34).

Chooses the Rekor log(s) and TSA(s) a signer should use instead of a hard-wired
Rekor v1 URL. The document (``application/vnd.dev.sigstore.signingconfig.v0.2+json``,
``dev.sigstore.trustroot.v1.SigningConfig``) lists ``caUrls``, ``oidcUrls``,
``rekorTlogUrls`` and ``tsaUrls`` as ``Service`` objects ``{url,
majorApiVersion, validFor {start, end?}, operator}`` plus ``rekorTlogConfig`` /
``tsaConfig`` ``{selector: ALL | ANY | EXACT, count}``.

Selection, as the protobuf comments describe it: keep services whose
``validFor`` holds *now* and whose ``majorApiVersion`` the client supports;
prefer the highest API version, then the newest ``validFor.start``; keep one
per operator; then ``ALL`` keeps all, ``ANY`` the first, ``EXACT`` the first
``count`` (fewer is an error). The file is read from disk (a TUF client put it
there); this module never fetches.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

MEDIA_TYPE = "application/vnd.dev.sigstore.signingconfig.v0.2+json"
MAX_BYTES = 1 << 20
SELECTORS = ("ALL", "ANY", "EXACT")
#: The Rekor API majors opentine verifies: v1 (SET + proof) and v2 (tile proofs).
REKOR_VERSIONS = (1, 2)
TSA_VERSIONS = (1,)


def _time(value: Any, what: str) -> datetime:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        raise ValueError(f"{what} is not an RFC 3339 time") from None


def _services(doc: dict, name: str) -> list[dict[str, Any]]:
    items = doc.get(name) or []
    if not isinstance(items, list) or len(items) > 100:
        raise ValueError(f"signing config {name} is not a bounded list")
    out = []
    for i, item in enumerate(items):
        what = f"{name}[{i}]"
        if not isinstance(item, dict) or not isinstance(item.get("url"), str):
            raise ValueError(f"{what} has no url")
        if not str(item["url"]).startswith("https://"):
            raise ValueError(f"{what} url is not https")
        major = item.get("majorApiVersion")
        if isinstance(major, bool) or not isinstance(major, int) or major < 1:
            raise ValueError(f"{what} majorApiVersion is not a positive integer")
        valid = item.get("validFor")
        if not isinstance(valid, dict) or "start" not in valid:
            raise ValueError(f"{what} has no validFor.start")
        start = _time(valid["start"], f"{what} validFor.start")
        end = _time(valid["end"], f"{what} validFor.end") if valid.get("end") else None
        out.append({"end": end, "major": major, "operator": str(item.get("operator", "")),
                    "start": start, "url": item["url"]})  # fmt: skip
    return out


def parse(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_BYTES:
        raise ValueError("signing config is too large")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ValueError("signing config is not JSON") from None
    if not isinstance(doc, dict) or doc.get("mediaType") != MEDIA_TYPE:
        raise ValueError(f"not a {MEDIA_TYPE} document")
    return doc


def select(
    doc: dict, kind: str, *, now: datetime | None = None, versions: tuple[int, ...] | None = None
) -> list[str]:
    """The URLs to use for ``kind`` (``rekor`` or ``tsa``), in preference order."""
    names = {"rekor": ("rekorTlogUrls", "rekorTlogConfig", REKOR_VERSIONS),
             "tsa": ("tsaUrls", "tsaConfig", TSA_VERSIONS)}  # fmt: skip
    if kind not in names:
        raise ValueError(f"unknown service kind {kind!r}")
    field, config_name, default = names[kind]
    supported = versions or default
    now = now or datetime.now(UTC)
    usable = [
        s for s in _services(doc, field)
        if s["major"] in supported and s["start"] <= now and (s["end"] is None or now < s["end"])
    ]  # fmt: skip
    usable.sort(key=lambda s: (s["major"], s["start"]), reverse=True)
    chosen, operators = [], set()
    for service in usable:
        if service["operator"] not in operators:
            operators.add(service["operator"])
            chosen.append(service["url"])
    config = doc.get(config_name) or {"selector": "ANY"}
    selector = config.get("selector") if isinstance(config, dict) else None
    if selector not in SELECTORS:
        raise ValueError(f"{config_name}.selector must be one of {', '.join(SELECTORS)}")
    if not chosen:
        raise ValueError(f"signing config lists no usable {kind} service now")
    if selector == "ANY":
        return chosen[:1]
    if selector == "EXACT":
        count = config.get("count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise ValueError(f"{config_name}.count must be a positive integer for EXACT")
        if len(chosen) < count:
            raise ValueError(
                f"signing config has {len(chosen)} usable {kind} services, needs {count}"
            )
        return chosen[:count]
    return chosen
