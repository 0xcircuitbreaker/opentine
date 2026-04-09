"""HTTP fetch and basic text extraction."""

from __future__ import annotations

import os
import re
from typing import Any

import httpx


async def fetch(url: str, max_chars: int = 8000) -> str:
    """Fetch a URL and return its text content, stripped of HTML tags."""
    proxy = os.environ.get("HTTP_PROXY")
    async with httpx.AsyncClient(timeout=30, proxy=proxy, follow_redirects=True) as client:
        resp = await client.get(url, headers={"User-Agent": "opentine/0.1"})
        resp.raise_for_status()
        text = resp.text

    # Strip HTML tags for a rough text extraction
    text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL)
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max_chars]


async def fetch_raw(url: str) -> dict[str, Any]:
    """Fetch a URL and return status, headers, and raw body."""
    proxy = os.environ.get("HTTP_PROXY")
    async with httpx.AsyncClient(timeout=30, proxy=proxy, follow_redirects=True) as client:
        resp = await client.get(url, headers={"User-Agent": "opentine/0.1"})
        return {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:16000],
        }
