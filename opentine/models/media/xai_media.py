"""xAI media: Grok Imagine image generation, billed per image.

xAI's image endpoint is OpenAI-shaped (``/v1/images/generations``) and returns
no token usage, so the call is billed per returned image against the catalog's
``grok-imagine-image*`` cards. ``XAI_API_KEY`` is used only for xAI's own host.
"""

from __future__ import annotations

import os
from typing import Any

from opentine.billing._media import media_usage
from opentine.models.media._http import MAX_MEDIA_BYTES, MediaError, parse_json, post
from opentine.models.media._result import MediaOutput, MediaResult, decode_b64, finish

DEFAULT_BASE_URL = "https://api.x.ai/v1"
_MAX_PROMPT_CHARS = 32_000


async def generate_image(
    prompt: str,
    model: str = "grok-imagine-image",
    *,
    n: int = 1,
    api_key: str | None = None,
    base_url: str | None = None,
    catalog: Any = None,
) -> MediaResult:
    if not isinstance(prompt, str) or not prompt or len(prompt) > _MAX_PROMPT_CHARS:
        raise ValueError(f"prompt must be 1..{_MAX_PROMPT_CHARS} characters")
    if not 1 <= n <= 10:
        raise ValueError("n must be 1..10")
    url = (base_url or DEFAULT_BASE_URL).rstrip("/")
    key = api_key or (os.environ.get("XAI_API_KEY", "") if url == DEFAULT_BASE_URL else "")
    if not key:
        raise MediaError("no API key: pass api_key or set XAI_API_KEY")
    body = {"model": model, "prompt": prompt, "n": n, "response_format": "b64_json"}
    raw, _ = await post(f"{url}/images/generations", key, json_body=body)
    data = parse_json(raw)
    items = data.get("data") if isinstance(data.get("data"), list) else []
    outputs = [
        MediaOutput(decode_b64(item.get("b64_json"), MAX_MEDIA_BYTES), "image/jpeg")
        for item in items[:n]
        if isinstance(item, dict) and item.get("b64_json")
    ]
    return finish(
        "xai",
        model,
        "image",
        media_usage(images=len(outputs)),
        outputs=outputs,
        request={"prompt": prompt, "n": n},
        catalog=catalog,
    )


__all__ = ["DEFAULT_BASE_URL", "generate_image"]
