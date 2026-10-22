"""OpenAI media endpoints: image generation, text-to-speech and transcription.

Each call returns a :class:`~opentine.models.media.MediaResult` whose usage is
in the catalog's media dimensions:

* images (``/images/generations``): gpt-image models report token usage, split
  into text and image input and image output (``input``/``input_image``/
  ``output_image``); a model that reports none is billed per image;
* speech (``/audio/speech``): ``tts_characters`` from the input text;
* transcription (``/audio/transcriptions``): ``audio_minutes`` when the
  response reports a duration, token buckets when it reports tokens.

A custom ``base_url`` never receives the ambient ``OPENAI_API_KEY``: pass
``api_key`` (or set ``OPENAI_COMPAT_API_KEY``), as for the chat adapters.
"""

from __future__ import annotations

import math
import os
from decimal import Decimal
from typing import Any

from opentine.billing import Usage
from opentine.billing._media import media_usage
from opentine.models.media._http import (
    MAX_MEDIA_BYTES,
    MAX_UPLOAD_BYTES,
    MediaError,
    parse_json,
    post,
)
from opentine.models.media._result import MediaOutput, MediaResult, decode_b64, finish

DEFAULT_BASE_URL = "https://api.openai.com/v1"
_MAX_PROMPT_CHARS = 32_000
_AUDIO_TYPES = {
    "mp3": "audio/mpeg",
    "opus": "audio/opus",
    "aac": "audio/aac",
    "flac": "audio/flac",
    "wav": "audio/wav",
    "pcm": "audio/pcm",
}


def _key(api_key: str | None, base_url: str | None) -> tuple[str, str]:
    url = (base_url or DEFAULT_BASE_URL).rstrip("/")
    if api_key:
        return url, api_key
    env = "OPENAI_API_KEY" if url == DEFAULT_BASE_URL else "OPENAI_COMPAT_API_KEY"
    key = os.environ.get(env, "")
    if not key:
        raise MediaError(f"no API key: pass api_key or set {env}")
    return url, key


def _text(value: str, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_PROMPT_CHARS:
        raise ValueError(f"{name} must be 1..{_MAX_PROMPT_CHARS} characters")
    return value


def _int(raw: Any, *keys: str) -> int:
    for key in keys:
        raw = raw.get(key) if isinstance(raw, dict) else None
    return raw if isinstance(raw, int) and not isinstance(raw, bool) and raw >= 0 else 0


async def generate_image(
    prompt: str,
    model: str = "gpt-image-2",
    *,
    size: str = "1024x1024",
    quality: str = "auto",
    n: int = 1,
    api_key: str | None = None,
    base_url: str | None = None,
    catalog: Any = None,
) -> MediaResult:
    if not 1 <= n <= 10:
        raise ValueError("n must be 1..10")
    url, key = _key(api_key, base_url)
    body = {"model": model, "prompt": _text(prompt, "prompt"), "size": size, "n": n}
    if quality != "auto":
        body["quality"] = quality
    raw, _ = await post(f"{url}/images/generations", key, json_body=body)
    data = parse_json(raw)
    items = data.get("data") if isinstance(data.get("data"), list) else []
    outputs = [
        MediaOutput(decode_b64(item.get("b64_json"), MAX_MEDIA_BYTES), "image/png")
        for item in items[:n]
        if isinstance(item, dict) and item.get("b64_json")
    ]
    usage_raw = data.get("usage")
    if isinstance(usage_raw, dict):
        text_in = _int(usage_raw, "input_tokens_details", "text_tokens")
        image_in = _int(usage_raw, "input_tokens_details", "image_tokens")
        total_in = _int(usage_raw, "input_tokens")
        if not text_in and not image_in:
            text_in = total_in
        usage = media_usage(
            tokens={
                "input": text_in,
                "input_image": image_in,
                "output_image": _int(usage_raw, "output_tokens"),
            }
        )
    else:
        usage = media_usage(images={f"{size}:{quality}": len(outputs)} if outputs else 0)
    return finish(
        "openai",
        model,
        "image",
        usage,
        outputs=outputs,
        request={"prompt": prompt, "size": size, "quality": quality, "n": n},
        catalog=catalog,
    )


async def speech(
    text: str,
    model: str = "gpt-4o-mini-tts",
    *,
    voice: str = "alloy",
    audio_format: str = "mp3",
    api_key: str | None = None,
    base_url: str | None = None,
    catalog: Any = None,
) -> MediaResult:
    if audio_format not in _AUDIO_TYPES:
        raise ValueError(f"audio_format must be one of {sorted(_AUDIO_TYPES)}")
    url, key = _key(api_key, base_url)
    body = {"model": model, "input": _text(text, "text"), "voice": voice}
    body["response_format"] = audio_format
    audio, content_type = await post(f"{url}/audio/speech", key, json_body=body)
    usage = media_usage(tts_characters=len(text))
    output = MediaOutput(audio, content_type or _AUDIO_TYPES[audio_format])
    return finish(
        "openai",
        model,
        "speech",
        usage,
        outputs=[output],
        request={"text": text, "voice": voice, "format": audio_format},
        catalog=catalog,
    )


async def transcribe(
    audio: bytes,
    model: str = "gpt-transcribe",
    *,
    filename: str = "audio.mp3",
    api_key: str | None = None,
    base_url: str | None = None,
    catalog: Any = None,
) -> MediaResult:
    if not audio or len(audio) > MAX_UPLOAD_BYTES:
        raise ValueError(f"audio must be 1..{MAX_UPLOAD_BYTES} bytes")
    url, key = _key(api_key, base_url)
    raw, _ = await post(
        f"{url}/audio/transcriptions",
        key,
        files={"file": (os.path.basename(filename) or "audio", audio)},
        data={"model": model, "response_format": "json"},
    )
    data = parse_json(raw)
    text = data.get("text") if isinstance(data.get("text"), str) else ""
    usage_raw = data.get("usage") if isinstance(data.get("usage"), dict) else {}
    reported = True
    seconds_raw = usage_raw.get("seconds")
    if (
        usage_raw.get("type") == "duration"
        and type(seconds_raw) in (int, float)
        and math.isfinite(seconds_raw)
        and seconds_raw >= 0
    ):
        seconds = Decimal(str(seconds_raw))
        usage = Usage(extra={"audio_minutes": seconds / 60} if seconds > 0 else {})
    elif usage_raw.get("type") == "tokens":
        audio_in = _int(usage_raw, "input_token_details", "audio_tokens")
        text_in = _int(usage_raw, "input_token_details", "text_tokens")
        if not isinstance(usage_raw.get("input_token_details"), dict):
            # No breakdown: a transcription's input is the audio it was sent.
            audio_in, text_in = _int(usage_raw, "input_tokens"), 0
        usage = media_usage(
            tokens={
                "input": text_in,
                "input_audio": audio_in,
                "output": _int(usage_raw, "output_tokens"),
            }
        )
    else:
        usage, reported = Usage(), False
    return finish(
        "openai",
        model,
        "transcription",
        usage,
        text=text,
        request={"filename": os.path.basename(filename), "bytes": len(audio)},
        usage_reported=reported,
        catalog=catalog,
    )


__all__ = ["DEFAULT_BASE_URL", "generate_image", "speech", "transcribe"]
