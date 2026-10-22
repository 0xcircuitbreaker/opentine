"""``tine media``: image generation, text-to-speech and transcription as recorded runs."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from typing import Any

from opentine._cli_common import _terminal, console

_EXTENSIONS = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp"}


def add_media_parser(sub: Any) -> None:
    media = sub.add_parser("media", help="Generate images or speech, or transcribe audio")
    kinds = media.add_subparsers(dest="media_kind", required=True)
    image = kinds.add_parser("image", help="Generate images from a prompt")
    image.add_argument("prompt")
    image.add_argument("--provider", choices=("openai", "xai"), default="openai")
    image.add_argument("--model", help="Model id (default per provider)")
    image.add_argument("--size", default="1024x1024")
    image.add_argument("--quality", default="auto")
    image.add_argument("-n", type=int, default=1, help="Number of images (1-10)")
    image.add_argument("--out", help="Directory for the images (default: .)")
    speech = kinds.add_parser("speech", help="Synthesize speech from text")
    speech.add_argument("text")
    speech.add_argument("--model", help="Default gpt-4o-mini-tts")
    speech.add_argument("--voice", default="alloy")
    speech.add_argument("--format", dest="audio_format", default="mp3")
    speech.add_argument("--out", help="Output file, extension added (default: speech)")
    transcribe = kinds.add_parser("transcribe", help="Transcribe an audio file")
    transcribe.add_argument("audio")
    transcribe.add_argument("--model", help="Default gpt-transcribe")
    for parser in (image, speech, transcribe):
        parser.add_argument("--base-url", help="Compatible endpoint (needs --api-key-env)")
        parser.add_argument("--api-key-env", help="Environment variable holding the API key")
        parser.add_argument("--save", help="Record the call as a run in this .tine file")
        parser.add_argument("--force", action="store_true", help="Overwrite --save / outputs")


def _key(args: argparse.Namespace) -> str | None:
    import os

    if args.base_url and not args.api_key_env:
        raise SystemExit("--base-url needs --api-key-env, so no first-party key is sent there")
    if args.api_key_env:
        value = os.environ.get(args.api_key_env, "")
        if not value:
            raise SystemExit(f"{args.api_key_env} is not set")
        return value
    return None


def _write(path: Path, data: bytes, force: bool) -> None:
    if path.exists() and not force:
        raise SystemExit(f"{path} exists; pass --force to overwrite")
    from opentine._codec_io import atomic_write_bytes

    atomic_write_bytes(path, data)


async def _call(args: argparse.Namespace) -> Any:
    from opentine.models.media import openai_media, xai_media

    key = _key(args)
    common = {"api_key": key, "base_url": args.base_url}
    if args.media_kind == "image":
        module = xai_media if args.provider == "xai" else openai_media
        extra = {} if args.provider == "xai" else {"size": args.size, "quality": args.quality}
        model = args.model or ("grok-imagine-image" if args.provider == "xai" else "gpt-image-2")
        return await module.generate_image(args.prompt, model, n=args.n, **extra, **common)
    if args.media_kind == "speech":
        return await openai_media.speech(
            args.text,
            args.model or "gpt-4o-mini-tts",
            voice=args.voice,
            audio_format=args.audio_format,
            **common,
        )
    audio = Path(args.audio)
    if not audio.is_file():
        raise SystemExit(f"{audio} is not a file")
    from opentine.models.media._http import MAX_UPLOAD_BYTES

    if audio.stat().st_size > MAX_UPLOAD_BYTES:
        raise SystemExit(f"{audio} is larger than {MAX_UPLOAD_BYTES} bytes")
    return await openai_media.transcribe(
        audio.read_bytes(), args.model or "gpt-transcribe", filename=audio.name, **common
    )


def cmd_media(args: argparse.Namespace) -> None:
    result = asyncio.run(_call(args))
    written: list[Path] = []
    if args.media_kind == "image":
        directory = Path(args.out or ".")
        directory.mkdir(parents=True, exist_ok=True)
        for index, output in enumerate(result.outputs, start=1):
            suffix = _EXTENSIONS.get(output.content_type, "bin")
            target = directory / f"image-{index}.{suffix}"
            _write(target, output.data, args.force)
            written.append(target)
    elif args.media_kind == "speech" and result.outputs:
        target = Path(f"{args.out or 'speech'}.{args.audio_format}")
        _write(target, result.outputs[0].data, args.force)
        written.append(target)
    else:
        console.print(_terminal(result.text))
    if args.save:
        from opentine import Run

        save = Path(args.save)
        if save.exists() and not args.force:
            raise SystemExit(f"{save} exists; pass --force to overwrite")
        run = Run(model_info=result.model)
        result.record(run)
        run.save(save)
        written.append(save)
    status = result.billing.get("status", "unknown")
    console.print(
        f"[dim]{_terminal(result.provider)}/{_terminal(result.model)} "
        f"cost=${result.cost:.6f} ({_terminal(str(status))})[/]"
    )
    for path in written:
        console.print(f"[dim]wrote {_terminal(str(path))}[/]")


COMMANDS = {"media": cmd_media}

__all__ = ["COMMANDS", "add_media_parser", "cmd_media"]
