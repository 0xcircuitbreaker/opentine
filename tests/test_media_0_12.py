"""0.12 media endpoints, the Gemini image/video input split and the xAI media cards."""

from __future__ import annotations

import asyncio
import base64
import json
import threading
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from opentine import Run
from opentine._pricing_pass import price_steps
from opentine.billing import bill, load_catalogs
from opentine.models._usage import google_usage
from opentine.models.media import MediaError, openai_media, xai_media
from opentine.models.media import _http as media_http

PNG = b"\x89PNG\r\n\x1a\nFAKEIMAGEBYTES"
WHEN = "2026-10-22"


class _Fake(BaseHTTPRequestHandler):
    seen: list[dict] = []
    oversize = False

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        type(self).seen.append(
            {"path": self.path, "auth": self.headers.get("Authorization"), "body": body}
        )
        if self.path.endswith("/redirect/images/generations"):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/steal")
            self.end_headers()
            return
        if self.path.endswith("/images/generations"):
            request = json.loads(body)
            data = [{"b64_json": base64.b64encode(PNG).decode()}] * request.get("n", 1)
            payload = {"data": data}
            if request.get("model", "").startswith("gpt-image"):
                payload["usage"] = {
                    "input_tokens": 50,
                    "input_tokens_details": {"text_tokens": 40, "image_tokens": 10},
                    "output_tokens": 1000,
                }
            return self._send(json.dumps(payload).encode(), "application/json")
        if self.path.endswith("/audio/speech"):
            size = media_http.MAX_MEDIA_BYTES + 10 if type(self).oversize else 32
            return self._send(b"A" * size, "audio/mpeg")
        if self.path.endswith("/audio/transcriptions"):
            payload = {"text": "hello world", "usage": {"type": "duration", "seconds": 120}}
            return self._send(json.dumps(payload).encode(), "application/json")
        self.send_response(404)
        self.end_headers()

    def _send(self, body: bytes, content_type: str):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def server():
    _Fake.seen = []
    _Fake.oversize = False
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Fake)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_port}/v1"
    httpd.shutdown()


@pytest.fixture(autouse=True)
def _today(monkeypatch):
    # Bill against the catalog as of the cards' verification date.
    import opentine.models._metered as metered

    real = metered.billing_moment
    monkeypatch.setattr(metered, "billing_moment", lambda value: real(value or WHEN))


def _run(coro):
    return asyncio.run(coro)


def test_openai_image_bills_text_image_input_and_image_output(server):
    result = _run(openai_media.generate_image("a cat", "gpt-image-2", base_url=server, api_key="k"))
    assert [item.data for item in result.outputs] == [PNG]
    calc = result.billing["calculation"]["components_usd"]
    assert result.billing["status"] == "complete"
    assert Decimal(calc["input"]) == Decimal(40) * Decimal("5.00") / 1_000_000
    assert Decimal(calc["input_image"]) == Decimal(10) * Decimal("8.00") / 1_000_000
    assert Decimal(calc["output_image"]) == Decimal(1000) * Decimal("30.00") / 1_000_000


def test_speech_bills_characters_and_returns_audio(server):
    result = _run(openai_media.speech("hello there", "tts-1", base_url=server, api_key="k"))
    assert result.outputs[0].data == b"A" * 32
    assert Decimal(result.billing["amount_usd"]) == Decimal(11) * Decimal("0.000015")


def test_transcription_bills_minutes(server):
    result = _run(openai_media.transcribe(b"RIFF....", "whisper-1", base_url=server, api_key="k"))
    assert result.text == "hello world"
    assert Decimal(result.billing["amount_usd"]) == Decimal(2) * Decimal("0.006")


def test_xai_image_bills_per_image(server):
    result = _run(
        xai_media.generate_image(
            "a dog", "grok-imagine-image-2.0", n=2, base_url=server, api_key="k"
        )
    )
    assert len(result.outputs) == 2
    assert result.billing["status"] == "complete"
    assert Decimal(result.billing["amount_usd"]) == Decimal("0.08")


def test_a_recorded_media_step_reprices_identically(server):
    result = _run(openai_media.speech("hello there", "tts-1", base_url=server, api_key="k"))
    run = Run(model_info="tts-1")
    step = result.record(run)
    assert "data" not in json.dumps(step.outputs) or "sha256" in json.dumps(step.outputs)
    assert step.outputs["media"][0]["bytes"] == 32
    priced = price_steps(run.steps, effective_at=WHEN)
    assert Decimal(str(priced.total_cost)) == Decimal(result.billing["amount_usd"])


def test_custom_base_url_never_gets_the_ambient_openai_key(server, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-ambient-secret")
    monkeypatch.delenv("OPENAI_COMPAT_API_KEY", raising=False)
    with pytest.raises(MediaError, match="OPENAI_COMPAT_API_KEY"):
        _run(openai_media.speech("hi", "tts-1", base_url=server))
    assert not any("sk-ambient-secret" in str(item["auth"]) for item in _Fake.seen)


def test_redirects_are_not_followed(server):
    with pytest.raises(MediaError, match="HTTP 302"):
        _run(xai_media.generate_image("x", base_url=server + "/redirect", api_key="k"))


def test_oversized_media_response_is_refused(server, monkeypatch):
    monkeypatch.setattr(media_http, "MAX_MEDIA_BYTES", 1024)
    _Fake.oversize = True
    with pytest.raises(MediaError, match="exceeds"):
        _run(openai_media.speech("hi", "tts-1", base_url=server, api_key="k"))


def test_cleartext_key_to_a_non_loopback_host_is_refused():
    with pytest.raises(ValueError, match="cleartext"):
        _run(openai_media.speech("hi", "tts-1", base_url="http://192.0.2.1/v1", api_key="k"))


def test_gemini_splits_prompt_image_and_video_tokens():
    usage = google_usage(
        {
            "promptTokenCount": 1000,
            "candidatesTokenCount": 10,
            "promptTokensDetails": [
                {"modality": "TEXT", "tokenCount": 700},
                {"modality": "IMAGE", "tokenCount": 200},
                {"modality": "VIDEO", "tokenCount": 100},
            ],
        }
    )
    assert usage.input == 700
    assert usage.extra["input_image"] == 200
    assert usage.extra["input_video"] == 100


def test_the_split_prices_identically_on_a_text_only_gemini_card():
    catalog = load_catalogs()
    split = google_usage(
        {
            "promptTokenCount": 1000,
            "candidatesTokenCount": 10,
            "promptTokensDetails": [
                {"modality": "TEXT", "tokenCount": 700},
                {"modality": "IMAGE", "tokenCount": 300},
            ],
        }
    )
    plain = google_usage({"promptTokenCount": 1000, "candidatesTokenCount": 10})
    a = bill("google", "gemini-3.8-flash", split, catalog=catalog, effective_at=WHEN)
    b = bill("google", "gemini-3.8-flash", plain, catalog=catalog, effective_at=WHEN)
    assert a.status == b.status == "complete"
    assert a.amount_usd == b.amount_usd


def test_an_inconsistent_gemini_breakdown_keeps_everything_in_input():
    usage = google_usage(
        {
            "promptTokenCount": 100,
            "candidatesTokenCount": 1,
            "promptTokensDetails": [{"modality": "IMAGE", "tokenCount": 500}],
        }
    )
    assert usage.input == 100 and "input_image" not in usage.extra


def test_media_input_on_a_non_google_card_is_not_folded_into_text():
    catalog = load_catalogs()
    from opentine.billing import Usage

    result = bill(
        "openai",
        "gpt-6.1-sol",
        Usage(input=10, output=1, extra={"input_video": 5}),
        catalog=catalog,
        effective_at=WHEN,
    )
    assert result.status != "complete"


def test_xai_media_cards_are_signed_and_present():
    catalog = load_catalogs()
    for model, rate in (
        ("grok-imagine-image", "0.02"),
        ("grok-imagine-image-quality", "0.05"),
        ("grok-imagine-video-1.5", "0.080"),
        ("grok-voice-3.0", "0.08"),
    ):
        card = catalog.lookup("xai", model, effective_at=WHEN)
        assert card is not None and str(next(iter(card.rates.values()))) == rate


def test_tine_media_image_cli_writes_files_and_a_run(server, tmp_path, monkeypatch):
    from opentine.cli import main

    monkeypatch.setenv("FAKE_MEDIA_KEY", "k")
    monkeypatch.chdir(tmp_path)
    main(
        [
            "media",
            "image",
            "a cat",
            "--provider",
            "xai",
            "--base-url",
            server,
            "--api-key-env",
            "FAKE_MEDIA_KEY",
            "--out",
            "imgs",
            "--save",
            "media.tine",
        ]
    )
    assert (tmp_path / "imgs" / "image-1.jpg").read_bytes() == PNG
    run = Run.load(tmp_path / "media.tine")
    assert run.steps[0].provider == "xai"


def test_tine_media_refuses_base_url_without_an_explicit_key(server):
    from opentine.cli import main

    with pytest.raises(SystemExit):
        main(["media", "speech", "hi", "--base-url", server])


@pytest.mark.parametrize(
    ("usage", "minutes", "audio"),
    [
        ({"type": "tokens", "input_tokens": 300, "output_tokens": 5}, None, 300),
        ({"type": "duration", "seconds": float("inf")}, None, None),
        ({"type": "duration", "seconds": -5}, None, None),
    ],
)
def test_transcription_usage_edge_cases(server, monkeypatch, usage, minutes, audio):
    real = _Fake.do_POST

    def do_post(self):
        if self.path.endswith("/audio/transcriptions"):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            body = json.dumps({"text": "hi", "usage": usage}, allow_nan=True).encode()
            return self._send(body, "application/json")
        return real(self)

    monkeypatch.setattr(_Fake, "do_POST", do_post)
    result = _run(openai_media.transcribe(b"RIFF....", "whisper-1", base_url=server, api_key="k"))
    if audio is not None:
        assert (
            result.usage.extra.get("input_audio") == audio or audio in result.usage.extra.values()
        )
    else:
        assert "audio_minutes" not in result.usage.extra
