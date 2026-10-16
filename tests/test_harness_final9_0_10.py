"""Final security pass 9 (0.10.0): PuTTY and RFC 4716 SSH2 keys in harness streams.

The record's scrubber learned PuTTY (``.ppk``) key files and ``---- BEGIN SSH2 …
PRIVATE KEY ----`` blocks, but the harness stream masker only anchored on the
five-dash PEM marker. A key printed line by line in text mode (``cat key.ppk``)
reached each per-line step before the scrubber saw the whole block. The masker
now opens a block on all three armors and closes a PuTTY one at ``Private-MAC``.
"""

from __future__ import annotations

import json
import time

import pytest

from opentine.harnesses import ClaudeCodeHarness, GenericHarness
from opentine.harnesses._key_extent import masked_text
from opentine.harnesses._key_mask import PLACEHOLDER, KeyLines, buffered
from opentine.redaction import redact_text
from tests.test_harness_core_0_10 import KEY_BODY, _printer, _record, _stored_bytes

PUBLIC = "AAAAC3NzaC1lZDI1NTE5AAAAIHB1YmxpY2tleXB1YmxpY2tleXB1YmxpY2tleXB1Ymxp"
PPK = [
    "PuTTY-User-Key-File-3: ssh-ed25519",
    "Encryption: none",
    "Comment: eddsa-key-20261016",
    "Public-Lines: 1",
    PUBLIC,
    "Private-Lines: 3",
    *KEY_BODY,
    "Private-MAC: 0f3a9b1c2d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8",
]
SSH2 = [
    "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----",
    'Comment: "rsa-key-20261016"',
    "Subject: deploy",
    "x-command: /usr/bin/true",
    *KEY_BODY,
    "---- END SSH2 ENCRYPTED PRIVATE KEY ----",
]
KEYS = {"ppk": PPK, "ssh2": SSH2}
_DECOR = [("", ""), ("# ", ""), ("  7  ", ""), ("\x1b[32m", "\x1b[0m"), ("│ ", " │")]


def _clean(text: str) -> bool:
    return not any(body in text for body in KEY_BODY)


@pytest.mark.parametrize("kind", KEYS)
@pytest.mark.parametrize(("prefix", "suffix"), _DECOR)
def test_each_line_of_the_key_is_masked_and_prose_after_it_kept(kind, prefix, suffix):
    keys = KeyLines()
    lines = ["$ cat key", *(prefix + line + suffix for line in KEYS[kind]), "done."]
    masked = [keys.mask(line) for line in lines]
    assert all(_clean(line) for line in masked)
    assert masked[0] == "$ cat key" and masked[-1] == "done." and not keys.open


@pytest.mark.parametrize("kind", KEYS)
def test_the_joined_output_is_never_less_redacted_than_the_raw_text(kind):
    raw = ["$ cat key", *KEYS[kind], "done."]
    keys = KeyLines()
    joined = "\n".join(buffered(keys, line, keys.mask(line)) for line in raw)
    assert _clean(redact_text(joined)) and _clean(redact_text("\n".join(raw)))
    assert redact_text(joined).endswith("done.")


@pytest.mark.parametrize("kind", KEYS)
def test_a_key_inside_one_string_is_masked_whole(kind):
    text = "here it is:\n" + "\n".join(KEYS[kind]) + "\nthat was the key"
    masked = masked_text(text)
    assert _clean(masked) and PLACEHOLDER in masked
    assert masked.startswith("here it is:") and masked.endswith("that was the key")


@pytest.mark.parametrize("kind", KEYS)
def test_a_key_in_a_json_event_string_is_masked_and_the_event_kept(kind):
    event = {"type": "text", "text": "\n".join(KEYS[kind]), "usage": {"input_tokens": 7}}
    keys = KeyLines()
    masked = keys.mask(json.dumps(event))
    parsed = json.loads(masked)
    assert _clean(parsed["text"]) and parsed["usage"] == {"input_tokens": 7}


@pytest.mark.parametrize("kind", KEYS)
def test_a_key_streamed_across_delta_events_is_masked(kind):
    lines = KEYS[kind]
    deltas = ["\n".join(lines[:2]) + "\n", "\n".join(lines[2:-1]) + "\n", lines[-1] + "\n"]
    keys = KeyLines()
    out = []
    for text in deltas:
        event = {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": text},
        }
        out.append(json.loads(keys.mask(json.dumps(event)))["delta"]["text"])
    assert all(_clean(text) for text in out)


@pytest.mark.parametrize("kind", KEYS)
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_a_printed_key_never_reaches_the_saved_record(tmp_path, kind, stream):
    printed = ["$ cat key", *KEYS[kind], "done."]
    if stream == "stdout":
        harness = GenericHarness(command=_printer(tmp_path, printed), cwd=tmp_path)
    else:
        harness = ClaudeCodeHarness(
            command=_printer(tmp_path, [], stderr=printed),
            extra_args=("--output-format", "stream-json"),
            cwd=tmp_path,
        )
    run, recorded = _record(harness)
    assert _clean(recorded)
    stored = _stored_bytes(run, tmp_path)
    assert not any(body.encode() in stored for body in KEY_BODY)
    assert b"done." in stored


def test_prose_mentioning_putty_is_not_a_key():
    keys = KeyLines()
    line = "Use PuTTYgen to convert the key; PuTTY-User-Key-File-3 is the header name."
    assert keys.mask(line) == line and not keys.open


def test_many_openers_on_one_line_stay_linear():
    def elapsed(n: int) -> float:
        line = "PuTTY-User-Key-File-3: ssh-ed25519 " * n
        started = time.perf_counter()
        KeyLines().mask(line)
        masked_text(line)
        return time.perf_counter() - started

    elapsed(200)
    small, large = elapsed(2000), elapsed(8000)
    assert large < max(small, 0.02) * 8
