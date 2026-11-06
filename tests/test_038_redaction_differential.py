"""0.38.0 differential redaction: the prefiltered, memoized scan is byte-identical.

The reference below is the 0.37 scan spelled out verbatim -- the same patterns in
the same order with no literal prefilter and no memo. Every string literal in the
test suite, every text fixture, and a generated corpus of credential shapes
(each ``TOKEN_SHAPES`` alternative embedded in prose, JSON and URLs) must redact
to the same bytes through both.
"""

from __future__ import annotations

import ast
import random
import re
from pathlib import Path

import pytest

import opentine.redaction as redaction
from opentine._redact_b64 import b64_text_step
from opentine._redact_edits import run, sub_step
from opentine._redact_flags import flag_edits
from opentine._redact_forms import B64_KEY_STEP, FORM_STEPS
from opentine._redact_json import redact_json
from opentine._redact_memo import LRU
from opentine._redact_obfuscated import disguised_edits, entropy_edits
from opentine._redact_pem import private_key_edits
from opentine._redact_ppk import ppk_edits
from opentine._redact_shapes import QUERY_SECRET, TOKEN_NEEDLES, TOKEN_SHAPES, URL_USERINFO

TESTS = Path(__file__).resolve().parent
MAX_LITERAL = 200_000


def _ends(match: re.Match[bytes]) -> bytes:
    return match.group(1) + b"[REDACTED]" + match.group(3)


def _head(match: re.Match[bytes]) -> bytes:
    return match.group(1) + b"[REDACTED]"


def _old_scan(value: bytes) -> bytes:
    return run(value, OLD_STEPS)


r = redaction
OLD_STEPS = [
    private_key_edits,
    ppk_edits,
    B64_KEY_STEP,
    b64_text_step(lambda value: _old_scan(value)),
    r._quoted_field_edits,
    *(sub_step(p, _ends) for p in (r._NAMED_HEADER, r._REVERSED_NAMED_HEADER, r._HEADER_PAIR)),
    *(sub_step(p, _ends) for p in (r._QUOTED_HEADER_LINE, r._QUOTED_HEADER, r._QUOTED_TOKEN)),
    sub_step(r._LINE_ASSIGNMENT, _head),
    sub_step(r._HEADER_LINE, _head),
    sub_step(r._ASSIGNMENT, r._assignment),
    sub_step(r._BEARER, _head),
    flag_edits,
    disguised_edits,
    sub_step(TOKEN_SHAPES, b"[REDACTED]"),
    sub_step(URL_USERINFO, _ends),
    sub_step(QUERY_SECRET, _head),
    *FORM_STEPS,
    entropy_edits,
]


def old_redact_blob(value: bytes) -> bytes:
    try:
        value.decode("utf-8")
    except UnicodeDecodeError:
        return value
    return redact_json(value, _old_scan, OLD_STEPS)


def _literals() -> list[bytes]:
    found: set[bytes] = set()
    for path in sorted(TESTS.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
                raw = (
                    node.value.encode("utf-8", "replace")
                    if isinstance(node.value, str)
                    else node.value
                )
                if 0 < len(raw) <= MAX_LITERAL:
                    found.add(raw)
    for path in sorted((TESTS / "fixtures").rglob("*")):
        if path.is_file() and path.stat().st_size <= MAX_LITERAL:
            data = path.read_bytes()
            found.add(data)
            found.update(line for line in data.splitlines()[:400] if line)
    return sorted(found)


SAMPLES = [
    "sk-" + "a" * 24,
    "AKIA" + "ABCDEFGHIJKLMNOP",
    "ghp_" + "x" * 30,
    "github_pat_" + "a1" * 12,
    "xoxb-" + "1234567890ab",
    "xoxe.xoxp-1-" + "a" * 24,
    "xapp-1-" + "b" * 24,
    "xai-" + "c" * 44,
    "gsk_" + "d" * 44,
    "r8_" + "e" * 34,
    "pplx-" + "f" * 44,
    "ya29." + "g" * 24,
    "GOCSPX-" + "h" * 24,
    "whsec_" + "i" * 24,
    "AIza" + "j" * 34,
    "sk_live_" + "k" * 20,
    "rk_test_" + "k" * 20,
    "glpat-" + "l" * 24,
    "hf_" + "m" * 34,
    "npm_" + "n" * 40,
    "pypi-" + "o" * 44,
    "SG." + "p" * 20 + "." + "q" * 20,
    "hvs." + "r" * 24,
    "eyJ" + "s" * 10 + ".eyJ" + "t" * 10 + "." + "u" * 10,
    "hooks.slack.com/services/" + "v" * 24,
    "discord.com/api/webhooks/123456/" + "w" * 24,
    "lsv2_pt_" + "x" * 34,
    "pcsk_" + "y" * 44,
    "tskey-auth-" + "z" * 24,
    "dop_v1_" + "a" * 64,
    "dapi" + "b" * 32,
    "lin_api_" + "C" * 34,
    "dp.st." + "d" * 34,
    "ops_eyJ" + "e" * 44,
    "shpat_" + "f" * 32,
    "vcp_" + "g" * 28,
    "AGE-SECRET-KEY-1" + "H" * 58,
    "SK" + "a" * 32,
    "api_org_" + "i" * 34,
    "sntrys_" + "j" * 44,
    "glsa_" + "k" * 34,
    "NRAK-" + "L" * 27,
    "ATATT3" + "m" * 104,
    "dckr_pat_" + "n" * 24,
    "ntn_" + "o" * 40,
    "PMAK-" + "a" * 24 + "-" + "b" * 34,
    "sq0csp-" + "p" * 44,
    "EAAA" + "q" * 64,
    "r" * 14 + ".atlasv1." + "s" * 64,
    "123456789:AA" + "t" * 33,
    "abc8Q~" + "u" * 32,
    "a" * 32 + "-us12",
]


def _generated() -> list[bytes]:
    rng = random.Random(38)
    shells = [
        "{}",
        "token {} here",
        '{{"auth": "{}", "note": "x"}}',
        "https://example.com/?key={}&a=1",
        "export API_KEY={}",
        "Authorization: Bearer {}",
        "postgres://admin:{}@db/x",
        "prefix-{}-suffix",
    ]
    out = []
    for sample in SAMPLES:
        for shell in shells:
            out.append(shell.format(sample).encode())
            cased = "".join(c.upper() if rng.random() < 0.3 else c for c in sample)
            out.append(shell.format(cased).encode())
    return out


CORPUS = _literals() + _generated()


def test_corpus_is_substantial():
    assert len(CORPUS) > 2_000


@pytest.mark.parametrize("chunk", range(8))
def test_new_scan_matches_old_scan_byte_for_byte(chunk):
    LRU.clear()
    for value in CORPUS[chunk::8]:
        assert redaction.redact_blob(value) == old_redact_blob(value), value[:200]
    # And again from the memo: a hit must return exactly what the scan would.
    for value in CORPUS[chunk::8]:
        assert redaction.redact_blob(value) == old_redact_blob(value), value[:200]


def test_every_token_sample_hits_a_needle_and_is_redacted():
    for sample in SAMPLES:
        raw = sample.encode()
        assert TOKEN_SHAPES.search(raw), sample
        assert any(needle in raw.lower() for needle in TOKEN_NEEDLES), sample
        assert raw not in redaction.redact_blob(b"value " + raw + b" end")
