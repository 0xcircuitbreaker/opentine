"""0.35 X6: credential shapes, disguises and key-ish names redaction used to keep.

Vendor prefixes the 0.34 shape set did not know, tokens hidden by URL escapes,
zero-width characters or fullwidth letters, ``DD_APP_KEY``/``TS_AUTHKEY`` names,
and an entropy fallback for high-entropy values under key-ish names. Every run
now records the ruleset it was redacted under; a run recorded before it still
loads. Every value is fake, and vendor prefixes are split so push-time secret
scanning never sees a joined one.
"""

from __future__ import annotations

import random
import string
import time

import pytest

from opentine import Run
from opentine._redact_obfuscated import REDACTION_RULESET
from opentine.policies import PolicySet, RedactionPolicy, run_redaction
from opentine.redaction import redact_text

_RNG = random.Random(35)
_ALNUM = string.ascii_letters + string.digits


def _body(n: int, alphabet: str = _ALNUM) -> str:
    return "".join(_RNG.choice(alphabet) for _ in range(n))


def _hex(n: int) -> str:
    return _body(n, "0123456789abcdef")


_SHAPES = {
    "langsmith": "lsv2" + "_pt_" + _body(32) + "_" + _hex(10),
    "pinecone": "pc" + "sk_" + _body(50),
    "tailscale": "ts" + "key-auth-" + _body(12) + "CNTRL-" + _body(24),
    "digitalocean": "do" + "p_v1_" + _hex(64),
    "databricks": "da" + "pi" + _hex(32),
    "linear": "lin" + "_api_" + _body(40),
    "doppler": "dp" + ".st." + _body(40),
    "onepassword": "op" + "s_eyJ" + _body(60),
    "shopify": "sh" + "pat_" + _hex(32),
    "vercel": "vc" + "p_" + _body(30),
    "age": "AGE-" + "SECRET-KEY-1" + _body(58, string.ascii_uppercase + string.digits),
    "twilio": "S" + "K" + _hex(32),
    "hf_org": "api" + "_org_" + _body(34),
    "sentry": "sntr" + "yu_" + _hex(64),
    "grafana": "gl" + "sa_" + _body(32) + "_" + _hex(8),
    "newrelic": "NR" + "AK-" + _body(27, string.ascii_uppercase + string.digits),
    "docker": "dckr" + "_pat_" + _body(27),
    "postman": "PM" + "AK-" + _hex(24) + "-" + _hex(34),
    "telegram": "1234567890:" + "A" + "A" + _body(33),
    "entra": _body(3) + "8Q~" + _body(34),
    "mailchimp": _hex(32) + "-us" + "12",
}


@pytest.mark.parametrize("name", sorted(_SHAPES))
def test_vendor_shapes_are_redacted_in_free_text(name):
    token = _SHAPES[name]
    out = redact_text(f"the deploy log printed {token} and moved on")
    assert token not in out
    assert "[REDACTED]" in out


@pytest.mark.parametrize(
    "disguise",
    [
        lambda t: t.replace("-", "%2D", 1),  # URL-encoded
        lambda t: t[:4] + "​" + t[4:],  # zero-width space split
        lambda t: t[:6] + "­" + t[6:],  # soft hyphen split
        lambda t: "".join(chr(ord(c) + 0xFEE0) for c in t[:2]) + t[2:],  # fullwidth
    ],
)
def test_disguised_tokens_are_redacted(disguise):
    token = "s" + "k-ant-api03-" + _body(40)
    shown = disguise(token)
    out = redact_text(f"key in url: https://x.test/?q={shown} done")
    assert _body_tail(token) not in out


def _body_tail(token: str) -> str:
    return token[-20:]


@pytest.mark.parametrize("name", ["DD_APP_KEY", "TS_AUTHKEY", "datadogAppKey"])
def test_key_names_the_rules_missed_are_redacted(name):
    secret = _hex(32)
    assert secret not in redact_text(f"{name}={secret}")
    assert secret not in redact_text(f'{{"{name}": "{secret}"}}')


def test_high_entropy_value_under_a_keyish_name_is_redacted():
    secret = _body(36)
    assert secret not in redact_text(f"acme_signkey = {secret}")
    assert secret not in redact_text(f"mykey: '{secret}'")


@pytest.mark.parametrize(
    "line",
    [
        "sha256 = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "public_key = MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE",
        "key = Ed25519PublicKey.from_public_bytes(raw)",
        'ZERO = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"',
        "idempotency_key: Xy9Kq2LmZ8pQ4rT7vW1nB6cD3fG",
        "token_count = 1234567890123456789012",
        "url = https://example.com/path%20with%20spaces/and-more-text",
        "sort_key = createdAtDescendingThenIdAscending",
    ],
)
def test_benign_lines_are_kept(line):
    assert redact_text(line) == line


def test_runs_record_the_redaction_ruleset_and_old_runs_still_load(tmp_path):
    policies = PolicySet().to_dict()
    assert policies["redaction"]["ruleset"] == REDACTION_RULESET
    assert RedactionPolicy().ruleset == REDACTION_RULESET
    run = Run(run_id="ruleset", policies=policies)
    path = run.save(tmp_path / "new.tine")
    assert Run.load(path).policies["redaction"]["ruleset"] == REDACTION_RULESET
    # A pre-0.35 policy has no ruleset key: it still applies and still loads.
    old = Run(run_id="old", policies={"redaction": {"extra_secret_keys": ["customer_ssn"]}})
    with run_redaction(old.policies):
        pass
    assert "ruleset" not in Run.load(old.save(tmp_path / "old.tine")).policies["redaction"]


def test_ruleset_is_a_reserved_field_name():
    with pytest.raises(ValueError, match="extra_secret_keys"):
        RedactionPolicy(extra_secret_keys=("ruleset",))


def test_new_steps_stay_linear():
    for chunk in ("a%2" * 40_000, "key=" + "Ab1" * 40_000, "x​" * 40_000):
        start = time.perf_counter()
        redact_text(chunk)
        assert time.perf_counter() - start < 1.5


@pytest.mark.parametrize("mark", ["‎", "‏", "‮", "⁡", "⁢", "⁤", "᠎"])
def test_tokens_split_by_other_invisible_characters_are_redacted(mark):
    token = "ghp_" + "a1B2" * 9
    assert "a1B2" not in redact_text(f"token {token[:10]}{mark}{token[10:]} end")


def test_double_url_encoded_tokens_are_redacted():
    token = "sk-ant-api03-" + "Ab3" * 30
    disguised = token.replace("-", "%252D", 1)
    assert "Ab3Ab3" not in redact_text(f"see {disguised} here")
