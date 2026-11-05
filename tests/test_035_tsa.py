"""0.35.0: a TSA retired in ``trusted_root.json`` stops vouching for new tokens.

The ``validFor`` window of a ``timestampAuthorities`` entry bounds the genTime
it may anchor: a token dated after ``validFor.end`` fails closed, one minted
while the authority was live keeps verifying.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

sys.path.insert(0, str(Path(__file__).parent))
from test_timestamp_offline_0_31 import NOW, pki, token  # noqa: E402

from opentine._tsp_verify import verify_token  # noqa: E402
from opentine._verify_timestamp import _roots  # noqa: E402

BOUND = b"run:sha256:" + b"a" * 64


def _stamp(when) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def _trusted_root(tmp_path: Path, ca, tsa, valid: dict) -> Path:
    def der(cert) -> str:
        return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()

    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    raw = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    start = {"start": "2020-01-01T00:00:00Z"}
    doc = {
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "tlogs": [
            {
                "publicKey": {"rawBytes": base64.b64encode(raw).decode(), "validFor": start},
                "logId": {"keyId": base64.b64encode(hashlib.sha256(raw).digest()).decode()},
            }
        ],
        "certificateAuthorities": [
            {"certChain": {"certificates": [{"rawBytes": der(ca)}]}, "validFor": start}
        ],
        "timestampAuthorities": [
            {
                "certChain": {"certificates": [{"rawBytes": der(tsa)}, {"rawBytes": der(ca)}]},
                "validFor": valid,
            }
        ],
    }
    path = tmp_path / "trusted_root.json"
    path.write_text(json.dumps(doc))
    return path


@pytest.fixture
def room(tmp_path: Path):
    def run(valid: dict, when=None):
        ca, tsa, key = pki()
        tr = _trusted_root(tmp_path, ca, tsa, valid)
        roots, windowed, _ = _roots(argparse.Namespace(tsa_roots=None, trusted_root=str(tr)))
        return verify_token(token(BOUND, tsa, key, when=when), BOUND, roots, windowed)

    return run


def test_a_tsa_retired_before_gentime_fails_closed(room):
    verdict = room({"start": "2020-01-01T00:00:00Z", "end": "2021-01-01T00:00:00Z"})
    assert not verdict.ok
    assert verdict.reason == "timestamp.tsa-retired"
    assert not verdict.no_roots


def test_a_token_minted_before_retirement_still_verifies(room):
    end = _stamp(NOW + timedelta(hours=1))
    verdict = room({"start": "2020-01-01T00:00:00Z", "end": end}, when=NOW)
    assert verdict.ok, verdict.reason


def test_a_tsa_not_yet_valid_at_gentime_fails(room):
    verdict = room({"start": _stamp(NOW + timedelta(hours=1))})
    assert verdict.reason == "timestamp.tsa-retired"


def test_an_open_ended_tsa_verifies(room):
    assert room({"start": "2020-01-01T00:00:00Z"}).ok
