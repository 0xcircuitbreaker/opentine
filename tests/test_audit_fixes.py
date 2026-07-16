"""Regression tests for the audit follow-up fixes (v0.2.1/v0.3.0).

Each test name references the audit finding it guards.
"""

from __future__ import annotations

import json
import threading
import zlib
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from pathlib import Path

import httpx
import pytest

from opentine import Run
from opentine._canon import _redact
from opentine.kernel import (
    KernelError,
    ObjectEnvelope,
    canonical_json,
    object_id,
)
from opentine.redaction import redact_blob
from opentine.repository import Repo
from opentine.repository.client import _read_pack, capabilities
from opentine.repository.pack import MAGIC, create_pack, inspect_pack, install_pack
from opentine.signing import SignatureError
from opentine.trace.capture import code_manifest

FIXTURES = Path(__file__).parent / "fixtures"


# --- H1: content-address integrity for large integers ---------------------------------


def test_h1_kernel_rejects_unsafe_integers_instead_of_colliding():
    # Distinct large integers previously coerced to the same float -> same object id.
    with pytest.raises(KernelError, match="2\\*\\*53"):
        canonical_json({"balance": 10**20})
    with pytest.raises(KernelError, match="2\\*\\*53"):
        canonical_json(9_223_372_036_854_775_807)
    with pytest.raises(KernelError, match="schema"):
        object_id("blob", 2**53, b"x")
    # The exactly representable boundary is still accepted.
    assert canonical_json(9_007_199_254_740_991) == b"9007199254740991"
    assert canonical_json(-9_007_199_254_740_991) == b"-9007199254740991"
    # Floats are unaffected (already IEEE-754 doubles).
    assert canonical_json(1e20) == b"100000000000000000000"
    envelope = ObjectEnvelope.create("annotation", {"x": 1e20})
    decoded = ObjectEnvelope.decode(envelope.encode(), envelope.oid)
    assert decoded.payload()["x"] == 1e20


def test_h1_nonrepresentable_integer_body_is_not_laundered_as_a_float():
    body = b'{"x":100000000000000000001}'
    header = canonical_json({"encoding": "json", "schema": 1, "type": "annotation"})
    oid = object_id("annotation", 1, body)
    with pytest.raises(KernelError, match="non-canonical object body"):
        ObjectEnvelope.decode(header + b"\n" + body, oid)


# --- H2: pack decompression bomb -------------------------------------------------------


def test_h2_pack_decompression_is_bounded():
    bomb = MAGIC + b"\0" * 32 + zlib.compress(b"A" * (4 * 1024 * 1024))
    with pytest.raises(KernelError, match="maximum decompressed size"):
        inspect_pack(bomb, max_body=64 * 1024)


def test_h2_legitimate_pack_still_round_trips(tmp_path: Path):
    repo = Repo.init(tmp_path / "a")
    oid = repo.put("blob", b"hello", redact=False)
    data = create_pack(repo, [oid])
    dest = Repo.init(tmp_path / "b")
    result = install_pack(dest, data)  # default generous bound
    assert oid in result.objects


def test_h2_pack_rejects_trailing_compressed_data(tmp_path: Path):
    repo = Repo.init(tmp_path)
    pack = create_pack(repo, [repo.put("blob", b"hello", redact=False)])
    with pytest.raises(KernelError, match="trailing compressed data"):
        inspect_pack(pack + b"uncommitted-tail")


def test_h2_remote_pack_is_bounded_before_install():
    declared = httpx.Response(200, headers={"content-length": "100"}, content=b"")
    with pytest.raises(ValueError, match="maximum transfer"):
        _read_pack(declared, limit=10)
    streamed = httpx.Response(200, content=b"x" * 11)
    with pytest.raises(ValueError, match="maximum transfer"):
        _read_pack(streamed, limit=10)
    with pytest.raises(ValueError, match="requires HTTPS"):
        capabilities("http://remote.example")


# --- M1: redaction of vendor-prefixed and header-style key names -----------------------


def test_m1_redaction_scrubs_prefixed_and_header_credentials():
    blob = (
        b'{"OPENAI_API_KEY":"sk-proj-longsecret1234567","x-api-key":"sk-ant-secretheader",'
        b'"input_tokens":1234,"cached_tokens":7,"public_key":"ssh-ed25519 AAAA"}'
    )
    out = redact_blob(blob)
    assert b"sk-proj-longsecret1234567" not in out
    assert b"sk-ant-secretheader" not in out
    # Usage counters and benign keys survive.
    assert b'"input_tokens":1234' in out
    assert b'"cached_tokens":7' in out
    assert b"ssh-ed25519 AAAA" in out
    headers = redact_blob(
        b'{"Authorization":"Basic dXNlcjpwYXNz","Cookie":"session=secret","token":"opaque"}'
    )
    assert b"dXNlcjpwYXNz" not in headers
    assert b"session=secret" not in headers
    assert b'"token":"opaque"' not in headers
    structured = _redact(
        {"AWS_SECRET_ACCESS_KEY": "secret", "input_tokens": 5, "public_key": "safe"}
    )
    assert structured == {
        "AWS_SECRET_ACCESS_KEY": "[REDACTED]",
        "input_tokens": 5,
        "public_key": "safe",
    }


# --- M2: v2 migration is fail-closed ---------------------------------------------------


def _tampered_v2(tmp_path: Path) -> Path:
    data = json.loads((FIXTURES / "golden_v2.tine").read_bytes())
    data["created_at"] = 1.0  # integrity-covered field, Run.load-safe
    dest = tmp_path / "tampered.tine"
    dest.write_text(json.dumps(data))
    return dest


def test_m2_migration_rejects_tampered_artifact(tmp_path: Path):
    repo = Repo.init(tmp_path / "repo")
    tampered = _tampered_v2(tmp_path)
    with pytest.raises(SignatureError, match="tampered"):
        repo.migrate_v2(str(tampered), ref="heads/x")


def test_m2_migration_escape_hatch_allows_unverified(tmp_path: Path):
    repo = Repo.init(tmp_path / "repo")
    tampered = _tampered_v2(tmp_path)
    result = repo.migrate_v2(str(tampered), ref="heads/x", strict=False)
    assert result.run_id.startswith("run:sha256:")


# --- M3: atomic compare-and-swap ref updates -------------------------------------------


def test_m3_ref_cas_mismatch_releases_lock(tmp_path: Path):
    repo = Repo.init(tmp_path)
    a = repo.put("blob", b"a", redact=False)
    b = repo.put("blob", b"b", redact=False)
    repo.update_ref("tags/main", a)
    with pytest.raises(ValueError, match="concurrent ref update"):
        repo.update_ref("tags/main", b, expected_old="wrong")
    assert not (repo.path / "refs" / "tags" / "main.lock").exists()
    # A correct CAS still succeeds after the mismatch (lock was not left stale).
    repo.update_ref("tags/main", b, expected_old=a)
    assert repo.read_ref("tags/main") == b
    assert set(repo.list_refs()) == {"tags/main"}


def test_m3_ref_cas_allows_exactly_one_concurrent_writer(tmp_path: Path):
    repo = Repo.init(tmp_path)
    old = repo.put("blob", b"old", redact=False)
    candidates = [repo.put("blob", value, redact=False) for value in (b"left", b"right")]
    repo.update_ref("tags/main", old)
    barrier = threading.Barrier(2)

    def update(candidate: str) -> bool:
        barrier.wait()
        try:
            repo.update_ref("tags/main", candidate, expected_old=old)
        except ValueError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(update, candidates))
    assert sorted(results) == [False, True]
    assert repo.read_ref("tags/main") in candidates


# --- N1: tiered context pricing replaces rather than compounds --------------------------


def test_n1_context_thresholds_do_not_compound():
    from opentine.billing.engine import _threshold_rates
    from opentine.billing.types import RateCard, Usage

    card = RateCard(
        id="t",
        provider="p",
        model="m",
        rates={"input": Decimal("1")},
        context_thresholds=(
            {"id": "gt200k", "input_tokens": 200_000, "multipliers": {"input": "2"}},
            {"id": "gt1m", "input_tokens": 1_000_000, "multipliers": {"input": "2"}},
        ),
    )
    rates, applied = _threshold_rates(card, Usage(input=2_000_000))
    assert rates["input"] == Decimal("2")  # highest tier only, not 2*2=4
    assert applied == ["gt1m"]


# --- M8: top-level cache fields billed at the cache rate --------------------------------


def test_m8_top_level_cache_tokens_are_cache_read():
    from opentine.models._usage import openai_usage

    usage = openai_usage(
        {"prompt_tokens": 100, "completion_tokens": 50, "prompt_cache_hit_tokens": 80}
    )
    assert usage.input == 20  # fresh input = prompt - cached
    assert usage.cache_read == 80

    # An explicit nested zero takes precedence over a provider's unrelated top-level field.
    nested = openai_usage(
        {
            "prompt_tokens": 100,
            "prompt_tokens_details": {"cached_tokens": 0},
            "prompt_cache_hit_tokens": 80,
        }
    )
    assert nested.input == 100 and nested.cache_read == 0


# --- LOW: envelope header cannot carry unbound extra keys -------------------------------


def test_envelope_header_binding_rejects_extra_keys():
    body = canonical_json({"a": 1})
    header = canonical_json({"encoding": "json", "extra": "x", "schema": 1, "type": "annotation"})
    stored = header + b"\n" + body
    oid = object_id("annotation", 1, body)
    with pytest.raises(KernelError, match="non-canonical object header"):
        ObjectEnvelope.decode(stored, oid)


# --- LOW: repository save target rejects artifact signing ------------------------------


def test_save_run_repo_target_rejects_signing(tmp_path: Path):
    Repo.init(tmp_path)
    run = Run(id="r1")
    with pytest.raises(SignatureError, match="do not support signing"):
        run.save(tmp_path, sign_key=b"k" * 32, sign_algorithm="hmac-sha256")


def test_code_manifest_reports_capture_failure(tmp_path: Path):
    manifest = code_manifest(tmp_path)
    assert manifest["capture_complete"] is False
    assert manifest["capture_errors"] and manifest["commit"] is None
