"""0.41 (X29): ML-DSA-65, the composite ed25519+ml-dsa-65, 0.34 compat, the hash tag."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import textwrap
from pathlib import Path

import pytest

from opentine._artifact_v4 import write_v4
from opentine._hash_tag import UnsupportedHashAlgorithm, hash_tag, parse_oid
from opentine._pyz import _mldsa, _sig
from opentine._signing_pq import (
    COMPOSITE,
    COMPOSITE_CONTEXT,
    HAS_MLDSA,
    MLDSA65,
    mldsa_verify,
    sign_hybrid,
)
from opentine._signing_v4 import append_signature, verify_artifact_v4
from opentine.core import Run
from opentine.kernel import KernelError, canonical_json
from opentine.kernel import parse_oid as kernel_parse_oid
from opentine.repository.store import Repo

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
ACVP = json.loads((FIXTURES / "acvp" / "ml_dsa_65_sigver.json").read_text(encoding="utf-8"))
ED_SEED = bytes(range(32))
PQ_SEED = bytes(range(32, 64))
AT = "2026-11-01T00:00:00Z"

needs_mldsa = pytest.mark.skipif(not HAS_MLDSA, reason="cryptography lacks ML-DSA")


def _acvp_cases(interface: str) -> list:
    cases: list = []
    for group in ACVP["testGroups"]:
        if group["signatureInterface"] == interface:
            for case in group["tests"]:
                cases.append(pytest.param(case, id=f"tc{case['tcId']}"))
    return cases


# -- ML-DSA-65 against NIST ACVP sigVer (FIPS 204) ---------------------------------


@pytest.mark.parametrize("case", _acvp_cases("external"))
def test_pure_python_mldsa_matches_acvp_external(case):
    pk, msg, sig = (bytes.fromhex(case[k]) for k in ("pk", "message", "signature"))
    ok = _mldsa.verify(pk, msg, sig, bytes.fromhex(case["context"]))
    assert ok is case["testPassed"], case["reason"]


@pytest.mark.parametrize("case", _acvp_cases("internal"))
def test_pure_python_mldsa_matches_acvp_internal(case):
    pk, msg, sig = (bytes.fromhex(case[k]) for k in ("pk", "message", "signature"))
    assert _mldsa.verify_internal(pk, msg, sig) is case["testPassed"], case["reason"]


@needs_mldsa
@pytest.mark.parametrize("case", _acvp_cases("external"))
def test_cryptography_mldsa_matches_acvp_external(case):
    pk, msg, sig = (bytes.fromhex(case[k]) for k in ("pk", "message", "signature"))
    ok = mldsa_verify(pk, msg, sig, bytes.fromhex(case["context"]))
    assert ok is case["testPassed"], case["reason"]


def test_acvp_fixture_has_both_verdicts():
    verdicts = {case["testPassed"] for group in ACVP["testGroups"] for case in group["tests"]}
    assert verdicts == {True, False}
    assert {g["parameterSet"] for g in ACVP["testGroups"]} == {"ML-DSA-65"}


@needs_mldsa
def test_pure_python_agrees_with_cryptography_signatures():
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

    key = MLDSA65PrivateKey.from_seed_bytes(PQ_SEED)
    public = key.public_key().public_bytes_raw()
    for n, context in enumerate((b"", COMPOSITE_CONTEXT, b"x" * 255)):
        message = bytes([n]) * (n * 97 + 1)
        signature = key.sign(message, context or None)
        assert _mldsa.verify(public, message, signature, context)
        assert not _mldsa.verify(public, message + b"!", signature, context)
        assert not _mldsa.verify(public, message, signature, context + b"?")
        forged = bytearray(signature)
        forged[100] ^= 1
        assert not _mldsa.verify(public, message, bytes(forged), context)
    assert not _mldsa.verify(public, b"m", key.sign(b"m"), b"c" * 256)  # context > 255 bytes
    assert not _mldsa.verify(public[:-1], b"m", key.sign(b"m"))


# -- tine-sig/3 blocks ----------------------------------------------------------


@pytest.fixture(scope="module")
def v4_doc():
    return json.loads(write_v4(Run.load(FIXTURES / "golden_v2.tine")))


@pytest.fixture(scope="module")
def hybrid(v4_doc):
    if not HAS_MLDSA:
        return json.loads((FIXTURES / "pq_hybrid_v4.tine").read_text(encoding="utf-8"))
    return json.loads(sign_hybrid(v4_doc, ED_SEED, PQ_SEED, key_id="pq-demo", signed_at=AT))


def _pub(block):
    return bytes.fromhex(block["public_key"])


def _with(doc, *blocks):
    return {**doc, "signatures": list(blocks)}


def test_hybrid_writes_a_classical_block_first(hybrid):
    classical, composite = hybrid["signatures"]
    assert (classical["alg"], composite["alg"]) == ("ed25519", COMPOSITE)
    assert composite["public_key"][:64] == classical["public_key"]
    assert len(composite["value"]) == 2 * (64 + _mldsa.SIGNATURE_BYTES)


def test_hybrid_verifies_under_the_composite_key(hybrid):
    composite = hybrid["signatures"][1]
    result = verify_artifact_v4(hybrid, public_key=_pub(composite), require_pq=True)
    assert (result.ok, result.state, result.algorithm) == (True, "verified", COMPOSITE)
    tofu = verify_artifact_v4(hybrid, trust_embedded=True, require_pq=True)
    assert (tofu.ok, tofu.state) == (True, "verified-tofu")
    assert _sig.artifact_verdict(hybrid, True, hmac_key=None, public_key=_pub(composite))[0]


def test_classical_key_alone_does_not_satisfy_require_pq(hybrid):
    classical = hybrid["signatures"][0]
    assert verify_artifact_v4(hybrid, public_key=_pub(classical)).ok  # the classical path
    strict = verify_artifact_v4(hybrid, public_key=_pub(classical), require_pq=True)
    assert not strict.ok and strict.state == "mismatch"
    alone = verify_artifact_v4(_with(hybrid, classical), trust_embedded=True, require_pq=True)
    assert (alone.ok, alone.state) == (False, "unsigned")


def _stripped(composite):
    value, public = composite["value"], composite["public_key"]
    return {
        "ed25519 half relabelled": {**composite, "alg": "ed25519", "value": value[:128],
                                    "public_key": public[:64]},
        "ml-dsa half relabelled": {**composite, "alg": MLDSA65, "value": value[128:],
                                   "public_key": public[64:]},
        "ed25519 half zeroed": {**composite, "value": "0" * 128 + value[128:]},
        "ml-dsa half zeroed": {**composite, "value": value[:128] + "0" * (len(value) - 128)},
        "ed25519 half flipped": {**composite, "value": ("1" if value[0] == "0" else "0")
                                 + value[1:]},
        "ml-dsa half flipped": {**composite, "value": value[:-1]
                                + ("1" if value[-1] == "0" else "0")},
    }  # fmt: skip


@pytest.mark.parametrize(
    "name",
    [
        "ed25519 half relabelled",
        "ml-dsa half relabelled",
        "ed25519 half zeroed",
        "ml-dsa half zeroed",
        "ed25519 half flipped",
        "ml-dsa half flipped",
    ],
)
def test_stripping_or_breaking_either_half_fails(hybrid, name):
    block = _stripped(hybrid["signatures"][1])[name]
    doc = _with(hybrid, block)
    for kwargs in ({"public_key": _pub(block)}, {"trust_embedded": True}):
        result = verify_artifact_v4(doc, **kwargs)
        assert not result.ok and result.state in ("mismatch", "error"), (name, result)
    assert not _sig.artifact_verdict(doc, True, hmac_key=None, public_key=_pub(block))[0]


@needs_mldsa
def test_pure_mldsa_block_round_trips(v4_doc):
    doc = json.loads(append_signature(v4_doc, PQ_SEED, algorithm=MLDSA65, signed_at=AT))
    block = doc["signatures"][0]
    assert len(block["public_key"]) == 2 * _mldsa.PUBLIC_KEY_BYTES
    assert verify_artifact_v4(doc, public_key=_pub(block)).state == "verified"
    assert verify_artifact_v4(doc).state == "no-key"
    assert _sig.artifact_verdict(doc, True, hmac_key=None, public_key=_pub(block))[0]
    edited = _with(doc, {**block, "signer": "someone-else"})
    assert verify_artifact_v4(edited, public_key=_pub(block)).state == "mismatch"


def test_the_committed_hybrid_fixture_still_verifies():
    doc = json.loads((FIXTURES / "pq_hybrid_v4.tine").read_text(encoding="utf-8"))
    composite = doc["signatures"][1]
    assert verify_artifact_v4(doc, public_key=_pub(composite), require_pq=True).ok
    ok, state, _ = _sig.artifact_verdict(doc, True, hmac_key=None, public_key=_pub(composite))
    assert (ok, state) == (True, "verified")


# -- the 0.34 verifier still accepts the run, through its Ed25519 block ------------

OLD_VERIFY = textwrap.dedent(
    """
    import sys
    sys.path.insert(0, sys.argv[1])
    import opentine
    assert opentine.__file__.startswith(sys.argv[1]), opentine.__file__
    print("version", opentine.__version__)
    from opentine.cli import main
    main(["verify", *sys.argv[2:]])
    """
)


def _v034(tmp_path: Path) -> Path:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    try:
        archive = subprocess.run(
            ["git", "-C", str(ROOT), "archive", "v0.34.0", "opentine"],
            capture_output=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("tag v0.34.0 is not available in this checkout")
    dest = tmp_path / "v034"
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(dest, filter="data")
    return dest


def _old(tmp_path, old, *args):
    script = tmp_path / "old_verify.py"
    script.write_text(OLD_VERIFY, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    return subprocess.run(
        [sys.executable, str(script), str(old), *map(str, args)],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
    )


def test_the_034_verifier_accepts_the_hybrid_run_through_ed25519(hybrid, tmp_path):
    old = _v034(tmp_path)
    artifact = tmp_path / "hybrid.tine"
    artifact.write_bytes(canonical_json(hybrid))
    pubkey = tmp_path / "ed.pub"
    pubkey.write_text(hybrid["signatures"][0]["public_key"], encoding="utf-8")
    for flags in (["--pubkey", pubkey], ["--trust-embedded-key"]):
        done = _old(tmp_path, old, artifact, *flags, "--require-signature")
        assert done.returncode == 0, done.stdout + done.stderr
        assert "version 0.34.0" in done.stdout
        assert "SIGNATURE OK alg=ed25519" in " ".join(done.stdout.split())


def test_the_034_verifier_does_not_accept_a_pq_block_alone(hybrid, tmp_path):
    """The classical block is what 0.34 checks; without it, 0.34 refuses the run."""
    old = _v034(tmp_path)
    artifact = tmp_path / "pq-only.tine"
    artifact.write_bytes(canonical_json(_with(hybrid, hybrid["signatures"][1])))
    done = _old(tmp_path, old, artifact, "--trust-embedded-key", "--require-signature")
    assert done.returncode != 0
    assert "SIGNATURE FAILED state=error" in done.stdout


# -- the reserved hash-algorithm tag (SPEC 1.3.1) ----------------------------------

HEX = "ab" * 32


@pytest.mark.parametrize("tag", ["sha3-256", "blake3", "sha512", "md5", "sha1"])
def test_a_tagged_oid_with_an_unsupported_hash_is_refused_by_name(tag):
    oid = f"blob:{tag}:{HEX}"
    assert hash_tag(oid) == tag
    with pytest.raises(KernelError, match="invalid typed object id"):
        kernel_parse_oid(oid)  # the kernel refuses every tag but sha256
    with pytest.raises(UnsupportedHashAlgorithm, match=f"unsupported hash algorithm '{tag}'"):
        parse_oid(oid)


def test_sha256_and_malformed_oids_keep_their_errors():
    assert parse_oid(f"run:sha256:{HEX}") == ("run", HEX)
    for bad in (f"run:sha256:{HEX[:-1]}", f"widget:blake3:{HEX}", f"run:SHA256:{HEX}"):
        with pytest.raises(KernelError, match="invalid typed object id"):
            parse_oid(bad)


def test_the_repository_refuses_a_tagged_oid_clearly(tmp_path):
    repo = Repo.init(tmp_path / "ws")
    with pytest.raises(UnsupportedHashAlgorithm, match="'blake3'.*only sha256"):
        repo.get(f"blob:blake3:{HEX}")


def test_a_v4_artifact_with_a_tagged_oid_is_refused_clearly(v4_doc):
    from opentine._artifact_v4_read import read_v4_data

    oid = next(o for o in v4_doc["objects"] if o.startswith("blob:"))
    tagged = oid.replace(":sha256:", ":sha3-256:")
    objects = {(tagged if k == oid else k): v for k, v in v4_doc["objects"].items()}
    with pytest.raises(UnsupportedHashAlgorithm, match="'sha3-256'"):
        read_v4_data({**v4_doc, "objects": objects})


def test_the_stdlib_pyz_verifies_the_hybrid_and_refuses_a_stripped_one(tmp_path):
    from opentine._pyz_build import build_bytes

    room = tmp_path / "room"
    room.mkdir()
    (room / "tine-verify.pyz").write_bytes(build_bytes())
    doc = json.loads((FIXTURES / "pq_hybrid_v4.tine").read_text(encoding="utf-8"))
    composite = doc["signatures"][1]
    (room / "pq.pub").write_text(composite["public_key"], encoding="utf-8")
    (room / "hybrid.tine").write_bytes(canonical_json(doc))
    stripped = _stripped(composite)["ml-dsa half relabelled"]
    (room / "stripped.tine").write_bytes(canonical_json(_with(doc, stripped)))
    (room / "ml.pub").write_text(stripped["public_key"], encoding="utf-8")
    verdicts = {}
    for name, key in (("hybrid", "pq.pub"), ("stripped", "ml.pub")):
        done = subprocess.run(
            [sys.executable, "-I", "-S", "tine-verify.pyz", f"{name}.tine", "--pubkey", key],
            capture_output=True, text=True, timeout=120, cwd=room,
        )  # fmt: skip
        verdicts[name] = (done.returncode, json.loads(done.stdout)["verdict"])
    assert verdicts == {"hybrid": (0, "pass"), "stripped": (1, "fail")}
