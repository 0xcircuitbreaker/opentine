"""0.41.0: key lifecycle (X23), RFC 3161 hardening (X26), tine-attest/2 signer
binding (X27) and stale TUF roots (X31).

Offline only: TSA tokens come from the 0.31 helpers, TUF metadata is written
by hand, and every CLI call runs inside ``no_network``.
"""

from __future__ import annotations

import argparse
import json
from datetime import timedelta
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

from opentine import Run, RunStatus, StepKind, cli  # noqa: E402
from opentine import _timestamp_sidecar as sidecar  # noqa: E402
from opentine._key_lifecycle import (  # noqa: E402
    evaluate,
    lifecycle_for,
    load_registry,
    save_registry,
    stamp,
)
from opentine._key_rotate import verify_endorsement  # noqa: E402
from opentine._offline_guard import no_network  # noqa: E402
from opentine._signing_keys import (  # noqa: E402
    ed25519_private_from_file,
    generate_ed25519,
    load_ed25519_private,
)
from opentine._signing_pins import key_fingerprint  # noqa: E402
from opentine._tsp_verify import verify_token  # noqa: E402
from tests.test_timestamp_offline_0_31 import (  # noqa: E402
    BOUND,
    NOW,
    POLICY,
    _tine,
    integer,
    octets,
    oid,
    pki,
    seq,
    tlv,
    token,
)

HOUR = timedelta(hours=1)


def tine(monkeypatch, *argv: str) -> int:
    with no_network():
        return _tine(monkeypatch, *argv)


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    run = Run(id="kl_run", model_info="mock-model", user_prompt="p")
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    run.save(tmp_path / "run.tine")
    return tmp_path


def _keys(where: Path, name: str = "k") -> tuple[Path, Path, str]:
    private, public = generate_ed25519()
    (where / name).write_text(private, encoding="ascii")
    (where / f"{name}.pub").write_text(public, encoding="ascii")
    return where / name, where / f"{name}.pub", key_fingerprint(bytes.fromhex(public))


def _signed_and_stamped(monkeypatch, room: Path, *, when=None, stamped=True) -> tuple[Path, str]:
    """Sign run.tine, attach a token over the signature dated *when*; ``(pub, fpr)``."""
    key, pub, fpr = _keys(room)
    argv = ("sign", "run.tine", "--algorithm", "ed25519", "--ed25519-key-file", str(key))
    assert tine(monkeypatch, *argv, "--save", "run.tine", "--overwrite") == 0
    if not stamped:
        return pub, fpr
    ca, tsa, tsa_key = pki()
    (room / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    bound = sidecar.signature_bounds(room / "run.tine")[0]
    sidecar.attach(room / "run.tine", bound, token(bound.encode(), tsa, tsa_key, when=when))
    return pub, fpr


def _offline(monkeypatch, room: Path, pub: Path) -> tuple[int, dict]:
    argv = ("verify", "run.tine", "--offline", "--pubkey", str(pub), "--tsa-roots", "ca.pem")
    code = tine(monkeypatch, *argv, "--report", "r.json")
    return code, json.loads((room / "r.json").read_text(encoding="utf-8"))


def _lifecycle(report: dict) -> dict | None:
    return next((c for c in report["checks"] if c["name"] == "key-lifecycle"), None)


# --------------------------------------------------------------------------- #
# X23: the window, judged against the verified signing time
# --------------------------------------------------------------------------- #


def test_evaluate_uses_the_verified_time_and_fails_closed_without_one():
    at = stamp(NOW)
    window = {"not_after": stamp(NOW + HOUR)}
    assert evaluate(window, at)[:2] == ("pass", "lifecycle.valid")
    assert evaluate({"not_after": stamp(NOW - HOUR)}, at)[1] == "lifecycle.expired"
    assert evaluate({"not_before": stamp(NOW + HOUR)}, at)[1] == "lifecycle.not-yet-valid"
    assert evaluate({"revoked_at": stamp(NOW - HOUR)}, at)[1] == "lifecycle.revoked"
    assert evaluate({"revoked_at": stamp(NOW + HOUR)}, at)[0] == "pass"
    # no verified time: a revoked key fails closed, even with an early claim
    revoked = {"revoked_at": stamp(NOW + HOUR)}
    assert evaluate(revoked, None, stamp(NOW))[1] == "lifecycle.revoked-unverified-time"
    assert evaluate(window, None, stamp(NOW))[:2] == (
        "unavailable-offline",
        "lifecycle.unverified-time",
    )
    assert evaluate(window, None, stamp(NOW + 2 * HOUR))[1] == "lifecycle.expired"


def test_lifecycle_sources_merge_to_the_strictest_window():
    a = {"k": {"not_after": stamp(NOW + 2 * HOUR), "not_before": stamp(NOW - 2 * HOUR)}}
    b = {"k": {"not_after": stamp(NOW + HOUR), "not_before": stamp(NOW - 3 * HOUR)}}
    merged = lifecycle_for("k", a, b)
    assert merged == {"not_after": stamp(NOW + HOUR), "not_before": stamp(NOW - 2 * HOUR)}
    assert lifecycle_for("other", a, b) is None


@pytest.mark.parametrize(
    ("window", "code", "reason"),
    [
        ({"not_after": +1}, 0, "lifecycle.valid"),
        ({"not_after": -1}, 1, "lifecycle.expired"),
        ({"revoked_at": -1}, 1, "lifecycle.revoked"),
        ({"revoked_at": +1}, 0, "lifecycle.valid"),
    ],
)
def test_a_signature_after_not_after_or_revoked_at_fails_and_an_earlier_one_passes(
    room, monkeypatch, window, code, reason
):
    pub, fpr = _signed_and_stamped(monkeypatch, room)
    ((field, sign),) = window.items()
    save_registry({fpr: {field: stamp(NOW + sign * HOUR)}})
    got, report = _offline(monkeypatch, room, pub)
    check = _lifecycle(report)
    assert got == code and check is not None and check["reason"] == reason
    assert check["trust_basis"].endswith("at the verified signing time")


def test_without_a_token_a_revoked_key_fails_closed(room, monkeypatch):
    pub, fpr = _signed_and_stamped(monkeypatch, room, stamped=False)
    save_registry({fpr: {"revoked_at": stamp(NOW + HOUR)}})
    argv = ("verify", "run.tine", "--offline", "--pubkey", str(pub), "--report", "r.json")
    assert tine(monkeypatch, *argv) == 1
    report = json.loads((room / "r.json").read_text(encoding="utf-8"))
    assert "signing_time" not in report
    assert _lifecycle(report)["reason"] == "lifecycle.revoked-unverified-time"


def test_no_window_adds_no_check(room, monkeypatch):
    pub, _ = _signed_and_stamped(monkeypatch, room)
    code, report = _offline(monkeypatch, room, pub)
    assert code == 0 and _lifecycle(report) is None


def test_plain_verify_refuses_a_revoked_key(room, monkeypatch, capsys):
    pub, fpr = _signed_and_stamped(monkeypatch, room)
    assert tine(monkeypatch, "verify", "run.tine", "--pubkey", str(pub)) == 0
    assert tine(monkeypatch, "key", "revoke", str(pub)) == 0
    capsys.readouterr()
    assert tine(monkeypatch, "verify", "run.tine", "--pubkey", str(pub)) == 4
    assert "KEY LIFECYCLE FAILED lifecycle.revoked-unverified-time" in capsys.readouterr().err
    assert load_registry()[fpr]["revoked_at"]


def test_key_revoke_records_the_earliest_time_and_validates_at(room, monkeypatch, capsys):
    _, pub, fpr = _keys(room)
    later, earlier = stamp(NOW + HOUR), stamp(NOW - HOUR)
    assert tine(monkeypatch, "key", "revoke", fpr, "--at", later, "--json") == 0
    assert json.loads(capsys.readouterr().out)["revoked_at"] == later
    assert tine(monkeypatch, "key", "revoke", str(pub), "--at", earlier) == 0
    assert tine(monkeypatch, "key", "revoke", fpr, "--at", later) == 0
    assert load_registry()[fpr]["revoked_at"] == earlier
    capsys.readouterr()
    assert tine(monkeypatch, "key", "revoke", fpr, "--at", "yesterday", "--json") == 2
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "usage"


def test_key_rotate_ends_the_old_window_and_the_old_key_endorses_the_new(room, monkeypatch, capsys):
    key, pub, old = _keys(room)
    assert tine(monkeypatch, "key", "rotate", str(key), "--json") == 0
    out = json.loads(capsys.readouterr().out)
    assert out["command"] == "key rotate" and out["old"] == old and out["new"] != old
    new_pub = bytes.fromhex(pub.read_text(encoding="ascii").strip())
    assert key_fingerprint(new_pub) == out["new"]
    assert key.read_text(encoding="ascii").startswith("-----BEGIN ENCRYPTED PRIVATE KEY")
    private = ed25519_private_from_file(key, signer=False)  # rotate writes it encrypted
    assert private.public_key().public_bytes_raw() == new_pub
    assert len(list(room.glob("k-retired-*"))) == 2  # the old pair is kept
    table = load_registry()
    assert table[old]["not_after"] == out["not_after"] and table[old]["successor"] == out["new"]
    entry = table[out["new"]]
    assert entry["predecessor"] == old and verify_endorsement(entry)
    entry["endorsement"]["statement"]["new"] = old
    assert not verify_endorsement(entry)


def test_key_rotate_refuses_a_revoked_key_and_ambiguous_targets(room, monkeypatch, capsys):
    key, _, fpr = _keys(room)
    assert tine(monkeypatch, "key", "rotate", "--json") == 2
    assert tine(monkeypatch, "key", "rotate", str(key), "--proxy") == 2
    assert tine(monkeypatch, "key", "rotate", "missing.key") == 3
    assert tine(monkeypatch, "key", "revoke", fpr) == 0
    assert tine(monkeypatch, "key", "rotate", str(key)) == 1
    assert key.read_text(encoding="ascii")  # untouched


def test_key_rotate_agent_key(room, monkeypatch, capsys):
    from opentine._agent_keys import key_paths, local_fingerprints

    assert tine(monkeypatch, "keygen", "--agent", "coder") == 0
    before = local_fingerprints()
    assert tine(monkeypatch, "key", "rotate", "--agent", "coder", "--json") == 0
    out = json.loads(capsys.readouterr().out)
    assert out["private_key"] == str(key_paths("coder")[0])
    assert {out["old"], out["new"]} <= local_fingerprints() and before < local_fingerprints()


def test_key_rotate_proxy_keeps_the_retired_key_trusted(room, monkeypatch, capsys):
    from opentine._assurance import proxy_witnesses
    from opentine._proxy_key import key_paths

    assert tine(monkeypatch, "proxy", "keygen") == 0
    capsys.readouterr()
    old_hex = key_paths()[1].read_text(encoding="ascii").strip()
    assert tine(monkeypatch, "key", "rotate", "--proxy", "--json") == 0
    out = json.loads(capsys.readouterr().out)
    new_hex = key_paths()[1].read_text(encoding="ascii").strip()
    assert new_hex != old_hex and out["private_key"] == str(key_paths()[0])
    assert (key_paths()[0].parent / "retired" / f"{old_hex}.pub").is_file()
    trusted = {bytes(k.public_bytes_raw()).hex() for _, k in proxy_witnesses()}
    assert {old_hex, new_hex} <= trusted


def test_trust_policy_and_agents_toml_carry_windows(room, tmp_path):
    from opentine import _agent_keys
    from opentine._key_lifecycle import agent_lifecycle
    from opentine._trust_policy import PolicyError, check_policy

    fpr = "sha256:" + "ab" * 32
    good = {"pin": [fpr], "key_lifecycle": {fpr: {"not_after": stamp(NOW)}}}
    assert check_policy("p", good) == good
    with pytest.raises(PolicyError):
        check_policy("p", {"pin": [fpr], "key_lifecycle": {fpr: {"not_after": "soon"}}})
    tine_dir = tmp_path / "proj"
    tine_dir.mkdir()
    (tine_dir / "agents.toml").write_text(
        f'[agents.coder]\nkeys = ["{fpr}"]\n'
        f'[agents.coder.lifecycle."{fpr}"]\nrevoked_at = "{stamp(NOW)}"\n',
        encoding="utf-8",
    )
    assert agent_lifecycle(tine_dir) == {}  # inert until trusted
    _agent_keys.trust(tine_dir)
    assert agent_lifecycle(tine_dir)[fpr]["revoked_at"] == stamp(NOW)


# --------------------------------------------------------------------------- #
# X26: RFC 3161 / RFC 5816 gaps
# --------------------------------------------------------------------------- #


def test_the_signing_certificate_must_be_bound_by_ess():
    ca, tsa, key = pki()
    assert verify_token(token(BOUND, tsa, key, ess="v1"), BOUND, [ca]).ok
    for ess in ("none", "wrong"):
        verdict = verify_token(token(BOUND, tsa, key, ess=ess), BOUND, [ca])
        assert verdict.reason == "timestamp.signing-cert-mismatch", ess


def test_policy_allow_list_and_nonce():
    ca, tsa, key = pki()
    raw = token(BOUND, tsa, key, extra=integer(7))  # nonce 7
    assert verify_token(raw, BOUND, [ca], policies=[POLICY], nonce=7).ok
    assert verify_token(raw, BOUND, [ca]).info["nonce"] == "7"
    other = verify_token(raw, BOUND, [ca], policies=["1.2.3.4"])
    assert other.reason == "timestamp.policy-not-allowed"
    assert verify_token(raw, BOUND, [ca], nonce=8).reason == "timestamp.nonce-mismatch"


def test_a_critical_tstinfo_extension_is_refused():
    ca, tsa, key = pki()
    ext = tlv(0xA1, seq(oid("1.2.3.4.5"), b"\x01\x01\xff", octets(b"x")))
    assert verify_token(token(BOUND, tsa, key, extra=ext), BOUND, [ca]).reason == (
        "timestamp.critical-extension"
    )
    benign = tlv(0xA1, seq(oid("1.2.3.4.5"), octets(b"x")))
    assert verify_token(token(BOUND, tsa, key, extra=benign), BOUND, [ca]).ok


def test_accuracy_must_keep_gen_time_inside_the_tsa_validity():
    ca, tsa, key = pki()
    inside = seq(integer(5))  # +/- 5 s
    raw = token(BOUND, tsa, key, extra=inside)
    verdict = verify_token(raw, BOUND, [ca])
    assert verdict.ok and verdict.info["accuracy_us"] == 5_000_000
    wide = seq(integer(3 * 86400))  # +/- 3 days: past the 1-day validity
    verdict = verify_token(token(BOUND, tsa, key, extra=wide), BOUND, [ca])
    assert verdict.reason == "timestamp.outside-validity"


def _tsa_with(usage, critical: bool):
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = lambda cn: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])  # noqa: E731
    ca = (
        x509.CertificateBuilder()
        .subject_name(name("R"))
        .issuer_name(name("R"))
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    tsa = (
        x509.CertificateBuilder()
        .subject_name(name("T"))
        .issuer_name(name("R"))
        .public_key(key.public_key())
        .serial_number(2)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
        .add_extension(x509.ExtendedKeyUsage(usage), critical=critical)
        .sign(ca_key, hashes.SHA256())
    )
    return ca, tsa, key


@pytest.mark.parametrize(
    ("usage", "critical"),
    [
        ([ExtendedKeyUsageOID.TIME_STAMPING], False),
        ([ExtendedKeyUsageOID.TIME_STAMPING, ExtendedKeyUsageOID.CODE_SIGNING], True),
    ],
)
def test_the_timestamping_eku_must_be_critical_and_alone(usage, critical):
    ca, tsa, key = _tsa_with(usage, critical)
    assert verify_token(token(BOUND, tsa, key), BOUND, [ca]).reason == "timestamp.missing-eku"
    ca, tsa, key = _tsa_with([ExtendedKeyUsageOID.TIME_STAMPING], True)
    assert verify_token(token(BOUND, tsa, key), BOUND, [ca]).ok


def test_tsa_policy_flag_reaches_the_offline_check(room, monkeypatch):
    pub, _ = _signed_and_stamped(monkeypatch, room)
    argv = ("verify", "run.tine", "--offline", "--pubkey", str(pub), "--tsa-roots", "ca.pem")
    assert tine(monkeypatch, *argv, "--tsa-policy", POLICY) == 0
    assert tine(monkeypatch, *argv, "--tsa-policy", "1.2.3", "--report", "r.json") == 1
    report = json.loads((room / "r.json").read_text(encoding="utf-8"))
    assert report["timestamps"][0]["reason"] == "timestamp.policy-not-allowed"
    assert tine(monkeypatch, "verify", "run.tine", "--tsa-policy", POLICY) != 0  # needs --offline


# --------------------------------------------------------------------------- #
# X27: the tine-attest/2 record is bound to the envelope signer
# --------------------------------------------------------------------------- #

ROOT = "run:sha256:" + "cd" * 32


def _statement(seed: str, *, bound: bool = True) -> dict:
    from opentine._signing_v4 import sign_attestation_v2
    from opentine.intoto import did_from_public

    public = load_ed25519_private(seed).public_key()
    payload = {
        "claim": {"predicateType": "x"},
        "evidence_ids": [],
        "signer": did_from_public(public),
        "target_id": ROOT,
    }
    if bound:
        payload["signer_key"] = key_fingerprint(public.public_bytes_raw())
    record = {**payload, "signature": sign_attestation_v2(payload, seed)}
    return {"predicate": {"attestation": record}}


def test_a_bound_record_must_name_and_be_signed_by_the_envelope_key():
    from opentine._signing_v4 import attestation_binding, check_v4_attestation

    seed, public = generate_ed25519()
    other_seed, other_public = generate_ed25519()
    mine, theirs = (key_fingerprint(bytes.fromhex(p)) for p in (public, other_public))
    statement = _statement(seed)
    assert attestation_binding(statement) == "bound"
    assert check_v4_attestation(statement, ROOT, mine) is None
    assert "names signer" in check_v4_attestation(statement, ROOT, theirs)
    # a record signed by another key than the envelope's fails even when unbound
    assert "different key" in check_v4_attestation(_statement(other_seed, bound=False), ROOT, mine)


def test_an_old_unbound_record_keeps_verifying_with_an_unbound_status():
    from opentine._signing_v4 import attestation_binding, check_v4_attestation

    seed, public = generate_ed25519()
    statement = _statement(seed, bound=False)
    assert attestation_binding(statement) == "unbound"
    assert check_v4_attestation(statement, ROOT, key_fingerprint(bytes.fromhex(public))) is None
    assert check_v4_attestation(statement, ROOT) is None


def test_statement_for_writes_a_bound_record(room):
    from opentine._signing_v4 import attestation_binding, statement_for
    from opentine.core import Run as CoreRun

    seed, public = generate_ed25519()
    run = CoreRun.load(room / "run.tine")
    statement = statement_for(run, ROOT, seed)
    record = statement["predicate"]["attestation"]
    assert record["signer_key"] == key_fingerprint(bytes.fromhex(public))
    assert attestation_binding(statement) == "bound"


# --------------------------------------------------------------------------- #
# X31: a stale TUF root is flagged and refused
# --------------------------------------------------------------------------- #


def _install_tuf(base: Path, expires: str) -> None:
    tuf = base / "tuf"
    tuf.mkdir(parents=True)
    for role in ("root", "timestamp"):
        signed = {"_type": role, "spec_version": "1.0", "version": 1, "expires": expires}
        doc = {"signed": signed, "signatures": []}
        (tuf / f"{role}.json").write_text(json.dumps(doc), encoding="utf-8")
    (tuf / "state.json").write_text("{}", encoding="utf-8")
    (base / "trusted_root.json").write_text("{}", encoding="utf-8")


def test_a_stale_tuf_root_is_refused_unless_overridden(room, capsys):
    from opentine._keyless_root import trusted_root_path
    from opentine._trusted_root import sigstore_dir
    from opentine._tuf_client import stale

    base = sigstore_dir()
    _install_tuf(base, stamp(NOW - HOUR))
    assert "timestamp" in stale(base) or "root" in stale(base)
    with pytest.raises(SystemExit) as exc:
        trusted_root_path(argparse.Namespace())
    assert exc.value.code == 6
    assert "--allow-stale-root" in capsys.readouterr().err
    path = trusted_root_path(argparse.Namespace(allow_stale_root=True))
    assert path == str(base / "trusted_root.json")
    assert "warning" in capsys.readouterr().err


def test_a_fresh_tuf_root_is_used_silently(room, capsys):
    from opentine._keyless_root import trusted_root_path
    from opentine._trusted_root import sigstore_dir
    from opentine._tuf_client import stale

    base = sigstore_dir()
    _install_tuf(base, stamp(NOW + 24 * HOUR))
    assert stale(base) is None
    assert trusted_root_path(argparse.Namespace()) == str(base / "trusted_root.json")
    assert capsys.readouterr().err == ""
