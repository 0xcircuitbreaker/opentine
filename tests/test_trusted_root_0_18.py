"""0.18 trust hardening: keyless verification under a Sigstore trusted_root.json.

Fully offline: the fake Rekor, Fulcio and CT log of the 0.15/0.18 tests, written
into a public-good-shaped ``trusted_root.json`` with chosen ``validFor`` windows.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from opentine import Run, RunStatus, StepKind, cli, rekor
from opentine._trusted_root import parse_trusted_root
from tests._sigstore_fakes import IDENTITY, ISSUER_URL, FakeLog, transport
from tests.test_fulcio_sct_0_18 import TOKEN, SctFulcio, _pem

MEDIA = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
NOW = dt.datetime.now(dt.UTC)
PAST = (NOW - dt.timedelta(days=400), NOW - dt.timedelta(days=200))
FUTURE = (NOW + dt.timedelta(days=200), None)
OPEN = (NOW - dt.timedelta(days=10), None)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _window(span) -> dict:
    start, end = span
    out = {"start": start.strftime("%Y-%m-%dT%H:%M:%S.000Z")}
    if end is not None:
        out["end"] = end.strftime("%Y-%m-%dT%H:%M:%SZ")
    return out


def _log_entry(public, span, key_id: bytes | None = None) -> dict:
    import hashlib

    der = public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {
        "baseUrl": "https://log.test",
        "hashAlgorithm": "SHA2_256",
        "publicKey": {
            "rawBytes": _b64(der),
            "keyDetails": "PKIX_ECDSA_P256_SHA_256",
            "validFor": _window(span),
        },
        "logId": {"keyId": _b64(key_id or hashlib.sha256(der).digest())},
    }


def make_root(log, fulcio, *, tlog=OPEN, ca=OPEN, ct=OPEN, bad_id=False) -> dict:
    chain = [c.public_bytes(serialization.Encoding.DER) for c in (fulcio.inter, fulcio.root)]
    return {
        "mediaType": MEDIA,
        "tlogs": [_log_entry(log.key.public_key(), tlog, b"\x00" * 32 if bad_id else None)],
        "certificateAuthorities": [
            {
                "subject": {"organization": "test", "commonName": "fake"},
                "uri": "https://fulcio.test",
                "certChain": {"certificates": [{"rawBytes": _b64(d)} for d in chain]},
                "validFor": _window(ca),
            }
        ],
        "ctlogs": [] if ct is None else [_log_entry(fulcio.ct_key.public_key(), ct)],
        "timestampAuthorities": [],
    }


@pytest.fixture
def ws(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    for name in ("SIGSTORE_ID_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    run = Run(id="tr_src", model_info="mock-model", user_prompt="hello")
    run.add_step(StepKind.model, {"prompt": "hello"}, outputs={"text": "hi"}, model_info="m")
    run.status = RunStatus.completed
    run.save(tmp_path / "run.tine")
    log, fulcio = FakeLog(), SctFulcio()
    (tmp_path / "rekor.pub").write_bytes(log.public_pem())
    (tmp_path / "fulcio.pem").write_bytes(fulcio.roots_pem())
    (tmp_path / "ct.pub").write_bytes(_pem(fulcio.ct_key.public_key()))
    monkeypatch.setattr(rekor, "TRANSPORT", transport(log, fulcio))
    return tmp_path, log, fulcio


def _cli(*argv: str) -> int:
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def _export(fulcio, mode: str = "valid") -> None:
    fulcio.mode = mode
    assert _cli("export", "run.tine", "--format", "intoto", "--keyless", "--rekor",
                "https://rekor.test", "--fulcio-url", "https://fulcio.test",
                "--identity-token", TOKEN, "--output", "a.sigstore.json") == 0  # fmt: skip


def _write_root(root: Path, doc: dict, name: str = "tr.json") -> str:
    (root / name).write_text(json.dumps(doc))
    return name


def _verify(capsys, *extra: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = _cli("verify", "run.tine", "--attestation", "a.sigstore.json", "--json",
                "--cert-identity", IDENTITY, "--cert-oidc-issuer", ISSUER_URL, *extra)  # fmt: skip
    return code, json.loads(capsys.readouterr().out)


def test_trusted_root_verifies_keyless(ws, capsys) -> None:
    root, log, fulcio = ws
    _export(fulcio)
    name = _write_root(root, make_root(log, fulcio))
    code, payload = _verify(capsys, "--trusted-root", name, "--require-sct")
    assert code == 0 and payload["signature"]["status"] == "verified-keyless"


def test_root_without_ctlogs_does_not_demand_sct(ws, capsys) -> None:
    root, log, fulcio = ws
    _export(fulcio, "none")
    name = _write_root(root, make_root(log, fulcio, ct=None))
    assert _verify(capsys, "--trusted-root", name)[0] == 0
    code, payload = _verify(capsys, "--trusted-root", name, "--require-sct")
    assert code == 1 and "no CT log" in payload["signature"]["reason"]


@pytest.mark.parametrize("mode", ["none", "tamper"])
def test_root_with_ctlogs_demands_a_valid_sct(ws, capsys, mode) -> None:
    root, log, fulcio = ws
    _export(fulcio, mode)
    code, payload = _verify(capsys, "--trusted-root", _write_root(root, make_root(log, fulcio)))
    assert code == 1 and "SCT" in payload["signature"]["reason"]


@pytest.mark.parametrize(
    ("windows", "reason"),
    [
        ({"tlog": PAST}, "keyless signature needs a verified receipt"),
        ({"tlog": FUTURE}, "keyless signature needs a verified receipt"),
        ({"ca": PAST}, "no certificate authority in --trusted-root is valid"),
        ({"ca": FUTURE}, "no certificate authority in --trusted-root is valid"),
        ({"ct": PAST}, "no CT log valid"),
        ({"ct": FUTURE}, "no CT log valid"),
    ],
)
def test_valid_for_windows_are_enforced(ws, capsys, windows, reason) -> None:
    root, log, fulcio = ws
    _export(fulcio)
    name = _write_root(root, make_root(log, fulcio, **windows))
    code, payload = _verify(capsys, "--trusted-root", name)
    assert code == 1 and reason in payload["signature"]["reason"]
    if "tlog" in windows:
        assert payload["receipt"]["status"] == "no-key"


def test_log_id_must_match_key(ws, capsys) -> None:
    root, log, fulcio = ws
    _export(fulcio)
    name = _write_root(root, make_root(log, fulcio, bad_id=True))
    code, payload = _verify(capsys, "--trusted-root", name)
    assert code == 1 and "logId is not the SHA-256" in payload["signature"]["reason"]


@pytest.mark.parametrize(
    "doc",
    [
        {"mediaType": "application/json"},
        {"mediaType": MEDIA, "tlogs": [], "certificateAuthorities": []},
        {"mediaType": MEDIA, "tlogs": "x"},
    ],
)
def test_malformed_roots_are_refused(doc) -> None:
    with pytest.raises(ValueError):
        parse_trusted_root(json.dumps(doc).encode())


@pytest.mark.parametrize(
    "extra", [["--rekor-key", "rekor.pub"], ["--fulcio-root", "fulcio.pem"], ["--ct-key", "ct.pub"]]
)
def test_trusted_root_conflicts_with_key_files(ws, capsys, extra) -> None:
    root, log, fulcio = ws
    _export(fulcio)
    name = _write_root(root, make_root(log, fulcio))
    capsys.readouterr()
    code = _cli("verify", "run.tine", "--attestation", "a.sigstore.json",
                "--trusted-root", name, *extra)  # fmt: skip
    assert code == 1 and "cannot be combined" in capsys.readouterr().out


def test_explicit_flags_unchanged(ws, capsys) -> None:
    _, _, fulcio = ws
    _export(fulcio)
    code, payload = _verify(capsys, "--rekor-key", "rekor.pub", "--fulcio-root", "fulcio.pem")
    assert code == 0 and payload["signature"]["status"] == "verified-keyless"


def test_installed_root_is_default_only_after_opt_in(ws, capsys) -> None:
    root, log, fulcio = ws
    _export(fulcio)
    base = root / "cfg/opentine/sigstore"
    base.mkdir(parents=True)
    _write_root(base, make_root(log, fulcio), "trusted_root.json")
    code, payload = _verify(capsys)
    assert code == 1 and "--rekor-key" in payload["signature"]["reason"]
    (base / "tuf").mkdir()
    (base / "tuf/state.json").write_text("{}")
    code, payload = _verify(capsys)
    assert code == 0 and payload["signature"]["status"] == "verified-keyless"
    # An explicit key file switches the default off (and still verifies).
    code, _ = _verify(capsys, "--rekor-key", "rekor.pub", "--fulcio-root", "fulcio.pem")
    assert code == 0


def test_trust_policy_carries_trusted_root(ws, capsys) -> None:
    root, log, fulcio = ws
    _export(fulcio)
    name = _write_root(root, make_root(log, fulcio))
    assert _cli("trust", "policy", "set", "tr", "--trusted-root", name, "--cert-identity",
                IDENTITY, "--cert-oidc-issuer", ISSUER_URL, "--require-sct") == 0  # fmt: skip
    stored = json.loads((root / "cfg/opentine/trust-policies.json").read_text())
    assert stored["policies"]["tr"]["trusted_root"] == str(root / name)
    capsys.readouterr()
    assert _cli("verify", "run.tine", "--attestation", "a.sigstore.json", "--policy", "tr") == 0
    capsys.readouterr()
    assert _cli("trust", "policy", "set", "bad", "--trusted-root", name, "--rekor-key",
                "rekor.pub", "--cert-identity", IDENTITY, "--cert-oidc-issuer",
                ISSUER_URL) == 1  # fmt: skip
    assert "replaces" in capsys.readouterr().out
    (root / "junk.json").write_text("{}")
    assert _cli("trust", "policy", "set", "bad", "--trusted-root", "junk.json", "--cert-identity",
                IDENTITY, "--cert-oidc-issuer", ISSUER_URL) == 1  # fmt: skip


def test_trusted_root_refused_for_key_signed_attestation(ws, capsys) -> None:
    from opentine._signing_keys import generate_ed25519

    root, log, fulcio = ws
    seed, public = generate_ed25519()
    (root / "k.key").write_text(seed + "\n")
    (root / "k.pub").write_text(public + "\n")
    name = _write_root(root, make_root(log, fulcio))
    assert _cli("export", "run.tine", "--format", "intoto", "--ed25519-key-file", "k.key",
                "--output", "k.json") == 0  # fmt: skip
    capsys.readouterr()
    code = _cli("verify", "run.tine", "--attestation", "k.json", "--pubkey", "k.pub",
                "--trusted-root", name)  # fmt: skip
    assert code == 1 and "--trusted-root" in capsys.readouterr().out
