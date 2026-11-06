"""0.41 (X24): encrypted key storage, the ``Signer`` protocol and its backends.

* New keys (``tine keygen``, ``--agent``, ``tine proxy keygen``) are encrypted
  PKCS#8; a wrong passphrase fails; plaintext hex still loads, with a warning;
  ``tine key encrypt`` converts one.
* ssh-agent against a real ``ssh-agent``; KMS against fake clients; PKCS#11
  against SoftHSM2 when it is installed.
* Every signing path accepts a signer and its signatures verify with the
  existing verifiers; the T2 proxy key migrates into a signer.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import warnings
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _key_store, _signer_kms, cli
from opentine._signer import Signer, SignerKey, is_uri, key_for, resolve
from opentine._signing_keys import SignatureError, ed25519_private_from_file

ARN = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
GCP = "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"


@pytest.fixture
def room(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _tine(monkeypatch, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["tine", *argv])
    try:
        cli.main()
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def _json(monkeypatch, capsys, *argv: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = _tine(monkeypatch, *argv, "--json")
    return code, json.loads(capsys.readouterr().out)


def _spki(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


class FakeAws:
    def __init__(self, signing: Ed25519PrivateKey | None = None) -> None:
        self.key = Ed25519PrivateKey.generate()
        self.signing = signing or self.key
        self.calls: list[dict] = []

    def get_public_key(self, KeyId):  # noqa: N803 - boto3 spelling
        return {"PublicKey": _spki(self.key), "KeySpec": "ECC_NIST_EDWARDS25519", "KeyId": KeyId}

    def sign(self, **kwargs):
        self.calls.append(kwargs)
        assert kwargs["MessageType"] == "RAW" and kwargs["SigningAlgorithm"] == "ED25519_SHA_512"
        return {"Signature": self.signing.sign(kwargs["Message"])}


class FakeGcp:
    def __init__(self) -> None:
        self.key = Ed25519PrivateKey.generate()

    def get_public_key(self, request):
        pem = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return SimpleNamespace(pem=pem.decode(), algorithm="EC_SIGN_ED25519", name=request["name"])

    def asymmetric_sign(self, request):
        return SimpleNamespace(signature=self.key.sign(request["data"]))


@pytest.fixture
def fake_kms(monkeypatch):
    clients = {"aws": FakeAws(), "gcp": FakeGcp()}
    monkeypatch.setattr(_signer_kms.AwsKmsSigner, "_default_client", lambda self: clients["aws"])
    monkeypatch.setattr(_signer_kms.GcpKmsSigner, "_default_client", lambda self: clients["gcp"])
    return clients


# --------------------------------------------------------------------------- #
# encrypted key storage
# --------------------------------------------------------------------------- #


def test_keygen_writes_encrypted_pkcs8_that_round_trips(room, monkeypatch):
    key = room / "k.key"
    assert _tine(monkeypatch, "keygen", "--out", str(key)) == 0
    raw = key.read_bytes()
    assert raw.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # an encrypted key loads without a warning
        signer = ed25519_private_from_file(key)
    assert isinstance(signer, SignerKey) and isinstance(signer.signer, Signer)
    public = (room / "k.key.pub").read_text().strip()
    assert signer.public_key().public_bytes_raw().hex() == public
    signer.public_key().verify(signer.sign(b"m"), b"m")
    assert signer.signer.key_id == "sha256:" + hashlib.sha256(bytes.fromhex(public)).hexdigest()


def test_wrong_passphrase_fails_and_no_source_refuses(room, monkeypatch):
    key = room / "k.key"
    assert _tine(monkeypatch, "keygen", "--out", str(key)) == 0
    monkeypatch.setenv(_key_store.PASSPHRASE_ENV, "not the passphrase")
    with pytest.raises(SignatureError, match="wrong passphrase"):
        ed25519_private_from_file(key)
    monkeypatch.delenv(_key_store.PASSPHRASE_ENV)
    with pytest.raises(SignatureError, match="no passphrase"):
        ed25519_private_from_file(key)
    assert _tine(monkeypatch, "keygen", "--out", str(room / "other.key")) == 1
    assert not (room / "other.key").exists()
    assert _tine(monkeypatch, "keygen", "--out", str(room / "old.key"), "--unencrypted") == 0
    assert re.fullmatch(r"[0-9a-f]{64}\n", (room / "old.key").read_text())


def test_plaintext_legacy_key_loads_with_a_warning_and_key_encrypt_converts(
    room, monkeypatch, capsys
):
    seed = Ed25519PrivateKey.generate()
    legacy = room / "legacy.key"
    legacy.write_text(seed.private_bytes_raw().hex() + "\n")
    with pytest.warns(_key_store.PlaintextKeyWarning, match="tine key encrypt"):
        loaded = ed25519_private_from_file(legacy)
    assert loaded.public_key().public_bytes_raw() == seed.public_key().public_bytes_raw()

    code, out = _json(monkeypatch, capsys, "key", "encrypt", str(legacy))
    assert code == 0 and out == {"command": "key encrypt", "path": str(legacy), "changed": True}
    assert legacy.read_bytes().startswith(_key_store.PEM_ENCRYPTED)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        again = ed25519_private_from_file(legacy)
    assert again.public_key().public_bytes_raw() == seed.public_key().public_bytes_raw()
    code, out = _json(monkeypatch, capsys, "key", "encrypt", str(legacy))
    assert code == 0 and out["changed"] is False
    code, out = _json(monkeypatch, capsys, "key", "encrypt", str(room / "missing.key"))
    assert code == 3 and out["error"]["code"] == "not_found"


def test_agent_and_proxy_keys_are_encrypted(room, monkeypatch, capsys):
    from opentine import _agent_keys, _proxy_key

    assert _tine(monkeypatch, "keygen", "--agent", "bot") == 0
    private, _ = _agent_keys.key_paths("bot")
    assert private.read_bytes().startswith(_key_store.PEM_ENCRYPTED)
    code, out = _json(monkeypatch, capsys, "proxy", "keygen")
    assert code == 0
    assert _proxy_key.key_paths()[0].read_bytes().startswith(_key_store.PEM_ENCRYPTED)
    assert _proxy_key.signing_key() is not None
    code, shown = _json(monkeypatch, capsys, "key", "show", f"file:{private}")
    assert code == 0 and shown["algorithm"] == "ed25519"
    assert shown["key_id"] in _agent_keys.local_fingerprints()


def test_signer_uris_are_not_paths():
    assert is_uri("ssh-agent:SHA256:x") and is_uri("kms:aws:arn") and is_uri("pkcs11:token=t")
    assert not is_uri("C:\\keys\\a.key") and not is_uri("relative/a.key")
    with pytest.raises(SignatureError, match="kms:aws:ARN"):
        resolve("kms:azure:thing")


# --------------------------------------------------------------------------- #
# KMS (fake clients)
# --------------------------------------------------------------------------- #


def test_aws_and_gcp_kms_signers_sign_pure_ed25519(fake_kms):
    for uri, client in ((f"kms:aws:{ARN}", fake_kms["aws"]), (f"kms:gcp:{GCP}", fake_kms["gcp"])):
        signer = key_for(uri)
        assert signer.signer.uri == uri and signer.signer.algorithm == "ed25519"
        assert signer.public_key().public_bytes_raw() == client.key.public_key().public_bytes_raw()
        client.key.public_key().verify(signer.sign(b"hello"), b"hello")
    assert fake_kms["aws"].calls[0]["KeyId"] == ARN
    with pytest.raises(SignatureError, match="at most 4096"):
        key_for(f"kms:aws:{ARN}").sign(b"x" * 5000)


def test_a_signer_that_signs_with_another_key_is_refused():
    wrong = _signer_kms.AwsKmsSigner(ARN, client=FakeAws(signing=Ed25519PrivateKey.generate()))
    with pytest.raises(SignatureError, match="does not verify"):
        SignerKey(wrong).sign(b"m")


# --------------------------------------------------------------------------- #
# ssh-agent (a real agent)
# --------------------------------------------------------------------------- #


@pytest.fixture
def agent(tmp_path, monkeypatch):
    agent_bin, add_bin = shutil.which("ssh-agent"), shutil.which("ssh-add")
    if os.name == "nt" or not agent_bin or not add_bin:
        pytest.skip("needs ssh-agent and ssh-add (POSIX)")
    sock = Path("/tmp") / f"tine-agent-{os.getpid()}-{tmp_path.name[-8:]}.sock"
    proc = subprocess.Popen([agent_bin, "-D", "-a", str(sock)], stdout=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if sock.exists():
                break
            subprocess.run([sys.executable, "-c", "import time; time.sleep(0.05)"], check=True)
        monkeypatch.setenv("SSH_AUTH_SOCK", str(sock))
        private = Ed25519PrivateKey.generate()
        path = tmp_path / "id_ed25519"
        path.write_bytes(
            private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.OpenSSH,
                serialization.NoEncryption(),
            )
        )
        path.chmod(0o600)
        env = {**os.environ, "SSH_AUTH_SOCK": str(sock)}
        subprocess.run([add_bin, "-q", str(path)], check=True, env=env, capture_output=True)
        listed = subprocess.run([add_bin, "-l"], env=env, capture_output=True, text=True)
        fingerprint = listed.stdout.split()[1]
        yield SimpleNamespace(private=private, fingerprint=fingerprint, sock=sock)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        sock.unlink(missing_ok=True)


def test_ssh_agent_signer_signs_with_the_agent_key(agent, room, monkeypatch, capsys):
    raw = agent.private.public_key().public_bytes_raw()
    for name in (agent.fingerprint, "*", "sha256:" + hashlib.sha256(raw).hexdigest()):
        signer = key_for(f"ssh-agent:{name}")
        assert signer.public_key().public_bytes_raw() == raw
        agent.private.public_key().verify(signer.sign(b"payload"), b"payload")
    with pytest.raises(SignatureError, match="0 Ed25519 keys"):
        key_for("ssh-agent:SHA256:nope")
    code, shown = _json(monkeypatch, capsys, "key", "show", f"ssh-agent:{agent.fingerprint}")
    assert code == 0 and shown["public_key"] == raw.hex()
    assert shown["signer"] == f"ssh-agent:{agent.fingerprint}"


def test_proxy_key_migrates_into_the_agent_and_old_runs_still_verify(
    agent, room, monkeypatch, capsys
):
    from opentine import _proxy_key
    from opentine._assurance import assess, proxy_marker, witness_save
    from opentine.core import Run, RunStatus, StepKind

    def proxied(path: Path) -> Path:
        run = Run(model_info="m", user_prompt="p")
        run.metadata["capture"] = proxy_marker("mcp-proxy")
        run.add_step(StepKind.done, {"text": "done"})
        run.status = RunStatus.completed
        assert witness_save(run, path)
        return path

    assert _tine(monkeypatch, "proxy", "keygen") == 0
    before = proxied(room / "before.tine")
    code, out = _json(
        monkeypatch, capsys, "proxy", "migrate", "--to", f"ssh-agent:{agent.fingerprint}"
    )
    assert code == 0 and out["command"] == "proxy migrate"
    assert not _proxy_key.key_paths()[0].exists()  # the file key is retired, not read
    raw = agent.private.public_key().public_bytes_raw()
    assert _proxy_key.key_paths()[1].read_text().strip() == raw.hex()
    after = proxied(room / "after.tine")
    assert assess(after)["verified"] == "T2" and assess(before)["verified"] == "T2"
    code, out = _json(monkeypatch, capsys, "proxy", "keygen", "--signer", "kms:aws:x")
    assert code == 1 and "already exists" in out["error"]["message"]


# --------------------------------------------------------------------------- #
# PKCS#11 (SoftHSM2)
# --------------------------------------------------------------------------- #

SOFTHSM = next(
    (p for p in ("/usr/lib/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so",
                 "/opt/homebrew/lib/softhsm/libsofthsm2.so") if Path(p).is_file()),
    None,
)  # fmt: skip


def test_pkcs11_signer_against_softhsm(tmp_path, monkeypatch):
    pkcs11 = pytest.importorskip("pkcs11")
    if SOFTHSM is None or not shutil.which("softhsm2-util"):
        pytest.skip("SoftHSM2 is not installed")
    (tmp_path / "tokens").mkdir()
    conf = tmp_path / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {tmp_path / 'tokens'}\nobjectstore.backend = file\n")
    monkeypatch.setenv("SOFTHSM2_CONF", str(conf))
    init = ["softhsm2-util", "--init-token", "--free", "--label", "tine"]
    subprocess.run([*init, "--so-pin", "0000", "--pin", "1234"], check=True, capture_output=True)
    lib = pkcs11.lib(SOFTHSM)
    with lib.get_token(token_label="tine").open(user_pin="1234", rw=True) as session:
        session.generate_keypair(
            pkcs11.KeyType.EC_EDWARDS,
            store=True,
            label="proxy",
            public_template={pkcs11.Attribute.EC_PARAMS: bytes.fromhex("06032b6570")},
        )
    monkeypatch.setenv("OPENTINE_PKCS11_PIN", "1234")
    uri = f"pkcs11:token=tine;object=proxy?module-path={SOFTHSM}"
    signer = key_for(uri)
    signer.public_key().verify(signer.sign(b"hsm"), b"hsm")
    assert "pin" not in key_for(uri + "&pin-value=1234").signer.uri
    _assert_every_path_verifies(signer)


# --------------------------------------------------------------------------- #
# every signing path
# --------------------------------------------------------------------------- #


def _assert_every_path_verifies(key) -> None:
    import tempfile

    from opentine import _custody, _push_preview, _verify_report_sign, intoto
    from opentine._evidence_export import custody_record, verify_custody
    from opentine.attest_signing import sign_attestation, verify_attestation
    from opentine.core import Run, RunStatus, StepKind

    public = key.public_key()
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        run = Run(model_info="m", user_prompt="p")
        run.add_step(StepKind.done, {"text": "done"})
        run.status = RunStatus.completed
        saved = run.save(base / "r.tine", sign_key=key, sign_algorithm="ed25519")
        assert Run.verify_signature(saved, public_key=public).ok  # tine-sig/3

        payload = {
            "claim": {"result": "pass"},
            "evidence_ids": [],
            "signer": "me",
            "target_id": "run:sha256:" + "11" * 32,
        }
        payload["signature"] = sign_attestation(payload, key, algorithm="ed25519")
        assert verify_attestation(payload, public_key=public).ok

        made = _custody.record(base, "received", "subject", key, actor="me")
        assert made["signature"]["public_key"] == public.public_bytes_raw().hex()
        assert _custody.verify(base, SimpleNamespace(), public_key=public)

        report = {"schema": _verify_report_sign.SCHEMA, "verdict": "pass", "path": "r.tine"}
        signed = _verify_report_sign.sign_report(report, key, signer="me")
        assert _verify_report_sign.check(signed, SimpleNamespace(), public_key=public)["ok"]

        manifest = _push_preview.sign({"refs": []}, key, algorithm="ed25519", key_id="k")
        assert _push_preview.verify(manifest, public_key=public).ok

        record = custody_record(operator="me", version="0", runs=[], manifest=b"m", signing_key=key)
        assert verify_custody(record)

        envelope = intoto.sign_statement({"_type": "x"}, key)
        sig = base64.b64decode(envelope["signatures"][0]["sig"])
        public.verify(sig, intoto.pae(intoto.PAYLOAD_TYPE, base64.b64decode(envelope["payload"])))


@pytest.mark.parametrize("kind", ["file", "gcp-kms"])
def test_every_signing_path_verifies_with_a_signer(kind, room, monkeypatch, fake_kms):
    if kind == "file":
        assert _tine(monkeypatch, "keygen", "--out", str(room / "k.key")) == 0
        key = ed25519_private_from_file(room / "k.key")
    else:
        key = ed25519_private_from_file(f"kms:gcp:{GCP}")
    assert isinstance(key, SignerKey)
    _assert_every_path_verifies(key)


def test_cli_signing_flags_take_a_signer_uri(room, monkeypatch, capsys, fake_kms):
    from opentine.core import Run, RunStatus, StepKind

    run = Run(model_info="m", user_prompt="p")
    run.add_step(StepKind.done, {"text": "done"})
    run.status = RunStatus.completed
    run.save(room / "r.tine")
    uri = f"kms:gcp:{GCP}"
    assert (
        _tine(
            monkeypatch,
            "sign",
            "r.tine",
            "--algorithm",
            "ed25519",
            "--ed25519-key-file",
            uri,
            "--save",
            "s.tine",
        )
        == 0
    )
    pub = room / "kms.pub"
    pub.write_text(fake_kms["gcp"].key.public_key().public_bytes_raw().hex() + "\n")
    assert _tine(monkeypatch, "verify", "s.tine", "--pubkey", str(pub)) == 0
