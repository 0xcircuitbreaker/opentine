"""Sigstore keyless signing: ``tine export --format intoto --keyless``.

Fully offline: a fake Fulcio CA (local root -> intermediate -> leaf with SAN,
code-signing EKU and the OIDC-issuer extension) and a fake Rekor, behind an
``httpx.MockTransport``. The claims: the keyless bundle verifies only for the
expected identity and issuer, under the supplied Fulcio root, at a logged time
inside the certificate's validity; and the OIDC token never leaves the request
body -- not in output, errors, or the written bundle.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, cli, rekor
from opentine.fulcio import identity_claim
from tests._sigstore_fakes import IDENTITY, ISSUER_URL, FakeFulcio, FakeLog, fake_jwt, transport

TOKEN = fake_jwt({"iss": ISSUER_URL, "sub": "repo:o/r", "email": IDENTITY, "aud": "sigstore"})


@pytest.fixture
def ws(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    for name in (
        "SIGSTORE_ID_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    run = Run(id="keyless_src", model_info="mock-model", user_prompt="hello")
    run.add_step(StepKind.model, {"prompt": "hello"}, outputs={"text": "hi"}, model_info="m")
    run.status = RunStatus.completed
    run.save(tmp_path / "run.tine")
    log, fulcio = FakeLog(), FakeFulcio()
    (tmp_path / "rekor.pub").write_bytes(log.public_pem())
    (tmp_path / "fulcio.pem").write_bytes(fulcio.roots_pem())
    monkeypatch.setattr(rekor, "TRANSPORT", transport(log, fulcio, gh_token=TOKEN))
    return tmp_path, log, fulcio


def _cli(*argv: str) -> int:
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def _export(*extra: str) -> int:
    return _cli("export", "run.tine", "--format", "intoto", "--keyless", "--rekor",
                "https://rekor.test", "--fulcio-url", "https://fulcio.test",
                "--output", "a.sigstore.json", *extra)  # fmt: skip


def _verify(capsys, *extra: str, identity=IDENTITY, issuer=ISSUER_URL) -> tuple[int, dict]:
    capsys.readouterr()
    code = _cli("verify", "run.tine", "--attestation", "a.sigstore.json", "--json",
                "--rekor-key", "rekor.pub", "--fulcio-root", "fulcio.pem",
                "--cert-identity", identity, "--cert-oidc-issuer", issuer, *extra)  # fmt: skip
    return code, json.loads(capsys.readouterr().out)


def _no_token_anywhere(root: Path, *texts: str) -> None:
    for text in texts:
        assert TOKEN not in text
    for path in root.rglob("*"):
        if path.is_file():
            assert TOKEN.encode() not in path.read_bytes(), path


def test_identity_claim_prefers_email() -> None:
    assert identity_claim(TOKEN) == IDENTITY
    assert identity_claim(fake_jwt({"sub": "repo:o/r"})) == "repo:o/r"
    with pytest.raises(ValueError):
        identity_claim("not-a-jwt")


def test_keyless_happy_path(ws, capsys) -> None:
    root, log, fulcio = ws
    assert _export("--identity-token", TOKEN) == 0
    out = capsys.readouterr()
    assert fulcio.seen_tokens == [TOKEN]
    bundle = json.loads((root / "a.sigstore.json").read_text())
    assert "certificate" in bundle["verificationMaterial"]
    assert len(bundle["verificationMaterial"]["tlogEntries"]) == 1
    code, payload = _verify(capsys)
    assert code == 0 and payload["ok"] is True
    assert payload["signature"]["status"] == "verified-keyless"
    assert payload["signature"]["keyid"] == IDENTITY
    assert payload["receipt"]["status"] == "verified"
    _no_token_anywhere(root, out.out, out.err, json.dumps(payload))


def test_token_from_env_and_github_ambient(ws, monkeypatch, capsys) -> None:
    root, _, fulcio = ws
    monkeypatch.setenv("SIGSTORE_ID_TOKEN", TOKEN)
    assert _export() == 0
    monkeypatch.delenv("SIGSTORE_ID_TOKEN")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://gh.test/gh-token?x=1")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "gh-request-bearer")
    assert _export("--force") == 0
    assert fulcio.seen_tokens == [TOKEN, TOKEN]
    assert _verify(capsys)[0] == 0


def test_no_token_and_conflicting_key_refused(ws) -> None:
    root, _, _ = ws
    assert _export() == 1
    (root / "k.key").write_text("00" * 32)
    assert _export("--identity-token", TOKEN, "--ed25519-key-file", "k.key") == 1
    assert not (root / "a.sigstore.json").exists()


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"identity": "someone@else.com"}, "--cert-identity"),
        ({"issuer": "https://accounts.example"}, "--cert-oidc-issuer"),
    ],
)
def test_wrong_identity_or_issuer_fails(ws, capsys, kwargs, reason) -> None:
    assert _export("--identity-token", TOKEN) == 0
    code, payload = _verify(capsys, **kwargs)
    assert code == 1 and payload["ok"] is False
    assert reason in payload["signature"]["reason"]


def test_untrusted_root_fails(ws, capsys) -> None:
    root, _, _ = ws
    assert _export("--identity-token", TOKEN) == 0
    (root / "fulcio.pem").write_bytes(FakeFulcio().roots_pem())
    code, payload = _verify(capsys)
    assert code == 1 and "chain" in payload["signature"]["reason"]


def test_signature_time_outside_cert_validity_fails(ws, capsys) -> None:
    _, log, _ = ws
    log.time_offset = 3600  # logged an hour later: the 10-minute cert had expired
    assert _export("--identity-token", TOKEN) == 0
    code, payload = _verify(capsys)
    assert code == 1 and payload["receipt"]["status"] == "verified"
    assert "not valid at the signing time" in payload["signature"]["reason"]


def test_keyless_needs_receipt_key_and_flags(ws, capsys) -> None:
    root, _, _ = ws
    assert _export("--identity-token", TOKEN) == 0
    capsys.readouterr()
    assert _cli("verify", "run.tine", "--attestation", "a.sigstore.json", "--json",
                "--fulcio-root", "fulcio.pem", "--cert-identity", IDENTITY,
                "--cert-oidc-issuer", ISSUER_URL) == 1  # fmt: skip
    assert "--rekor-key" in json.loads(capsys.readouterr().out)["signature"]["reason"]
    bundle = json.loads((root / "a.sigstore.json").read_text())
    bundle["verificationMaterial"]["tlogEntries"] = []
    (root / "a.sigstore.json").write_text(json.dumps(bundle))
    code, payload = _verify(capsys)
    assert code == 1 and payload["receipt"]["status"] == "absent"
    assert _cli("verify", "run.tine", "--attestation", "a.sigstore.json", "--trust-embedded-key",
                "--rekor-key", "rekor.pub") == 1  # fmt: skip


def test_fulcio_error_never_echoes_token(ws, monkeypatch, capsys) -> None:
    import httpx

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"refused while sending {request.content.decode()}")

    monkeypatch.setattr(rekor, "TRANSPORT", httpx.MockTransport(boom))
    assert _export("--identity-token", TOKEN) == 1
    out = capsys.readouterr()
    assert "[REDACTED]" in out.out + out.err
    _no_token_anywhere(ws[0], out.out, out.err)
