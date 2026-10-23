"""0.12 security residuals: OIDC fetch bounds, catalog signature domain
separation, opt-in python sandboxes, private exports, Windows path spellings."""

from __future__ import annotations

import base64
import json
import os
import stat
import sys
import time
from pathlib import Path

import httpx
import pytest

from opentine import Run, StepKind, cli
from opentine.billing import _catalog_verify as cv
from opentine.policies import PythonPolicy
from opentine.remote import _jwks
from opentine.tools.python import execute

# -- R1: OIDC discovery / JWKS fetch ------------------------------------------


def _patch_client(monkeypatch, handler):
    real = httpx.Client

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", factory)


JWKS = {"keys": [{"kid": "a", "kty": "EC"}]}


def test_https_fetch_returns_a_json_document(monkeypatch):
    _patch_client(monkeypatch, lambda request: httpx.Response(200, json=JWKS))
    assert json.loads(_jwks.https_fetch("https://idp.example/jwks")) == JWKS


@pytest.mark.parametrize("url", ["http://idp.example/jwks", "ftp://x", "", None])
def test_https_fetch_refuses_non_https(url):
    with pytest.raises(_jwks.OIDCError):
        _jwks.https_fetch(url)


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(302, headers={"location": "https://evil.example/"}),
        httpx.Response(200, text="<html/>", headers={"content-type": "text/html"}),
        httpx.Response(
            200,
            content=json.dumps({"keys": ["x" * 2_000_000]}).encode(),
            headers={"content-type": "application/json"},
        ),
    ],
    ids=["redirect", "not-json", "oversized"],
)
def test_https_fetch_refuses_redirects_wrong_types_and_oversize(monkeypatch, response):
    _patch_client(monkeypatch, lambda request: response)
    with pytest.raises(_jwks.OIDCError):
        _jwks.https_fetch("https://idp.example/jwks")


def test_https_fetch_has_a_total_deadline_against_a_trickling_server(monkeypatch):
    class Trickle(httpx.SyncByteStream):
        def __iter__(self):
            yield b'{"keys": ['
            for _ in range(100):
                time.sleep(0.05)
                yield b" "

    _patch_client(
        monkeypatch,
        lambda request: httpx.Response(
            200, stream=Trickle(), headers={"content-type": "application/json"}
        ),
    )
    started = time.monotonic()
    with pytest.raises(_jwks.OIDCError):
        _jwks.https_fetch("https://idp.example/jwks", seconds=0.5)
    assert time.monotonic() - started < 3


# -- R3: catalog signature domain separation -----------------------------------


def _signed_catalog(monkeypatch, algorithm: str, generated_at: str, key_id: str = "test-key"):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    monkeypatch.setitem(cv.TRUSTED_KEYS, key_id, base64.b64encode(public).decode())
    data = {"schema": "opentine-pricing/2", "generated_at": generated_at, "cards": []}
    data["catalog_id"] = f"sha256:{cv.catalog_hash(data)}"
    body = {k: v for k, v in data.items() if k not in {"catalog_id", "signature"}}
    value = base64.b64encode(private.sign(cv.signed_message(algorithm, body))).decode()
    data["signature"] = {"algorithm": algorithm, "key_id": key_id, "value": value}
    return data


def test_v2_catalog_signature_verifies(monkeypatch):
    data = _signed_catalog(monkeypatch, cv.SCHEME_V2, "2027-01-01T00:00:00Z")
    assert cv.verify_catalog(data) == data["catalog_id"].split(":", 1)[1]


def test_v1_signature_is_refused_for_keys_that_never_signed_v1(monkeypatch):
    data = _signed_catalog(monkeypatch, cv.SCHEME_V1, "2026-10-01T00:00:00Z")
    with pytest.raises(cv.CatalogError, match="v2"):
        cv.verify_catalog(data)


def test_v1_signature_is_refused_after_the_cutoff_even_for_the_release_key(monkeypatch):
    key = "opentine-release-2026-07-r3"
    data = _signed_catalog(monkeypatch, cv.SCHEME_V1, "2027-01-01T00:00:00Z", key_id=key)
    with pytest.raises(cv.CatalogError, match="v2"):
        cv.verify_catalog(data)


def test_v1_signature_still_verifies_for_shipped_release_catalogs(monkeypatch):
    key = "opentine-release-2026-07-r3"
    data = _signed_catalog(monkeypatch, cv.SCHEME_V1, "2026-10-01T00:00:00Z", key_id=key)
    assert cv.verify_catalog(data)
    shipped = Path(__file__).parent / "fixtures" / "pricing" / "release_catalog_2026_07_20.json"
    monkeypatch.undo()
    assert cv.verify_catalog(json.loads(shipped.read_text(encoding="utf-8")))


def test_a_v2_signature_does_not_verify_as_v1_or_without_its_domain(monkeypatch):
    data = _signed_catalog(monkeypatch, cv.SCHEME_V2, "2026-10-01T00:00:00Z")
    monkeypatch.setattr(cv, "V1_KEYS", frozenset({"test-key"}))
    data["signature"]["algorithm"] = cv.SCHEME_V1
    with pytest.raises(cv.CatalogError, match="mismatch"):
        cv.verify_catalog(data)


def test_unknown_signature_algorithm_is_refused(monkeypatch):
    data = _signed_catalog(monkeypatch, cv.SCHEME_V2, "2027-01-01T00:00:00Z")
    data["signature"]["algorithm"] = "ed25519/other"
    with pytest.raises(cv.CatalogError, match="algorithm"):
        cv.verify_catalog(data)


# -- R4: python isolation backends ----------------------------------------------


def _probe(secret: Path) -> str:
    return (
        "import socket\n"
        f"try:\n    print(open({str(secret)!r}).read())\n"
        "except OSError as e:\n    print('blocked', type(e).__name__)\n"
        "open('scratch.txt', 'w').write('x'); print('scratch-ok')\n"
    )


@pytest.fixture
def outside_secret(tmp_path):
    secret = tmp_path / "outside-secret.txt"
    secret.write_text("TOPSECRET-OUTSIDE", encoding="utf-8")
    return secret


def test_unknown_backend_is_refused():
    out = execute("print(1)", policy=PythonPolicy(enabled=True, isolation_backend="gvisor"))
    assert out.startswith("Error:") and "gvisor" in out


# -- R5: export files ---------------------------------------------------------


def _invoke(monkeypatch, capsys, *argv: str) -> tuple[int, str]:
    monkeypatch.setattr(sys, "argv", ["tine", *argv])
    try:
        cli.main()
        code = 0
    except SystemExit as exc:
        code = int(exc.code or 0)
    return code, capsys.readouterr().out


@pytest.fixture
def export_workspace(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.chdir(tmp_path)
    run = Run(id="export-src")
    run.add_step(StepKind.done, {"text": "hello"})
    run.save(tmp_path / "source.tine")
    return tmp_path


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
@pytest.mark.parametrize("compress", [None, "gzip"])
def test_exports_are_owner_only_even_when_forced_over_a_readable_file(
    monkeypatch, capsys, export_workspace, compress
):
    target = export_workspace / "out.json"
    target.write_text("old", encoding="utf-8")
    target.chmod(0o644)
    extra = ["--compress", compress] if compress else []
    code, _ = _invoke(
        monkeypatch, capsys, "export", "source.tine", "--output", "out.json", "--force", *extra
    )
    assert code == 0
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt" or not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_export_refuses_a_fifo_destination_even_with_force(monkeypatch, capsys, export_workspace):
    os.mkfifo(export_workspace / "pipe")
    code, out = _invoke(monkeypatch, capsys, "export", "source.tine", "--output", "pipe", "--force")
    assert code == 1 and "not a regular file" in out


def test_export_refuses_a_directory_destination(monkeypatch, capsys, export_workspace):
    (export_workspace / "dir").mkdir()
    code, out = _invoke(monkeypatch, capsys, "export", "source.tine", "--output", "dir", "--force")
    assert code == 1 and "not a regular file" in out


# -- R6: Windows path spellings (pure normalisers; run on every platform) ------


@pytest.mark.parametrize(
    "spelling",
    [
        ".git",
        ".GIT",
        ".git.",
        ".git ",
        ".git. .",
        "GIT~1",
        "git~12",
        ".git::$INDEX_ALLOCATION",
        ".git:stream",
        ".g\u200cit",
    ],
)
def test_dotgit_aliases_are_recognised_everywhere(spelling):
    from opentine.tools._dotgit import is_dotgit

    assert is_dotgit(spelling)


@pytest.mark.parametrize("name", ["gitx", ".github", "legit", "git", ".gitignore"])
def test_ordinary_names_are_not_dotgit(name):
    from opentine.tools._dotgit import is_dotgit

    assert not is_dotgit(name)


@pytest.mark.parametrize(
    "ref", ["heads/con", "heads/NUL", "heads/com1", "heads/a.", "heads/a ", "heads/aux.txt"]
)
def test_windows_reserved_ref_names_are_refused_everywhere(ref):
    from opentine.repository._refs import normalize_ref

    with pytest.raises(ValueError):
        normalize_ref(ref)
