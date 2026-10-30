"""0.16 named trust policies: ``tine trust policy ...`` and ``tine verify --policy``.

Policies live only in the user's ``$XDG_CONFIG_HOME/opentine/trust-policies.json``
(0600, regular, owned, not group/world-writable); a repository can never define
or select one. Verifying with a policy must equal verifying with the same flags.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from opentine import Run, RunStatus, StepKind, cli, rekor
from opentine.repository import Repo
from opentine.signing import generate_ed25519

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")


@pytest.fixture
def ws(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setattr(cli, "RUNS_DIR", tmp_path / ".tine_runs")
    monkeypatch.chdir(tmp_path)
    run = Run(id="policy_src", model_info="mock-model", user_prompt="hello")
    run.add_step(StepKind.model, {"prompt": "hello"}, outputs={"text": "hi"}, model_info="m")
    run.status = RunStatus.completed
    run.save(tmp_path / "run.tine")
    seed, public = generate_ed25519()
    (tmp_path / "k.key").write_text(seed + "\n", encoding="utf-8")
    (tmp_path / "k.pub").write_text(public + "\n", encoding="utf-8")
    other_seed, other = generate_ed25519()
    (tmp_path / "other.pub").write_text(other + "\n", encoding="utf-8")
    run.save(tmp_path / "ed.tine", sign_key=seed, sign_algorithm="ed25519")
    assert _cli("export", "run.tine", "--format", "intoto", "--ed25519-key-file", "k.key",
                "--output", "a.intoto.jsonl") == 0  # fmt: skip
    return tmp_path


def _cli(*argv: str) -> int:
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def _json(capsys, *argv: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = _cli(*argv, "--json")
    return code, json.loads(capsys.readouterr().out)


def _policy_file(root: Path) -> Path:
    return root / "cfg" / "opentine" / "trust-policies.json"


VERIFY = ("verify", "run.tine", "--attestation", "a.intoto.jsonl")


def test_set_list_show_default_rm(ws, capsys) -> None:
    assert _cli("trust", "policy", "set", "prod", "--pubkey", "k.pub", "--require-receipt") == 0
    assert _cli("trust", "policy", "set", "dev", "--pin", "sha256:" + "a" * 64) == 0
    code, listing = _json(capsys, "trust", "policy", "list")
    assert code == 0 and sorted(listing["policies"]) == ["dev", "prod"]
    assert listing["default"] is None
    code, shown = _json(capsys, "trust", "policy", "show", "prod")
    assert shown["policy"] == {"pubkey": str(ws / "k.pub"), "require_receipt": True}
    assert Path(shown["policy"]["pubkey"]).is_absolute()
    assert _cli("trust", "policy", "default", "prod") == 0
    assert _json(capsys, "trust", "policy", "list")[1]["default"] == "prod"
    assert _cli("trust", "policy", "default", "--clear") == 0
    assert _json(capsys, "trust", "policy", "list")[1]["default"] is None
    assert _cli("trust", "policy", "default", "prod") == 0
    assert _cli("trust", "policy", "rm", "prod") == 0
    listing = _json(capsys, "trust", "policy", "list")[1]
    assert listing == {"command": "trust policy", "default": None, "policies": listing["policies"]}
    assert list(listing["policies"]) == ["dev"]
    assert _cli("trust", "policy", "rm", "prod") == 1
    assert _cli("trust", "policy", "show", "prod") == 1
    assert _cli("trust", "policy", "default", "nope") == 1


def test_set_refuses_bad_input(ws) -> None:
    assert _cli("trust", "policy", "set", "empty") == 1  # no trust root
    assert _cli("trust", "policy", "set", "Bad/Name", "--pubkey", "k.pub") == 1
    assert _cli("trust", "policy", "set", "p", "--pubkey", "missing.pub") == 1
    assert _cli("trust", "policy", "set", "p", "--pin", "nothex") == 1
    assert _cli("trust", "policy", "set", "p", "--cert-identity", "a@b") == 1  # partial keyless
    assert not _policy_file(ws).exists()


def test_policy_equals_flags(ws, capsys) -> None:
    assert _cli("trust", "policy", "set", "prod", "--pubkey", "k.pub") == 0
    code_flags, by_flags = _json(capsys, *VERIFY, "--pubkey", "k.pub")
    code_policy, by_policy = _json(capsys, *VERIFY, "--policy", "prod")
    assert code_flags == code_policy == 0
    assert by_policy.pop("policy") == "prod"
    assert by_policy == by_flags and "policy" not in by_flags
    # the plain run-signature path too
    code_flags, by_flags = _json(capsys, "verify", "ed.tine", "--pubkey", "k.pub")
    code_policy, by_policy = _json(capsys, "verify", "ed.tine", "--policy", "prod")
    assert code_flags == code_policy == 0 and by_flags["signature"]["ok"] is True
    assert by_policy.pop("policy") == "prod" and by_policy == by_flags


def test_explicit_flag_overrides_policy(ws, capsys) -> None:
    assert _cli("trust", "policy", "set", "wrong", "--pubkey", "other.pub") == 0
    assert _json(capsys, *VERIFY, "--policy", "wrong")[0] == 1
    code, payload = _json(capsys, *VERIFY, "--policy", "wrong", "--pubkey", "k.pub")
    assert code == 0 and payload["ok"] is True and payload["policy"] == "wrong"
    # TOFU is never in a policy, but an explicit flag still replaces the policy key
    code, payload = _json(capsys, *VERIFY, "--policy", "wrong", "--trust-embedded-key")
    assert code == 0 and payload["signature"]["status"] == "verified-tofu"


def test_unknown_policy_and_conflicting_switches(ws, capsys) -> None:
    capsys.readouterr()
    assert _cli(*VERIFY, "--policy", "nope") == 1
    assert "unknown policy 'nope'" in capsys.readouterr().out
    assert _cli(*VERIFY, "--policy", "nope", "--no-policy") == 1


def test_default_applies_and_no_policy_disables(ws, capsys) -> None:
    before = _json(capsys, "verify", "ed.tine")
    assert _cli("trust", "policy", "set", "prod", "--pubkey", "other.pub") == 0
    assert _cli("trust", "policy", "default", "prod") == 0
    code, payload = _json(capsys, "verify", "ed.tine")
    assert code == 1 and payload["policy"] == "prod" and payload["signature_checked"] is True
    assert _json(capsys, "verify", "ed.tine", "--no-policy") == before
    # an explicit key flag means the default is not consulted at all
    code, payload = _json(capsys, "verify", "ed.tine", "--pubkey", "k.pub")
    assert code == 0 and "policy" not in payload


def test_no_config_leaves_verify_json_unchanged(ws, capsys) -> None:
    code, payload = _json(capsys, *VERIFY, "--pubkey", "k.pub")
    assert code == 0 and "policy" not in payload
    assert not _policy_file(ws).exists()


def test_policy_paths_are_validated_on_use(ws, capsys) -> None:
    assert _cli("trust", "policy", "set", "prod", "--pubkey", "k.pub") == 0
    (ws / "k.pub").unlink()
    capsys.readouterr()
    assert _cli(*VERIFY, "--policy", "prod") == 1
    assert "not a readable file" in capsys.readouterr().out


def test_repository_cannot_define_or_select_a_policy(ws, capsys) -> None:
    Repo.init(ws)
    for key in ("trust.default", "trust.policy", "policy.prod"):
        assert _cli("config", key, "prod") != 0
    porcelain = ws / ".tine" / "porcelain.json"
    assert not porcelain.exists() or "trust" not in porcelain.read_text()
    # a cloned porcelain.json carrying trust keys, even trusted, selects nothing
    assert _cli("trust", "policy", "set", "prod", "--pubkey", "other.pub") == 0
    porcelain.write_text(json.dumps({"config": {"trust.default": "prod"}}), encoding="utf-8")
    assert _cli("config", "--trust") == 0
    code, payload = _json(capsys, *VERIFY, "--pubkey", "k.pub")
    assert code == 0 and "policy" not in payload
    code, payload = _json(capsys, "verify", "ed.tine")
    assert code == 0 and "policy" not in payload and payload["signature_checked"] is False
    # and no repository file is ever read as a policy store
    (ws / ".tine" / "trust-policies.json").write_text(
        json.dumps({"default": "evil", "policies": {"evil": {"pubkey": str(ws / "other.pub")}}})
    )
    assert _cli(*VERIFY, "--policy", "evil") == 1


@posix_only
def test_policy_file_is_private_and_refused_when_unsafe(ws, capsys) -> None:
    assert _cli("trust", "policy", "set", "prod", "--pubkey", "k.pub") == 0
    path = _policy_file(ws)
    assert path.stat().st_mode & 0o777 == 0o600
    path.chmod(0o666)
    capsys.readouterr()
    assert _cli(*VERIFY, "--policy", "prod") == 1
    assert "writable" in capsys.readouterr().out
    assert _cli("trust", "policy", "list") == 1
    path.chmod(0o600)
    real = ws / "elsewhere.json"
    path.rename(real)
    path.symlink_to(real)
    capsys.readouterr()
    assert _cli(*VERIFY, "--policy", "prod") == 1
    assert "symlink" in capsys.readouterr().out
    assert _cli("trust", "policy", "set", "x", "--pubkey", "k.pub") == 1
    assert path.is_symlink()


def test_trust_embedded_key_is_not_a_policy_field(ws) -> None:
    assert _cli("trust", "policy", "set", "tofu", "--trust-embedded-key") != 0
    path = _policy_file(ws)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"policies": {"t": {"trust_embedded_key": True}}}))
    path.chmod(0o600)
    assert _cli(*VERIFY, "--policy", "t") == 1


def test_keyless_policy(monkeypatch, tmp_path, capsys) -> None:
    pytest.importorskip("httpx")
    from tests._sigstore_fakes import (
        IDENTITY,
        ISSUER_URL,
        FakeFulcio,
        FakeLog,
        fake_jwt,
        transport,
    )

    token = fake_jwt({"iss": ISSUER_URL, "sub": "repo:o/r", "email": IDENTITY, "aud": "x"})
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    for name in ("SIGSTORE_ID_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"):
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
    monkeypatch.setattr(rekor, "TRANSPORT", transport(log, fulcio, gh_token=token))
    assert _cli("export", "run.tine", "--format", "intoto", "--keyless", "--rekor",
                "https://rekor.test", "--fulcio-url", "https://fulcio.test",
                "--output", "a.sigstore.json", "--identity-token", token) == 0  # fmt: skip
    flags = ("--rekor-key", "rekor.pub", "--fulcio-root", "fulcio.pem",
             "--cert-identity", IDENTITY, "--cert-oidc-issuer", ISSUER_URL)  # fmt: skip
    assert _cli("trust", "policy", "set", "ci", *flags) == 0
    base = ("verify", "run.tine", "--attestation", "a.sigstore.json")
    code_flags, by_flags = _json(capsys, *base, *flags)
    code_policy, by_policy = _json(capsys, *base, "--policy", "ci")
    assert code_flags == code_policy == 0
    assert by_policy.pop("policy") == "ci" and by_policy == by_flags
    assert by_flags["signature"]["status"] == "verified-keyless"
    # a wrong identity typed on the command line overrides the policy's
    code, payload = _json(capsys, *base, "--policy", "ci", "--cert-identity", "x@y")
    assert code == 1 and payload["ok"] is False
