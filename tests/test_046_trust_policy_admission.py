"""0.46: named server trust policies for VSA admission, and the VSA verifier (SPEC 8.17)."""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import zipfile
from argparse import Namespace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _schemas, _vsa_verify
from opentine._pyz import _vsa as pyz_vsa
from opentine._pyz_build import build_bytes
from opentine.remote import (
    FilesystemObjectStore,
    Identity,
    LocalKeyProvider,
    RemoteApp,
    RemoteService,
    RoleAuthorizationPolicy,
    SQLiteBackend,
    StaticTokenIdentityProvider,
)
from opentine.remote._admission_policy import PolicyCheck, load_policies, parse_policy
from opentine.remote._serve_admission import serve_admission
from opentine.remote._vsa import TrustPolicyAdmission
from opentine.repository import Repo
from tests.conformance import tagged

ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / "docs/conformance/vectors/61-vsa.json").read_text("utf-8"))["cases"]
WRITER = Identity("ci@acme", "acme", ("writer",))
OTHER = Identity("dev@acme", "acme", ("writer", "maintainer"))
PROD = {"kind": "opentine.admission-policy", "version": 1, "refs": ["tags/v*"],
        "subjects": ["ci@acme"], "levels": ["OPENTINE_ADMITTED", "CI"]}  # fmt: skip
DEV = {"kind": "opentine.admission-policy", "version": 1, "refs": ["tags/*"]}


def _write(tmp_path: Path, name: str, value: dict) -> str:
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return f"{name}={path.as_posix()}"


def _service(tmp_path: Path, admission):
    objects = FilesystemObjectStore(tmp_path / "objects", LocalKeyProvider(b"k" * 32))
    index = SQLiteBackend(tmp_path / "remote.sqlite3")
    identities = StaticTokenIdentityProvider({"ci-token": WRITER, "dev-token": OTHER})
    service = RemoteService(
        objects, index, identities, RoleAuthorizationPolicy(), admission=admission
    )
    local = Repo.init(tmp_path / "local")
    oid = local.put("blob", b"payload", redact=False)
    objects.put("acme", oid, local.raw(oid))
    return service, oid


def _put_ref(app, oid: str, ref: str, token: str) -> str:
    state: dict = {}
    body = json.dumps({"new": oid, "expected_old": None}).encode()
    environ = {
        "REQUEST_METHOD": "PUT",
        "PATH_INFO": f"/v1/tenants/acme/refs/{ref}",
        "CONTENT_LENGTH": str(len(body)),
        "CONTENT_TYPE": "application/json",
        "HTTP_AUTHORIZATION": f"Bearer {token}",
        "wsgi.input": __import__("io").BytesIO(body),
    }
    b"".join(app(environ, lambda status, headers: state.update(status=status)))
    return state["status"]


def test_policies_parse_and_refuse_bad_files(tmp_path: Path):
    policy = parse_policy("prod", json.dumps(PROD).encode())
    assert policy.descriptor()["uri"] == "opentine:trust-policy/prod"
    assert len(policy.descriptor()["digest"]["sha256"]) == 64
    assert parse_policy("dev", json.dumps(DEV).encode()).rules["levels"] == ("OPENTINE_ADMITTED",)
    bad = [
        ("Prod", PROD),
        ("x", {**PROD, "kind": "other"}),
        ("x", {**PROD, "version": 2}),
        ("x", {**PROD, "extra": 1}),
        ("x", {k: v for k, v in PROD.items() if k != "refs"}),
        ("x", {**PROD, "roles": []}),
        ("x", {**PROD, "roles": [1]}),
    ]
    for name, value in bad:
        with pytest.raises(ValueError):
            parse_policy(name, json.dumps(value).encode())
    with pytest.raises(ValueError):
        parse_policy("x", b"\xff")
    with pytest.raises(ValueError):
        load_policies([_write(tmp_path, "a", DEV), _write(tmp_path, "a", DEV)])
    with pytest.raises(ValueError):
        load_policies(["no-equals-sign"])
    assert _schemas.detect(PROD) == "opentine-admission-policy-1"
    assert _schemas.validate(PROD, "opentine-admission-policy-1")[1] == []
    assert _schemas.validate({**PROD, "extra": 1}, "opentine-admission-policy-1")[1]


def test_first_covering_policy_decides_and_the_vsa_records_it(tmp_path: Path):
    policies = load_policies([_write(tmp_path, "prod", PROD), _write(tmp_path, "dev", DEV)])
    admission = TrustPolicyAdmission(
        PolicyCheck(policies), private_key=Ed25519PrivateKey.generate()
    )
    service, oid = _service(tmp_path, admission)
    assert service.update_ref(WRITER, "acme", "tags/v1", oid, None)
    assert service.update_ref(OTHER, "acme", "tags/feature", oid, None)
    first, second = (
        json.loads(base64.b64decode(envelope["payload"])) for envelope in admission.recent
    )
    assert first["predicate"]["policy"] == policies[0].descriptor()
    assert first["predicate"]["verifiedLevels"] == ["CI", "OPENTINE_ADMITTED"]
    assert second["predicate"]["policy"]["uri"] == "opentine:trust-policy/dev"
    with pytest.raises(PermissionError):  # prod covers tags/v2 and OTHER is not its subject
        service.update_ref(OTHER, "acme", "tags/v2", oid, None)
    with pytest.raises(PermissionError, match="no trust policy"):  # fail-closed
        PolicyCheck(policies[:1])(WRITER, "update_ref", {"tenant": "acme", "name": "tags/x"})
    with pytest.raises(PermissionError, match="no trust policy"):  # another tenant
        PolicyCheck([parse_policy("t", json.dumps({**DEV, "tenants": ["other"]}).encode())])(
            WRITER, "update_ref", {"tenant": "acme", "name": "tags/x"}
        )
    assert len(admission.recent) == 2


def test_object_type_and_role_rules(tmp_path: Path):
    typed = {**DEV, "object_types": ["run"], "roles": ["maintainer"]}
    check = PolicyCheck(load_policies([_write(tmp_path, "typed", typed)]))
    facts = {"tenant": "acme", "name": "tags/x", "new": "blob:" + "0" * 64}
    with pytest.raises(PermissionError, match="roles"):
        check(WRITER, "update_ref", {**facts, "object_type": "run"})
    with pytest.raises(PermissionError, match="object type"):
        check(OTHER, "update_ref", {**facts, "object_type": "blob"})
    assert check(OTHER, "update_ref", {**facts, "object_type": "run"})[0] == ["OPENTINE_ADMITTED"]
    assert check(WRITER, "upload", {"tenant": "acme"}) == []


def test_refusal_over_http_is_a_uniform_403(tmp_path: Path):
    policies = load_policies([_write(tmp_path, "prod", PROD)])
    admission = TrustPolicyAdmission(PolicyCheck(policies))
    service, oid = _service(tmp_path, admission)
    app = RemoteApp(service, tmp_path / "state")
    assert _put_ref(app, oid, "tags/v1", "dev-token") == "403 Forbidden"
    assert _put_ref(app, oid, "tags/elsewhere", "ci-token") == "403 Forbidden"
    assert _put_ref(app, oid, "tags/v1", "ci-token").startswith("200")


def test_serve_flags_load_named_policies(tmp_path: Path):
    spec = _write(tmp_path, "prod", PROD)
    args = Namespace(quota_rate=None, vsa_dir=str(tmp_path / "vsa"), admission_policy=[spec])
    chain = serve_admission(args)
    assert isinstance(chain, TrustPolicyAdmission)
    assert isinstance(chain.check, PolicyCheck)
    no_dir = serve_admission(Namespace(quota_rate=None, vsa_dir=None, admission_policy=[spec]))
    assert no_dir.sink is None
    with pytest.raises(SystemExit, match="tine serve"):
        serve_admission(
            Namespace(quota_rate=None, vsa_dir=None, admission_policy=["x=" + str(tmp_path / "no")])
        )


def test_a_server_signed_vsa_passes_the_gate_verifier(tmp_path: Path):
    key = Ed25519PrivateKey.generate()
    policies = load_policies([_write(tmp_path, "prod", PROD)])
    admission = TrustPolicyAdmission(PolicyCheck(policies), private_key=key)
    admission.admit(
        WRITER, "update_ref", {"tenant": "acme", "name": "tags/v9", "new": "run:" + "ab" * 32}
    )
    raw = key.public_key().public_bytes_raw()
    envelope = admission.recent[0]
    ok = _vsa_verify.classify(envelope, raw, "run:" + "ab" * 32, levels=["CI"],
                              policy="opentine:trust-policy/prod")  # fmt: skip
    assert ok == "valid"
    assert _vsa_verify.classify(envelope, raw, "run:" + "cd" * 32) == "wrong-subject"
    assert _vsa_verify.classify(envelope, bytes(32), "run:" + "ab" * 32) == "bad-signature"


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_reference_and_pyz_answer_every_vsa_vector(case):
    value = tagged.decode(case["input"]["value"])
    assert _vsa_verify.verify_case(value) == case["output"]
    assert pyz_vsa.verify_case(value) == case["output"]


def test_the_built_pyz_runs_the_vsa_vectors_without_opentine(tmp_path: Path):
    pyz = tmp_path / "tine-verify.pyz"
    pyz.write_bytes(build_bytes())
    with zipfile.ZipFile(pyz) as archive:
        assert {"tine_verify/_vsa_verify.py", "tine_verify/_pyz/_vsa.py"} <= set(archive.namelist())
    vectors = tmp_path / "vsa.json"
    cases = [tagged.decode(case["input"]["value"]) for case in CASES]
    vectors.write_text(json.dumps(cases), encoding="utf-8")
    script = (
        "import json, sys\nsys.path.insert(0, sys.argv[1])\n"
        "import importlib.util\nassert importlib.util.find_spec('opentine') is None\n"
        "from tine_verify._pyz import _vsa\n"
        "print(json.dumps([_vsa.verify_case(c) for c in json.load(open(sys.argv[2]))]))\n"
    )
    done = subprocess.run(
        [sys.executable, "-I", "-S", "-c", script, pyz.as_posix(), vectors.as_posix()],
        capture_output=True, text=True, timeout=120, check=True,
    )  # fmt: skip
    assert json.loads(done.stdout) == [case["output"] for case in CASES]


def test_the_signing_key_flag_signs_vsas_and_caps_advertise_it(tmp_path: Path):
    seed = tmp_path / "server.key"
    seed.write_text("11" * 32, encoding="utf-8")
    spec = _write(tmp_path, "prod", PROD)
    args = Namespace(
        quota_rate=None, vsa_dir=None, admission_policy=[spec], vsa_signing_key=str(seed)
    )
    admission = serve_admission(args)
    service, oid = _service(tmp_path, admission)
    caps = service.capabilities()["vsa"]
    assert caps["policies"] == ["opentine:trust-policy/prod"]
    (key,) = caps["keys"]
    assert key["alg"] == "ed25519" and key["kid"].startswith("ed25519:")
    assert service.update_ref(WRITER, "acme", "tags/v1", oid, None)
    raw = base64.urlsafe_b64decode(key["public_key"] + "=" * (-len(key["public_key"]) % 4))
    assert _vsa_verify.classify(admission.recent[0], raw, oid, levels=["CI"]) == "valid"
    assert "vsa" not in _service(tmp_path / "plain", None)[0].capabilities()
    seed.write_text("not a key", encoding="utf-8")
    with pytest.raises(SystemExit, match="vsa-signing-key"):
        serve_admission(args)
