"""0.51: owner-signed browser trust bundles (SPEC 8.26), Python and the TS bundle.

A bundle is a signed note over existing trust documents. ``tine trust bundle
create`` signs one and ``verify`` checks it against the owner key pinned out of
band; the committed browser verifier (``opentine/data/ui/tine-verifier.js``)
opens the same bytes and pins its signers, so a signature that held only
"unpinned" in the viewer reads "verified" (pinned key) or "failed" (any other).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from opentine import Run, _trust_bundle, cli
from opentine._signing_keys import ed25519_private_from_file, generate_ed25519
from opentine._signing_pins import key_fingerprint
from opentine._trust_bundle import BundleError, open_bundle, sign
from opentine.core import RunStatus, StepKind
from opentine.repository._tlog_note import vkey_for

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "opentine" / "data" / "ui"
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed")
pytestmark = pytest.mark.filterwarnings("ignore::opentine._key_store.PlaintextKeyWarning")
NAME = "example.com/trust"


def _key(path: Path) -> tuple[Path, str]:
    private, public = generate_ed25519()
    path.write_text(private + "\n", encoding="ascii")
    path.chmod(0o600)
    return path, public


def _payload(**extra) -> dict:
    return {
        "trust_bundle": 1,
        "serial": 2,
        "issued_at": "2026-11-13T00:00:00Z",
        "trust_policy": {"pin": ["sha256:" + "a" * 64]},
        **extra,
    }


def _owner(tmp_path: Path):
    path, public = _key(tmp_path / "owner.key")
    return ed25519_private_from_file(path), vkey_for(NAME, bytes.fromhex(public)), path


def _registry() -> dict:
    from opentine.repository._tlog_cosign import witness_vkey

    witnesses = []
    for n in range(3):
        _, public = generate_ed25519()
        name = f"w{n}.example"
        witnesses.append({"name": name, "operator": f"Org {n}", "url": f"https://{name}",
                          "vkeys": [witness_vkey(name, bytes.fromhex(public))]})  # fmt: skip
    _, log_public = generate_ed25519()
    origin = "log.example/main"
    log = {"origin": origin, "vkey": vkey_for(origin, bytes.fromhex(log_public))}
    return {"schema": "opentine-witness-network/1", "log": log, "policy": {"quorum": "2-of-3"},
            "witnesses": witnesses}  # fmt: skip


def test_a_bundle_round_trips_and_carries_only_existing_documents(tmp_path):
    key, owner, _ = _owner(tmp_path)
    registry = _registry()
    admission = {"kind": "opentine.admission-policy", "version": 1, "refs": ["refs/heads/*"]}
    payload = _payload(witness_network=registry, log_keys=[registry["log"]["vkey"]],
                       admission_policies={"main": admission})  # fmt: skip
    note = sign(payload, key, NAME)
    assert open_bundle(note, owner) == payload
    assert note.startswith(NAME.encode() + b"\n{")


@pytest.mark.parametrize(
    "change, message",
    [
        ({"trust_bundle": 2}, "not a trust bundle payload"),
        ({"serial": 0}, "serial"),
        ({"serial": True}, "serial"),
        ({"issued_at": "2026-11-13"}, "issued_at"),
        ({"expires_at": "2026-11-12T00:00:00Z"}, "after issued_at"),
        ({"trust_policy": {"pubkey": "/home/me/key.pub"}}, "may only hold"),
        ({"trust_policy": {"pin": ["sha256:abc"]}}, "fingerprint"),
        ({"log_keys": ["not-a-vkey"]}, "log key"),
        ({"witness_network": {"schema": "opentine-witness-network/1"}}, "witness network"),
        ({"admission_policies": {"main": {"kind": "other"}}}, "admission policy"),
        ({"extra": 1}, "not a trust bundle payload"),
    ],
)
def test_each_part_is_held_to_its_own_format(change, message):
    with pytest.raises(BundleError, match=message):
        _trust_bundle.validate(_payload(**change))


def test_a_bundle_the_pinned_owner_did_not_sign_is_refused(tmp_path):
    key, owner, _ = _owner(tmp_path)
    note = sign(_payload(), key, NAME)
    other = vkey_for(NAME, bytes.fromhex(_key(tmp_path / "other.key")[1]))
    with pytest.raises(BundleError, match="not signed by the pinned owner"):
        open_bundle(note, other)
    tampered = note.replace(b'"serial":2', b'"serial":9')
    with pytest.raises(BundleError, match="not signed by the pinned owner"):
        open_bundle(tampered, owner)
    renamed = vkey_for("other.example/trust", bytes.fromhex(_key(tmp_path / "x.key")[1]))
    with pytest.raises(BundleError, match="names owner"):
        open_bundle(note, renamed)


def test_expiry_and_rollback_are_refused(tmp_path):
    key, owner, _ = _owner(tmp_path)
    note = sign(_payload(expires_at="2026-12-01T00:00:00Z"), key, NAME)
    early = datetime(2026, 11, 20, tzinfo=UTC)
    assert open_bundle(note, owner, now=early)["serial"] == 2
    with pytest.raises(BundleError, match="expired"):
        open_bundle(note, owner, now=early + timedelta(days=30))
    with pytest.raises(BundleError, match="older than 3"):
        open_bundle(note, owner, now=early, min_serial=3)


def test_the_cli_creates_and_verifies_with_the_published_schema(tmp_path, capsys):
    from opentine._schemas import validate_output

    _, owner, key = _owner(tmp_path)
    out = tmp_path / "bundle.note"
    code = cli.main(["trust", "bundle", "create", "--key", str(key), "--name", NAME,
                     "--serial", "5", "--pin", "a" * 64, "--out", str(out), "--json"])  # fmt: skip
    created = json.loads(capsys.readouterr().out)
    assert code in (0, None) and created["owner_vkey"] == owner and created["serial"] == 5
    assert created["pins"] == ["sha256:" + "a" * 64] and not validate_output(created)
    code = cli.main(["trust", "bundle", "verify", str(out), "--owner-vkey", owner, "--json"])
    checked = json.loads(capsys.readouterr().out)
    assert code in (0, None) and checked["digest"] == created["digest"]
    assert not validate_output(checked)
    with pytest.raises(SystemExit) as exc:
        cli.main(["trust", "bundle", "verify", str(out), "--owner-vkey", owner,
                  "--min-serial", "6", "--json"])  # fmt: skip
    assert exc.value.code == 4


def test_a_named_policy_with_local_files_cannot_go_into_a_bundle(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    _, _, key = _owner(tmp_path)
    public = tmp_path / "signer.pub"
    public.write_text(generate_ed25519()[1], encoding="ascii")
    assert cli.main(["trust", "policy", "set", "team", "--pubkey", str(public)]) in (0, None)
    with pytest.raises(SystemExit) as exc:
        cli.main(["trust", "bundle", "create", "--key", str(key), "--name", NAME,
                  "--serial", "1", "--policy", "team"])  # fmt: skip
    assert exc.value.code == 1


def _signed_run(room: Path) -> tuple[Path, str]:
    run = Run(user_prompt="hello", model_info="model-a")
    run.add_step(StepKind.model, inputs={"messages": [{"role": "user", "content": "hi"}]})
    run.status = RunStatus.completed
    path = room / "run.tine"
    run.save(path)
    key, public = _key(room / "signer.key")
    cli.main(["sign", str(path), "--algorithm", "ed25519", "--ed25519-key-file",
              str(key), "--save", str(path), "--overwrite"])  # fmt: skip
    return path, key_fingerprint(bytes.fromhex(public))


PINNED = """
import { readFileSync } from "node:fs";
import { openTrustBundle, verifyArtifact } from "./tine-verifier.js";
import { badge, browserStates } from "./verify-browser.js";
const [run, note, owner] = process.argv.slice(1);
const bundle = openTrustBundle(new Uint8Array(readFileSync(note)), owner);
const report = await verifyArtifact(new Uint8Array(readFileSync(run)), "artifact", bundle);
const mine = { ...browserStates(report), trustSerial: bundle.serial };
const b = badge({ integrity: "verified", signature: "verified", overall: "verified" }, mine);
let refused = "";
const next = { minSerial: bundle.serial + 1 };
try { openTrustBundle(new Uint8Array(readFileSync(note)), owner, next); }
catch (exc) { refused = exc.message; }
const sig = report.signature;
console.log(JSON.stringify({ serial: bundle.serial, pins: [...bundle.pins], state: sig.state,
  reason: sig.reason, mine, badge: b, refused }));
"""


def _node(*args: str) -> dict:
    done = subprocess.run([NODE, "--input-type=module", "-e", PINNED, *args],
                          capture_output=True, text=True, timeout=120, cwd=UI)  # fmt: skip
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


@needs_node
def test_the_browser_bundle_pins_the_signers_a_trust_bundle_names(tmp_path):
    run, fingerprint = _signed_run(tmp_path)
    key, owner, _ = _owner(tmp_path)
    pinned = tmp_path / "pinned.note"
    pinned.write_bytes(sign(_payload(trust_policy={"pin": [fingerprint]}), key, NAME))
    found = _node(run.as_posix(), pinned.as_posix(), owner)
    assert found["pins"] == [fingerprint] and found["state"] == "verified"
    assert found["reason"] == "ok (pinned key)" and found["mine"]["signature"] == "verified"
    assert "trust bundle serial 2" in found["badge"]["rows"][3][2]
    assert "older than 3" in found["refused"]
    other = tmp_path / "other.note"
    other.write_bytes(sign(_payload(), key, NAME))
    found = _node(run.as_posix(), other.as_posix(), owner)
    assert found["state"] == "mismatch" and "is not a pinned key" in found["reason"]
    assert found["mine"]["signature"] == "failed" and found["badge"]["state"] == "failed"
