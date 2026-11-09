"""0.47: the prompt registry and team memory (SPEC 4.21, 4.22).

The 68-prompt and 69-memory families agree in Python and the pyz (the TS
verifier runs them in ``ts/verifier``'s conformance test); ``tine prompt``
keeps a signed chain whose labels move and whose versions never do, and links a
version to a run; ``tine memory`` refuses a secret, keeps a hex digest, and
shows only notes the team signed.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _memory, _prompt, _schemas, cli
from opentine._pyz import _registry as pyz
from opentine._pyz_build import build_bytes
from opentine._signed_record import RecordError
from opentine.repository import Repo
from opentine.repository import _registry_refs as refs
from tests.conformance import tagged

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "docs" / "conformance" / "vectors"
WHEN = "2026-11-09T00:00:00Z"
DIGEST = "blob:sha256:0a3bc54dc894c69be6d8b8efeef1892fd88831c202aa1fef3cf65a8a60b145f4"


def _cases(name: str) -> list[dict]:
    return json.loads((VECTORS / name).read_text("utf-8"))["cases"]


def _tine(capsys, *argv: str) -> tuple[int, dict | str]:
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 1
    out = capsys.readouterr().out
    try:
        return code, json.loads(out)
    except ValueError:
        return code, out


def _answer(verifier: str, op: str, value: dict):
    key = bytes.fromhex(value["public_key"]) if value.get("public_key") else None
    if op == "prompt.verify":
        if verifier == "python":
            return _prompt.check(value["record"], previous=value["previous"], public_key=key)
        return pyz.prompt_verify(value["record"], value["previous"], key)
    if verifier == "python":
        return _memory.check(value["record"], public_key=key, team=value["team"])
    return pyz.memory_verify(value["record"], key, value["team"])


@pytest.mark.parametrize("verifier", ["python", "pyz"])
@pytest.mark.parametrize(("family", "count"), [("68-prompt.json", 24), ("69-memory.json", 18)])
def test_the_68_and_69_families_agree_in_python_and_the_pyz(verifier, family, count):
    cases = _cases(family)
    assert len(cases) == count
    for case in cases:
        value = tagged.decode(case["input"]["value"])
        if case["expect"] == "accept":
            assert _answer(verifier, case["op"], value) == case["output"], case["id"]
        else:
            with pytest.raises(ValueError) as caught:
                _answer(verifier, case["op"], value)
            assert caught.value.code == case["reason"], case["id"]  # type: ignore[attr-defined]


def test_the_record_schemas_hold_the_accepted_vectors():
    for name in ("68-prompt.json", "69-memory.json"):
        for case in _cases(name):
            if case["expect"] == "accept":
                record = tagged.decode(case["input"]["value"])["record"]
                stem, errors = _schemas.validate(record)
                assert errors == [] and stem in {"opentine-prompt-1", "opentine-memory-1"}


def test_the_built_pyz_checks_a_prompt_history_and_a_memory_note(tmp_path):
    cases = {c["id"]: tagged.decode(c["input"]["value"]) for c in
             _cases("68-prompt.json") + _cases("69-memory.json")}  # fmt: skip
    history = tmp_path / "history.json"
    first, second = cases["prompt.valid-first"]["record"], cases["prompt.valid-next"]["record"]
    history.write_text(json.dumps({"versions": [first, second]}))
    note = tmp_path / "note.json"
    note.write_text(json.dumps(cases["memory.valid-tofu"]["record"]))
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(cases["memory.tampered"]["record"]))
    pyz_path = tmp_path / "tine-verify.pyz"
    pyz_path.write_bytes(build_bytes())

    def run(path: Path) -> tuple[int, dict]:
        argv = [sys.executable, "-I", "-S", pyz_path.as_posix(), path.as_posix()]
        done = subprocess.run(argv, capture_output=True, text=True, timeout=300, cwd=tmp_path)
        return done.returncode, json.loads(done.stdout)

    code, result = run(history)
    assert code == 0 and result["mode"] == "prompt" and result["checks"][0]["versions"] == 2
    code, result = run(note)
    assert code == 0 and result["mode"] == "memory" and result["verdict"] == "pass"
    code, result = run(tampered)
    assert code == 1 and result["checks"][0]["reason"] == "memory.bad-signature"


# --- tine prompt ------------------------------------------------------------- #


@pytest.fixture
def keyed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Repo.init(tmp_path)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    path = tmp_path / "k.key"
    path.write_text(key.private_bytes_raw().hex())
    pub = tmp_path / "k.pub"
    pub.write_text(key.public_key().public_bytes_raw().hex())
    return tmp_path, path.as_posix(), pub.as_posix()


def _valid(document: dict) -> None:
    assert _schemas.validate_output(document) == [], document


@pytest.mark.filterwarnings("ignore::Warning")
def test_prompt_push_label_get_and_verify(keyed, capsys):
    root, key, pub = keyed
    code, first = _tine(capsys, "prompt", "push", "review", "--template", "Review {{diff}}",
                        "--key", key, "--label", "production", "--json")  # fmt: skip
    assert code == 0 and first["prompt"]["version"] == 1, first
    _valid(first)
    code, second = _tine(capsys, "prompt", "push", "review", "--template",
                         "Review {{diff}} against {{policy}}", "--key", key, "--json")  # fmt: skip
    assert (
        second["prompt"]["version"] == 2 and second["record"]["prev"] == first["prompt"]["digest"]
    )
    code, got = _tine(capsys, "prompt", "get", "review@production", "--json")
    assert got["prompt"]["digest"] == first["prompt"]["digest"]  # the label did not move
    _valid(got)
    code, moved = _tine(capsys, "prompt", "label", "review", "production", "--json")
    assert moved["labels"] == {"production": 2}
    _valid(moved)
    code, text = _tine(capsys, "prompt", "get", "review@v2", "--var", "diff=D", "--var",
                       "policy=P")  # fmt: skip
    assert text.strip() == "Review D against P"
    code, checked = _tine(capsys, "prompt", "verify", "review", "--pubkey", pub, "--json")
    assert code == 0 and checked["result"]["versions"] == 2
    assert checked["result"]["state"] == "verified"
    _valid(checked)
    code, listed = _tine(capsys, "prompt", "list", "--json")
    assert [p["name"] for p in listed["prompts"]] == ["review"]
    _valid(listed)


@pytest.mark.filterwarnings("ignore::Warning")
def test_prompt_link_records_the_version_in_the_runs_annotation(keyed, capsys):
    from opentine.repository._annotations import load_run_annotation
    from opentine.trace import Recorder, TraceEvent

    root, key, _ = keyed
    repo = Repo.open(root)
    recorder = Recorder.start(repo, capture=False)
    recorder.append(TraceEvent("model", 1, "trace", "span", outputs={"text": "ok"}))
    run = recorder.finalize()
    _tine(capsys, "prompt", "push", "review", "--template", "Review {{diff}}", "--key", key)
    code, linked = _tine(capsys, "prompt", "link", "review", run, "--json")
    assert code == 0 and linked["run"] == run, linked
    _valid(linked)
    metadata, _ = load_run_annotation(Repo.open(root), run)
    assert metadata["prompt"]["name"] == "review" and metadata["prompt"]["version"] == 1


def test_a_prompt_ref_refuses_a_record_of_another_kind(keyed):
    root, _, _ = keyed
    repo = Repo.open(root)
    oid = repo.put("blob", b'{"kind":"opentine.memory"}', redact=False)
    with pytest.raises(ValueError):
        repo.update_ref("prompts/review/head", oid, expected_old=None)


def test_a_stranger_cannot_extend_a_prompt(keyed):
    root, _, _ = keyed
    repo = Repo.open(root)
    owner = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    stranger = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    first = _prompt.sign(_prompt.build("review", "A {{x}}", created_at=WHEN), owner)
    refs.push_prompt(repo, first)
    record = _prompt.build("review", "B {{x}}", previous=first, created_at=WHEN)
    with pytest.raises(RecordError) as caught:
        refs.push_prompt(repo, _prompt.sign(record, stranger))
    assert caught.value.code == "prompt.wrong-signer"
    assert refs.prompt_head(repo, "review") == first


# --- tine memory ------------------------------------------------------------- #


@pytest.mark.filterwarnings("ignore::Warning")
def test_memory_add_trust_list_and_recall(keyed, capsys):
    root, key, pub = keyed
    text = f"Run pytest with the venv python; the baseline is {DIGEST}"
    code, added = _tine(capsys, "memory", "add", "testing", text, "--key", key, "--tag", "ci",
                        "--json")  # fmt: skip
    assert code == 0 and added["note"]["state"] == "verified-tofu", added  # a digest is no secret
    _valid(added)
    code, listed = _tine(capsys, "memory", "list", "--json")
    assert listed["notes"] == [] and listed["team"] == 0  # no team file: nothing is trusted
    code, trusted = _tine(capsys, "memory", "trust", pub, "--json")
    assert len(trusted["team"]) == 1
    _valid(trusted)
    code, found = _tine(capsys, "memory", "recall", "venv pytest", "--json")
    assert [n["topic"] for n in found["notes"]] == ["testing"]
    assert found["notes"][0]["state"] == "verified"
    _valid(found)
    code, missing = _tine(capsys, "memory", "recall", "docker", "--json")
    assert missing["notes"] == []


@pytest.mark.filterwarnings("ignore::Warning")
def test_memory_add_refuses_a_secret(keyed, capsys):
    root, key, _ = keyed
    code, _ = _tine(capsys, "memory", "add", "creds", "token AKIAIOSFODNN7EXAMPLE", "--key", key)
    assert code != 0
    assert not [name for name in Repo.open(root).list_refs() if name.startswith("memory/")]


def test_a_superseded_note_is_not_shown(keyed):
    root, _, _ = keyed
    repo = Repo.open(root)
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    old = _memory.sign(_memory.build("team", "ci", "Use tox", author="a", created_at=WHEN), key)
    refs.add_note(repo, old)
    new = _memory.build("team", "ci", "Use uv", author="a", supersedes=_memory.digest(old),
                        created_at=WHEN)  # fmt: skip
    refs.add_note(repo, _memory.sign(new, key))
    assert [n["record"]["text"] for n in refs.notes(repo)] == ["Use uv"]
