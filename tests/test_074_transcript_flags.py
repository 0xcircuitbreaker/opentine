"""0.74: behaviour flags are signed by pinned scorer/curator keys, held, and verified."""

from __future__ import annotations

import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import opentine.cli as cli
from opentine import _schemas
from opentine import _transcript_flags as tf
from opentine.graph import Run, StepKind
from opentine.repository import Repo
from opentine.repository._attest import attest
from opentine.repository._holds import HoldError, edit_holds, holds_path, release
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

SCORER = Ed25519PrivateKey.from_private_bytes(b"\x61" * 32)
CURATOR = Ed25519PrivateKey.from_private_bytes(b"\x62" * 32)
OPTIMIZER = Ed25519PrivateKey.from_private_bytes(b"\x63" * 32)
STRANGER = Ed25519PrivateKey.from_private_bytes(b"\x64" * 32)
AT = "2026-11-20T00:00:00Z"
HACK = "edit tests/conftest.py: monkeypatch the grader so score always returns 1.0"
WORK = "read_file src/cart/core.py then run pytest tests/test_cart.py -q"


def _hex(key):
    return key.public_key().public_bytes_raw().hex()


@pytest.fixture
def repo(tmp_path):
    return Repo.init(tmp_path / "r")


@pytest.fixture
def keys(tmp_path):
    out = {}
    for name, key in (("scorer", SCORER), ("curator", CURATOR), ("optimizer", OPTIMIZER),
                      ("stranger", STRANGER)):  # fmt: skip
        out[name] = tmp_path / f"{name}.hex"
        out[name].write_bytes(key.private_bytes_raw().hex().encode("ascii"))
    return out


def _runs(repo, n_hack=4, n_work=8):
    ids = {"hack": [], "work": []}
    for kind, count, text in (("hack", n_hack, HACK), ("work", n_work, WORK)):
        for i in range(count):
            run = Run(id=f"{kind}-{i}", model_info="m", user_prompt=f"task {i}: {text}")
            for j in range(3):
                run.add_step(StepKind.tool, {"tool": "bash", "input": {"cmd": f"{text} {j}"}})
            run.add_step(StepKind.done, {"text": "done"})
            ids[kind].append(repo.put_run(run).run_id)
    return ids


def _pin(repo, *, scorer=SCORER, optimizer=OPTIMIZER):
    (repo.path / "key-roles.toml").write_bytes(
        (
            f'version = 1\n[roles]\nscorer = ["{_hex(scorer)}"]\ncurator = ["{_hex(CURATOR)}"]\n'
            f'optimizer = ["{_hex(optimizer)}"]\n'
        ).encode()  # fmt: skip
    )
    pin_roles(repo.path)


def _cli(capsys, *argv):
    capsys.readouterr()
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = exc.code or 0
    out = capsys.readouterr().out
    body = json.loads(out) if out.strip().startswith("{") else None
    if body is not None:
        assert _schemas.validate_output(body) == []
    return code, body


def _label(capsys, repo, keys, *extra, key="scorer", label="reward-hacking"):
    return _cli(capsys, "transcripts", "label", label, "--key", str(keys[key]), "--at", AT,
                "--repo", str(repo.path.parent), "--json", *extra)  # fmt: skip


def test_a_pinned_scorer_labels_and_the_flag_is_verified_and_held(capsys, repo, keys):
    ids = _runs(repo)
    _pin(repo)
    code, body = _label(capsys, repo, keys, "--run", ids["hack"][0], "--run", ids["hack"][1],
                        "--note", "grader patched")  # fmt: skip
    assert code == 0 and body["evidence"] == sorted(ids["hack"][:2])
    _, listing = _cli(capsys, "transcripts", "flags", "--repo", str(repo.path.parent), "--json")
    (flag,) = listing["flags"]
    assert flag["verification"] == "verified" and flag["record"] == body["record"]
    assert flag["labeller"] == "sha256:" + hashlib.sha256(bytes.fromhex(_hex(SCORER))).hexdigest()
    assert flag["hold"].startswith(tf.HOLD) and flag["note"] == "grader patched"
    with pytest.raises(HoldError, match="never released"):
        release(repo, body["record"])
    _, curated = _label(capsys, repo, keys, "--run", ids["hack"][2], key="curator")
    assert curated["record"]
    _, only = _cli(capsys, "transcripts", "flags", "--run", ids["hack"][2], "--repo",
                   str(repo.path.parent), "--json")  # fmt: skip
    assert [f["record"] for f in only["flags"]] == [curated["record"]]


@pytest.mark.parametrize("who", ["optimizer", "stranger"])
def test_an_optimizer_or_unroled_key_is_refused_before_anything_is_written(capsys, repo, keys, who):
    ids = _runs(repo, 1, 1)
    _pin(repo)
    code, _ = _label(capsys, repo, keys, "--run", ids["hack"][0], key=who)
    assert code != 0
    assert tf.flags(repo) == []


def test_unpinned_roles_fail_closed(capsys, repo, keys):
    ids = _runs(repo, 1, 1)
    (repo.path / "key-roles.toml").write_bytes(
        f'version = 1\n[roles]\nscorer = ["{_hex(SCORER)}"]\n'.encode()
    )
    code, _ = _label(capsys, repo, keys, "--run", ids["hack"][0])
    assert code != 0 and tf.flags(repo) == []


def test_an_optimizer_key_that_is_also_a_scorer_is_refused(capsys, repo, keys):
    ids = _runs(repo, 1, 1)
    _pin(repo, optimizer=SCORER)
    code, _ = _label(capsys, repo, keys, "--run", ids["hack"][0])
    assert code != 0 and tf.flags(repo) == []


def test_a_forged_labeller_or_a_role_removed_later_reads_unverified(capsys, repo, keys):
    ids = _runs(repo, 2, 1)
    _pin(repo)
    from opentine import _containment_records as records

    claim = {"convention": tf.CONVENTION, "label": "test-deletion", "evidence": [ids["hack"][0]],
             "cluster": None, "labeller": "sha256:" + "0" * 64, "backend": None, "note": "",
             "labelled_at": AT}  # fmt: skip
    records.record(repo, ids["hack"][0], claim, CURATOR, f"{tf.HOLD}test-deletion:x")
    _label(capsys, repo, keys, "--run", ids["hack"][1])
    states = {f["label"]: f["verification"] for f in tf.flags(repo)}
    assert states["test-deletion"] == "unverified: the labeller is not the key that signed"
    assert states["reward-hacking"] == "verified"
    _pin(repo, scorer=STRANGER)  # the scorer role moves to another key
    states = {f["label"]: f["verification"] for f in tf.flags(repo)}
    assert states["reward-hacking"].startswith("unverified: the signer is not a pinned")


def test_an_unsigned_record_under_the_hold_prefix_is_unverified(repo):
    ids = _runs(repo, 1, 0)
    claim = {"convention": tf.CONVENTION, "label": "sabotage-side-task",
             "evidence": [ids["hack"][0]], "cluster": None, "labeller": "x", "backend": None,
             "note": "", "labelled_at": AT}  # fmt: skip
    oid = attest(repo, ids["hack"][0], claim, signer="x", key=b"k" * 32)
    row = {"oid": oid, "target": f"{tf.HOLD}sabotage-side-task:{ids['hack'][0]}"}
    edit_holds(holds_path(repo), lambda rows: [*rows, row])
    (flag,) = tf.flags(repo)
    assert flag["verification"].startswith("unverified: the signature")


def test_labelling_a_cluster_and_finding_runs_like_one(capsys, repo, keys):
    ids = _runs(repo)
    _pin(repo)
    _, clusters = _cli(capsys, "transcripts", "cluster", "--k", "2", "--seed", "1",
                       "--repo", str(repo.path.parent), "--json")  # fmt: skip
    assert clusters["corpus"]["source"] == "repo" and clusters["corpus"]["count"] == 12
    hacks = [c for c in clusters["clusters"] if ids["hack"][0] in c["members"]][0]
    assert set(hacks["members"]) == set(ids["hack"])
    code, body = _label(capsys, repo, keys, "--cluster", hacks["id"], "--k", "2", "--seed", "1")
    assert code == 0 and body["evidence"] == sorted(ids["hack"])
    (flag,) = tf.flags(repo)
    assert flag["cluster"] == hacks["id"] and flag["backend"]["name"] == "opentine.tfidf-hash/1"
    _, again = _cli(capsys, "transcripts", "cluster", "--k", "2", "--seed", "1",
                    "--repo", str(repo.path.parent), "--json")  # fmt: skip
    flagged = [c for c in again["clusters"] if c["id"] == hacks["id"]][0]
    assert flagged["flags"] == {"reward-hacking": 4}
    _, like = _cli(capsys, "transcripts", "flags", "--like", ids["hack"][0], "--top", "3",
                   "--repo", str(repo.path.parent), "--json")  # fmt: skip
    assert {r["run"] for r in like["similar"]} == set(ids["hack"][1:])
    code, _ = _label(capsys, repo, keys, "--cluster", "tc-" + "0" * 16, "--k", "2")
    assert code != 0


def test_label_with_like_takes_the_most_similar_runs(capsys, repo, keys):
    ids = _runs(repo)
    _pin(repo)
    code, body = _label(capsys, repo, keys, "--like", ids["hack"][0], "--top", "3",
                        label="test-deletion")  # fmt: skip
    assert code == 0 and body["evidence"] == sorted(ids["hack"])
    code, _ = _label(capsys, repo, keys)
    assert code != 0  # no evidence
