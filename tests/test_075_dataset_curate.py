"""0.75: curated dataset versions leave tainted runs out unless a pinned key justifies them."""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import opentine.cli as cli
from opentine import _containment_records as records
from opentine import _dataset_claims as dc
from opentine import _dataset_version as dv
from opentine import _oversight, _schemas
from opentine import _transcript_flags as tf
from opentine.graph import Run, StepKind
from opentine.repository import Repo
from opentine.repository._holds import (
    MONITOR_VERDICT,
    SABOTAGE_TASK,
    TAINT,
    HoldError,
    release,
)
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401

pytestmark = pytest.mark.filterwarnings("ignore::Warning")

CURATOR = Ed25519PrivateKey.from_private_bytes(b"\x71" * 32)
POLICY = Ed25519PrivateKey.from_private_bytes(b"\x72" * 32)
OPTIMIZER = Ed25519PrivateKey.from_private_bytes(b"\x73" * 32)
SCORER = Ed25519PrivateKey.from_private_bytes(b"\x74" * 32)
STRANGER = Ed25519PrivateKey.from_private_bytes(b"\x75" * 32)
AT = "2026-11-21T00:00:00Z"


def _hex(key):
    return key.public_key().public_bytes_raw().hex()


@pytest.fixture(name="repo")
def repo_fixture(tmp_path):
    return Repo.init(tmp_path / "r")


@pytest.fixture(name="keys")
def keys_fixture(tmp_path):
    out = {}
    for name, key in (("curator", CURATOR), ("policy", POLICY), ("optimizer", OPTIMIZER),
                      ("scorer", SCORER), ("stranger", STRANGER)):  # fmt: skip
        out[name] = tmp_path / f"{name}.hex"
        out[name].write_bytes(key.private_bytes_raw().hex().encode("ascii"))
    return out


def _pin(repo):
    (repo.path / "key-roles.toml").write_bytes(
        (
            f'version = 1\n[roles]\ncurator = ["{_hex(CURATOR)}"]\npolicy = ["{_hex(POLICY)}"]\n'
            f'scorer = ["{_hex(SCORER)}"]\noptimizer = ["{_hex(OPTIMIZER)}"]\n'
        ).encode()  # fmt: skip
    )
    pin_roles(repo.path)


def _run(repo, i, text=None):
    run = Run(id=f"r-{i}", model_info="m", user_prompt=text or f"task {i}: fix bug {i}")
    run.add_step(StepKind.tool, {"tool": "bash", "input": {"cmd": f"pytest -k case{i}"}})
    run.add_step(StepKind.done, {"text": f"done {i}"})
    return repo.put_run(run).run_id


def _seed_taints(repo, runs):
    """Two tainted runs per source: ten in all."""
    for run in runs[0:2]:
        records.record(repo, run, {"convention": "opentine.integrity.taint", "run": run},
                       STRANGER, TAINT + run)  # fmt: skip
    for i, run in enumerate(runs[2:4]):
        verdict = {"convention": "opentine.monitor-verdict/1", "action": "block", "enforced": True}
        records.record(repo, run, verdict, STRANGER, f"{MONITOR_VERDICT}s{i}")
    for run in runs[4:6]:
        _oversight.decide(repo, _oversight.promotion_item("prod", run), "reject", STRANGER, at=AT)
    for i, run in enumerate(runs[6:8]):
        records.record(repo, run, {"convention": "opentine.sabotage-task/1",
                                   "side_task": {"id": "x", "attempted": True,
                                                 "achieved": False}},
                       STRANGER, f"{SABOTAGE_TASK}t{i}")  # fmt: skip
    tf.record(repo, {"label": "reward-hacking", "evidence": runs[8:10], "cluster": None,
                     "backend": None, "note": "", "labelled_at": AT}, SCORER)  # fmt: skip


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


def _curate(capsys, repo, keys, *extra, key="curator", select="all"):
    return _cli(capsys, "dataset", "curate", "--select", select, "--out", "train",
                "--key", str(keys[key]), "--at", AT, "--repo", str(repo.path.parent),
                "--json", *extra)  # fmt: skip


def test_ten_seeded_tainted_runs_never_enter_by_default(capsys, repo, keys):
    _pin(repo)
    tainted = [_run(repo, i) for i in range(10)]
    clean = [_run(repo, i) for i in range(10, 16)]
    _seed_taints(repo, tainted)
    code, body = _curate(capsys, repo, keys)
    assert code == 0, body
    assert set(body["members"]) == set(clean)
    assert set(body["excluded"]) == set(tainted)
    assert body["mode"] == "default" and body["included_tainted"] == []
    (row,) = dv.versions(repo, "train")
    assert row["verification"] == "verified" and row["members"] == 6
    claim = repo.get(body["record"]).payload()["claim"]
    assert claim["taint_filter"]["sources"] == list(dc.SOURCES)
    with pytest.raises(HoldError, match="never released"):
        release(repo, body["record"])


def test_include_tainted_needs_a_justification_from_a_pinned_curator_or_policy_key(
    capsys, repo, keys
):
    _pin(repo)
    tainted = [_run(repo, i) for i in range(10)]
    _seed_taints(repo, tainted)
    code, _ = _curate(capsys, repo, keys, "--include-tainted")
    assert code != 0
    code, _ = _cli(
        capsys,
        "dataset",
        "justify",
        "train",
        "--run",
        tainted[0],
        "--reason",
        "r",
        "--key",
        str(keys["optimizer"]),
        "--repo",
        str(repo.path.parent),
        "--json",
    )
    assert code != 0
    code, just = _cli(
        capsys,
        "dataset",
        "justify",
        "train",
        "--run",
        tainted[0],
        "--run",
        tainted[9],
        "--reason",
        "negative examples for a monitor",
        "--key",
        str(keys["policy"]),
        "--at",
        AT,
        "--repo",
        str(repo.path.parent),
        "--json",
    )
    assert code == 0, just
    code, body = _curate(capsys, repo, keys, "--include-tainted", "--justification",
                         just["record"])  # fmt: skip
    assert code == 0, body
    assert body["included_tainted"] == sorted([tainted[0], tainted[9]])
    assert set(body["members"]) == {tainted[0], tainted[9]}
    assert len(body["excluded"]) == 8


def test_a_forged_or_other_dataset_justification_is_refused(capsys, repo, keys):
    _pin(repo)
    tainted = [_run(repo, i) for i in range(10)]
    _seed_taints(repo, tainted)
    other = dv.justify(repo, "eval-set", [tainted[0]], "other", CURATOR, AT)
    code, _ = _curate(capsys, repo, keys, "--include-tainted", "--justification", other)
    assert code != 0
    forged = records.record(
        repo,
        tainted[0],
        {
            "convention": dc.JUSTIFICATION,
            "dataset": "train",
            "for_version": 1,
            "runs": [tainted[0]],
            "reason": "x",
            "curator": records.fingerprint(STRANGER),
            "at": AT,
        },
        STRANGER,
        "dataset-record:x",
    )
    code, _ = _curate(capsys, repo, keys, "--include-tainted", "--justification", forged)
    assert code != 0
    assert dv.versions(repo) == []


def test_an_optimizer_key_cannot_curate(capsys, repo, keys):
    _pin(repo)
    _run(repo, 1)
    code, _ = _curate(capsys, repo, keys, key="optimizer")
    assert code != 0 and dv.versions(repo) == []


def test_duplicates_are_dropped_by_content_defined_chunks(capsys, repo, keys):
    _pin(repo)
    a = _run(repo, 1, "same transcript text " * 40)
    b = _run(repo, 1, "same transcript text " * 40)
    c = _run(repo, 2)
    assert a != b
    code, body = _curate(capsys, repo, keys)
    assert code == 0
    keep, drop = sorted([a, b])
    assert sorted(body["members"]) == sorted([keep, c])
    assert body["dropped"] == [{"run": drop, "same_as": keep}]
