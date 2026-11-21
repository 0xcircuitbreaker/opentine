"""0.75 end to end: curate, feed eval and holdouts, withdraw, query, export an AI-BOM.

The acceptance path in one repository: runs tainted by each source (0.60
integrity taint, 0.63 monitor verdict, 0.64 oversight rejection, 0.68 sabotage
task, 0.74 behaviour flag) stay out of the curated version; the verified version
becomes an eval dataset that ``tine dataset show`` digests and ``tine dataset
seal`` seals as a holdout; a contributor's ``tine dataset withdraw`` removes a
run from the next version with a tombstone; versions and tombstones appear in
``tine query`` with per-row verification; and ``tine bom export`` of a lineage
node carries the version with its taint filter. No network, no clock.
"""

from __future__ import annotations

import json

import pytest

from opentine import _dataset_version as dv
from opentine import cli
from opentine._dataset_claims import SOURCES
from tests.aibom_helpers import lineage
from tests.dataset_contrib_helpers import annotate, pin_contributor
from tests.key_roles_helpers import isolated_trust_config, pin_roles  # noqa: F401
from tests.promote_helpers import EVALER, fingerprint
from tests.test_075_dataset_curate import (  # noqa: F401
    AT,
    CURATOR,
    OPTIMIZER,
    POLICY,
    SCORER,
    STRANGER,
    _cli,
    _curate,
    _hex,
    _run,
    _seed_taints,
    keys_fixture,
    repo_fixture,
)

pytestmark = pytest.mark.filterwarnings("ignore::Warning")


def _tine(*argv: str) -> int:
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def _pin(repo):
    """The curator also holds the ``dataset`` role, which sealing a holdout needs."""
    roles = {"curator": [_hex(CURATOR)], "dataset": [_hex(CURATOR)], "policy": [_hex(POLICY)],
             "scorer": [_hex(SCORER), fingerprint(EVALER)],  # EVALER signs the lineage's eval
             "optimizer": [_hex(OPTIMIZER)]}  # fmt: skip
    lines = ["version = 1", "[roles]"] + [f"{r} = {json.dumps(k)}" for r, k in roles.items()]
    (repo.path / "key-roles.toml").write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    pin_roles(repo.path)


def test_curated_versions_feed_evals_holdouts_query_and_the_bom(capsys, repo, keys, tmp_path):
    _pin(repo)
    root = str(repo.path.parent)
    tainted = [_run(repo, i) for i in range(10)]
    clean = [_run(repo, i) for i in range(10, 14)]
    _seed_taints(repo, tainted)

    code, first = _curate(capsys, repo, keys)
    assert code == 0, first
    assert set(first["members"]) == set(clean) and set(first["excluded"]) == set(tainted)

    # The verified version is an eval dataset: show digests it, seal makes it a holdout.
    data = tmp_path / "train.jsonl"
    code, mat = _cli(capsys, "dataset", "materialize", first["record"], "--out", str(data),
                     "--repo", root, "--json")  # fmt: skip
    assert code == 0, mat
    assert mat["items"] == 4 and mat["withdrawn"] == []
    items = [json.loads(line) for line in data.read_bytes().decode("utf-8").splitlines()]
    assert sorted(i["run"] for i in items) == sorted(clean)
    assert {i["metadata"]["dataset_version"] for i in items} == {first["record"]}
    code, shown = _cli(capsys, "dataset", "show", str(data), "--json")
    assert code == 0 and shown["digest"] == mat["digest"] and shown["items"] == 4
    seal_key = tmp_path / "seal.hex"
    code, sealed = _cli(capsys, "dataset", "seal", str(data), "--out", str(tmp_path / "held"),
                        "--name", "train-holdout", "--max-unseals", "1", "--max-items", "4",
                        "--key", str(keys["curator"]), "--seal-key", str(seal_key),
                        "--repo", root, "--json")  # fmt: skip
    assert code == 0, sealed

    # A contributor withdraws one clean run: the next version leaves it out with a tombstone.
    annotate(repo, clean[0], STRANGER)  # the contributor's licence annotation on its run
    pin_contributor(repo, STRANGER)  # a contributor key is pinned in the runner role
    code, gone = _cli(capsys, "dataset", "withdraw", clean[0], "--key", str(keys["stranger"]),
                      "--reason", "consent-withdrawn", "--at", AT, "--repo", root,
                      "--json")  # fmt: skip
    assert code == 0, gone
    code, second = _curate(capsys, repo, keys)
    assert code == 0 and clean[0] not in second["members"] and second["withdrawn"] == [clean[0]]
    assert len(second["tombstones"]) == 1 and second["previous"] == first["record"]
    code, mat = _cli(capsys, "dataset", "materialize", first["record"], "--out",
                     str(tmp_path / "again.jsonl"), "--repo", root, "--json")  # fmt: skip
    assert code == 0 and mat["withdrawn"] == [clean[0]] and mat["items"] == 3

    # Versions and tombstones are queryable, each row verified on its own.
    code, out = _cli(capsys, "query", "SELECT oid, version FROM dataset_versions ORDER BY version",
                     "--verify", "--repo", root, "--json")  # fmt: skip
    assert code == 0, out
    assert [r["oid"] for r in out["rows"]] == [first["record"], second["record"]]
    assert [c["status"] for c in out["verification"]["rows"]] == ["verified", "verified"]
    code, out = _cli(capsys, "query", "SELECT oid, run, version, signed FROM dataset_tombstones",
                     "--verify", "--repo", root, "--json")  # fmt: skip
    assert code == 0, out
    assert out["rows"] == [{"oid": second["tombstones"][0], "run": clean[0],
                            "version": first["record"], "signed": 1}]  # fmt: skip
    assert [c["status"] for c in out["verification"]["rows"]] == ["verified"]

    # The AI-BOM of a lineage node carries the curated version and its taint filter.
    _store, _parent, child = lineage(repo.path.parent)
    version = tmp_path / "v1.json"
    payload = repo.get(first["record"]).payload()
    version.write_bytes(json.dumps(payload, sort_keys=True).encode("utf-8"))
    bom = tmp_path / "bom.json"
    capsys.readouterr()
    code = _tine("bom", "export", child, "--format", "cyclonedx", "--repo", root,
                 "--dir", (repo.path.parent / "lineage").as_posix(), "--out", bom.as_posix(),
                 "--dataset", f"training={version.as_posix()}")  # fmt: skip
    assert code == 0, capsys.readouterr().err
    doc = json.loads(bom.read_bytes())
    ref = f"dataset:training:{payload['claim']['members_digest']}"
    train = next(c for c in doc["components"] if c["bom-ref"] == ref)
    props = {p["name"]: p["value"] for p in train["properties"]}
    taint = json.loads(props["opentine:taint-filter"])
    assert taint["sources"] == list(SOURCES) and set(taint["excluded"]) == set(tainted)

    # A late taint makes the version unverified and stops materializing it (fail closed).
    _seed_taints(repo, [*second["members"], *tainted][:10])
    assert dv.versions(repo, "train")[-1]["verification"].startswith("unverified")
    code, _ = _cli(capsys, "dataset", "materialize", second["record"], "--out",
                   str(tmp_path / "late.jsonl"), "--repo", root, "--json")  # fmt: skip
    assert code != 0 and not (tmp_path / "late.jsonl").exists()

    # Once a member is tainted after curation the BOM export refuses the version too.
    capsys.readouterr()
    code = _tine("bom", "export", child, "--format", "cyclonedx", "--repo", root,
                 "--dir", (repo.path.parent / "lineage").as_posix(), "--out", bom.as_posix(),
                 "--dataset", f"training={version.as_posix()}")  # fmt: skip
    assert code == 1 and "tainted since" in " ".join(capsys.readouterr().err.split())
