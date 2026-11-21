"""0.78: ``tine bom export`` (CycloneDX 1.6 ML-BOM, SPDX 3.0.1 AI/Dataset) of a lineage node.

The documents are validated against the official schemas vendored under
``tests/data/aibom`` and pinned by sha256 (``SHA256SUMS``, docs/AIBOM.md).
Nothing here reads the network or the clock: records are signed at a fixed time.
"""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import sys

import pytest

from opentine import cli
from tests.aibom_helpers import (
    FILTER,
    SCHEMAS,
    TRAIN,
    dataset_version,
    lineage,
    pin_curator,
    validator,
)
from tests.key_roles_helpers import isolated_trust_config  # noqa: F401 - autouse
from tests.promote_helpers import EVALER, fingerprint

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")

CDX = "bom-1.6.schema.json"
SPDX = "spdx-json-schema-3.0.1.json"


def _tine(*argv: str) -> int:
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def _export(tmp_path, variant, fmt, out, *extra) -> int:
    where = ("--repo", tmp_path.as_posix(), "--dir", (tmp_path / "lineage").as_posix())
    return _tine("bom", "export", variant, "--format", fmt, *where, "--out", out.as_posix(), *extra)


@pytest.fixture
def node(tmp_path):
    _store, root, child = lineage(tmp_path)
    pin_curator(tmp_path, fingerprint(EVALER))
    version = dataset_version(tmp_path / "train.json")
    extra = ("--dataset", f"training={version.as_posix()}", "--licence", "Apache-2.0",
             "--name", "toy-agent")  # fmt: skip
    return tmp_path, root, child, extra


def test_vendored_schemas_match_their_pinned_digests() -> None:
    sums = (SCHEMAS / "SHA256SUMS").read_bytes().decode("ascii").splitlines()
    pinned = dict(reversed(line.split("  ")) for line in sums)
    assert set(pinned) == {p.name for p in SCHEMAS.glob("*.json")} and len(pinned) == 4
    for name, digest in pinned.items():
        assert hashlib.sha256((SCHEMAS / name).read_bytes()).hexdigest() == digest, name
    docs = (SCHEMAS.parents[2] / "docs" / "AIBOM.md").read_bytes().decode("utf-8")
    assert all(digest in docs for digest in pinned.values())


@pytest.mark.parametrize(("fmt", "schema"), [("cyclonedx", CDX), ("spdx", SPDX)])
def test_export_validates_against_the_official_schema(node, fmt, schema) -> None:
    tmp_path, _root, child, extra = node
    out = tmp_path / f"bom.{fmt}.json"
    assert _export(tmp_path, child, fmt, out, *extra) == 0
    errors = list(validator(schema).iter_errors(json.loads(out.read_bytes())))
    assert errors == [], [e.message for e in errors[:5]]


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx"])
def test_reruns_are_byte_identical_and_stdout_matches_the_file(node, fmt, monkeypatch) -> None:
    tmp_path, _root, child, extra = node
    first, second = tmp_path / "a.json", tmp_path / "b.json"
    assert _export(tmp_path, child, fmt, first, *extra) == 0
    assert _export(tmp_path, child, fmt, second, *extra) == 0
    assert first.read_bytes() == second.read_bytes()
    assert b"\r" not in first.read_bytes() and first.read_bytes().endswith(b"}\n")
    sink = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(sink, encoding="utf-8"))
    code = _tine("bom", "export", child, "--format", fmt, "--repo", tmp_path.as_posix(),
                 "--dir", (tmp_path / "lineage").as_posix(), *extra)  # fmt: skip
    sys.stdout.flush()
    assert code == 0 and sink.getvalue() == first.read_bytes()


def test_cyclonedx_carries_lineage_datasets_taint_filter_evals_and_licences(node) -> None:
    tmp_path, root, child, extra = node
    out = tmp_path / "bom.json"
    assert _export(tmp_path, child, "cyclonedx", out, *extra) == 0
    bom = json.loads(out.read_bytes())
    head = bom["metadata"]["component"]
    assert head["bom-ref"] == child and head["name"] == "toy-agent"
    assert head["type"] == "machine-learning-model"
    assert head["licenses"] == [{"expression": "Apache-2.0"}]
    assert {"alg": "SHA-256", "content": TRAIN[7:]} in head["hashes"]
    props = {p["name"]: p["value"] for p in head["properties"]}
    evals = [json.loads(p["value"]) for p in head["properties"] if p["name"] == "opentine:eval"]
    assert len(evals) == 1 and evals[0]["signers"] == [fingerprint(EVALER)]
    assert evals[0]["items"] == 40 and evals[0]["passed"] == 36
    assert props["opentine:selector"] == "tournament" and props["opentine:promotion-decision"]
    metrics = head["modelCard"]["quantitativeAnalysis"]["performanceMetrics"]
    assert [m["value"] for m in metrics] == ["36/40"]
    deps = {d["ref"]: d["dependsOn"] for d in bom["dependencies"]}
    assert root in deps[child] and f"dataset:training:{TRAIN}" in deps[child]
    assert deps[root] == []  # the training version is the exported node's, not its parent's
    train = next(c for c in bom["components"] if c["bom-ref"] == f"dataset:training:{TRAIN}")
    tprops = {p["name"]: p["value"] for p in train["properties"]}
    assert json.loads(tprops["opentine:taint-filter"]) == FILTER
    assert tprops["opentine:dataset-signer"] == fingerprint(EVALER)
    assert not train.get("licenses")  # a version claim asserts no licence
    assert bom["serialNumber"].startswith("urn:uuid:")


def test_spdx_carries_ancestry_training_testing_and_taint_filter(node) -> None:
    tmp_path, root, child, extra = node
    out = tmp_path / "bom.json"
    assert _export(tmp_path, child, "spdx", out, *extra) == 0
    graph = json.loads(out.read_bytes())["@graph"]
    rels = {(e["relationshipType"], e["from"]): e["to"] for e in graph
            if e["type"] == "Relationship"}  # fmt: skip
    cid, rid = f"urn:opentine:variant:{child[7:]}", f"urn:opentine:variant:{root[7:]}"
    assert rels[("ancestorOf", rid)] == [cid]
    assert rels[("trainedOn", cid)] == [f"urn:opentine:dataset:training:{TRAIN[7:]}"]
    assert len(rels[("testedOn", cid)]) == 1 and ("hasDeclaredLicense", cid) in rels
    data = next(e for e in graph if e["type"] == "dataset_DatasetPackage"
                and e["software_packageVersion"] == TRAIN)  # fmt: skip
    assert "integrity-taint" in data["dataset_dataPreprocessing"][0]
    model = next(e for e in graph if e.get("spdxId") == cid)
    assert model["ai_metric"][0]["value"] == "36/40"
    document = next(e for e in graph if e["type"] == "SpdxDocument")
    assert document["rootElement"] == [cid]


def test_a_node_that_fails_lineage_check_is_refused_and_nothing_is_written(node) -> None:
    tmp_path, _root, child, extra = node
    shutil.rmtree(tmp_path / "lineage" / "evals")
    out = tmp_path / "bom.json"
    assert _export(tmp_path, child, "cyclonedx", out, *extra) == 1
    assert not out.exists()
    assert _export(tmp_path, "sha256:" + "e" * 64, "spdx", out) == 1 and not out.exists()


def test_dataset_versions_must_be_signed_and_well_formed(node) -> None:
    tmp_path, _root, child, _extra = node
    out = tmp_path / "bom.json"
    good = dataset_version(tmp_path / "v.json")
    payload = json.loads(good.read_bytes())
    payload["claim"]["taint_filter"] = None  # edited after signing: the signature fails
    forged = tmp_path / "forged.json"
    forged.write_bytes(json.dumps(payload).encode())
    for spec in (f"training={forged.as_posix()}", f"holdout={good.as_posix()}",
                 good.as_posix()):  # fmt: skip
        assert _export(tmp_path, child, "cyclonedx", out, "--dataset", spec) == 1, spec
        assert not out.exists()
    bad = dataset_version(tmp_path / "bad.json", digest="md5:00")
    assert _export(tmp_path, child, "spdx", out, "--dataset", f"eval={bad.as_posix()}") == 1


def test_a_dataset_version_without_a_taint_filter_is_refused(node) -> None:
    tmp_path, _root, child, _extra = node
    bare = dataset_version(tmp_path / "bare.json", taint=None)
    out = tmp_path / "bom.json"
    assert _export(tmp_path, child, "cyclonedx", out, "--dataset", f"training={bare}") == 1
    assert not out.exists()


def test_json_summary_names_the_file_digest(node, capsys) -> None:
    tmp_path, _root, child, extra = node
    out = tmp_path / "bom.json"
    capsys.readouterr()
    assert _export(tmp_path, child, "spdx", out, *extra, "--json") == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["schema"] == "tine-cli-bom/1" and summary["format"] == "spdx"
    assert summary["sha256"] == hashlib.sha256(out.read_bytes()).hexdigest()
    assert _tine("bom", "export", child, "--format", "spdx", "--json") == 2
