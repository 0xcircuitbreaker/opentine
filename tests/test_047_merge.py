"""0.47 (F2): ``tine merge`` and ``tine pick``, merge/v1 attestations and the merge gates.

A merge is a pure function of its two runs, so the same inputs give the same
merge oid in a second repository, in the pyz port and (``68-merge.json``) in
the TS verifier. The merged run is an ordinary run: it loads, passes ``fsck``
and keeps its parents as links.
"""

from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _merge_record, _schemas, cli
from opentine._merge import MergeError, merge_payloads
from opentine._merge_gates import GateError, digest, evaluate
from opentine._pyz import _merge as pyz_merge
from opentine._pyz import _mergerec as pyz_records
from opentine._pyz_build import build_bytes
from opentine._signed_record import RecordError
from opentine._tree import put_tree
from opentine.kernel import canonical_json
from opentine.repository import Repo
from opentine.repository._merge_ops import merge_runs, pick_events
from tests.conformance import tagged

ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / "docs/conformance/vectors/68-merge.json").read_text("utf-8"))["cases"]
WHEN = "2026-11-09T00:00:00Z"


def _tine(monkeypatch, capsys, *argv: str) -> tuple[int, str]:
    monkeypatch.setattr(sys, "argv", ["tine", *argv])
    code = 0
    try:
        cli.main()
    except SystemExit as exc:
        code = int(exc.code or 0) if not isinstance(exc.code, str) else 1
    return code, capsys.readouterr().out


def _text(repo: Repo, text: str) -> str:
    return repo.put("blob", canonical_json({"text": text}), redact=False)


def _event(repo: Repo, text: str, *parents: str) -> str:
    payload = {"causal_ids": [], "kind": "think", "output_blob": _text(repo, text),
               "parent_ids": list(parents), "time_unix": 1794100000}  # fmt: skip
    return repo.put("event", payload, redact=False)


def _put_run(repo: Repo, events: list[str], ref: str, **extra) -> str:
    payload = {"created_at": 1794100000, "events": events, "manifests": {}, "roots": events[:1],
               "status": "completed", "tips": events[-1:], **extra}  # fmt: skip
    oid = repo.put("run", payload, redact=False)
    repo.update_ref(ref, oid, expected_old=repo.read_ref(ref))
    return oid


def _forks(path: Path) -> tuple[Repo, str, str, str]:
    """A repository with a base run and two forks of it, each one step further."""
    repo = Repo.init(path)
    root = _event(repo, "plan")
    base = _put_run(repo, [root], "heads/main")
    ours = _put_run(repo, [root, _event(repo, "ours", root)], "heads/ours", forked_from=base)
    theirs = _put_run(repo, [root, _event(repo, "theirs", root)], "heads/theirs",
                      forked_from=base)  # fmt: skip
    return repo, base, ours, theirs


def test_a_merge_is_deterministic_across_repositories(tmp_path):
    first, _, ours, theirs = _forks(tmp_path / "a")
    second, _, ours2, theirs2 = _forks(tmp_path / "b")
    assert (ours, theirs) == (ours2, theirs2)
    one = merge_runs(first, "heads/ours", "heads/theirs", ref="heads/main")
    two = merge_runs(second, ours2, theirs2)
    assert one["run"] == two["run"] and one["event"] == two["event"]
    assert one["conflicts"] == [] and one["status"] == "completed"
    payload = first.get(one["run"]).payload()
    assert payload["parents"] == [ours, theirs] and payload["tips"] == [one["event"]]
    assert first.read_ref("heads/main") == one["run"]
    loaded = first.load_run(one["run"])
    assert loaded.steps[-1].v3_kind == "merge" and len(loaded.steps) == 4
    assert len(first.get(one["run"]).payload()["events"]) == 4
    assert first.fsck().ok
    assert merge_runs(first, ours, theirs)["run"] == one["run"]  # idempotent rewrite


def test_the_pyz_and_the_reference_agree_on_a_repository_merge(tmp_path):
    repo, _, ours, theirs = _forks(tmp_path / "r")
    result = merge_runs(repo, ours, theirs)
    value = {"ours": repo.get(ours).payload(), "theirs": repo.get(theirs).payload(),
             "trees": None}  # fmt: skip
    assert pyz_merge.compute_case(value)["run"] == result["run"]


def _tree_run(repo: Repo, parent: str | None, name: str, files: dict[str, bytes]) -> str:
    entries = [{"mode": "100644", "name": k, "oid": repo.put("blob", v, redact=False)}
               for k, v in files.items()]  # fmt: skip
    payload = {"causal_ids": [], "kind": "tool", "output_blob": _text(repo, name),
               "parent_ids": [parent] if parent else [], "time_unix": 1,
               "tree": put_tree(repo, entries)}  # fmt: skip
    return repo.put("event", payload, redact=False)


def _run_of(repo: Repo, events: list[str]) -> str:
    return repo.put("run", {"events": events, "manifests": {}, "roots": events[:1],
                            "tips": events[-1:], "created_at": 5}, redact=False)  # fmt: skip


def test_trees_merge_three_ways_and_conflicts_pause_the_run(tmp_path):
    repo = Repo.init(tmp_path / "r")
    base = _tree_run(repo, None, "base", {"a.txt": b"1", "b.txt": b"1"})
    ours = _tree_run(repo, base, "ours", {"a.txt": b"2", "b.txt": b"1"})
    theirs = _tree_run(repo, base, "theirs", {"a.txt": b"1", "b.txt": b"3"})
    clean = merge_runs(repo, _run_of(repo, [base, ours]), _run_of(repo, [base, theirs]))
    assert clean["conflicts"] == [] and clean["tree"]
    from opentine._merge_tree import flatten

    flat = flatten(repo, clean["tree"])
    assert {k: repo.get(v["oid"]).body for k, v in flat.items()} == {"a.txt": b"2", "b.txt": b"3"}
    clash = _tree_run(repo, base, "clash", {"a.txt": b"9", "b.txt": b"1"})
    paused = merge_runs(repo, _run_of(repo, [base, ours]), _run_of(repo, [base, clash]))
    assert paused["status"] == "paused" and [c["path"] for c in paused["conflicts"]] == ["a.txt"]
    assert repo.get(paused["run"]).payload()["status"] == "paused"
    assert repo.fsck().ok


def test_refusals_carry_their_codes(tmp_path):
    repo, base, ours, _ = _forks(tmp_path / "r")
    with pytest.raises(MergeError) as same:
        merge_runs(repo, ours, ours)
    assert same.value.code == "merge.same-run"
    with pytest.raises(MergeError) as ahead:
        merge_runs(repo, ours, base)
    assert ahead.value.code == "merge.up-to-date"
    with pytest.raises(MergeError) as missing:
        merge_runs(repo, ours, "heads/nope")
    assert missing.value.code == "merge.missing"
    with pytest.raises(MergeError):
        merge_payloads({"events": []}, {"events": ["x"]})


def test_the_ref_moves_only_from_the_head_the_merge_read(tmp_path, monkeypatch):
    from opentine.repository._ref_retry import RefCasMismatch

    repo, _, ours, theirs = _forks(tmp_path / "r")
    real = repo.read_ref

    def racing(name):  # another writer moves heads/main between the read and the move
        value = real(name)
        if name == "heads/main":
            repo.update_ref("heads/main", ours, expected_old=value)
        return value

    monkeypatch.setattr(repo, "read_ref", racing)
    with pytest.raises(RefCasMismatch):
        merge_runs(repo, ours, theirs, ref="heads/main")


def test_pick_copies_events_onto_the_tip(tmp_path):
    repo, _, ours, theirs = _forks(tmp_path / "r")
    source = repo.get(theirs).payload()["tips"][0]
    first = pick_events(repo, ours, [source], ref="heads/ours")
    assert first == pick_events(repo, ours, [source], ref=None) | {"ref": "heads/ours"}
    payload = repo.get(first["run"]).payload()
    copy = repo.get(first["picked"][0]["event"]).payload()
    assert copy["picked_from"] == source and copy["parent_ids"] == repo.get(ours).payload()["tips"]
    assert payload["forked_from"] == ours and "parents" not in payload
    with pytest.raises(MergeError):
        pick_events(repo, first["run"], [first["picked"][0]["event"]])
    assert repo.fsck().ok


def test_the_cli_merges_picks_and_validates(monkeypatch, capsys, tmp_path):
    _forks(tmp_path / "r")
    repo = (tmp_path / "r").as_posix()
    code, out = _tine(monkeypatch, capsys, "merge", "heads/ours", "heads/theirs", "--ref",
                      "heads/merged", "--repo", repo, "--json")  # fmt: skip
    body = json.loads(out)
    assert code == 0 and body["ok"] and _schemas.validate_output(body) == []
    code, out = _tine(monkeypatch, capsys, "merge", "heads/ours", "heads/ours", "--repo", repo,
                      "--json")  # fmt: skip
    assert code == 1 and "merge.same-run" in json.loads(out)["error"]["message"]
    tip = Repo.open(repo).get(Repo.open(repo).read_ref("heads/theirs")).payload()["tips"][0]
    code, out = _tine(monkeypatch, capsys, "pick", "heads/ours", tip, "--repo", repo, "--json")
    assert code == 0 and _schemas.validate_output(json.loads(out)) == []
    code, out = _tine(monkeypatch, capsys, "merge", "heads/ours", "heads/theirs", "--repo", repo)
    assert code == 0 and out.startswith("merged ")


# --- merge/v1 and approvals -------------------------------------------------- #


def _key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(b"\x05" * 32)


def test_a_merge_attestation_signs_verifies_and_names_its_run(tmp_path):
    repo, _, ours, theirs = _forks(tmp_path / "r")
    merged = merge_runs(repo, ours, theirs)
    body = _merge_record.build(merged["run"], merged["parents"], actor="w1",
                               target="heads/main", fencing=7, merged_at=WHEN)  # fmt: skip
    record = _merge_record.sign(body, _key(), algorithm="ed25519", signed_at=WHEN)
    assert _schemas.validate(record) == ("opentine-merge-1", [])
    run = repo.get(merged["run"]).payload()
    found = _merge_record.check(record, run=run)
    assert found["fencing"] == 7 and found["state"] == "verified-tofu"
    assert pyz_records.verify(record, run=run)["fencing"] == 7
    with pytest.raises(RecordError) as other:
        _merge_record.check(record, run=repo.get(ours).payload())
    assert other.value.code == "merge.run-mismatch"
    with pytest.raises(RecordError):
        _merge_record.check({**record, "fencing": 8})


def test_the_pyz_verifies_a_merge_record_file(tmp_path):
    body = _merge_record.build("run:sha256:" + "1" * 64, ["run:sha256:" + "2" * 64,
                               "run:sha256:" + "3" * 64], actor="w", merged_at=WHEN)  # fmt: skip
    record = _merge_record.sign(body, _key(), algorithm="ed25519", signed_at=WHEN)
    (tmp_path / "merge.json").write_text(json.dumps(record), encoding="utf-8")
    (tmp_path / "bad.json").write_text(json.dumps({**record, "actor": "x"}), encoding="utf-8")
    (tmp_path / "tine-verify.pyz").write_bytes(build_bytes())
    with zipfile.ZipFile(tmp_path / "tine-verify.pyz") as archive:
        assert "tine_verify/_pyz/_mergerec.py" in archive.namelist()
    for name, code in (("merge.json", 0), ("bad.json", 1)):
        done = subprocess.run([sys.executable, "-I", (tmp_path / "tine-verify.pyz").as_posix(),
                               (tmp_path / name).as_posix()], capture_output=True, text=True,
                              timeout=300)  # fmt: skip
        assert done.returncode == code, done.stderr
        assert json.loads(done.stdout)["checks"][0]["name"] == "merge"


def _case_value(case: dict) -> dict:
    return tagged.decode(case["input"]["value"])


def _pyz_answer(case: dict) -> dict:
    value = _case_value(case)
    if case["op"] == "merge.compute":
        return pyz_merge.compute_case(value)
    if case["op"] == "merge.pick":
        return pyz_merge.pick_case(value)
    keys = {
        "hmac_key": bytes.fromhex(value["hmac_key_hex"]) if value["hmac_key_hex"] else None,
        "public_key": bytes.fromhex(value["public_key"]) if value["public_key"] else None,
    }
    if case["op"] == "merge-approval.verify":
        return pyz_records.verify(value["record"], kind=pyz_records.APPROVAL, **keys)
    return pyz_records.verify(value["record"], run=value.get("run"), **keys)  # fmt: skip


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_the_pyz_answers_every_merge_vector(case):
    if case["expect"] == "reject":
        with pytest.raises(pyz_merge.Refused) as refused:
            _pyz_answer(case)
        assert refused.value.code == case["reason"]
    else:
        assert _pyz_answer(case) == case["output"]


# --- gates ------------------------------------------------------------------- #


def _approval(key: Ed25519PrivateKey, run: str, decision: str = "approve") -> dict:
    body = _merge_record.build_approval(run, "heads/main", "alice", decision, WHEN)
    return _merge_record.sign_approval(body, key, algorithm="ed25519", signed_at=WHEN)


def test_approval_gates_count_distinct_listed_keys_and_a_reject_blocks():
    run = "run:sha256:" + "4" * 64
    alice, bob, eve = (Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32) for n in (1, 2, 3))
    hexes = [k.public_key().public_bytes_raw().hex() for k in (alice, bob)]
    policy = {"format": "opentine-merge-gates/1", "approvals": {"required": 2, "keys": hexes}}
    assert _schemas.validate(policy) == ("opentine-merge-gates-1", [])
    one = evaluate(policy, {"approvals": [_approval(alice, run), _approval(alice, run)]}, run,
                   "heads/main")  # fmt: skip
    assert not one["ok"] and "1 approvals" in one["failures"][0]
    two = evaluate(policy, {"approvals": [_approval(alice, run), _approval(bob, run),
                                          _approval(eve, run)]}, run, "heads/main")  # fmt: skip
    assert two["ok"] and [g["gate"] for g in two["gates"]] == ["approval", "approval"]
    assert two["gates"][0]["digest"] == digest(_approval(alice, run))
    other = evaluate(policy, {"approvals": [_approval(alice, "run:sha256:" + "5" * 64),
                                            _approval(bob, run)]}, run, "heads/main")  # fmt: skip
    assert not other["ok"]
    vetoed = evaluate(policy, {"approvals": [_approval(alice, run), _approval(bob, run, "reject")]},
                      run, "heads/main")  # fmt: skip
    assert not vetoed["ok"] and "rejected by alice" in vetoed["failures"][0]
    with pytest.raises(GateError):
        evaluate({"format": "opentine-merge-gates/1", "approvals": {"required": 0}}, {}, run, "t")


def test_vsa_and_eval_gates_check_signatures_and_the_subject():
    from opentine import _eval_verdict
    from opentine._webhook_sig import b64url
    from opentine.intoto import sign_statement
    from opentine.remote._vsa import build_vsa

    run = "run:sha256:" + "6" * 64
    server = Ed25519PrivateKey.from_private_bytes(b"\x09" * 32)
    pin = b64url(server.public_key().public_bytes_raw())
    policy = {"format": "opentine-merge-gates/1", "vsa": {"key": pin, "levels": ["T1"]},
              "evals": {"min": 1}}  # fmt: skip
    vsa = sign_statement(build_vsa("acme", "heads/main", run, ["T1"]), server)
    wrong = sign_statement(build_vsa("acme", "heads/main", "run:sha256:" + "7" * 64, ["T1"]),
                           server)  # fmt: skip
    fields = {"eval": "sha256:" + "a" * 64, "dataset": "sha256:" + "b" * 64, "item": "q1",
              "item_digest": "sha256:" + "c" * 64, "run": run, "scorer": "exact",
              "scorer_version": "1", "created_at": WHEN}  # fmt: skip
    good = _eval_verdict.make(b"\x0a" * 32, **fields, score=1, threshold=1)
    bad = _eval_verdict.make(b"\x0a" * 32, **{**fields, "item": "q2"}, score=0, threshold=1)
    passed = evaluate(policy, {"vsa": [wrong, vsa], "evals": [good]}, run, "heads/main")
    assert passed["ok"] and [g["gate"] for g in passed["gates"]] == ["vsa", "eval"]
    assert not evaluate(policy, {"vsa": [wrong], "evals": [good]}, run, "heads/main")["ok"]
    failed = evaluate(policy, {"vsa": [vsa], "evals": [good, bad]}, run, "heads/main")
    assert not failed["ok"] and "item q2 failed" in failed["failures"][0]
    tampered = {**good, "score": "0.5"}
    assert not evaluate(policy, {"vsa": [vsa], "evals": [tampered]}, run, "heads/main")["ok"]
