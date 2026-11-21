"""0.75: contributor tooling for open run datasets, through the CLI.

``contrib-redact`` removes deny-list terms in every normalised form, signs a
public bundle with a licence annotation, and keeps it only when the leak scan
of the unbundled copy finds nothing; the deny-list never reaches the bundle.
``check`` refuses missing, foreign-key or disallowed licences and dirty scans.
``withdraw`` signs a held claim whose tombstone a dataset build honours.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import opentine.cli as cli
from opentine import _bundle, _contrib_bundle, _contrib_denylist, _dataset_licence, _schemas
from opentine._dataset_withdraw import digest
from opentine.graph import Run, StepKind
from opentine.policies import PolicySet
from opentine.repository import Repo
from opentine.repository._holds import HoldError, release

AT = "2026-11-20T00:00:00Z"
DENY = "# contributor deny-list\nJane Doe\nacme corp\nProjectZebra\nbuildhost-07.internal\n"
PROMPT = "ask Jane Doe at Acme-Corp about ProjectZebra on buildhost-07.internal"
ANSWER = "JANE_DOE: j.a.n.e d.o.e, ＡＣＭＥ corp and Pro​jectZebra are done"


def _key(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _tine(capsys, *argv: str) -> tuple[int, dict]:
    capsys.readouterr()
    code = 0
    try:
        cli.main(list(argv))
    except SystemExit as exc:
        code = int(exc.code) if isinstance(exc.code, int) else 1
    out = capsys.readouterr().out
    body = json.loads(out) if out.strip().startswith("{") else {}
    if body and "error" not in body:
        assert _schemas.validate_output(body) == [], body
    return code, body


@pytest.fixture
def room(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    repo = Repo.init(tmp_path / "r")
    run = Run(id="r", model_info="m", user_prompt=PROMPT, policies=PolicySet().to_dict())
    run.add_step(StepKind.done, {"text": ANSWER})
    run_id = repo.put_run(run, ref="heads/main").run_id
    keys = {}
    for name, seed in (("alice", 21), ("other", 22)):
        keys[name] = tmp_path / f"{name}.hex"
        keys[name].write_bytes(_key(seed).private_bytes_raw().hex().encode("ascii"))
    deny = tmp_path / "deny.txt"
    deny.write_bytes(DENY.encode("utf-8"))
    return {"repo": repo, "run": run_id, "keys": keys, "deny": deny, "tmp": tmp_path}


def _redact(capsys, room, *extra: str) -> tuple[int, dict]:
    out = room["tmp"] / "public.bundle"
    return _tine(
        capsys,
        "dataset",
        "contrib-redact",
        "main",
        "--deny-list",
        str(room["deny"]),
        "--licence",
        "CC-BY-4.0",
        "--key",
        str(room["keys"]["alice"]),
        "--out",
        str(out),
        "--at",
        AT,
        "--repo",
        str(room["repo"].path),
        "--json",
        *extra,
    )


def test_deny_list_normalises_case_unicode_and_split_forms():
    deny = _contrib_denylist.DenyList(["Jane Doe", "acme corp"])
    for text in (
        "JANE DOE",
        "jane.doe",
        "j-a-n-e_d-o-e",
        "Ja​ne Doe",
        "Jáne Doe",
        "Ｊａｎｅ doe",
        "AcmeCorp",
        "acme-corp",
    ):
        assert deny.scrub_text(text)[1] == 1, text
    assert deny.count("run:sha256:" + "ab" * 32) == 0  # ids are never text
    assert "Jane" not in repr(deny) and len(deny) == 2
    with pytest.raises(_contrib_denylist.DenyListError):
        _contrib_denylist.DenyList(["ab"])
    with pytest.raises(_contrib_denylist.DenyListError):
        _contrib_denylist.DenyList([])


def test_contrib_redact_writes_a_clean_signed_bundle_without_the_list(capsys, room):
    code, body = _redact(capsys, room)
    assert code == 0 and body["ok"] and body["leak_scan"]["hits"] == 0, body
    assert body["totals"]["contributor"] >= 6
    data = (room["tmp"] / "public.bundle").read_bytes()
    deny = _contrib_denylist.load(room["deny"])
    assert _contrib_bundle.leak_scan(data, deny)["hits"] == 0
    _, objects = _contrib_bundle.objects_of(data)
    head = data[len(_bundle.MAGIC) + 32 :]
    manifest = head[4 : 4 + int.from_bytes(head[:4], "big")]
    flat = b"".join(env.encode() for env in objects.values()) + manifest
    for word in (b"deny-list", b"Zebra", b"buildhost", b"Jane", b"acme", b"ACME"):
        assert word not in flat
    assert body["ruleset"].endswith("+contributor/1")
    code, checked = _tine(capsys, "dataset", "check", str(room["tmp"] / "public.bundle"), "--json")
    assert code == 0 and checked["ok"], checked
    assert checked["licence"][0]["spdx"] == "CC-BY-4.0" and checked["scan"] == []


def test_a_hit_left_in_the_copy_refuses_and_writes_nothing(capsys, room, monkeypatch):
    monkeypatch.setattr(_contrib_bundle, "leak_scan", lambda data, deny: {"objects": 1, "hits": 2})
    code, body = _redact(capsys, room)
    assert code == 1 and body["ok"] is False and body["out"] is None
    assert not (room["tmp"] / "public.bundle").exists()


def test_disallowed_licence_and_missing_list_are_refused(capsys, room):
    code, _ = _tine(
        capsys,
        "dataset",
        "contrib-redact",
        "main",
        "--deny-list",
        str(room["tmp"] / "absent.txt"),
        "--licence",
        "CC-BY-4.0",
        "--key",
        str(room["keys"]["alice"]),
        "--out",
        str(room["tmp"] / "x.bundle"),
        "--repo",
        str(room["repo"].path),
    )
    assert code != 0 and not (room["tmp"] / "x.bundle").exists()
    code, _ = _tine(
        capsys,
        "dataset",
        "contrib-redact",
        "main",
        "--deny-list",
        str(room["deny"]),
        "--licence",
        "LicenseRef-Proprietary",
        "--key",
        str(room["keys"]["alice"]),
        "--out",
        str(room["tmp"] / "x.bundle"),
        "--repo",
        str(room["repo"].path),
    )
    assert code != 0 and not (room["tmp"] / "x.bundle").exists()


def _rebundle(room, objects_change) -> bytes:
    """The contributed bundle with its licence attestation swapped, re-signed by alice."""
    deny = _contrib_denylist.load(room["deny"])
    allow = _dataset_licence.DEFAULT_ALLOW
    real = _dataset_licence.envelope
    _dataset_licence.envelope = objects_change(real)
    try:
        data, _ = _contrib_bundle.build(
            room["repo"],
            "heads/main",
            room["run"],
            _key(21),
            deny,
            spdx="CC-BY-4.0",
            grant=False,
            at=AT,
            allow=allow,
        )
    finally:
        _dataset_licence.envelope = real
    return data


def test_check_refuses_a_licence_by_another_key_or_off_the_allow_list(capsys, room):
    foreign = _rebundle(
        room,
        lambda real: (
            lambda run, spdx, grant, key, at, allow: real(run, spdx, grant, _key(22), at, allow)
        ),
    )
    row = _contrib_bundle.check(foreign, allow=_dataset_licence.DEFAULT_ALLOW)
    assert not row["ok"] and "contributor key" in row["licence"][0]["state"]
    _redact(capsys, room)
    path = str(room["tmp"] / "public.bundle")
    code, body = _tine(capsys, "dataset", "check", path, "--allow", "CC0-1.0", "--json")
    assert code == 1 and "not on the allow-list" in body["licence"][0]["state"]
    other = room["tmp"] / "other.pub"
    other.write_bytes(_key(22).public_key().public_bytes_raw().hex().encode("ascii"))
    code, body = _tine(capsys, "dataset", "check", path, "--pubkey", str(other), "--json")
    assert code == 1 and body["record_state"].startswith("failed")


def test_check_refuses_a_bundle_without_an_annotation_or_with_a_dirty_scan(room, monkeypatch):
    plain = _bundle.create(room["repo"], ["heads/main"])
    assert not _contrib_bundle.check(plain, allow=_dataset_licence.DEFAULT_ALLOW)["ok"]
    deny = _contrib_denylist.DenyList(["nothing-matches-this"])
    run = Run(
        id="g",
        model_info="m",
        user_prompt="SPDX-License-Identifier: GPL-3.0-only",
        policies=PolicySet().to_dict(),
    )
    run.add_step(StepKind.done, {"text": "Copyright 2020. All rights reserved."})
    run_id = room["repo"].put_run(run, ref="heads/gpl").run_id
    data, _ = _contrib_bundle.build(
        room["repo"],
        "heads/gpl",
        run_id,
        _key(21),
        deny,
        spdx="MIT",
        grant=True,
        at=AT,
        allow=_dataset_licence.DEFAULT_ALLOW,
    )
    row = _contrib_bundle.check(data, allow=_dataset_licence.DEFAULT_ALLOW)
    findings = {f["finding"] for f in row["scan"]}
    assert not row["ok"] and {"licence tag GPL-3.0-only", "notice: all rights reserved"} <= findings
    assert row["licence"][0]["state"] == "verified" and row["licence"][0]["relicensing_grant"]


def test_withdraw_is_held_and_its_tombstone_is_honoured(capsys, room):
    stones = room["tmp"] / "tombstones.json"
    code, body = _tine(
        capsys,
        "dataset",
        "withdraw",
        room["run"],
        "--key",
        str(room["keys"]["alice"]),
        "--reason",
        "consent-withdrawn",
        "--tombstones",
        str(stones),
        "--at",
        AT,
        "--repo",
        str(room["repo"].path),
        "--json",
    )
    assert code == 0 and body["state"] == "verified" and body["tombstones"] == 1
    assert body["tombstone"] == {
        "digest": digest(room["run"]),
        "date": "2026-11-20",
        "reason": "consent-withdrawn",
    }
    doc = json.loads(stones.read_bytes())
    assert set(doc["tombstones"][0]) == {"digest", "date", "reason"}
    with pytest.raises(HoldError, match="dataset withdrawal"):
        release(room["repo"], f"dataset-withdraw:{room['run']}")
    ds = room["tmp"] / "d.jsonl"
    code, _ = _tine(
        capsys, "dataset", "add", str(ds), "--from-run", "main", "--repo", str(room["repo"].path)
    )
    assert code != 0 and not ds.exists()
    _redact(capsys, room)
    code, body = _tine(
        capsys,
        "dataset",
        "check",
        str(room["tmp"] / "public.bundle"),
        "--tombstones",
        str(stones),
        "--json",
    )
    assert code == 1 and any("tombstoned" in p for p in body["problems"])
