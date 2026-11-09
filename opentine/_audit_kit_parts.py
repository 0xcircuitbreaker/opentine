"""The pieces an audit kit carries beside its evidence folder (0.49).

Each helper writes one existing format into the kit and returns the build-time
check it implies, ``{"name", "outcome", "detail"}``:

* :func:`write_crate` -- the Provenance Run Crate (``tine export --format
  run-crate``) beside a copy of its run, validated by :mod:`_run_crate_check`;
* :func:`replay_attestation` -- a ``replay/v1`` DSSE envelope, either copied
  (``--replay-attestation``) or produced now by a cache replay signed with
  ``--attest-key``, with the signer's public key beside it;
* :func:`write_witnesses` -- the pinned witness set (``cosignature/v1`` vkeys)
  and the log keys the set is pinned for, as ``trust/witnesses.json``;
* :func:`bundle_runs` -- a ``tine bundle`` input verified and its runs written
  out as ``.tine`` files through a throwaway repository.

None of these is a new object kind: the kit only places existing ones.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

REPLAY_FILE = "attestations/replay.intoto.jsonl"
REPLAY_KEY = "attestations/replay-signer.pub"
WITNESSES = "trust/witnesses.json"


def check(name: str, ok: bool | None, detail: str) -> dict[str, str]:
    outcome = "skip" if ok is None else ("pass" if ok else "fail")
    return {"name": name, "outcome": outcome, "detail": detail}


def write_crate(out: Path, run_file: Path) -> dict[str, str]:
    from opentine._citation_export import render
    from opentine._run_crate_check import validate
    from opentine.core import Run

    room = out / "crate" / run_file.stem
    room.mkdir(parents=True)
    shutil.copyfile(run_file, room / run_file.name)
    try:
        body = render("run-crate", room / run_file.name, Run.load(room / run_file.name))
    except (OSError, ValueError) as exc:
        return check(f"crate:{run_file.name}", False, f"cannot build the crate: {exc}")
    (room / "ro-crate-metadata.json").write_bytes(body)
    errors = validate(json.loads(body))
    return check(f"crate:{run_file.name}", not errors, "; ".join(errors) or "valid run crate")


def replay_attestation(
    out: Path, run_file: Path, *, copy: Path | None, attest_key: Path | None, pubkey: Path | None
) -> dict[str, str]:
    """Place (or make) the replay/v1 envelope and check it against the run's digest."""
    target = out / REPLAY_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    if attest_key is not None:
        from opentine._signing_keys import ed25519_private_from_file

        key = ed25519_private_from_file(attest_key)
        target.write_bytes(_attest_now(run_file, key))
        public = key.public_key().public_bytes_raw().hex()
        (out / REPLAY_KEY).write_text(public + "\n", encoding="utf-8")
    elif copy is not None:
        shutil.copyfile(copy, target)
        if pubkey is not None:
            shutil.copyfile(pubkey, out / REPLAY_KEY)
    else:
        target.parent.rmdir()
        return check("replay", None, "no replay attestation (--attest-key or --replay-attestation)")
    return verify_replay(out, run_file)


def _attest_now(run_file: Path, key: Any) -> bytes:
    from opentine._cli_verify_replay import _cache_verdict
    from opentine._intoto_replay import build_statement
    from opentine.core import Run
    from opentine.intoto import sign_statement

    run = Run.load(run_file)
    room = Path(tempfile.mkdtemp(prefix="tine-kit-replay-"))
    try:
        args = argparse.Namespace(from_step=None, ignore_cost_drift=False)
        verdict = _cache_verdict(run, run_file, args, room)
    finally:
        shutil.rmtree(room, ignore_errors=True)
    digest = run_digest(run_file)
    envelope = sign_statement(build_statement(verdict, verdict.run_id, str(digest)), key)
    return (json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n").encode()


def verify_replay(kit: Path, run_file: Path) -> dict[str, str]:
    """The envelope's signature, shape, subject digest and verdict, offline."""
    from opentine._intoto_replay import verify_envelope

    path, key = kit / REPLAY_FILE, kit / REPLAY_KEY
    if not path.is_file():
        return check("replay", None, "the kit carries no replay attestation")
    if not key.is_file():
        return check("replay", False, f"{REPLAY_KEY} is missing: the envelope cannot be checked")
    try:
        envelope = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        statement = verify_envelope(envelope, bytes.fromhex(key.read_text().strip()))
    except (OSError, IndexError, ValueError) as exc:
        return check("replay", False, f"replay/v1 envelope does not verify: {exc}")
    digest = run_digest(run_file)
    subjects = [s.get("digest", {}).get("sha256") for s in statement.get("subject", [])]
    if not digest or digest.removeprefix("sha256:") not in subjects:
        return check("replay", False, "the attestation's subject is not this run's digest")
    result = statement["predicate"]["result"]
    if not result["reproduced"]:
        return check("replay", False, "signed, but the replay did not reproduce the run")
    mode = statement["predicate"]["mode"]
    return check("replay", True, f"replay/v1 signed, {mode} replay reproduced the run")


def write_witnesses(out: Path, vkeys: list[str], log_keys: list[Path], quorum: str | None):
    """``trust/witnesses.json``: the pinned set; log keys copied under ``trust/log-keys``."""
    from opentine.repository._tlog_cosign import LogError, parse_quorum, parse_witness_vkey

    rows = []
    try:
        for vkey in sorted(set(v.strip() for v in vkeys if v.strip())):
            rows.append({"name": parse_witness_vkey(vkey)[0], "vkey": vkey})
        need = parse_quorum(quorum) if quorum else None
    except (LogError, ValueError) as exc:
        raise ValueError(f"witness set: {exc}") from exc
    if need and need[1] != len(rows):
        raise ValueError(f"--quorum {quorum} names {need[1]} witnesses; {len(rows)} are pinned")
    names = []
    for path in log_keys:
        (out / "trust" / "log-keys").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, out / "trust" / "log-keys" / path.name)
        names.append(f"trust/log-keys/{path.name}")
    (out / "trust").mkdir(exist_ok=True)
    doc = {"witnesses": rows, "quorum": quorum, "log_keys": sorted(names)}
    (out / WITNESSES).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", "utf-8")
    return check_witnesses(out)


def check_witnesses(kit: Path) -> dict[str, str]:
    from opentine.repository._tlog_cosign import LogError, parse_quorum, parse_witness_vkey

    try:
        doc = json.loads((kit / WITNESSES).read_text(encoding="utf-8"))
        for row in doc["witnesses"]:
            if parse_witness_vkey(row["vkey"])[0] != row["name"]:
                raise ValueError(f"witness {row['name']!r} does not match its key")
        if doc["quorum"]:
            need, total = parse_quorum(doc["quorum"])
            if total != len(doc["witnesses"]):
                raise ValueError("the quorum does not match the pinned set")
        for name in doc["log_keys"]:
            if not (kit / name).is_file():
                raise ValueError(f"{name} is missing")
    except (OSError, KeyError, TypeError, LogError, ValueError) as exc:
        return check("witnesses", False, f"pinned witness set is unreadable: {exc}")
    count = len(doc["witnesses"])
    if not count:
        return check("witnesses", None, "no witnesses pinned (pass --witness or --witness-set)")
    return check("witnesses", True, f"{count} witness key(s) pinned, quorum {doc['quorum']}")


def bundle_runs(bundle: Path, room: Path) -> tuple[list[Path], dict[str, str]]:
    """Verify *bundle*; write each run it carries to ``room/<run id>.tine``."""
    from opentine import _bundle
    from opentine.repo import Repo

    data = _bundle.read_file(bundle)
    verified = _bundle.verify(data)
    repo = Repo.init(room / "repo")
    _bundle.unbundle(repo, data, "kit")
    files: list[Path] = []
    for oid in sorted(set(verified.refs.values())):
        try:
            run = repo.load_run(oid)
        except (KeyError, ValueError, TypeError):
            continue  # a ref to something that is not a run
        from opentine._audit_kit_guard import safe_stem

        target = room / f"{safe_stem(run.id, oid)}.tine"
        if not target.exists():
            run.save(target)
            files.append(target)
    detail = f"bundle {verified.digest}: {len(verified.refs)} ref(s), {verified.objects} object(s)"
    return files, check("bundle", True, detail)


def run_digest(path: Path) -> str:
    """``sha256:HEX`` of a run file whose integrity verifies; ``""`` otherwise."""
    from opentine.core import Run

    result = Run.verify_integrity(path)
    if not result.ok or not isinstance(result.actual, str):
        return ""
    return "sha256:" + result.actual.rsplit(":", 1)[-1]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()
