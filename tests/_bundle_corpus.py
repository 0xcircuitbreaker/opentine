"""A corpus of ``tine bundle`` files and Python's verdict on each (0.51).

Written at test time (never committed, so no new vector family): good bundles
in every shape ``_bundle.create`` writes (TINEPACK3, TINEPACK5, tine-sig/3
sidecars, tombstones, ``--redacted-public`` copies) and tampered ones that
reach each refusal of ``_bundle.verify``. tests/test_051_browser_bundles.py
compares ts/verifier's streaming reader with these verdicts in Node, and the
Playwright harness (ts/browser-tests) in real browsers.

``python -m tests._bundle_corpus OUT`` writes ``OUT/*.bundle`` and
``OUT/verdicts.json``.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from opentine import Run, StepKind, _bundle, _tombstone
from opentine.repo import Repo

KEY = b"ab" * 32


def _run(repo: Repo, label: str, ref: str = "heads/main") -> str:
    run = Run(id=label, model_info="mock-model", user_prompt="p")
    run.add_step(StepKind.think, {"text": f"the step text of {label}"}, {"a": 1})
    return repo.put_run(run, ref=ref).run_id


def _ed25519_block(root: str, key: Any) -> dict:
    from opentine._signing_v4 import SCHEME_V3, artifact_message
    from opentine._signing_verify import sign_block

    view = {"annotations": [], "root": root}
    return sign_block(lambda header: artifact_message(view, header), key, algorithm="ed25519",
                      scheme=SCHEME_V3)  # fmt: skip


def _split(data: bytes) -> tuple[dict, bytes]:
    size = int.from_bytes(data[44:48], "big")
    return json.loads(data[48 : 48 + size]), data[48 + size :]


def _raw(manifest_bytes: bytes, pack: bytes) -> bytes:
    """A bundle with exactly these manifest bytes and pack, checksummed."""
    body = len(manifest_bytes).to_bytes(4, "big") + manifest_bytes + pack
    return _bundle.MAGIC + hashlib.sha256(body).digest() + body


def _canonical(manifest: dict) -> bytes:
    from opentine.kernel import canonical_json

    return canonical_json(manifest)


def _repath(manifest: dict, pack: bytes) -> dict:
    return {**manifest, "pack": "sha256:" + hashlib.sha256(pack).hexdigest(), "pack_bytes": len(pack)}


def build(root: Path) -> dict[str, bytes]:
    """Every corpus file by name."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from opentine import _redacted_derive
    from opentine.repository._pack5 import V5
    from opentine.repository._purge import purge
    from opentine.repository._sig_sidecar import add_signatures

    out: dict[str, bytes] = {}
    repo = Repo.init(root / "plain")
    main = _run(repo, "one")
    _run(repo, "two", ref="heads/feature")
    out["v3-two-refs"] = _bundle.create(repo, None)
    out["v5-two-refs"] = _bundle.create(repo, None, pack_format=V5)
    base = out["v3-two-refs"]
    manifest, pack = _split(base)

    signed = Repo.init(root / "signed")
    root_oid = _run(signed, "signed")
    key = Ed25519PrivateKey.generate()
    add_signatures(signed, root_oid, None, [_ed25519_block(root_oid, key)])
    out["signed-ed25519"] = _bundle.create(signed, ["heads/main"])
    sig_manifest, sig_pack = _split(out["signed-ed25519"])
    block = sig_manifest["signatures"][root_oid][0]["block"]
    forged = {root_oid: [{"annotations_head": None, "block": {**block, "signer": "mallory"}}]}
    out["signed-tampered"] = _bundle.assemble(sig_pack, sig_manifest["refs"], {"signatures": forged})

    purged = Repo.init(root / "purged")
    run = _run(purged, "purged")
    from opentine.repository.pack import reachable

    blob = next(o for o in reachable(purged, [run], include_associated=False)
                if o.startswith("blob:") and b"the step text" in purged.get(o).body)  # fmt: skip
    tomb = _tombstone.sign(_tombstone.build(blob, "erasure request", "alice"), KEY,
                           algorithm="hmac-sha256", key_id="k1")  # fmt: skip
    purge(purged, tomb)
    out["tombstone"] = _bundle.create(purged, ["heads/main"])
    t_manifest, t_pack = _split(out["tombstone"])
    stray = _tombstone.sign(_tombstone.build("blob:sha256:" + "8" * 64, "erasure", "alice"), KEY,
                            algorithm="hmac-sha256", key_id="k1")  # fmt: skip
    out["tombstone-stray"] = _bundle.assemble(t_pack, t_manifest["refs"], {"tombstones": [stray]})

    public = Repo.init(root / "public")
    prun = _run(public, "public")
    out["redacted-public-hmac"] = _redacted_derive.public_bundle(
        public, "heads/main", prun, KEY, algorithm="hmac-sha256"
    )
    out["redacted-public-ed25519"] = _redacted_derive.public_bundle(
        public, "heads/main", prun, key, algorithm="ed25519"
    )
    p_manifest, p_pack = _split(out["redacted-public-ed25519"])
    record = dict(p_manifest["redacted_public"])
    record["signature"] = {**record["signature"], "signer": "mallory"}
    out["redacted-public-bad-signature"] = _raw(_canonical({**p_manifest, "redacted_public": record}), p_pack)

    # Refusals of the outer layer, in _bundle.verify's order.
    out["bad-magic"] = b"TINEBUNDLE2\n" + base[12:]
    out["truncated"] = base[:-7]
    flipped = bytearray(base)
    flipped[60] ^= 0x01
    out["checksum-mismatch"] = bytes(flipped)
    out["manifest-length"] = _bundle.MAGIC + hashlib.sha256(b"\xff\xff\xff\x00").digest() + b"\xff\xff\xff\x00"
    out["manifest-not-canonical"] = _raw(json.dumps(manifest, indent=1).encode(), pack)
    out["manifest-unknown-key"] = _raw(_canonical({**manifest, "extra": 1}), pack)
    out["manifest-wrong-format"] = _raw(_canonical({**manifest, "format": "opentine-bundle/9"}), pack)
    out["pack-length-mismatch"] = _raw(_canonical({**manifest, "pack_bytes": len(pack) + 1}), pack)
    out["pack-digest-mismatch"] = _raw(_canonical({**manifest, "pack": "sha256:" + "0" * 64}), pack)
    bad_pack = pack[:-1] + bytes([pack[-1] ^ 0xFF])
    out["pack-invalid"] = _raw(_canonical(_repath(manifest, bad_pack)), bad_pack)
    trailing = pack + b"xx"
    out["pack-trailing-bytes"] = _raw(_canonical(_repath(manifest, trailing)), trailing)
    out["ref-outside"] = _bundle.assemble(pack, {**manifest["refs"], "heads/ghost": "run:sha256:" + "1" * 64}, {})
    out["ref-unsafe"] = _bundle.assemble(pack, {"heads/../x": main}, {})
    out["ref-remotes"] = _bundle.assemble(pack, {"remotes/o/main": main}, {})
    out["ref-collision"] = _bundle.assemble(pack, {"heads/tags/x": main, "tags/x": main}, {})
    out["transparency-not-list"] = _raw(_canonical({**manifest, "transparency": {}}), pack)
    out["signatures-not-object"] = _raw(_canonical({**manifest, "signatures": []}), pack)
    out["signatures-foreign-root"] = _bundle.assemble(pack, manifest["refs"], {"signatures": sig_manifest["signatures"]})
    return out


def verdict(data: bytes) -> dict[str, Any]:
    """What ``tine bundle verify`` concludes: ``{ok, reason, refs, objects, pack, ...}``."""
    import argparse

    from opentine import _bundle_share

    try:
        checked = _bundle.verify(data)
    except _bundle.BundleError as exc:
        return {"ok": False, "reason": str(exc)}
    extra = _bundle_share.verified(checked, argparse.Namespace(key_file=None, pubkey=None))
    failed = extra.get("redacted_public", {}).get("state") == "failed"
    return {
        "ok": not failed,
        "reason": None,
        "bundle": checked.digest,
        "pack": checked.pack_id,
        "objects": checked.objects,
        "refs": checked.refs,
        "content_unavailable": extra.get("content_unavailable", []),
        "redacted_public": extra.get("redacted_public"),
    }


def write(out: Path, work: Path) -> dict[str, dict]:
    out.mkdir(parents=True, exist_ok=True)
    verdicts = {}
    for name, data in sorted(build(work).items()):
        (out / f"{name}.bundle").write_bytes(data)
        verdicts[name] = verdict(data)
    (out / "verdicts.json").write_text(json.dumps(verdicts, indent=2, sort_keys=True), encoding="utf-8")
    return verdicts


def large(root: Path, mib: int) -> bytes:
    """A valid TINEPACK5 bundle of at least *mib* MiB: incompressible blobs under ``tags/``."""
    import os

    from opentine.repository import _pack5

    repo = Repo.init(root / "large")
    chosen, objects = {}, []
    for index in range(mib + 1):
        oid = repo.put("blob", os.urandom(1 << 20), redact=False)
        chosen[f"tags/b{index:04d}"] = oid
        objects.append((oid, repo.raw(oid)))
    # A TINEPACK3 of this much incompressible data would pass its inflated cap
    # (base64), so the pack is written as TINEPACK5 directly.
    return _bundle.assemble(_pack5.build(sorted(objects), []), chosen, {})


if __name__ == "__main__":  # pragma: no cover - used by ts/browser-tests
    import tempfile

    with tempfile.TemporaryDirectory() as scratch:
        if sys.argv[1] == "--large":
            Path(sys.argv[2]).write_bytes(large(Path(scratch), int(sys.argv[3])))
        else:
            write(Path(sys.argv[1]), Path(scratch))
