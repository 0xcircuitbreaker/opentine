#!/usr/bin/env python3
"""A minimal, independent opentine verifier: standard library only.

It imports nothing from opentine. It exists to show that the checks behind
``tine verify --offline`` can be reproduced from ``docs/SPEC.md`` alone
(Part 8, "Verifying without opentine"), and so that a reviewer can check an
artifact on a machine where opentine is not installed::

    python3 -I minimal_verifier.py artifact RUN.tine [--pubkey KEY.pub]
    python3 -I minimal_verifier.py evidence EVIDENCE_DIR
    python3 -I minimal_verifier.py dataset DIR

It prints one ``tine-minimal-verify/1`` JSON report and exits 0 on a pass, 1
on a fail and 2 on a usage error. Check names, outcomes and reason codes are
the ``tine-verify-report/1`` ones where the two overlap. Ed25519 signatures
are checked only when the ``cryptography`` package happens to be importable;
otherwise that check is ``unavailable-offline`` with reason
``signature.crypto-unavailable`` -- never a pass. zstd-compressed artifacts
need ``compression.zstd`` (Python 3.14+); zlib and uncompressed ones always
work. Repositories (``.tine/`` directories) are out of scope.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zlib
from pathlib import Path

SCHEMA = "tine-minimal-verify/1"
SUPPORTED = (1, 2)
MAGIC = b"TINEZ1\0"
SIG_DOMAIN = b"opentine.signature.v1:"
CUSTODY_DOMAIN = b"opentine.custody.v1:"
HEADER_KEYS = ("alg", "key_id", "scheme", "signed_at", "signer")
V1_METADATA = (
    "model_info", "system_prompt", "user_prompt", "forked_from", "fork_point", "warnings",
    "replay", "context", "next_harness", "migration", "fork",
)  # fmt: skip
UNLISTED = ("MANIFEST.sha256", "custody.jsonl")


def check(name: str, outcome: str, reason: str, detail: str) -> dict:
    return {"name": name, "outcome": outcome, "reason": reason, "detail": detail}


# --------------------------------------------------------------- decoding (§2.3)


def unwrap(raw: bytes) -> bytes:
    """Strip the ``TINEZ1\\0`` storage wrapper; anything else is stored raw."""
    if not raw.startswith(MAGIC):
        return raw
    codec, pos, length, shift = raw[len(MAGIC)], len(MAGIC) + 1, 0, 0
    while True:  # uvarint: the declared uncompressed length
        byte = raw[pos]
        length |= (byte & 0x7F) << shift
        pos, shift = pos + 1, shift + 7
        if byte < 0x80:
            break
    frame = raw[pos:]
    if codec == 0:
        body = frame
    elif codec == 1:
        body = zlib.decompress(frame)
    elif codec == 2:
        try:
            from compression import zstd  # Python 3.14+
        except ImportError as exc:
            raise ValueError("zstd-compressed artifact: needs Python 3.14+") from exc
        body = zstd.decompress(frame)
    else:
        raise ValueError(f"unknown storage codec {codec}")
    if len(body) != length:
        raise ValueError("decompressed length does not match the declared length")
    return body


def _pairs(items: list) -> dict:
    out: dict = {}
    for key, value in items:
        if key in out:
            raise ValueError(f"duplicate object key {key[:80]!r}")
        out[key] = value
    return out


def _no_constant(value: str) -> None:
    raise ValueError(f"non-finite number {value}")


def parse(raw: bytes) -> object:
    """JSON with the reader's refusals: duplicate keys and NaN/Infinity."""
    if b"\0" in raw:
        raise ValueError("artifacts must be UTF-8 JSON")
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_no_constant)


# --------------------------------------------------------- canonical forms (§0.2/§0.3)


def canon_v2(value: object) -> bytes:
    """§0.3: CPython ``json.dumps(sort_keys=True, separators=(",", ":"))``."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def canon_v3(value: object) -> bytes:
    """§0.2 for the values these files hold: strings, integers, booleans, null."""
    out, stack = [], [value]
    while stack:
        item = stack.pop()
        if isinstance(item, bytes):
            out.append(item)
        elif isinstance(item, dict):
            seq: list = [b"{"]
            for index, key in enumerate(sorted(item, key=lambda k: k.encode("utf-16be"))):
                seq += ([b","] if index else []) + [_scalar(key) + b":", item[key]]
            stack.extend(reversed([*seq, b"}"]))
        elif isinstance(item, list):
            seq = [b"["]
            for index, element in enumerate(item):
                seq += ([b","] if index else []) + [element]
            stack.extend(reversed([*seq, b"]"]))
        else:
            out.append(_scalar(item))
    return b"".join(out)


def _scalar(value: object) -> bytes:
    if isinstance(value, float) or (isinstance(value, int) and abs(value) > 2**53 - 1):
        raise ValueError("floats and integers past 2**53-1 are outside this verifier")
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


# ------------------------------------------------------------- artifact (§3.5, Part 4)


def digest_check(path: Path) -> tuple[dict, dict | None, str]:
    """The ``digest`` check, the parsed artifact, and the recomputed digest."""
    try:
        data = parse(unwrap(path.read_bytes()))
    except OSError as exc:
        return check("digest", "fail", "digest.unreadable", f"read error: {exc}"), None, ""
    except (ValueError, IndexError, RecursionError, zlib.error) as exc:
        return check("digest", "fail", "artifact.malformed-json", str(exc)), None, ""
    if not isinstance(data, dict):
        return check("digest", "fail", "digest.unreadable", "root is not an object"), None, ""
    version = data.get("format_version")
    if type(version) is not int or version not in SUPPORTED:
        detail = f"unsupported format_version {version!r}"
        return check("digest", "fail", "digest.unsupported-format", detail), data, ""
    meta = data.get("metadata")
    block = meta.get("integrity") if isinstance(meta, dict) else None
    if not isinstance(block, dict):
        return check("digest", "fail", "digest.missing", "no metadata.integrity"), data, ""
    if block.get("algorithm") != "sha256":
        return check("digest", "fail", "digest.unsupported-algorithm", "not sha256"), data, ""
    expected = block.get("digest")
    if not (isinstance(expected, str) and len(expected) == 64 and _hex(expected)):
        return check("digest", "fail", "digest.malformed", "not 64 hex chars"), data, ""
    try:
        actual = hashlib.sha256(canon_v2({k: v for k, v in data.items() if k != "metadata"}))
    except (ValueError, RecursionError) as exc:
        return check("digest", "fail", "digest.mismatch", f"not canonicalizable: {exc}"), data, ""
    actual_hex = actual.hexdigest()
    if actual_hex != expected:
        detail = f"expected {expected}, actual {actual_hex}"
        return check("digest", "fail", "digest.mismatch", detail), data, ""
    return check("digest", "pass", "digest.match", f"sha256:{actual_hex}"), data, actual_hex


def _hex(text: str) -> bool:
    try:
        int(text, 16)
    except ValueError:
        return False
    return True


def signature_check(data: dict | None, digest_ok: bool, pubkey: str | None) -> dict:
    if not digest_ok or data is None:
        return check("signature", "not-applicable", "signature.integrity-failed", "digest failed")
    meta = data["metadata"]
    block = meta["integrity"].get("signature")
    if block is None:
        return check("signature", "unavailable-offline", "signature.unsigned", "no signature")
    if not isinstance(block, dict) or block.get("alg") != "ed25519" or pubkey is None:
        detail = "signature present but no trusted Ed25519 key was given: pass --pubkey"
        return check("signature", "unavailable-offline", "signature.no-key", detail)
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        detail = "the cryptography package is not importable; nothing was checked"
        return check("signature", "unavailable-offline", "signature.crypto-unavailable", detail)
    scheme = block.get("scheme")
    if scheme == "tine-sig/2":
        signed_meta = {k: v for k, v in meta.items() if k != "integrity"}
    elif scheme == "tine-sig/1":
        signed_meta = {k: meta[k] for k in V1_METADATA if k in meta}
    else:
        return check("signature", "fail", "signature.error", f"unknown scheme {scheme!r}")
    view = {
        "body": {k: v for k, v in data.items() if k != "metadata"},
        "header": {k: block.get(k) for k in HEADER_KEYS},
        "metadata": signed_meta,
    }
    try:
        key = bytes.fromhex(pubkey)
        if block.get("public_key") != key.hex():
            raise InvalidSignature
        Ed25519PublicKey.from_public_bytes(key).verify(
            bytes.fromhex(block["value"]), SIG_DOMAIN + canon_v2(view)
        )
    except InvalidSignature:
        return check("signature", "fail", "signature.mismatch", "the supplied key disagrees")
    except (KeyError, TypeError, ValueError) as exc:
        return check("signature", "fail", "signature.error", f"malformed block: {exc}")
    return check("signature", "pass", "signature.verified", f"{scheme} under the supplied key")


def verify_artifact(path: Path, pubkey: str | None = None) -> dict:
    digest, data, actual = digest_check(path)
    checks = [digest, signature_check(data, digest["outcome"] == "pass", pubkey)]
    run_id = data.get("run_id") if isinstance(data, dict) else None
    return _report("artifact", path, checks, run_id=run_id, digest=actual)


# ---------------------------------------------------------------- dataset / Merkle


def merkle_root(pairs: list) -> str:
    level = [hashlib.sha256(b"\x00" + canon_v3([r, d])).digest() for r, d in sorted(pairs)]
    if not level:
        return hashlib.sha256(b"").hexdigest()
    while len(level) > 1:
        nxt = [hashlib.sha256(b"\x01" + a + b).digest() for a, b in zip(level[::2], level[1::2])]
        level = nxt + ([level[-1]] if len(level) % 2 else [])
    return level[0].hex()


def verify_dataset(root: Path) -> dict:
    runs = []
    for path in sorted(p for p in root.rglob("*.tine") if p.is_file() and not p.is_symlink()):
        one = verify_artifact(path)
        run_id = one["run_id"] if isinstance(one["run_id"], str) else None
        runs.append(
            {
                "run_id": run_id or path.relative_to(root).as_posix(),
                "path": path.relative_to(root).as_posix(),
                "digest": one["digest"],
                "ok": one["ok"],
            }
        )
    runs.sort(key=lambda r: (r["run_id"], r["digest"]))
    checks = [
        check("run:" + r["path"], "pass" if r["ok"] else "fail", "dataset.run", r["run_id"])
        for r in runs
    ]
    report = _report("dataset", root, checks)
    report["runs"] = runs
    report["merkle"] = {"root": merkle_root([(r["run_id"], r["digest"]) for r in runs])}
    return report


# ---------------------------------------------------------------- evidence folder


def verify_evidence(root: Path) -> dict:
    checks, manifest = [], root / "MANIFEST.sha256"
    try:
        text = manifest.read_bytes()
        listed = dict(reversed(line.split("  ", 1)) for line in text.decode().splitlines())
    except (OSError, ValueError) as exc:
        listed, text = {}, b""
        checks.append(check("manifest", "fail", "evidence.manifest-unreadable", str(exc)))
    on_disk = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()} - set(
        UNLISTED
    )
    bad = sorted(
        rel
        for rel, digest in listed.items()
        if rel not in on_disk or hashlib.sha256((root / rel).read_bytes()).hexdigest() != digest
    )
    extra = sorted(on_disk - set(listed))
    if text:
        ok = not bad and not extra
        detail = f"{len(listed)} file(s); changed or missing: {bad or 'none'}; unlisted: {extra}"
        reason = "evidence.manifest-match" if ok else "evidence.manifest-mismatch"
        checks.append(check("manifest", "pass" if ok else "fail", reason, detail))
    checks += _custody(root, text)
    dataset = verify_dataset(root / "runs")
    checks += dataset["checks"]
    report = _report("evidence", root, checks)
    report["runs"], report["merkle"] = dataset["runs"], dataset["merkle"]
    return report


def _custody(root: Path, manifest: bytes) -> list:
    try:
        record = parse((root / "custody.jsonl").read_bytes().splitlines()[0])
        assert isinstance(record, dict)
    except (OSError, ValueError, IndexError, AssertionError) as exc:
        return [check("custody", "fail", "evidence.custody-unreadable", str(exc))]
    linked = record.get("manifest_sha256") == hashlib.sha256(manifest).hexdigest()
    reason = "evidence.custody-linked" if linked else "evidence.custody-manifest-mismatch"
    first = check("custody", "pass" if linked else "fail", reason, "manifest_sha256 vs MANIFEST")
    block = record.get("signature")
    if not isinstance(block, dict):
        return [first, check("custody-signature", "not-applicable", "signature.unsigned", "-")]
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        detail = "the cryptography package is not importable; nothing was checked"
        reason = "signature.crypto-unavailable"
        return [first, check("custody-signature", "unavailable-offline", reason, detail)]
    body = {k: v for k, v in record.items() if k != "signature"}
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(block["public_key"]))
        key.verify(bytes.fromhex(block["value"]), CUSTODY_DOMAIN + canon_v3(body))
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return [first, check("custody-signature", "fail", "signature.mismatch", "does not verify")]
    detail = f"under its own key {block['public_key'][:16]}... (compare trust/custody-signer.pub)"
    return [first, check("custody-signature", "pass", "signature.verified-tofu", detail)]


# --------------------------------------------------------------------------- CLI


def _report(mode: str, path: Path, checks: list, **extra: object) -> dict:
    ok = not any(c["outcome"] == "fail" for c in checks)
    verdict = "pass" if ok else "fail"
    return {"schema": SCHEMA, "mode": mode, "path": str(path), "verdict": verdict, "ok": ok,
            "checks": checks, **extra}  # fmt: skip


def _pubkey(path: str) -> str:
    text = Path(path).read_bytes().removesuffix(b"\n")
    key = text.decode().strip() if len(text) != 32 else text.hex()
    if len(key) != 64 or not _hex(key):
        raise ValueError("--pubkey must hold a raw 32-byte or 64-hex Ed25519 public key")
    return key.lower()


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("mode", choices=("artifact", "evidence", "dataset"))
    parser.add_argument("path")
    parser.add_argument("--pubkey", help="trusted Ed25519 public key file (artifact mode)")
    args = parser.parse_args(argv)
    path = Path(args.path)
    if args.mode == "artifact":
        try:
            key = _pubkey(args.pubkey) if args.pubkey else None
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        report = verify_artifact(path, key)
    elif not path.is_dir():
        parser.error(f"{args.mode} mode needs a directory: {path}")
    else:
        report = verify_evidence(path) if args.mode == "evidence" else verify_dataset(path)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
