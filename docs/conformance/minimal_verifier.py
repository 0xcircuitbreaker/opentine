#!/usr/bin/env python3
"""A minimal, independent opentine verifier: standard library only.

It imports nothing from opentine. It exists to show that the checks behind
``tine verify --offline`` can be reproduced from ``docs/SPEC.md`` alone
(Part 8, "Verifying without opentine"), and so that a reviewer can check an
artifact on a machine where opentine is not installed::

    python3 -I minimal_verifier.py artifact RUN.tine [--pubkey KEY.pub] [--source SRC]
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

Format v4 (SPEC Part 9) is read too: every envelope id is recomputed (§1.3),
the root must name a run the file carries, ``tine-sig/3`` is checked
(Ed25519 only), and the run's ``upgraded_from`` record gives the
``provenance`` check (§9.9; ``--source`` re-hashes the source file). Link
closure (every object reachable from the root, §9.4) is the full reader's
job and is not repeated here.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import zlib
from pathlib import Path

SCHEMA = "tine-minimal-verify/1"
SUPPORTED = (1, 2)
MAGIC = b"TINEZ1\0"
SIG_DOMAIN = b"opentine.signature.v1:"
SIG3_DOMAIN = b"opentine.signature.v3:"
V4_KIND = "tine-artifact/4"
V4_KEYS = {"annotations", "format_version", "kind", "objects", "root", "signatures"}
MAX_SAFE = 2**53 - 1
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


def _int(text: str) -> object:
    value = int(text)
    return float(text) if abs(value) > MAX_SAFE else value  # §9.4: a wide literal is a double


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
    """§0.2 (RFC 8785): strings, integers, doubles, booleans, null, arrays, objects."""
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
    if isinstance(value, float):
        return es_number(value).encode()
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) > MAX_SAFE:
        raise ValueError("integers past 2**53-1 are refused by §0.2")
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


def es_number(value: float) -> str:
    """ECMAScript ``Number.prototype.toString`` of a finite double (§9.2)."""
    from decimal import Decimal

    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("non-finite numbers are refused by §0.2")
    if value == 0:
        return "0"
    sign, digits, exponent = Decimal(repr(abs(value))).normalize().as_tuple()
    text, k = "".join(map(str, digits)), len(digits)
    n = exponent + k  # value = 0.<text> * 10**n
    minus = "-" if value < 0 else ""
    if k <= n <= 21:
        return minus + text + "0" * (n - k)
    if 0 < n <= 21:
        return minus + text[:n] + "." + text[n:]
    if -6 < n <= 0:
        return minus + "0." + "0" * -n + text
    e = n - 1
    mantissa = text[0] + ("." + text[1:] if k > 1 else "")
    return f"{minus}{mantissa}e{'+' if e > 0 else '-'}{abs(e)}"


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
    if data.get("format_version") == 4 and data.get("kind") == V4_KIND:
        result, root = v4_digest_check(data)
        return result, data, root
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


# ------------------------------------------------------------------ format v4 (Part 9)


def envelope_oid(entry: object, where: str) -> str:
    """Recompute one v4 envelope's oid (§1.2, §1.3) from its JSON spelling."""
    if not isinstance(entry, dict):
        raise ValueError(f"{where}: an envelope is an object")
    kind, schema, encoding = entry.get("type"), entry.get("schema"), entry.get("encoding")
    raw = encoding == "raw"
    if set(entry) != {"encoding", "schema", "type", "data" if raw else "body"}:
        raise ValueError(f"{where}: envelope keys are encoding, schema, type and data|body")
    if raw != (kind == "blob") or encoding not in ("raw", "json"):
        raise ValueError(f"{where}: encoding must be raw exactly for a blob")
    if type(schema) is not int or not 1 <= schema <= MAX_SAFE or not isinstance(kind, str):
        raise ValueError(f"{where}: bad type or schema")
    if raw:
        body = base64.b64decode(entry["data"], validate=True)
        if base64.b64encode(body).decode("ascii") != entry["data"]:
            raise ValueError(f"{where}: blob data is not canonical base64")
    else:
        body = canon_v3(json.loads(json.dumps(entry["body"]), parse_int=_int))
    framed = kind.encode() + b"\0" + str(schema).encode() + b"\0" + body
    return f"{kind}:sha256:{hashlib.sha256(framed).hexdigest()}"


def v4_digest_check(data: dict) -> tuple[dict, str]:
    """The ``digest`` check of a v4 file: every id re-derives and the root is a run."""
    try:
        if set(data) != V4_KEYS or not isinstance(data["objects"], dict):
            raise ValueError("v4 keys must be exactly " + ", ".join(sorted(V4_KEYS)))
        for oid, entry in data["objects"].items():
            if envelope_oid(entry, f"objects[{oid}]") != oid:
                raise ValueError(f"objects[{oid}]: the envelope does not re-derive its id")
        previous = None
        for index, item in enumerate(data["annotations"]):
            body = {k: v for k, v in item.items() if k != "id"}
            if envelope_oid(body, f"annotations[{index}]") != item.get("id"):
                raise ValueError(f"annotations[{index}]: the envelope does not re-derive its id")
            payload = body.get("body") or {}
            if body.get("type") != "annotation" or payload.get("target_id") != data["root"]:
                raise ValueError(f"annotations[{index}]: not an annotation of the root")
            if payload.get("previous_id") != previous:
                raise ValueError(f"annotations[{index}]: the chain is broken")
            previous = item["id"]
        root = data["root"]
        if not (isinstance(root, str) and root.startswith("run:") and root in data["objects"]):
            raise ValueError("the root must name a run the artifact carries")
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError) as exc:
        return check("digest", "fail", "digest.mismatch", f"invalid v4 artifact: {exc}"), ""
    return check("digest", "pass", "digest.match", f"root {root}"), root


def _verify_ed25519(block: dict, message: bytes, pubkey: str) -> dict | None:
    """``None`` when the block verifies under *pubkey*, else the failing check."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        detail = "the cryptography package is not importable; nothing was checked"
        return check("signature", "unavailable-offline", "signature.crypto-unavailable", detail)
    try:
        key = bytes.fromhex(pubkey)
        if block.get("public_key") != key.hex():
            raise InvalidSignature
        Ed25519PublicKey.from_public_bytes(key).verify(bytes.fromhex(block["value"]), message)
    except InvalidSignature:
        return check("signature", "fail", "signature.mismatch", "the supplied key disagrees")
    except (KeyError, TypeError, ValueError) as exc:
        return check("signature", "fail", "signature.error", f"malformed block: {exc}")
    return None


def v4_signature_check(data: dict | None, digest_ok: bool, pubkey: str | None) -> dict:
    """``tine-sig/3`` (§9.6): the root, the annotation head and the five-key header."""
    if not digest_ok or data is None:
        return check("signature", "not-applicable", "signature.integrity-failed", "digest failed")
    blocks = data["signatures"]
    if not blocks:
        return check("signature", "unavailable-offline", "signature.unsigned", "no signature")
    if any(not isinstance(b, dict) or b.get("scheme") != "tine-sig/3" for b in blocks):
        return check("signature", "fail", "signature.error", "unsupported signature scheme")
    usable = [b for b in blocks if b.get("alg") == "ed25519"]
    if not usable or pubkey is None:
        detail = "signature present but no trusted Ed25519 key was given: pass --pubkey"
        return check("signature", "unavailable-offline", "signature.no-key", detail)
    head = data["annotations"][-1]["id"] if data["annotations"] else None
    first = None
    for block in usable:
        view = {"annotations_head": head, "format_version": 4, "kind": V4_KIND,
                "header": {k: block.get(k) for k in HEADER_KEYS}, "root": data["root"]}  # fmt: skip
        failed = _verify_ed25519(block, SIG3_DOMAIN + canon_v3(view), pubkey)
        if failed is None:
            return check("signature", "pass", "signature.verified", "tine-sig/3 under the key")
        first = first or failed
    return first


def provenance_check(data: dict | None, digest_ok: bool, source: str | None) -> dict:
    """§9.9: the run payload's ``upgraded_from``, re-hashed against ``--source``."""
    payload = {}
    if digest_ok and isinstance(data, dict) and data.get("kind") == V4_KIND:
        payload = data["objects"][data["root"]].get("body") or {}
    record = payload.get("upgraded_from") if isinstance(payload, dict) else None
    if not isinstance(record, dict):
        return check("provenance", "not-applicable", "provenance.none", "no upgraded_from")
    state = (record.get("signature") or {}).get("state")
    claim = f"upgraded from {record.get('format')} {record.get('digest')}; signature then {state}"
    if source is None:
        return check("provenance", "unavailable-offline", "provenance.recorded", claim)
    if record.get("format") == "tine-repo/3":
        detail = "a repository source is out of scope for this verifier"
        return check("provenance", "unavailable-offline", "provenance.recorded", detail)
    try:
        actual = hashlib.sha256(unwrap(Path(source).read_bytes())).hexdigest()
    except (OSError, ValueError, IndexError, zlib.error) as exc:
        return check("provenance", "fail", "provenance.source-mismatch", f"unreadable: {exc}")
    if actual != record.get("digest"):
        detail = f"source sha256 {actual} is not the recorded {record.get('digest')}"
        return check("provenance", "fail", "provenance.source-mismatch", detail)
    return check("provenance", "pass", "provenance.source-match", claim)


def verify_artifact(path: Path, pubkey: str | None = None, source: str | None = None) -> dict:
    digest, data, actual = digest_check(path)
    ok = digest["outcome"] == "pass"
    if isinstance(data, dict) and data.get("kind") == V4_KIND:
        root = data.get("root")
        payload = (data.get("objects") or {}).get(root, {}).get("body") if ok else None
        run_id = payload.get("source_run_id") if isinstance(payload, dict) else None
        signature = v4_signature_check(data, ok, pubkey)
    else:
        run_id = data.get("run_id") if isinstance(data, dict) else None
        signature = signature_check(data, ok, pubkey)
    checks = [digest, signature, provenance_check(data, ok, source)]
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
    parser.add_argument("--source", help="the file a v4 run was upgraded from (artifact mode)")
    args = parser.parse_args(argv)
    path = Path(args.path)
    if args.mode == "artifact":
        try:
            key = _pubkey(args.pubkey) if args.pubkey else None
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        report = verify_artifact(path, key, args.source)
    elif not path.is_dir():
        parser.error(f"{args.mode} mode needs a directory: {path}")
    else:
        report = verify_evidence(path) if args.mode == "evidence" else verify_dataset(path)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
