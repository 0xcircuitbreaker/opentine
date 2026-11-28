"""``tine lineage record``: a signed node of the self-modification lineage (0.58).

A variant (a code tree, prompt, config, weights or skill tree, by digest) is recorded as an
existing ``attestation`` (tine-attest/2, Ed25519) on its mutation run, whose
claim follows the ``opentine.lineage.variant`` convention (docs/SPEC.md,
docs/LINEAGE.md)::

    {"convention": "opentine.lineage.variant",
     "variant": "sha256:HEX",            # over the artifacts, see variant_id
     "artifacts": {"code_tree"|"prompt"|"config"|"weights"|"skill": "sha256:HEX"},
     "parents": ["sha256:HEX", ...],     # zero for a root, many for a merge
     "mutation_run": "run:sha256:HEX",   # also the attestation's target
     "evals": [{"eval": "sha256:HEX", "verdicts_sha256": HEX}],
     "selector": "...", "decision": null | {"sha256": HEX},
     "policy": null | HEX, "loop": null | "LOOP"}

The record, every justifying eval's ``verdicts.jsonl`` and the promotion
decision it cites are kept in a lineage folder (default ``REPO/.tine/lineage``)
named by digest, so ``tine lineage check`` (:mod:`opentine._lineage_check`)
runs offline over the folder alone. Nothing in the folder is trusted for being
there: every file is re-hashed and every signature re-checked.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from opentine import _json_shallow
from opentine.kernel import canonical_json

CONVENTION = "opentine.lineage.variant"
DOMAIN = b"opentine.lineage.variant.v1:"
ARTIFACTS = ("code_tree", "prompt", "config", "weights", "skill")  # skill: 0.88
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
HEX_RE = re.compile(r"[0-9a-f]{64}")
RUN_RE = re.compile(r"run:sha256:[0-9a-f]{64}")
LOOP_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
FOLDER = Path(".tine") / "lineage"


def variant_id(artifacts: dict[str, str]) -> str:
    """``sha256:`` over the domain and JCS of the artifact digests."""
    return "sha256:" + hashlib.sha256(DOMAIN + canonical_json(artifacts)).hexdigest()


def _write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not (path.is_file() and path.read_bytes() == raw):
        path.write_bytes(raw)


def _append_only(path: Path, claim: dict[str, Any]) -> None:
    """Refuse to re-sign a recorded variant with another claim (new parents or evals):
    a loop must not re-root a regressed variant to drop its parent link (0.72)."""
    try:
        old = loads(path.read_bytes()).get("claim")
    except (OSError, ValueError, AttributeError):
        return
    if old != claim:
        raise ValueError(f"variant {claim['variant']} is already recorded with another claim; "
                         "records are append-only")  # fmt: skip


def _artifacts(given: dict[str, str | None]) -> dict[str, str]:
    out = {k: v for k, v in given.items() if v is not None}
    if not out:
        raise ValueError("a variant names at least one of --code-tree, --prompt, --config, "
                         "--weights, --skill")  # fmt: skip
    for name, value in out.items():
        if name not in ARTIFACTS or not DIGEST_RE.fullmatch(value):
            raise ValueError(f"--{name.replace('_', '-')} must be a sha256:HEX digest")
    return out


def _eval(folder: Path, store: Path, run: str) -> dict[str, str]:
    from opentine._eval_run import VERDICTS, read_verdicts, verify_eval

    checked = verify_eval(folder)
    if not checked["ok"]:
        raise ValueError(f"eval {folder} does not verify: a justifying eval must be signed")
    if {row.get("run") for row in read_verdicts(Path(folder))} != {run}:
        raise ValueError(f"eval {folder} scores another run than the mutation run {run}")
    raw = (Path(folder) / VERDICTS).read_bytes()
    _write(store / "evals" / f"{checked['eval'][7:]}.jsonl", raw)
    return {"eval": checked["eval"], "verdicts_sha256": hashlib.sha256(raw).hexdigest()}


def _decision(path: Path, store: Path) -> tuple[dict[str, str], dict[str, Any]]:
    raw = Path(path).read_bytes()
    claim = _json_shallow.loads(raw).get("claim") or {}
    digest = hashlib.sha256(raw).hexdigest()
    _write(store / "decisions" / f"{digest}.json", raw)
    return {"sha256": digest}, claim


def _loop_open(repo_path: Path, loop: str) -> None:
    from opentine.coord import _loop_stop
    from opentine.repo import Repo

    state = _loop_stop.loop_state(Repo.open(repo_path), loop)
    if state["status"] == "stopped":
        raise ValueError(f"loop {loop} is stopped ({state.get('verification')}): no new variant")


def record(key: Any, *, run: str, artifacts: dict[str, str | None], store: Path,
           parents: list[str] = (), evals: list[Path] = (), selector: str = "",
           decision: Path | None = None, policy: str | None = None,
           loop: str | None = None, repo_path: Path | None = None,
           at: str | None = None) -> dict[str, Any]:  # fmt: skip
    """Sign and file a variant record; ``{"variant", "record", "parents", ...}``."""
    from opentine._promote import _now, _who
    from opentine.attest_signing import sign_attestation

    if not RUN_RE.fullmatch(run):
        raise ValueError("--run must be a run:sha256: oid (the mutation run)")
    found = _artifacts(artifacts)
    if len(set(parents)) != len(parents) or not all(DIGEST_RE.fullmatch(p) for p in parents):
        raise ValueError("--parent names distinct sha256:HEX variant ids")
    if policy is not None and not HEX_RE.fullmatch(policy):
        raise ValueError("--policy is the promotion policy's sha256 (64 hex)")
    if loop is not None:
        if not LOOP_RE.fullmatch(loop):
            raise ValueError(f"invalid loop id: {loop!r}")
        if repo_path is not None:
            _loop_open(Path(repo_path), loop)
    store = Path(store)
    rows = [_eval(Path(folder), store, run) for folder in evals]
    cited, claim_of = (None, {}) if decision is None else _decision(decision, store)
    if policy is None and isinstance(claim_of.get("policy_sha256"), str):
        policy = claim_of["policy_sha256"]
    ident = variant_id(found)
    if ident in parents:
        raise ValueError("a variant cannot be its own parent")
    claim = {"convention": CONVENTION, "variant": ident, "artifacts": found,
             "parents": list(parents), "mutation_run": run, "evals": rows,
             "selector": selector, "decision": cited, "policy": policy,
             "loop": loop}  # fmt: skip
    payload = {"claim": claim, "evidence_ids": [], "signer": _who(key), "target_id": run}
    signed = {**payload, "signature": sign_attestation(payload, key, algorithm="ed25519",
                                                        signed_at=at or _now())}  # fmt: skip
    path = store / "variants" / f"{ident[7:]}.json"
    _append_only(path, claim)
    _write(path, (json.dumps(signed, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return {"variant": ident, "record": path.as_posix(), "parents": list(parents),
            "evals": rows, "decision": cited}  # fmt: skip


def loads(raw: bytes | str) -> Any:
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    return _json_shallow.loads(text, object_pairs_hook=_json_shallow.unique_pairs)


def signed(payload: Any) -> bool:
    """Ed25519-signed, verifying under its embedded key, and that key is the signer."""
    from opentine._signing_pins import key_fingerprint
    from opentine.attest_signing import verify_attestation

    block = payload.get("signature") if isinstance(payload, dict) else None
    if not isinstance(block, dict) or block.get("alg") != "ed25519":
        return False
    raw = block.get("public_key")
    if not (isinstance(raw, str) and HEX_RE.fullmatch(raw)):
        return False
    if key_fingerprint(bytes.fromhex(raw)) != payload.get("signer"):
        return False
    return verify_attestation(payload, trust_embedded=True).ok


MAX_FILES = 200_000  # records + evals + decisions a lineage command will read
MAX_BYTES = 1 << 30  # 1 GiB over those files


class LineageTooLarge(ValueError):
    """The lineage folder is over the node or byte limit: refused before it is read."""


def read_folder(folder: Any, *, max_files: int = MAX_FILES,
                max_bytes: int = MAX_BYTES) -> dict[str, bytes]:  # fmt: skip
    """The lineage folder as ``{relative posix path: bytes}`` (the three subfolders only).

    The folder is listed and sized first; over *max_files* files or *max_bytes*
    bytes it raises :class:`LineageTooLarge` without reading any file.
    """
    root = Path(folder)
    found: list[tuple[str, Path]] = []
    total = 0
    for sub in ("variants", "evals", "decisions"):
        for path in sorted((root / sub).glob("*")) if (root / sub).is_dir() else []:
            if path.is_file():
                found.append((f"{sub}/{path.name}", path))
                total += path.stat().st_size
                if len(found) > max_files or total > max_bytes:
                    raise LineageTooLarge(
                        f"lineage.too-large: {root} is over {max_files} files or {max_bytes} "
                        "bytes; raise --max-files/--max-bytes to read it")  # fmt: skip
    return {name: path.read_bytes() for name, path in found}


__all__ = [
    "ARTIFACTS",
    "CONVENTION",
    "FOLDER",
    "MAX_BYTES",
    "MAX_FILES",
    "LineageTooLarge",
    "loads",
    "read_folder",
    "record",
    "signed",
    "variant_id",
]
