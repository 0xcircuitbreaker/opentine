"""``tine lineage diff``: a signed structural diff between two variants (0.88).

Two scaffold trees (a directory or one file each) are compared file by file. A
file whose bytes are equal is unchanged; every other file is listed with both
digests and a structural reading by kind:

``python``  AST symbols (:mod:`opentine._sdiff_py`), tokens when it does not parse;
``prompt``  Markdown/text sections by heading (:mod:`opentine._sdiff_text`);
``tools``   a tool set by name and ``tool_def_digest`` (:mod:`opentine._sdiff_config`);
``config``  JSON/TOML/YAML leaves by path; a repeated key refuses the whole diff;
``text``    any other UTF-8 file, by tokens;
``binary``  digests only.

``structural`` is false when the bytes changed but the structure did not; the
file is still listed, with the hidden-edit ``flags`` that explain the change.
With a key the result is signed as an existing ``attestation`` payload whose
claim follows the ``opentine.lineage.diff`` convention (docs/LINEAGE.md); its
``target_id`` is the newer variant id when one is named, else the newer tree's
digest. :func:`check` re-verifies such a file and, given the trees, recomputes it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from opentine import _sdiff_config as cfg
from opentine import _sdiff_py, _sdiff_text
from opentine.kernel import canonical_json

CONVENTION = "opentine.lineage.diff"
TREE_DOMAIN = b"opentine.lineage.diff.tree.v1:"
MAX_FILES = 20_000
MAX_BYTES = 256 << 20
PROMPT_SUFFIXES = (".md", ".markdown", ".mdc", ".txt", ".prompt")


class DiffRefused(ValueError):
    """``lineage-diff.*``: the diff cannot be computed or checked."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code


def listing(root: Path) -> dict[str, bytes]:
    """``{posix path: bytes}`` of every regular file under *root* (or *root* itself).

    Symbolic links are listed by their target text, never followed.
    """
    root = Path(root)
    if root.is_file() and not root.is_symlink():
        return {root.name: root.read_bytes()}
    if not root.is_dir():
        raise DiffRefused("lineage-diff.unreadable", f"{root} is not a file or directory")
    out: dict[str, bytes] = {}
    total = 0
    stack = [root]
    while stack:
        here = stack.pop()
        for path in sorted(here.iterdir()):
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                data = b"symlink:" + str(path.readlink().as_posix()).encode("utf-8")
            elif path.is_dir():  # no folder is skipped: a cache or VCS folder can hold scaffold
                stack.append(path)
                continue
            elif path.is_file():
                data = path.read_bytes()
            else:
                continue
            out[rel] = data
            total += len(data)
            if len(out) > MAX_FILES or total > MAX_BYTES:
                why = f"{root} is over {MAX_FILES} files or {MAX_BYTES} bytes"
                raise DiffRefused("lineage-diff.too-large", why)
    return dict(sorted(out.items()))


def tree_digest(files: dict[str, bytes]) -> str:
    rows = {path: hashlib.sha256(data).hexdigest() for path, data in files.items()}
    return "sha256:" + hashlib.sha256(TREE_DOMAIN + canonical_json(rows)).hexdigest()


def kind(path: str, data: bytes) -> str:
    suffix = PurePosixPath(path).suffix.lower()
    if data.startswith(b"symlink:") or _sdiff_text.decode(data) is None:
        return "binary"
    if suffix in (".py", ".pyi"):
        return "python"
    if suffix in cfg.CONFIG_SUFFIXES:
        return "config"
    if suffix in PROMPT_SUFFIXES or "prompt" in PurePosixPath(path).name.lower():
        return "prompt"
    return "text"


def _config(path: str, before: str, after: str) -> dict[str, Any]:
    suffix = PurePosixPath(path).suffix.lower()
    try:
        old, new = cfg.parse(suffix, before), cfg.parse(suffix, after)
    except cfg.DuplicateKey as exc:
        raise DiffRefused("lineage-diff.duplicate-key", f"{path}: {exc}") from None
    except cfg.Unreadable as exc:
        return {"kind": "config", "note": str(exc), **_text("config", before, after)}
    old_tools, new_tools = cfg.tools(old), cfg.tools(new)
    if old_tools is not None and new_tools is not None:
        changes = cfg.tool_diff(old_tools, new_tools)
        return {"kind": "tools", "structural": bool(changes), "changes": changes}
    changes = cfg.config_diff(old, new)
    return {"kind": "config", "structural": bool(changes), "changes": changes}


def _text(name: str, before: str, after: str) -> dict[str, Any]:
    row = _sdiff_text.token_diff(before, after)
    return {"kind": name, "structural": row.pop("structural"), "changes": row.pop("hunks"), **row}


def file_row(path: str, before: bytes | None, after: bytes | None) -> dict[str, Any]:
    head = {"path": path, "before": None if before is None else _sdiff_text.sha(before),
            "after": None if after is None else _sdiff_text.sha(after)}  # fmt: skip
    if before is None or after is None:
        data = after if before is None else before
        status = "added" if before is None else "removed"
        return {**head, "status": status, "kind": kind(path, data), "structural": True,
                "changes": [], "flags": []}  # fmt: skip
    kinds = {kind(path, before), kind(path, after)}
    old, new = _sdiff_text.decode(before), _sdiff_text.decode(after)
    if "binary" in kinds or old is None or new is None:
        return {**head, "status": "changed", "kind": "binary", "structural": True,
                "changes": [], "flags": []}  # fmt: skip
    name = kinds.pop() if len(kinds) == 1 else "text"
    if name == "python":
        row = _sdiff_py.diff(old, new)
        fallback = {**_text("python", old, new), "note": "does not parse: token diff"}
        body = {"kind": "python", **row} if row is not None else fallback
    elif name == "config":
        body = _config(path, old, new)
    elif name == "prompt":
        changes = _sdiff_text.section_diff(old, new)
        body = {"kind": "prompt", "structural": bool(changes), "changes": changes}
    else:
        body = _text("text", old, new)
    return {**head, "status": "changed", **body, "flags": _sdiff_text.flags(old, new)}


def _side(files: dict[str, bytes], variant: str | None, artifacts: dict | None) -> dict:
    tree = tree_digest(files)
    bound = None if artifacts is None else tree in artifacts.values()
    return {"tree": tree, "variant": variant, "bound": bound}


def compute(old_root: Path, new_root: Path, *, from_variant: str | None = None,
            to_variant: str | None = None, from_artifacts: dict | None = None,
            to_artifacts: dict | None = None) -> dict[str, Any]:  # fmt: skip
    """The ``opentine.lineage.diff`` claim of *old_root* -> *new_root*.

    ``bound`` says whether a named variant's recorded artifacts include the tree's
    digest (``None`` when no variant is named)."""
    old, new = listing(Path(old_root)), listing(Path(new_root))
    rows = [file_row(p, old.get(p), new.get(p)) for p in sorted(set(old) | set(new))
            if old.get(p) != new.get(p)]  # fmt: skip
    totals = {"files": len(set(old) | set(new)), "changed": len(rows),
              "structural": sum(1 for r in rows if r["structural"]),
              "flagged": sum(1 for r in rows if r["flags"])}  # fmt: skip
    return {"convention": CONVENTION,
            "from": _side(old, from_variant, from_artifacts),
            "to": _side(new, to_variant, to_artifacts),
            "totals": totals, "files": rows}  # fmt: skip


def sign(claim: dict[str, Any], key: Any, *, at: str) -> dict[str, Any]:
    from opentine._promote import _who
    from opentine.attest_signing import sign_attestation

    target = claim["to"]["variant"] or claim["to"]["tree"]
    payload = {"claim": claim, "evidence_ids": [], "signer": _who(key), "target_id": target}
    return {**payload, "signature": sign_attestation(payload, key, algorithm="ed25519",
                                                      signed_at=at)}  # fmt: skip


def dumps(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def check(path: Path, old_root: Path | None = None, new_root: Path | None = None, *,
          from_artifacts: dict | None = None,
          to_artifacts: dict | None = None) -> dict[str, Any]:  # fmt: skip
    """Re-verify a signed diff file; recompute it when both trees are given.

    ``bound`` is recomputed from the named variants' recorded artifacts; a signed
    ``bound`` that cannot be recomputed (no artifacts given) must be ``None``."""
    from opentine._lineage import loads, signed

    try:
        doc = loads(Path(path).read_bytes())
    except (OSError, ValueError, RecursionError) as exc:
        raise DiffRefused("lineage-diff.unreadable", f"{path}: {exc}") from None
    claim = doc.get("claim") if isinstance(doc, dict) else None
    if not isinstance(claim, dict) or claim.get("convention") != CONVENTION:
        raise DiffRefused("lineage-diff.unreadable", f"{path} is not a {CONVENTION} claim")
    target = (claim.get("to") or {}).get("variant") or (claim.get("to") or {}).get("tree")
    findings = []
    if not signed(doc) or doc.get("target_id") != target:
        findings.append(
            {
                "code": "lineage-diff.bad-signature",
                "detail": "not Ed25519-signed by its signer, or another target",
            }
        )
    if old_root is not None and new_root is not None:
        again = compute(old_root, new_root, from_variant=claim["from"].get("variant"),
                        to_variant=claim["to"].get("variant"), from_artifacts=from_artifacts,
                        to_artifacts=to_artifacts)  # fmt: skip
        if canonical_json(again) != canonical_json(claim):
            findings.append(
                {"code": "lineage-diff.mismatch", "detail": "the trees do not give the signed diff"}
            )
    return {"ok": not findings, "signer": doc.get("signer"), "target": target,
            "findings": findings, "totals": claim.get("totals")}  # fmt: skip


__all__ = ["CONVENTION", "DiffRefused", "check", "compute", "dumps", "file_row", "listing",
           "sign", "tree_digest"]  # fmt: skip
