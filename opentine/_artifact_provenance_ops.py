"""``tine provenance embed`` and ``verify`` (0.84): pointer, C2PA, sidecar, findings.

:func:`embed` checks that the run exists and verifies, writes the pointer the
format allows (:mod:`opentine._artifact_trailer`), optionally a C2PA manifest
(:mod:`opentine._artifact_c2pa`), then the signed sidecar
(:mod:`opentine._artifact_provenance`) and its held record.

:func:`verify` returns findings, each ``{"code", "message"}``; none means the
artifact verifies. The codes are command-level (docs/PROVENANCE.md):

``artifact.sidecar-missing`` / ``artifact.sidecar-invalid``, ``artifact.bad-signature``,
``artifact.signer-unverified``, ``artifact.digest-mismatch`` (modified),
``artifact.pointer-stripped``, ``artifact.pointer-repointed``, ``artifact.run-missing``,
``artifact.c2pa-invalid``, ``artifact.c2pa-stripped``, ``artifact.dataset-version-unknown``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from opentine import _artifact_c2pa as c2pa
from opentine import _artifact_provenance as ap
from opentine import _artifact_trailer as trailer

MAX_ARTIFACT = 512 * 1024 * 1024


def read_capped(path: Path, cap: int) -> bytes:
    with open(path, "rb") as handle:
        data = handle.read(cap + 1)
    if len(data) > cap:
        raise ValueError(f"{path.as_posix()} is larger than {cap} bytes")
    return data


def sidecar_path(artifact: Path, sidecar: str | None = None) -> Path:
    return Path(sidecar) if sidecar else artifact.with_name(artifact.name + ap.SUFFIX)


def run_problem(repo: Any, run: str) -> str | None:
    """Why *run* does not exist and verify in *repo* (``None``: it does)."""
    try:
        obj = repo.get(run)
        if obj.object_type != "run" or obj.oid != run:
            return f"{run} is not a run object"
        repo.load_run(run)
    except Exception as exc:  # noqa: BLE001 - any failure to read it back is a failure
        return f"{run} does not exist or does not verify here ({exc})"
    return None


def _dataset_known(repo: Any, oid: str) -> bool:
    from opentine._dataset_version import versions

    try:
        return any(row.get("record") == oid for row in versions(repo))
    except Exception:  # noqa: BLE001 - an unreadable registry knows nothing (fail closed)
        return False


def embed(repo: Any, artifact: Path, *, run: str, key: Any, subject: str = "artifact",
          pointer: bool = True, dataset_version: str | None = None,
          c2pa_signing: dict[str, Any] | None = None,
          sidecar: str | None = None) -> dict[str, Any]:  # fmt: skip
    """Embed the pointer (and C2PA), write the signed sidecar; a summary dict."""
    problem = run_problem(repo, run)
    if problem:
        raise ValueError(problem)
    if dataset_version is not None and not _dataset_known(repo, dataset_version):
        raise ValueError(f"{dataset_version} is not a held dataset version in this repository")
    data = read_capped(artifact, MAX_ARTIFACT)
    canonical, _ = trailer.split(data)
    digest = trailer.digest(canonical)
    slot = None
    if pointer:
        try:
            data, slot = trailer.embed(canonical, run)
        except trailer.PointerUnsupported:
            data, slot = canonical, None
    if c2pa_signing is not None:
        data = c2pa.sign(data, run=run, artifact_digest=digest, title=artifact.name,
                         **c2pa_signing)  # fmt: skip
    if trailer.digest(data) != digest:
        raise ValueError("embedding changed the canonical bytes; refusing to write")
    doc = ap.make(key, subject=subject, run=run, pointer=slot, c2pa=trailer.stores(data),
                  dataset_version=dataset_version,
                  artifact={"name": artifact.name, "media": trailer.media(canonical),
                            "digest": digest, "size": len(canonical)})  # fmt: skip
    oid = ap.record(repo, doc, key)
    if data != read_capped(artifact, MAX_ARTIFACT):
        artifact.write_bytes(data)
    out = sidecar_path(artifact, sidecar)
    from opentine.kernel import canonical_json

    out.write_bytes(canonical_json(doc) + b"\n")
    return {"artifact": artifact.as_posix(), "sidecar": out.as_posix(), "record": oid,
            "digest": digest, "run": run, "pointer": slot, "c2pa": doc["c2pa"] is not None,
            "subject": subject, "signer": doc["signer"]}  # fmt: skip


def _finding(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def _load(path: Path) -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    from opentine import _json_shallow

    try:
        doc = _json_shallow.loads(read_capped(path, ap.MAX_SIDECAR))
    except FileNotFoundError:
        return None, [_finding("artifact.sidecar-missing", f"no sidecar at {path.as_posix()}")]
    except (OSError, ValueError) as exc:
        return None, [_finding("artifact.sidecar-invalid", str(exc))]
    try:
        ap.body(doc)
    except ap.SidecarInvalid as exc:
        return None, [_finding("artifact.sidecar-invalid", str(exc))]
    return doc, []


def _pointer_findings(doc: dict[str, Any], found: list[str]) -> list[dict[str, str]]:
    other = sorted({t for t in found if t != doc["run"]})
    if other:
        why = f"the embedded pointer names {', '.join(other)}, not {doc['run']}"
        return [_finding("artifact.pointer-repointed", why)]
    if doc["pointer"] and not found:
        why = f"the sidecar records a {doc['pointer']} pointer; the file has none"
        return [_finding("artifact.pointer-stripped", why)]
    return []


def _c2pa_findings(doc: dict[str, Any], data: bytes) -> tuple[str, list[dict[str, str]]]:
    report = c2pa.check(data)
    state, bound = report["state"], trailer.stores(data)
    if state != "absent" and bound != doc["c2pa"]:
        why = "the file's C2PA store bytes are not the ones the sidecar signs"
        return "invalid", [_finding("artifact.c2pa-invalid", why)]
    if state == "absent":
        bad = [_finding("artifact.c2pa-stripped", "the sidecar records a C2PA manifest; "
                        "the file has none")] if doc["c2pa"] else []  # fmt: skip
        return state, bad
    if state == "invalid":
        return state, [_finding("artifact.c2pa-invalid", "; ".join(report["failures"]))]
    named = (report["run"], report["artifact_digest"])
    if state == "valid" and named != (doc["run"], doc["artifact"]["digest"]):
        return "invalid", [_finding("artifact.c2pa-invalid",
                                    "the C2PA manifest names another run or digest")]  # fmt: skip
    return state, []


def verify(repo: Any, artifact: Path, *, sidecar: str | None = None) -> dict[str, Any]:
    """``{"ok", "artifact", "sidecar", "digest", "run", "signer", "verification",
    "pointer", "c2pa", "held", "findings"}``."""
    from opentine import _containment_records as records

    path = sidecar_path(artifact, sidecar)
    out: dict[str, Any] = {"artifact": artifact.as_posix(), "sidecar": path.as_posix(),
                           "digest": None, "run": None, "signer": None, "verification": None,
                           "pointer": None, "c2pa": None, "held": False}  # fmt: skip
    doc, findings = _load(path)
    try:
        data = read_capped(artifact, MAX_ARTIFACT)
        canonical, found = trailer.split(data)
        actual = trailer.digest(canonical)
    except (OSError, ValueError) as exc:
        data, found, actual = None, [], None
        findings.append(_finding("artifact.digest-mismatch", f"artifact unreadable: {exc}"))
    out["digest"] = actual
    if doc is None:
        return {**out, "ok": False, "findings": findings}
    out.update(run=doc["run"], signer=doc["signer"], pointer=doc["pointer"])
    signed, why = ap.signature_ok(doc)
    if not signed:
        findings.append(_finding("artifact.bad-signature", why))
    state = records.role_state(repo, doc["signer"], "runner") if signed else f"unverified: {why}"
    out["verification"] = state
    if signed and state != "verified":
        findings.append(_finding("artifact.signer-unverified", state))
    if actual is not None and actual != doc["artifact"]["digest"]:
        findings.append(_finding("artifact.digest-mismatch",
                                 f"the artifact is {actual}; the sidecar signs "
                                 f"{doc['artifact']['digest']}"))  # fmt: skip
    if data is not None:
        findings += _pointer_findings(doc, found)
        out["c2pa"], bad = _c2pa_findings(doc, data)
        findings += bad
    problem = run_problem(repo, doc["run"])
    if problem:
        findings.append(_finding("artifact.run-missing", problem))
    if doc["dataset_version"] and not _dataset_known(repo, doc["dataset_version"]):
        why = f"{doc['dataset_version']} is not a held dataset version"
        findings.append(_finding("artifact.dataset-version-unknown", why))
    out["held"] = any(r["claim"].get("run") == doc["run"] and r["signer"] == doc["signer"]
                      for r in ap.held(repo, doc["artifact"]["digest"]))  # fmt: skip
    return {**out, "ok": not findings, "findings": findings}


__all__ = ["MAX_ARTIFACT", "embed", "run_problem", "sidecar_path", "verify"]
