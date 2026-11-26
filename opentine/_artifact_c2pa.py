"""C2PA manifests for produced PNG and JPEG artifacts (0.84), via an optional extra.

Writing and validating a C2PA manifest uses the open-source ``c2pa-python``
library (``pip install 'opentine[c2pa]'``). It is never a hard dependency: without
it ``tine provenance embed --c2pa-cert`` refuses and ``tine provenance verify``
reports the manifest as ``unchecked``.

The manifest carries a ``c2pa.actions`` assertion (``c2pa.created``) and an
``org.opentine.provenance`` assertion ``{"run": RUN, "artifact_digest": DIGEST}``.
It is signed with an X.509 certificate chain the caller supplies (C2PA requires
one); trust in that chain is a C2PA matter. opentine's own trust rests on the
signed sidecar, so the validator's ``signingCredential.untrusted`` status is
reported but is not a failure. Every other validation failure is.
"""

from __future__ import annotations

import io
from typing import Any

from opentine import _artifact_trailer as trailer
from opentine import _json_shallow

LABEL = "org.opentine.provenance"
MIME = {"png": "image/png", "jpeg": "image/jpeg"}
ALGS = ("es256", "es384", "es512", "ps256", "ps384", "ps512", "ed25519")
_IGNORED = ("signingCredential.untrusted",)
SOURCE = "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
ACTION = {"action": "c2pa.created", "digitalSourceType": SOURCE}


def library() -> Any | None:
    try:
        import c2pa
    except ImportError:
        return None
    return c2pa


def present(data: bytes) -> bool:
    """Whether *data* carries a C2PA manifest store (``caBX`` chunk or ``APP11`` segment)."""
    kind = trailer.media(data)
    try:
        if kind == "png":
            return any(c == b"caBX" for c, _, _ in trailer._png_chunks(data))
        if kind == "jpeg":
            return any(m == 0xEB for m, _ in trailer._jpeg_segments(data)[0])
    except ValueError:
        return False
    return False


def sign(data: bytes, *, run: str, artifact_digest: str, title: str, cert_chain: bytes,
         private_key: bytes, alg: str = "es256") -> bytes:  # fmt: skip
    """*data* with a signed C2PA manifest; ``RuntimeError`` without the extra."""
    c2pa = library()
    if c2pa is None:
        raise RuntimeError("C2PA needs the optional extra: pip install 'opentine[c2pa]'")
    kind = trailer.media(data)
    if kind not in MIME:
        raise ValueError("C2PA manifests are written for PNG and JPEG artifacts only")
    if alg not in ALGS:
        raise ValueError(f"unknown C2PA signing algorithm {alg!r}; one of {', '.join(ALGS)}")
    from opentine import __version__

    manifest = {
        "claim_generator_info": [{"name": "opentine", "version": __version__}],
        "title": title,
        "assertions": [
            {"label": "c2pa.actions", "data": {"actions": [ACTION]}},
            {"label": LABEL, "data": {"run": run, "artifact_digest": artifact_digest}},
        ],
    }
    info = c2pa.C2paSignerInfo(alg.encode("ascii"), cert_chain, private_key, None)
    out = io.BytesIO()
    try:
        signer = c2pa.Signer.from_info(info)
        c2pa.Builder(manifest).sign(signer, MIME[kind], io.BytesIO(data), out)
    except Exception as exc:  # noqa: BLE001 - the library's errors are its own types
        raise ValueError(f"C2PA signing failed: {exc}") from exc
    return out.getvalue()


def check(data: bytes) -> dict[str, Any]:
    """``{"state", "run", "artifact_digest", "failures"}`` for the active manifest.

    ``state`` is ``absent``, ``unchecked`` (no extra installed), ``valid`` or
    ``invalid``.
    """
    empty = {"run": None, "artifact_digest": None, "failures": []}
    if not present(data):
        return {"state": "absent", **empty}
    c2pa = library()
    if c2pa is None:
        return {"state": "unchecked", **empty}
    try:
        reader = c2pa.Reader(MIME[trailer.media(data)], io.BytesIO(data))
        report = _json_shallow.loads(reader.json())
    except Exception as exc:  # noqa: BLE001 - the library's errors are its own types
        return {"state": "invalid", **empty, "failures": [f"c2pa: {exc}"]}
    active = (report.get("manifests") or {}).get(report.get("active_manifest") or "") or {}
    found = next((a.get("data") for a in active.get("assertions") or []
                  if isinstance(a, dict) and a.get("label") == LABEL), None)  # fmt: skip
    found = found if isinstance(found, dict) else {}
    results = (report.get("validation_results") or {}).get("activeManifest") or {}
    failures = sorted({str(f.get("code")) for f in results.get("failure") or []
                       if isinstance(f, dict) and f.get("code") not in _IGNORED})  # fmt: skip
    if not active:
        failures.append("c2pa: no active manifest")
    return {"state": "invalid" if failures else "valid", "run": found.get("run"),
            "artifact_digest": found.get("artifact_digest"), "failures": failures}  # fmt: skip


__all__ = ["ALGS", "LABEL", "check", "library", "present", "sign"]
