"""Repository-level type rules for Git-shaped references."""

import re

from opentine.kernel import parse_oid

TYPED_REF_NAMESPACES = {
    "annotations": "annotation",
    "experiments": "run",
    "heads": "run",
    "promotions": "run",
}
_REF = re.compile(r"^(?:annotations|heads|tags|experiments|promotions|remotes)/[a-z0-9._/-]+$")
_WINDOWS_NAMES = {"con", "prn", "aux", "nul"} | {
    f"{prefix}{number}" for prefix in ("com", "lpt") for number in range(1, 10)
}
MAX_REF_COMPONENT_BYTES = 240


def normalize_ref(name: str) -> str:
    if not isinstance(name, str):
        raise ValueError(f"invalid ref name: {name!r}")
    normalized = name.removeprefix("refs/")
    parts = normalized.split("/")
    if (
        not _REF.fullmatch(normalized)
        or len(normalized.encode("utf-8")) > 512
        or normalized != normalized.casefold()
        or any(
            part in {"", ".", ".."}
            or ".." in part
            or part.casefold().endswith(".lock")
            or part.endswith((".", " "))
            or part.split(".", 1)[0].casefold() in _WINDOWS_NAMES
            or len(part.encode("utf-8")) > MAX_REF_COMPONENT_BYTES
            for part in parts
        )
    ):
        raise ValueError(f"invalid ref name: {name!r}")
    return normalized


def validate_ref_oid(name: str, oid: str) -> None:
    """Reject an impossible typed ref target before touching object storage."""
    object_type, _ = parse_oid(oid)
    namespace = name.removeprefix("refs/").partition("/")[0]
    expected = TYPED_REF_NAMESPACES.get(namespace)
    if expected and object_type != expected:
        raise ValueError(f"{namespace} refs require {expected} objects, got {object_type}")


def validate_ref_target(name: str, object_type: str, payload: object | None = None) -> None:
    namespace = name.removeprefix("refs/").partition("/")[0]
    expected = TYPED_REF_NAMESPACES.get(namespace)
    if expected and object_type != expected:
        raise ValueError(f"{namespace} refs require {expected} objects, got {object_type}")
    if namespace == "annotations":
        if not isinstance(payload, dict) or not isinstance(payload.get("target_id"), str):
            raise ValueError("annotation refs require a run-targeted annotation")
        target_type, target_digest = parse_oid(payload["target_id"])
        suffix = name.removeprefix("refs/").partition("/")[2]
        if target_type != "run" or suffix != target_digest:
            raise ValueError("annotation ref name must match its target run")
