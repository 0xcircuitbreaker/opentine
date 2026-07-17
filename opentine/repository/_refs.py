"""Repository-level type rules for Git-shaped references."""

import re

from opentine.kernel import parse_oid

TYPED_REF_NAMESPACES = {
    "annotations": "annotation",
    "experiments": "run",
    "heads": "run",
    "promotions": "run",
}
_REF = re.compile(r"^(?:annotations|heads|tags|experiments|promotions|remotes)/[A-Za-z0-9._/-]+$")


def normalize_ref(name: str) -> str:
    normalized = name.removeprefix("refs/")
    parts = normalized.split("/")
    if (
        len(normalized) > 512
        or not _REF.fullmatch(normalized)
        or any(part in {"", ".", ".."} or part.endswith(".lock") for part in parts)
    ):
        raise ValueError(f"invalid ref name: {name!r}")
    return normalized


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
