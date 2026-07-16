"""Repository-level type rules for Git-shaped references."""

import re

RUN_REF_NAMESPACES = frozenset({"experiments", "heads", "promotions"})
_REF = re.compile(r"^(?:heads|tags|experiments|promotions|remotes)/[A-Za-z0-9._/-]+$")


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


def validate_ref_target(name: str, object_type: str) -> None:
    namespace = name.removeprefix("refs/").partition("/")[0]
    if namespace in RUN_REF_NAMESPACES and object_type != "run":
        raise ValueError(f"{namespace} refs require run objects, got {object_type}")
