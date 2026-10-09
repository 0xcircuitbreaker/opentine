"""Security policy objects and explicit profiles."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from opentine._canon_redact import _field_name
from opentine._redact_extra import secret_keys

#: Field names the formats themselves use. Redacting one corrupts the run
#: (``steps``, ``parent_ids``) instead of hiding a secret, so no policy names one.
RESERVED_FIELD_NAMES = frozenset(
    (
        "billing cache causal_ids claim compatibility content cost created_at duration "
        "encoding error events evidence_ids extra_secret_keys format_version graph id inputs "
        "integrity kind legacy_refs manifest manifests metadata model model_info name order "
        "outputs parent_ids policies previous_id prompt_blob provider redact_secrets "
        "redaction refs role roots run_id schema signature signer source_run_id status steps "
        "system_blob system_prompt tags target_id timestamp tips tool_info transcript type "
        "usage user_prompt value"
    ).split()
)


@dataclass(frozen=True)
class FilesystemPolicy:
    roots: tuple[str, ...] = (".",)
    write_roots: tuple[str, ...] = ()
    deny_symlinks: bool = True
    max_file_bytes: int = 1_000_000


@dataclass(frozen=True)
class NetworkPolicy:
    allowed_schemes: tuple[str, ...] = ("https",)
    allowed_hosts: tuple[str, ...] = ()
    allow_private_hosts: bool = False
    max_body_bytes: int = 1_000_000
    timeout_seconds: float = 30.0


@dataclass(frozen=True)
class ShellPolicy:
    enabled: bool = False
    executables: tuple[str, ...] = ()
    cwd_root: str = "."
    inherit_env: bool = False
    env_allowlist: tuple[str, ...] = ()
    timeout_seconds: int = 30
    max_output_chars: int = 8_000


@dataclass(frozen=True)
class PythonPolicy:
    enabled: bool = False
    inherit_env: bool = False
    env_allowlist: tuple[str, ...] = ()
    timeout_seconds: int = 30
    max_output_chars: int = 8_000
    isolation_backend: str = "subprocess"


def _secret_key_names(names: Any) -> tuple[str, ...] | None:
    if not isinstance(names, list | tuple):
        return None
    normalized: list[str] = []
    for name in names:
        if not isinstance(name, str) or not name.strip() or len(name) > 128:
            return None
        if (field_name := _field_name(name)) in RESERVED_FIELD_NAMES:
            return None
        normalized.append(field_name)
    return tuple(normalized)


@dataclass(frozen=True)
class RedactionPolicy:
    """Redaction is always on; ``extra_secret_keys`` names more fields to redact.

    A run records the policy it ran under (``PolicySet.to_dict()`` in
    ``Run.policies``), and every writer of that run -- ``Run.save``, autosave and
    ``Repo.put_run`` -- redacts the named fields as it does ``api_key``.
    """

    redact_secrets: bool = True
    extra_secret_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        # Both used to be recorded and read by nothing: False never disabled
        # anything and the extra names were never redacted. Refuse what cannot be honoured.
        if self.redact_secrets is not True:
            raise ValueError("OpenTine always redacts credentials; redact_secrets must be True")
        if _secret_key_names(self.extra_secret_keys) is None:
            raise ValueError(
                "extra_secret_keys must be non-empty field names of at most 128 characters, "
                "none of them a field the run format itself uses"
            )


def run_redaction(policies: Any) -> AbstractContextManager[None]:
    """Redact the extra secret fields a run's recorded policy names, inside the block."""
    redaction = policies.get("redaction") if isinstance(policies, dict) else None
    names = redaction.get("extra_secret_keys") if isinstance(redaction, dict) else ()
    return secret_keys(_secret_key_names(names) or ())


@dataclass(frozen=True)
class PolicySet:
    filesystem: FilesystemPolicy = field(default_factory=FilesystemPolicy)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    shell: ShellPolicy = field(default_factory=ShellPolicy)
    python: PythonPolicy = field(default_factory=PythonPolicy)
    redaction: RedactionPolicy = field(default_factory=RedactionPolicy)
    max_output_chars: int = 8_000

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def secure_profile(root: str | Path = ".") -> PolicySet:
    return PolicySet(filesystem=FilesystemPolicy(roots=(str(root),), write_roots=()))


def dev_profile(root: str | Path = ".") -> PolicySet:
    root_s = str(root)
    return PolicySet(
        filesystem=FilesystemPolicy(roots=(root_s,), write_roots=(root_s,), deny_symlinks=False),
        network=NetworkPolicy(allowed_schemes=("http", "https"), allow_private_hosts=True),
        shell=ShellPolicy(
            enabled=True,
            executables=("git", "python", "python3", "pytest"),
            cwd_root=root_s,
        ),
        python=PythonPolicy(enabled=True),
    )


def isolated_profile(root: str | Path = ".") -> PolicySet:
    root_s = str(root)
    return PolicySet(
        filesystem=FilesystemPolicy(roots=(root_s,), write_roots=(), deny_symlinks=True),
        network=NetworkPolicy(allowed_schemes=(), allowed_hosts=()),
        shell=ShellPolicy(enabled=False, cwd_root=root_s),
        python=PythonPolicy(enabled=False, isolation_backend="external"),
        max_output_chars=4_000,
    )
