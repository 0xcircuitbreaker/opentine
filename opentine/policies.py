"""Security policy objects and explicit profiles."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


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


@dataclass(frozen=True)
class RedactionPolicy:
    redact_secrets: bool = True
    extra_secret_keys: tuple[str, ...] = ()


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
