"""SPEC 4.16 project manifests, 4.17 mirror states and 4.18 the git object check (0.46.1).

Manifests are signed with the published Ed25519 seeds in ``keys`` (deterministic,
and every record fixes ``signed_at`` and ``created_at``), so the input bytes are
stable. ``ed25519_seed`` is the project owner, ``ed25519_seed_b`` a stranger and
``ed25519_seed_c`` the host service key. Only the ops in ``adapter_project``
produce an answer.
"""

from __future__ import annotations

import base64
import copy
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _mirror_state, _project
from opentine._signed_record import sign as raw_sign
from tests.conformance.cases import ACCEPT, REJECT, Case, Family, V
from tests.conformance.keys import KEYS

VERIFIER = "verifier"
WHEN = "2026-11-08T00:00:00Z"


def _key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(KEYS[name])


def _hex(name: str) -> str:
    return _key(name).public_key().public_bytes_raw().hex()


OWNER, STRANGER, HOST = _hex("ed25519_seed"), _hex("ed25519_seed_b"), _hex("ed25519_seed_c")


def _edited(record: dict, **fields) -> dict:
    out = copy.deepcopy(record)
    out.update(fields)
    return out


def _slot(**fields) -> dict:
    return {"role": "primary", "forge": "github", "forge_repo_id": "R_kgDOExample",
            "upstream_visibility": "public",
            "locator": {"url": "https://github.com/example/app.git"},
            "default_branch": "main", **fields}  # fmt: skip


_COMMITTED = {"commitment": _project.commitment("https://github.com/example/secret.git", b"s" * 32)}
_PRIVATE_SLOT = _slot(upstream_visibility="private", locator=_COMMITTED)


def _manifest(previous=None, **fields) -> dict:
    record = {"kind": _project.KIND, "project_version": 1, "project_id": "app", "tenant": "acme",
              "seq": 0 if previous is None else previous["seq"] + 1,
              "prev": None if previous is None else _project.digest(previous),
              "visibility": "public", "owners": [OWNER], "slots": [_slot()],
              "forked_from": None, "created_at": WHEN, **fields}  # fmt: skip
    return record


def _signed(record: dict, key: str = "ed25519_seed") -> dict:
    """Sign without the field rules, so a refused body still carries a good signature."""
    return raw_sign(record, _project.DOMAIN, "project manifest", _key(key), algorithm="ed25519",
                    key_id="vector", signed_at=WHEN)  # fmt: skip


_V0 = _signed(_manifest())
_V1 = _signed(_manifest(_V0, owners=[OWNER, STRANGER]))
_V2 = _signed(_manifest(_V1), "ed25519_seed_b")  # by an owner the previous version added
_PRIV = _signed(_manifest(visibility="private", slots=[_PRIVATE_SLOT]))
_TWO = _signed(
    _manifest(
        slots=[
            _slot(),
            _slot(
                role="secondary",
                forge="git",
                forge_repo_id=None,
                locator={"url": "ssh://git.example.org/app.git"},
            ),
        ]
    )
)


def _p(name, expect, intent, record, reason=None, *, previous=None, owner=None) -> Case:
    value = {"manifest": record, "previous": previous, "owner_key": owner}
    return Case(id=f"project.{name}", section="4.16", checklist=(8,), op="project.verify",
                profile=VERIFIER, expect=expect, intent=intent, input=V(value),
                reason=reason)  # fmt: skip


def _c(name, expect, intent, versions, reason=None) -> Case:
    return Case(id=f"project.chain.{name}", section="4.16", checklist=(8,), op="project.chain",
                profile=VERIFIER, expect=expect, intent=intent,
                input=V({"versions": versions, "owner_key": None}), reason=reason)  # fmt: skip


PROJECT = Family(
    "65-project.json",
    "4.16",
    "project",
    (
        _p("valid-genesis", ACCEPT, "a first version signed by its own owner (trust on first use)",
           _V0),
        _p("valid-genesis-pinned", ACCEPT, "a first version under the pinned owner key", _V0,
           owner=OWNER),
        _p("valid-next", ACCEPT, "a version that links its predecessor, signed by its owner",
           _V1, previous=_V0),
        _p("valid-added-owner", ACCEPT, "an owner the previous version added may sign the next",
           _V2, previous=_V1),
        _p("valid-private-commitment", ACCEPT,
           "a private project names its upstream by a salted commitment", _PRIV),
        _p("valid-secondary-slot", ACCEPT, "a primary slot and a plain-git secondary slot", _TWO),
        _p("chain-break-prev", REJECT, "prev names something other than the predecessor",
           _signed(_manifest(_V0, prev="blob:sha256:" + "9" * 64)), "project.chain-break",
           previous=_V0),
        _p("chain-break-seq", REJECT, "seq skips a version",
           _signed(_manifest(_V0, seq=2)), "project.chain-break", previous=_V0),
        _p("chain-break-project", REJECT, "a version cannot move to another project",
           _signed(_manifest(_V0, project_id="other")), "project.chain-break", previous=_V0),
        _p("wrong-signer", REJECT, "signed by a key outside the previous version's owners",
           _signed(_manifest(_V0), "ed25519_seed_b"), "project.wrong-signer", previous=_V0),
        _p("wrong-signer-self-added", REJECT,
           "a stranger cannot add itself and sign that same version",
           _signed(_manifest(_V0, owners=[OWNER, STRANGER]), "ed25519_seed_b"),
           "project.wrong-signer", previous=_V0),
        _p("wrong-signer-genesis", REJECT, "a first version signed by a key it does not list",
           _signed(_manifest(), "ed25519_seed_b"), "project.wrong-signer"),
        _p("wrong-pinned-owner", REJECT, "a first version under another pinned owner key", _V0,
           "project.wrong-signer", owner=STRANGER),
        _p("public-over-private", REJECT, "a public project may not reference a private upstream",
           _signed(_manifest(slots=[_slot(upstream_visibility="private")])),
           "project.private-upstream"),
        _p("private-plaintext-url", REJECT, "a private project must not hold a plaintext URL",
           _signed(_manifest(visibility="private", slots=[_slot(upstream_visibility="private")])),
           "project.plaintext-locator"),
        _p("public-commitment", REJECT, "a public project names its upstream by url",
           _signed(_manifest(slots=[_slot(locator=_COMMITTED)])), "project.malformed"),
        _p("bad-commitment", REJECT, "a commitment is sha256:<64 hex>",
           _signed(_manifest(visibility="private",
                             slots=[_slot(upstream_visibility="private",
                                          locator={"commitment": "sha256:abc"})])),
           "project.malformed"),
        _p("credentials-in-url", REJECT, "a clone URL never carries credentials",
           _signed(_manifest(slots=[_slot(locator={"url": "https://u:p@github.com/a/b.git"})])),
           "project.malformed"),
        _p("unknown-forge", REJECT, "forge is one of the five known forges",
           _signed(_manifest(slots=[_slot(forge="svn")])), "project.malformed"),
        _p("git-with-repo-id", REJECT, "a plain git forge has no forge_repo_id",
           _signed(_manifest(slots=[_slot(forge="git")])), "project.malformed"),
        _p("two-primaries", REJECT, "one primary slot, at most one secondary",
           _signed(_manifest(slots=[_slot(), _slot()])), "project.malformed"),
        _p("genesis-with-prev", REJECT, "seq 0 has no predecessor",
           _signed(_manifest(prev="blob:sha256:" + "1" * 64)), "project.malformed"),
        _p("extra-field", REJECT, "a field the manifest format does not define",
           _edited(_V0, homepage="https://example.com"), "project.malformed"),
        _p("unsigned", REJECT, "a manifest without a signature is refused", _manifest(),
           "project.unsigned"),
        _p("tampered", REJECT, "a manifest edited after signing fails",
           _edited(_V0, owners=[STRANGER]), "project.bad-signature"),
        _c("valid", ACCEPT, "three versions, oldest first", [_V0, _V1, _V2]),
        _c("truncated", REJECT, "a history must start at its first version", [_V1, _V2],
           "project.chain-break"),
        _c("reordered", REJECT, "versions out of order break the chain", [_V0, _V2, _V1],
           "project.chain-break"),
    ),
)  # fmt: skip


# --- 4.17 mirror states, 4.18 git objects ----------------------------------- #

_TIP = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def _state(**fields) -> dict:
    return {"kind": _mirror_state.KIND, "mirror_state_version": 1, "tenant": "acme",
            "project_id": "app", "manifest": _project.digest(_V0), "slot": "primary",
            "object_format": "sha1", "refs": {"refs/heads/main": _TIP, "refs/tags/v1": "a" * 40},
            "synced_at": WHEN, "status": "synced", "reasons": [], **fields}  # fmt: skip


def _host(record: dict, key: str = "ed25519_seed_c") -> dict:
    return raw_sign(record, _mirror_state.DOMAIN, "mirror state", _key(key), algorithm="ed25519",
                    key_id="host", signed_at=WHEN)  # fmt: skip


def _m(name, expect, intent, record, reason=None, *, host=HOST, owners=(OWNER,)) -> Case:
    value = {"state": record, "host_key": host, "owners": list(owners)}
    return Case(id=f"mirror-state.{name}", section="4.17", checklist=(8,),
                op="mirror-state.verify", profile=VERIFIER, expect=expect, intent=intent,
                input=V(value), reason=reason)  # fmt: skip


def _git_bytes(kind: str, fmt: str) -> tuple[bytes, str]:
    width = 20 if fmt == "sha1" else 32
    blob = b"hello\n"
    blob_id = hashlib.new(fmt, b"blob 6\0" + blob).hexdigest()
    tree = b"100644 a.txt\0" + bytes.fromhex(blob_id)[:width]
    tree_id = hashlib.new(fmt, b"tree %d\0" % len(tree) + tree).hexdigest()
    commit = (f"tree {tree_id}\nauthor t <t@example.com> 0 +0000\n"
              f"committer t <t@example.com> 0 +0000\n\nfirst\n").encode()  # fmt: skip
    data = {"blob": blob, "tree": tree, "commit": commit}[kind]
    return data, hashlib.new(fmt, f"{kind} {len(data)}".encode() + b"\0" + data).hexdigest()


def _g(name, expect, intent, kind, data: bytes, oid, reason=None) -> Case:
    value = {"type": kind, "data_b64": base64.b64encode(data).decode("ascii"), "oid": oid}
    return Case(id=f"git-object.{name}", section="4.18", checklist=(8,), op="git-object.check",
                profile=VERIFIER, expect=expect, intent=intent, input=V(value),
                reason=reason)  # fmt: skip


_GOOD = _host(_state())
_STALE = _host(_state(status="stale", reasons=["mirror.stale", "mirror.upstream-unverifiable"]))
_FAILED = _host(_state(status="failed", refs={}, reasons=["mirror.upstream-unreachable"]))
_PAUSED = _host(_state(status="paused", reasons=["mirror.limit-exceeded"]))
_SHA256 = _host(_state(object_format="sha256", refs={"refs/heads/main": "b" * 64}))
_BLOB1, _BLOB1_ID = _git_bytes("blob", "sha1")
_TREE1, _TREE1_ID = _git_bytes("tree", "sha1")
_COMMIT1, _COMMIT1_ID = _git_bytes("commit", "sha1")
_TREE2, _TREE2_ID = _git_bytes("tree", "sha256")
_COMMIT2, _COMMIT2_ID = _git_bytes("commit", "sha256")

MIRROR = Family(
    "66-mirror-state.json",
    "4.17",
    "mirror-state",
    (
        _m("host-statement", ACCEPT, "a synced state under the pinned host key: never a pass",
           _GOOD),
        _m("host-statement-tofu", ACCEPT, "with no host key it rests on its embedded key", _GOOD,
           host=None),
        _m("stale", ACCEPT, "a stale mirror says so with mirror.stale", _STALE),
        _m("failed", ACCEPT, "a failed sync names why the upstream is unavailable", _FAILED),
        _m("paused", ACCEPT, "a mirror over its limit stops advancing", _PAUSED),
        _m("sha256-refs", ACCEPT, "a sha256 upstream records 64-hex commit ids", _SHA256),
        _m("user-signed", REJECT, "a project owner's key never signs a host statement",
           _host(_state(), "ed25519_seed"), "mirror-state.user-signed", host=None),
        _m("wrong-host-key", REJECT, "signed by a key other than the pinned host key",
           _host(_state(), "ed25519_seed_b"), "mirror-state.wrong-key"),
        _m("tampered-ref", REJECT, "a ref moved after signing",
           _edited(_GOOD, refs={"refs/heads/main": "c" * 40}), "mirror-state.bad-signature"),
        _m("unsigned", REJECT, "a state without a signature is refused", _state(),
           "mirror-state.unsigned"),
        _m("unknown-reason", REJECT, "only the seven mirror.* codes",
           _host(_state(status="stale", reasons=["mirror.stale", "pass"])),
           "mirror-state.unknown-reason"),
        _m("synced-but-unreachable", REJECT, "synced contradicts an unavailable upstream",
           _host(_state(reasons=["mirror.upstream-unreachable"])), "mirror-state.inconsistent"),
        _m("stale-without-reason", REJECT, "stale needs mirror.stale",
           _host(_state(status="stale")), "mirror-state.inconsistent"),
        _m("wrong-width", REJECT, "a sha1 state holds 40-hex ids",
           _host(_state(refs={"refs/heads/main": "b" * 64})), "mirror-state.malformed"),
        _m("unsorted-reasons", REJECT, "reasons are sorted and distinct",
           _host(_state(status="stale", reasons=["mirror.upstream-unverifiable", "mirror.stale"])),
           "mirror-state.malformed"),
        _m("pass-status", REJECT, "there is no pass status for a host to claim",
           _host(_state(status="verified")), "mirror-state.malformed"),
        _g("blob-sha1", ACCEPT, "a blob matches its SHA-1 id", "blob", _BLOB1, _BLOB1_ID),
        _g("tree-sha1", ACCEPT, "a tree matches and links its entry", "tree", _TREE1, _TREE1_ID),
        _g("commit-sha1", ACCEPT, "a commit matches and links its tree", "commit", _COMMIT1,
           _COMMIT1_ID),
        _g("tree-sha256", ACCEPT, "a tree matches its SHA-256 id", "tree", _TREE2, _TREE2_ID),
        _g("commit-sha256", ACCEPT, "a commit matches its SHA-256 id", "commit", _COMMIT2,
           _COMMIT2_ID),
        _g("one-byte", REJECT, "one changed byte is a mismatch", "blob", b"hellp\n", _BLOB1_ID,
           "git-object.mismatch"),
        _g("wrong-type", REJECT, "the same bytes under another type", "tree", _BLOB1, _BLOB1_ID,
           "git-object.mismatch"),
        _g("sha1-links-in-sha256", REJECT, "a sha256 commit cannot link a sha1 tree", "commit",
           _COMMIT1, hashlib.sha256(b"commit %d\0" % len(_COMMIT1) + _COMMIT1).hexdigest(),
           "git-object.malformed"),
        _g("bad-id", REJECT, "an id is 40 or 64 lowercase hex", "blob", _BLOB1,
           _BLOB1_ID.upper(), "git-object.malformed"),
    ),
)  # fmt: skip

FAMILIES = (PROJECT, MIRROR)
