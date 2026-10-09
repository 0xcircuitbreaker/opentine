"""Pin ``docs/SPEC.md`` to the code it specifies.

``docs/SPEC.md`` is the artifact a third-party implementer builds against, so a
claim in it that the implementation does not honour is worse than no claim at
all: it is a false promise to whoever is verifying opentine data. Review
discipline does not keep a 1200-line document true across releases; a test does.

Every assertion below derives its expected value from the *code* and then
requires the document to say it. Change a constant, a scheme name, a domain
prefix, an object type or a verdict without updating the spec, and this module
fails. It follows the idiom ``test_release_audit_round9_docs.py`` established
for the CHANGELOG.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

import pytest

from opentine._attest_view import ATTEST_DOMAIN_PREFIX, ATTEST_SCHEMES, SCHEME_ATTEST_V1
from opentine._canon import FORMAT_VERSION, SUPPORTED_VERSIONS, _integrity_digest
from opentine._canon_redact import MAX_CANONICAL_DEPTH
from opentine._signing_verify import HEADER_KEYS, MIN_HMAC_KEY_BYTES, VALUE_LENGTHS
from opentine._signing_view import (
    _SIGNED_METADATA_KEYS,
    DOMAIN_PREFIX,
    SCHEME_V1,
    SCHEME_V2,
    SCHEMES,
)
from opentine.attest_signing import sign_attestation
from opentine.kernel import MAX_JSON_DEPTH, OBJECT_TYPES, OID_RE, ObjectEnvelope

ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = ROOT / "docs" / "SPEC.md"


def spec() -> str:
    return SPEC_PATH.read_text(encoding="utf-8")


def _section(text: str, heading: str) -> str:
    start = text.index(heading)
    end = text.find("\n## ", start + len(heading))
    return text[start : end if end > 0 else len(text)]


def _grouped(value: int) -> tuple[str, ...]:
    """Both spellings a bound may legitimately be written in."""
    return (str(value), f"{value:,}".replace(",", " "), f"{value:,}".replace(",", " "))


def _row_states(text: str) -> set[str]:
    """The first backticked cell of every row of the verdict table."""
    section = _section(text, "## 4.7 The verdict vocabulary")
    found = re.findall(r"^\|\s*`([a-z-]+)`\s*\|", section, flags=re.MULTILINE)
    return set(found) - {"state", "ok"}


def _code_states() -> set[str]:
    """Every ``SignatureResult.state`` value the verifier can return.

    Read out of the modules' AST rather than restated here: the second argument
    of a ``SignatureResult(...)`` / ``result(...)`` call (following both arms of
    a conditional), plus anything assigned to a local named ``state``. The block
    checks live in ``_signing_verify`` and the keyed verdicts in
    ``_signing_verdicts``, so both are read.
    """
    tree = ast.Module(body=[], type_ignores=[])
    for name in ("_signing_verify.py", "_signing_verdicts.py"):
        source = (ROOT / "opentine" / name).read_text(encoding="utf-8")
        tree.body.extend(ast.parse(source).body)
    states: set[str] = set()

    def collect(node: ast.AST) -> None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            states.add(node.value)
        elif isinstance(node, ast.IfExp):
            collect(node.body)
            collect(node.orelse)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {"SignatureResult", "result"} and len(node.args) > 1:
                collect(node.args[1])
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "state" for target in node.targets
        ):
            collect(node.value)
    return states


# --------------------------------------------------------------------------- #
# Names and vocabularies
# --------------------------------------------------------------------------- #


def test_spec_exists_and_is_linked_from_the_companion_docs() -> None:
    assert SPEC_PATH.is_file()
    for name in ("TINE_FORMAT.md", "REPOSITORY.md", "SECURITY_MODEL.md"):
        assert "SPEC.md" in (ROOT / "docs" / name).read_text(encoding="utf-8"), name


def test_object_types_match_the_kernel() -> None:
    match = re.search(r"`kernel\.OBJECT_TYPES` = exactly `\{(.+?)\}`", spec(), flags=re.S)
    assert match, "SPEC.md must enumerate OBJECT_TYPES"
    assert set(re.findall(r'"([a-z]+)"', match.group(1))) == set(OBJECT_TYPES)


def test_oid_regex_is_quoted_verbatim() -> None:
    assert OID_RE.pattern in spec()


def test_ref_name_regex_is_quoted_verbatim() -> None:
    from opentine.repository._refs import _REF

    assert _REF.pattern in spec()


def test_typed_ref_namespaces_match_the_repository_rules() -> None:
    from opentine.repository._refs import TYPED_REF_NAMESPACES

    text = spec()
    for namespace, object_type in TYPED_REF_NAMESPACES.items():
        row = [
            line
            for line in text.splitlines()
            if f"`{namespace}/`" in line and f"`{object_type}`" in line
        ]
        assert row, f"SPEC.md must document {namespace}/ -> {object_type}"


def test_layout_dirs_are_all_documented() -> None:
    from opentine.repository._paths import LAYOUT_DIRS

    text = spec()
    for directory in LAYOUT_DIRS:
        assert directory in text, directory


def test_run_statuses_and_token_dimensions_match_the_validators() -> None:
    from opentine.repository._run_graph import _RUN_STATUSES, _TOKEN_USAGE

    text = spec()
    statuses = re.search(r"`status` \| absent \(⇒ `\"running\"`\) or one of ([^|]+)\|", text)
    assert statuses, "SPEC.md must enumerate the run statuses"
    assert set(re.findall(r"`([a-z]+)`", statuses.group(1))) == set(_RUN_STATUSES)

    dimensions = re.search(r"for ((?:`[a-z0-9_]+`,?\s*)+): MUST additionally", text)
    assert dimensions, "SPEC.md must enumerate the token usage dimensions"
    assert set(re.findall(r"`([a-z0-9_]+)`", dimensions.group(1))) == set(_TOKEN_USAGE)


def test_legacy_migration_fields_are_all_documented() -> None:
    from opentine.repository._run_blobs import LEGACY_MIGRATION_FIELDS

    text = spec()
    for field in LEGACY_MIGRATION_FIELDS:
        assert f"`{field}`" in text, field


# --------------------------------------------------------------------------- #
# Signing: schemes, domains, header, verdicts
# --------------------------------------------------------------------------- #


def test_every_scheme_name_is_documented() -> None:
    text = spec()
    for scheme in (*SCHEMES, *ATTEST_SCHEMES):
        assert f"`{scheme}`" in text, scheme
    assert (SCHEME_V1, SCHEME_V2, SCHEME_ATTEST_V1) == (
        "tine-sig/1",
        "tine-sig/2",
        "tine-attest/1",
    )


def test_domain_prefixes_are_documented_and_still_distinct() -> None:
    text = spec()
    assert DOMAIN_PREFIX.decode() in text
    assert ATTEST_DOMAIN_PREFIX.decode() in text
    # The artifact and attestation families must never share a prefix, or a
    # signature could be lifted from one into the other.
    assert DOMAIN_PREFIX != ATTEST_DOMAIN_PREFIX
    # The two artifact schemes deliberately DO share one; the spec says so.
    assert "share one domain prefix" in text


def test_signed_header_keys_are_documented_verbatim() -> None:
    assert str(tuple(HEADER_KEYS)).replace("'", '"') in spec()


def test_signature_value_lengths_match_the_verifier() -> None:
    text = spec().splitlines()
    for algorithm, length in VALUE_LENGTHS.items():
        assert any(f"`{algorithm}`" in line and str(length) in line for line in text), (
            f"SPEC.md must give the {algorithm} value length"
        )


def test_verdict_vocabulary_matches_the_code_exactly() -> None:
    documented = _row_states(spec())
    produced = _code_states()
    assert documented <= produced, f"SPEC.md invents states: {documented - produced}"
    assert produced <= documented, f"code returns states SPEC.md omits: {produced - documented}"


def test_tine_sig_v1_metadata_allowlist_is_documented_in_full() -> None:
    text = spec()
    listed = _section(text, "## 4.3 `tine-sig/1`")
    start = listed.index("_SIGNED_METADATA_KEYS")
    fragment = listed[start : listed.index("The allowlist is frozen")]
    assert set(re.findall(r"`([a-z_]+)`", fragment)) - {"_SIGNED_METADATA_KEYS"} == set(
        _SIGNED_METADATA_KEYS
    )


# --------------------------------------------------------------------------- #
# Numeric bounds
# --------------------------------------------------------------------------- #


def _bounds() -> list[tuple[str, int]]:
    from opentine._artifact_io import MAX_TINE_ARTIFACT_BYTES, MAX_TINE_INTEGER_DIGITS
    from opentine.repository._annotations import MAX_LEGACY_OBJECTS
    from opentine.repository._associations import MAX_ASSOCIATION_SCAN
    from opentine.repository._config import MAX_CONFIG_BYTES
    from opentine.repository._objects import MAX_TYPED_OBJECT_SCAN
    from opentine.repository._ref_store import MAX_REF_BYTES
    from opentine.repository._refs import MAX_REF_COMPONENT_BYTES
    from opentine.repository._run_graph import _MAX_SAFE_INTEGER
    from opentine.repository._shallow import MAX_SHALLOW_BYTES, MAX_SHALLOW_OBJECTS
    from opentine.repository._traversal import MAX_TRAVERSAL_OBJECTS
    from opentine.repository.pack import MAX_PACK_BODY_BYTES, MAX_PACK_BYTES, MAX_PACK_OBJECTS

    return [
        ("MAX_JSON_DEPTH", MAX_JSON_DEPTH),
        ("MAX_CANONICAL_DEPTH", MAX_CANONICAL_DEPTH),
        ("_MAX_SAFE_INTEGER", _MAX_SAFE_INTEGER),
        ("MAX_REF_BYTES", MAX_REF_BYTES),
        ("MAX_REF_COMPONENT_BYTES", MAX_REF_COMPONENT_BYTES),
        ("MAX_CONFIG_BYTES", MAX_CONFIG_BYTES),
        ("MAX_SHALLOW_OBJECTS", MAX_SHALLOW_OBJECTS),
        ("MAX_SHALLOW_BYTES", MAX_SHALLOW_BYTES),
        ("MAX_PACK_BYTES", MAX_PACK_BYTES),
        ("MAX_PACK_BODY_BYTES", MAX_PACK_BODY_BYTES),
        ("MAX_PACK_OBJECTS", MAX_PACK_OBJECTS),
        ("MAX_TRAVERSAL_OBJECTS", MAX_TRAVERSAL_OBJECTS),
        ("MAX_TYPED_OBJECT_SCAN", MAX_TYPED_OBJECT_SCAN),
        ("MAX_ASSOCIATION_SCAN", MAX_ASSOCIATION_SCAN),
        ("MAX_LEGACY_OBJECTS", MAX_LEGACY_OBJECTS),
        ("MAX_TINE_ARTIFACT_BYTES", MAX_TINE_ARTIFACT_BYTES),
        ("MAX_TINE_INTEGER_DIGITS", MAX_TINE_INTEGER_DIGITS),
        ("MIN_HMAC_KEY_BYTES", MIN_HMAC_KEY_BYTES),
    ]


@pytest.mark.parametrize(("name", "value"), _bounds(), ids=[name for name, _ in _bounds()])
def test_every_bound_is_documented_with_its_real_value(name: str, value: int) -> None:
    """The spec row naming a constant must also carry that constant's value."""
    rows = [line for line in spec().splitlines() if name in line]
    assert rows, f"SPEC.md must name {name}"
    spellings = _grouped(value)
    assert any(any(spelling in row for spelling in spellings) for row in rows), (
        f"SPEC.md rows for {name} do not carry {value}"
    )


def test_signing_key_file_limit_and_envelope_header_limit_are_documented() -> None:
    from opentine._signing_keys import MAX_SIGNING_KEY_BYTES

    text = spec()
    assert MAX_SIGNING_KEY_BYTES == 1024 * 1024 and "1 MiB" in text
    # The envelope header cap is a literal in kernel.ObjectEnvelope.decode.
    source = (ROOT / "opentine" / "kernel.py").read_text(encoding="utf-8")
    assert "len(raw_header) > 256" in source
    assert "256 bytes" in text


def test_default_structural_token_budget_is_documented() -> None:
    source = (ROOT / "opentine" / "kernel.py").read_text(encoding="utf-8")
    assert "max_tokens: int = 200_000" in source
    assert "200 000" in spec()


# --------------------------------------------------------------------------- #
# Worked vectors: recompute from the code, require the document to state them
# --------------------------------------------------------------------------- #


def test_blob_and_event_oid_vectors_match() -> None:
    text = spec()
    blob = ObjectEnvelope.create("blob", b"hello\n")
    event = ObjectEnvelope.create("event", {"cost": 0, "kind": "model", "parent_ids": []})
    assert blob.oid in text
    assert event.oid in text
    assert event.body.decode() in text
    assert blob.encode().decode().replace("\n", "\\n") in text
    assert event.encode().decode().replace("\n", "\\n") in text


def test_repository_config_bytes_vector_matches(tmp_path: Path) -> None:
    from opentine.repository.store import Repo

    Repo.init(tmp_path)
    written = (tmp_path / ".tine" / "config.json").read_bytes()
    assert written.decode().strip() in spec()


def test_pack_magic_and_frame_offsets_match() -> None:
    from opentine.repository.pack import MAGIC

    text = spec()
    assert len(MAGIC) == 10
    assert "TINEPACK3\\x00" in text
    # header (10) + digest (32) = 42, the offset the reader slices at.
    assert "42" in text


def test_v2_integrity_digest_vector_matches() -> None:
    artifact: dict[str, Any] = {
        "format_version": 2,
        "run_id": "demo",
        "created_at": 0,
        "status": "completed",
        "graph": {"order": [], "steps": {}},
        "refs": {},
        "transcript": [],
        "manifest": {},
        "policies": {},
        "cache": {},
        "metadata": {"model_info": "m"},
    }
    assert _integrity_digest(artifact) in spec()


def test_attestation_signature_vector_matches() -> None:
    payload = {
        "claim": {"result": "pass"},
        "evidence_ids": [],
        "signer": "release-bot",
        "target_id": "run:sha256:" + "11" * 32,
    }
    block = sign_attestation(
        payload,
        b"0123456789abcdef0123456789abcdef",
        key_id="demo-key",
        signed_at="2026-09-05T00:00:00Z",
    )
    assert block["scheme"] == SCHEME_ATTEST_V1
    assert block["value"] in spec()


def test_format_versions_are_documented() -> None:
    text = spec()
    assert f"SUPPORTED_VERSIONS = {SUPPORTED_VERSIONS}" in text
    assert f"currently **{FORMAT_VERSION}**" in text
