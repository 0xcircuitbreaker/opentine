"""SPEC 5.1: the read guarantee, over bytes eight real published releases wrote.

These cases point at ``tests/fixtures/compat/`` rather than copying it. Those
fixtures were produced by the REAL published ``opentine==X.Y.Z`` installed from
PyPI, and their bytes ARE the evidence for the read guarantee; a second copy
inside the suite could drift from them. ``docs/conformance/compat/index.json``
carries the same fixture set with every verdict the current build must reach.
"""

from __future__ import annotations

from pathlib import Path

from opentine.kernel import ObjectEnvelope, validate_links
from tests.conformance.cases import ACCEPT, VERDICT, Case, Family, P
from tests.test_backwards_compat import GOLDEN

ROOT = Path(__file__).resolve().parents[2]
READER, VERIFIER = "reader", "verifier"


def _relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _run_object(golden) -> tuple[str, list[str]]:
    """The main run object's fixture path, and the links a reader must resolve."""
    object_type, digest = golden.repo_main_oid.split(":")[0], golden.repo_main_oid.split(":")[-1]
    path = golden.path / "repo" / ".tine" / "objects" / object_type / digest[:2] / digest[2:]
    envelope = ObjectEnvelope.decode(path.read_bytes(), golden.repo_main_oid)
    return _relative(path), sorted(validate_links(envelope))


def _cases() -> tuple[Case, ...]:
    found: list[Case] = []
    for golden in GOLDEN:
        version = golden.version.replace("_", "-")
        object_path, links = _run_object(golden)
        found.append(
            Case(
                id=f"compat.{version}.artifact-parses",
                section="5.1",
                checklist=(7, 9),
                op="artifact.parse",
                profile=READER,
                expect=ACCEPT,
                intent=f"a .tine artifact written by the published opentine {golden.version} "
                "still parses under every reader bound this build enforces",
                input=P(_relative(golden.artifact("artifact.tine"))),
            )
        )
        found.append(
            Case(
                id=f"compat.{version}.integrity-verifies",
                section="5.1",
                checklist=(7,),
                op="integrity.verify",
                profile=READER,
                expect=VERDICT,
                intent="and the integrity digest that release computed still recomputes to "
                "the same value, which is why neither canonicalization may be unified",
                input=P(_relative(golden.artifact("artifact.tine"))),
            )
        )
        found.append(
            Case(
                id=f"compat.{version}.signature-verifies",
                section="5.1",
                checklist=(8,),
                op="sig.verify",
                profile=VERIFIER,
                expect=VERDICT,
                intent="a genuine signature that release wrote still verifies byte-identically "
                "under the same key -- the reason tine-sig/1's metadata allowlist is "
                "frozen forever",
                input=P(_relative(golden.artifact("artifact_signed.tine"))),
                args={"family": "artifact", "key": "hmac_compat"},
            )
        )
        found.append(
            Case(
                id=f"compat.{version}.partial-block-signature-verifies",
                section="4.1",
                checklist=(8,),
                op="sig.verify",
                profile=VERIFIER,
                expect=VERDICT,
                intent="this release's other signed artifact stores a block with key_id, "
                "signer and signed_at absent, so verifying it exercises SPEC 4.1's rebuild "
                "MUST: a verifier that canonicalizes the keys the block carries, rather "
                "than the five-key header filled with nulls, reports mismatch here and "
                "verified on the full-header artifact beside it",
                input=P(_relative(golden.artifact("artifact_signed_fork_reason.tine"))),
                args={"family": "artifact", "key": "hmac_compat"},
            )
        )
        found.append(
            Case(
                id=f"compat.{version}.repo-run-object-loads",
                section="5.1",
                checklist=(3, 4, 5),
                op="object.load",
                profile=READER,
                expect=ACCEPT,
                intent="and the v3 run object that release stored still decodes to its own "
                "oid and satisfies every link rule",
                input=P(object_path),
                args={"expected_oid": golden.repo_main_oid, "shallow": links},
            )
        )
    return tuple(found)


COMPAT = Family("51-compat.json", "5.1", "compat", _cases())
FAMILIES = (COMPAT,)
