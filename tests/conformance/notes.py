"""Every ``spec_note`` and its mandatory resolution.

A note records a place where ``docs/SPEC.md``'s prose and the reference
implementation's behaviour did not line up, found by building a vector for the
rule. The resolution column is mandatory and is what stops this file becoming a
graveyard: a note with no resolution fails ``test_conformance_drift``, and an
empty table is a success.
"""

from __future__ import annotations

RESOLUTIONS: dict[str, str] = {
    (
        "SPEC 0.2 rule 10 says nesting is rejected 'at or beyond 512 levels'; the "
        "encoder accepts 512 nested containers and rejects 513."
    ): (
        "SPEC 0.2 rule 10 amended in this change to read 'rejects a container nested at "
        "depth >= 512 -- at most 512 nested containers', which is what the code does."
    ),
    (
        "SPEC 0.3 rule 4's 4096-digit bound is enforced at the .tine layer "
        "(_artifact_io), not by _canonical_bytes; this op accepts a 4097-digit "
        "integer that artifact.parse refuses."
    ): (
        "No change: SPEC 0.3 rule 4 already says the bound is 'enforced at save and at "
        "read'. The note is kept because the *op* boundary is what an implementer "
        "partitions their code along, and canon.v2 and artifact.parse disagree here."
    ),
    (
        "SPEC 0.1 says both formats reject a lone surrogate at write and at read; "
        "_canonical_bytes alone does not -- the refusal lives in "
        "_artifact_io.parse_artifact_json and _v3_guards.guarded_redaction."
    ): (
        "SPEC 0.1 amended in this change to name the enforcement points, so an "
        "implementer who partitions their code the way opentine does is not surprised "
        "that their canonicalizer alone accepts what the format refuses."
    ),
    (
        "SPEC 0.2's hazard says 'every kernel reader' demotes an integer literal "
        "past 2**53-1; ObjectEnvelope.decode's header parse is the one that does "
        "not, so the reference reports the integer bound here where a reader that "
        "demotes uniformly reports the schema type or range."
    ): (
        "SPEC 0.2's hazard amended in this change: the demotion MUST is scoped to the "
        "json-encoded object *body* and to .tine documents, and the three-key envelope "
        "header is called out as parsed without it -- a header schema is bounded by "
        "SPEC 1.2 at 2**53 anyway, so demotion there could only ever mask a rejection. "
        "The vector carries reason_any over all three codes, because the input is "
        "genuinely dual-fault and no order between the two rules is normative."
    ),
    (
        "SPEC 2.7 describes the shallow file as 'Sorted', but the reader enforces "
        "uniqueness, ASCII and line shape only -- an unsorted file is accepted."
    ): (
        "SPEC 2.7 amended in this change: sortedness is a *writer* property. Inventing "
        "a rejection the code does not perform would make the suite lie."
    ),
    (
        "SPEC 2.7 says 'the last line is terminated', but the reader accepts a shallow "
        "file with no trailing LF."
    ): (
        "SPEC 2.7 amended in this change: termination is a *writer* property, for the same reason."
    ),
}
