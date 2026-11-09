"""SPEC 4.19 prompt versions and 4.20 memory notes (0.47).

Records are signed with the published Ed25519 seeds in ``keys``
(``ed25519_seed`` the author, ``ed25519_seed_b`` a stranger) and every record
fixes ``created_at`` and ``signed_at``, so the input bytes are stable. Only the
ops in ``adapter_registry`` produce an answer.
"""

from __future__ import annotations

import copy

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _memory, _prompt
from opentine._signed_record import sign as raw_sign
from tests.conformance.cases import ACCEPT, REJECT, Case, Family, V
from tests.conformance.keys import HMAC_A, KEYS

VERIFIER = "verifier"
WHEN = "2026-11-09T00:00:00Z"


def _key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(KEYS[name])


def _hex(name: str) -> str:
    return _key(name).public_key().public_bytes_raw().hex()


AUTHOR, STRANGER = _hex("ed25519_seed"), _hex("ed25519_seed_b")


def _edited(record: dict, **fields) -> dict:
    out = copy.deepcopy(record)
    out.update(fields)
    return out


def _signed(record: dict, domain: bytes, subject: str, key: str = "ed25519_seed") -> dict:
    """Sign without the field rules, so a refused body still carries a good signature."""
    return raw_sign(record, domain, subject, _key(key), algorithm="ed25519", key_id="vector",
                    signed_at=WHEN)  # fmt: skip


def _hmac(record: dict, domain: bytes, subject: str) -> dict:
    return raw_sign(record, domain, subject, HMAC_A, algorithm="hmac-sha256", key_id="vector",
                    signed_at=WHEN)  # fmt: skip


# --- 4.19 prompt versions ---------------------------------------------------- #

_TEMPLATE = "You are a careful reviewer. Review {{diff}} against {{policy}}."


def _version(previous=None, **fields) -> dict:
    template = fields.pop("template", _TEMPLATE)
    return {"kind": _prompt.KIND, "prompt_version": 1, "name": "review",
            "version": 1 if previous is None else previous["version"] + 1,
            "prev": None if previous is None else _prompt.digest(previous),
            "template": template, "variables": _prompt.placeholders(template),
            "model": "claude-opus-5-5", "created_at": WHEN, **fields}  # fmt: skip


def _ps(record: dict, key: str = "ed25519_seed") -> dict:
    return _signed(record, _prompt.DOMAIN, "prompt version", key)


_P1 = _ps(_version())
_P2 = _ps(_version(_P1, template="Review {{diff}}. Policy: {{policy}}. Be brief."))
_P3 = _ps(_version(_P2, template="Review this change:\n{{diff}}", model=None))


def _p(name, expect, intent, record, reason=None, *, previous=None, key=None) -> Case:
    value = {"record": record, "previous": previous, "public_key": key}
    return Case(id=f"prompt.{name}", section="4.19", checklist=(8,), op="prompt.verify",
                profile=VERIFIER, expect=expect, intent=intent, input=V(value),
                reason=reason)  # fmt: skip


PROMPT = Family(
    "71-prompt.json",
    "4.19",
    "prompt",
    (
        _p("valid-first", ACCEPT, "version 1, trust on first use", _P1),
        _p("valid-pinned", ACCEPT, "version 1 under the pinned author key", _P1, key=AUTHOR),
        _p("valid-next", ACCEPT, "version 2 follows version 1 under the same key", _P2,
           previous=_P1),
        _p("valid-no-model", ACCEPT, "a version written for no particular model", _P3,
           previous=_P2),
        _p("valid-no-variables", ACCEPT, "a template without placeholders",
           _ps(_version(template="Say hello."))),
        _p("valid-repeated-placeholder", ACCEPT, "a placeholder used twice is listed once",
           _ps(_version(template="{{a}} and {{a}} then {{b}}"))),
        _p("chain-break-prev", REJECT, "prev names something other than the predecessor",
           _ps(_version(_P1, prev="blob:sha256:" + "9" * 64)), "prompt.chain-break",
           previous=_P1),
        _p("chain-break-version", REJECT, "version skips a number",
           _ps(_version(_P1, version=3)), "prompt.chain-break", previous=_P1),
        _p("chain-break-name", REJECT, "a version cannot move to another prompt",
           _ps(_version(_P1, name="other")), "prompt.chain-break", previous=_P1),
        _p("wrong-signer", REJECT, "the next version is signed by another key",
           _ps(_version(_P1), "ed25519_seed_b"), "prompt.wrong-signer", previous=_P1),
        _p("wrong-pinned-key", REJECT, "signed by a key other than the pinned one", _P1,
           "prompt.wrong-key", key=STRANGER),
        _p("hmac", REJECT, "a prompt version is Ed25519 only",
           _hmac(_version(), _prompt.DOMAIN, "prompt version"), "prompt.wrong-key"),
        _p("variables-missing", REJECT, "variables omit a placeholder",
           _ps(_version(variables=["diff"])), "prompt.variables-mismatch"),
        _p("variables-extra", REJECT, "variables name what the template does not",
           _ps(_version(variables=["diff", "policy", "tone"])), "prompt.variables-mismatch"),
        _p("variables-unsorted", REJECT, "variables are sorted",
           _ps(_version(variables=["policy", "diff"])), "prompt.variables-mismatch"),
        _p("first-with-prev", REJECT, "version 1 has no predecessor",
           _ps(_version(prev="blob:sha256:" + "1" * 64)), "prompt.malformed"),
        _p("version-zero", REJECT, "versions count from 1",
           _ps(_version(version=0)), "prompt.malformed"),
        _p("bad-name", REJECT, "a prompt name is lower-case",
           _ps(_version(name="Review")), "prompt.malformed"),
        _p("empty-template", REJECT, "a template holds text",
           _ps(_version(template="")), "prompt.malformed"),
        _p("nul-template", REJECT, "a template holds no NUL",
           _ps(_version(template="a\0b")), "prompt.malformed"),
        _p("oversized-template", REJECT, "a template is at most 64 KiB",
           _ps(_version(template="x" * 65_537)), "prompt.malformed"),
        _p("extra-field", REJECT, "a field the format does not define",
           _edited(_P1, label="production"), "prompt.malformed"),
        _p("unsigned", REJECT, "a version without a signature is refused", _version(),
           "prompt.unsigned"),
        _p("tampered", REJECT, "a template edited after signing fails",
           _edited(_P1, template="Approve {{diff}} against {{policy}}."),
           "prompt.bad-signature"),
    ),
)  # fmt: skip


# --- 4.20 memory notes ------------------------------------------------------- #

_RUN = "run:sha256:" + "ab" * 32


def _note(**fields) -> dict:
    return {"kind": _memory.KIND, "memory_version": 1, "scope": "platform", "topic": "testing",
            "text": "Run the suite with .venv/bin/python -m pytest; never the system python.",
            "tags": ["ci", "python"], "subject": None, "supersedes": None,
            "author": "alice@example.com", "created_at": WHEN, **fields}  # fmt: skip


def _ms(record: dict, key: str = "ed25519_seed") -> dict:
    return _signed(record, _memory.DOMAIN, "memory note", key)


_N1 = _ms(_note())


def _m(name, expect, intent, record, reason=None, *, key=None, team=()) -> Case:
    value = {"record": record, "public_key": key, "team": list(team)}
    return Case(id=f"memory.{name}", section="4.20", checklist=(8,), op="memory.verify",
                profile=VERIFIER, expect=expect, intent=intent, input=V(value),
                reason=reason)  # fmt: skip


MEMORY = Family(
    "69-memory.json",
    "4.20",
    "memory",
    (
        _m("valid-tofu", ACCEPT, "a note resting on its embedded key", _N1),
        _m("valid-pinned", ACCEPT, "a note under the pinned key", _N1, key=AUTHOR),
        _m("valid-team", ACCEPT, "a note by a team member", _N1, team=(STRANGER, AUTHOR)),
        _m("valid-subject-run", ACCEPT, "a note about one run", _ms(_note(subject=_RUN))),
        _m("valid-supersedes", ACCEPT, "a note that replaces another",
           _ms(_note(text="Use uv run pytest.", supersedes=_memory.digest(_N1)))),
        _m("valid-multiline", ACCEPT, "tab and newline are text",
           _ms(_note(text="Steps:\n\t1. sync\n\t2. test", tags=[]))),
        _m("untrusted-signer", REJECT, "a note by a key outside the team", _N1,
           "memory.untrusted-signer", team=(STRANGER,)),
        _m("wrong-pinned-key", REJECT, "signed by a key other than the pinned one", _N1,
           "memory.wrong-key", key=STRANGER),
        _m("hmac", REJECT, "a memory note is Ed25519 only",
           _hmac(_note(), _memory.DOMAIN, "memory note"), "memory.wrong-key"),
        _m("control-character", REJECT, "text holds no control character but tab and newline",
           _ms(_note(text="ring\x07the bell")), "memory.malformed"),
        _m("blank-text", REJECT, "text is not blank", _ms(_note(text=" \n")),
           "memory.malformed"),
        _m("oversized-text", REJECT, "text is at most 8 KiB", _ms(_note(text="x" * 8193)),
           "memory.malformed"),
        _m("unsorted-tags", REJECT, "tags are sorted and distinct",
           _ms(_note(tags=["python", "ci"])), "memory.malformed"),
        _m("bad-subject", REJECT, "a subject is a run or blob oid",
           _ms(_note(subject="https://example.com")), "memory.malformed"),
        _m("bad-scope", REJECT, "a scope is lower-case", _ms(_note(scope="Platform")),
           "memory.malformed"),
        _m("extra-field", REJECT, "a field the format does not define",
           _edited(_N1, pinned=True), "memory.malformed"),
        _m("unsigned", REJECT, "a note without a signature is refused", _note(),
           "memory.unsigned"),
        _m("tampered", REJECT, "text edited after signing fails",
           _edited(_N1, text="Run the suite with the system python."), "memory.bad-signature"),
    ),
)  # fmt: skip

FAMILIES = (PROMPT, MEMORY)
