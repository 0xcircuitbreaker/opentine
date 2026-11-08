"""SPEC 4.13 redaction reports: verifying a signed ``opentine.redaction-report`` (0.45.1).

Reports are signed here with the published keys in ``keys`` (HMAC and Ed25519
are deterministic and every report fixes ``signed_at``), so the input bytes are
stable. ``inconsistent`` is a signed body ``run_report`` would never produce.
Only the op in ``adapter_redaction_report`` produces an answer.
"""

from __future__ import annotations

import copy

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentine import _push_gate
from tests.conformance.cases import ACCEPT, REJECT, Case, Family, V
from tests.conformance.keys import KEYS

VERIFIER = "verifier"
WHEN = "2026-11-08T00:00:00Z"
RUN = "run:sha256:" + "1" * 64
BLOB = "blob:sha256:" + "2" * 64


def _private(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(KEYS[name])


def _public(name: str) -> str:
    return _private(name).public_key().public_bytes_raw().hex()


def _body(findings: list | None = None, **fields) -> dict:
    hits = [{"oid": BLOB, "kind": "blob"}] if findings is None else findings
    return {
        "kind": _push_gate.REPORT_KIND,
        "report_version": 1,
        "ruleset": "opentine-redaction/2",
        "run": RUN,
        "objects": 3,
        "findings": hits,
        "clean": not hits,
        **fields,
    }


def _hmac(body: dict | None = None) -> dict:
    return _push_gate.sign(body or _body(), KEYS["hmac_a"], algorithm="hmac-sha256",
                           key_id="vector", signed_at=WHEN)  # fmt: skip


def _ed(body: dict | None = None, key: str = "ed25519_seed") -> dict:
    return _push_gate.sign(body or _body(), _private(key), algorithm="ed25519",
                           key_id="vector", signed_at=WHEN)  # fmt: skip


def _edited(report: dict, **fields) -> dict:
    out = copy.deepcopy(report)
    out.update(fields)
    return out


def _case(name, expect, intent, report, reason=None, *, hmac=None, public=None) -> Case:
    return Case(
        id=f"redaction-report.{name}",
        section="4.13",
        checklist=(8,),
        op="redaction-report.verify",
        profile=VERIFIER,
        expect=expect,
        intent=intent,
        input=V({"report": report, "hmac_key_hex": hmac, "public_key": public}),
        reason=reason,
    )


_HMAC_A = KEYS["hmac_a"].hex()

REDACTION_REPORT = Family(
    "60-redaction-report.json",
    "4.13",
    "redaction-report",
    (
        _case("valid-hmac", ACCEPT, "an HMAC report verifies under its key", _hmac(),
              hmac=_HMAC_A),
        _case("valid-ed25519-trusted", ACCEPT, "an Ed25519 report verifies under the trusted key",
              _ed(_body([])), public=_public("ed25519_seed")),
        _case("valid-ed25519-tofu", ACCEPT,
              "with no key an Ed25519 report verifies under its embedded key (tofu)", _ed()),
        _case("clean-edited", REJECT, "a report marked clean after signing fails the signature",
              _edited(_hmac(), clean=True, findings=[]), "redaction-report.bad-signature",
              hmac=_HMAC_A),
        _case("objects-edited", REJECT, "an object count edited after signing fails",
              _edited(_ed(), objects=4), "redaction-report.bad-signature"),
        _case("wrong-hmac-key", REJECT, "an HMAC report under another key fails", _hmac(),
              "redaction-report.bad-signature", hmac=KEYS["hmac_b"].hex()),
        _case("wrong-key", REJECT, "an Ed25519 report by a key other than the trusted one",
              _ed(), "redaction-report.wrong-key", public=_public("ed25519_seed_b")),
        _case("hmac-key-ed25519-report", REJECT,
              "an Ed25519 report cannot pass under a supplied HMAC key (no TOFU fallback)",
              _ed(), "redaction-report.wrong-key", hmac=_HMAC_A),
        _case("no-key", REJECT, "an HMAC report with no key supplied cannot verify", _hmac(),
              "redaction-report.no-key"),
        _case("unsigned", REJECT, "a report without a signature is refused", _body(),
              "redaction-report.unsigned", hmac=_HMAC_A),
        _case("inconsistent", REJECT, "a signed report whose clean disagrees with its findings",
              _hmac(_body(clean=True)), "redaction-report.inconsistent", hmac=_HMAC_A),
        _case("extra-field", REJECT, "a report with a field it does not define is malformed",
              _edited(_hmac(), note="x"), "redaction-report.malformed", hmac=_HMAC_A),
        _case("wrong-version", REJECT, "a report_version other than 1 is malformed",
              _edited(_hmac(), report_version=2), "redaction-report.malformed", hmac=_HMAC_A),
    ),
)  # fmt: skip

FAMILIES = (REDACTION_REPORT,)
