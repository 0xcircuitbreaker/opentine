"""Op dispatch and record assembly, shared by the generator and the self-gates.

One code path answers every case exactly once, so the checked-in vectors and the
pytest gate can never diverge on *how* a case was run -- only on whether the
reference still answers it the same way.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tests.conformance import tagged
from tests.conformance.adapter import OPS, OpInput
from tests.conformance.cases import ACCEPT, REJECT, VERDICT, Case
from tests.conformance.opsmeta import OP_META

ROOT = Path(__file__).resolve().parents[2]

#: An ``output`` whose canonical form is larger than this is pinned by SHA-256
#: instead of by value: three bounds vectors answer with hundreds of kilobytes,
#: and a vector file no one can read is worse than one extra rule. Every case
#: that uses it is stress-tier, which ``test_conformance_drift`` enforces.
OUTPUT_INLINE_LIMIT = 16384

#: Bytes above this size move out of the vector file into ``blobs/``/``frames/``.
INLINE_BYTE_LIMIT = 1024


def assemble_value(recipe: dict[str, Any]) -> Any:
    """The one value-shaped recipe: a container nested ``depth`` levels deep.

    Deep nesting is the only input a *value*-consuming op needs that would cost
    O(depth**2) bytes if it were spelled inline in an indented JSON file, so it
    is a recipe rather than a literal. It carries no ``input.sha256`` because it
    has no byte spelling; a value-shaped input is compared as a value.
    """
    node: Any = tagged.decode(recipe["inner"])
    for _ in range(int(recipe["depth"])):
        node = [node] if recipe.get("container", "array") == "array" else {recipe["key"]: node}
    return node


def assemble(recipe: dict[str, Any]) -> bytes:
    """The four closed byte-shaped ``input.gen`` recipes, as bytes."""
    kind = recipe["kind"]
    if kind == "nest":
        depth, inner = int(recipe["depth"]), recipe["inner"]
        return (recipe["open"] * depth + inner + recipe["close"] * depth).encode("ascii")
    if kind == "repeat":
        prefix = base64.b64decode(recipe.get("prefix_b64", ""))
        suffix = base64.b64decode(recipe.get("suffix_b64", ""))
        return prefix + base64.b64decode(recipe["unit_b64"]) * int(recipe["count"]) + suffix
    if kind == "fill":
        return bytes([int(recipe["byte"])]) * int(recipe["count"])
    if kind == "oids":
        start, count = int(recipe.get("start", 0)), int(recipe["count"])
        object_type = recipe["object_type"]
        terminator = recipe.get("terminator", "\n")
        lines = [
            f"{object_type}:sha256:{index:064x}{terminator}"
            for index in range(start, start + count)
        ]
        return ("".join(lines)).encode("ascii")
    raise ValueError(f"unknown input.gen recipe: {kind!r}")


def op_input(case: Case) -> tuple[OpInput, bytes | None]:
    """The adapter input for one case, plus its assembled bytes when byte-shaped."""
    spec = case.input
    if "value" in spec:
        return OpInput("value", None, spec["value"]), None
    if "gen" in spec and spec["gen"]["kind"] == "nest-value":
        return OpInput("value", None, assemble_value(spec["gen"])), None
    if "gen" in spec:
        raw = assemble(spec["gen"])
    elif "path" in spec:
        raw = (ROOT / spec["path"]).read_bytes()
    else:
        raw = spec["bytes"]
    return OpInput("bytes", raw, None), raw


@dataclass(frozen=True)
class Observation:
    disposition: str
    output: dict[str, Any] | None
    exception: BaseException | None


def observe(case: Case) -> Observation:
    """Run one case through the reference implementation."""
    payload, _ = op_input(case)
    try:
        result = OPS[case.op](payload, dict(case.args))
    except Exception as exc:  # noqa: BLE001 -- a refusal is the answer here
        return Observation(REJECT, None, exc)
    return Observation(ACCEPT, result, None)


def canonical_output(output: dict[str, Any] | None) -> bytes:
    """The byte form an ``output_sha256`` digests, and the one a runner must match."""
    return json.dumps(output, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def display_bytes(raw: bytes, limit: int = 400) -> str:
    out: list[str] = []
    for byte in raw[:limit]:
        if byte == 0x5C:
            out.append("\\\\")
        elif byte == 0x0A:
            out.append("\\n")
        elif 0x20 <= byte < 0x7F:
            out.append(chr(byte))
        else:
            out.append(f"\\x{byte:02x}")
    return "".join(out) + ("..." if len(raw) > limit else "")


def display_value(value: Any, limit: int = 400) -> str:
    text = json.dumps(tagged.encode(value), sort_keys=True, ensure_ascii=True)
    return text[:limit] + ("..." if len(text) > limit else "")


def _record_input(case: Case, raw: bytes | None, side_file: str | None) -> dict[str, Any]:
    if raw is None:
        if "gen" in case.input:
            return {"gen": case.input["gen"]}
        return {"value": tagged.encode(case.input["value"])}
    digest = hashlib.sha256(raw).hexdigest()
    if "gen" in case.input:
        return {"gen": case.input["gen"], "sha256": digest}
    if "path" in case.input:
        return {"path": case.input["path"], "sha256": digest}
    if side_file is not None:
        return {"blob": side_file, "sha256": digest}
    return {"bytes_b64": base64.b64encode(raw).decode("ascii"), "sha256": digest}


def build_record(case: Case, observation: Observation, side_file: str | None) -> dict[str, Any]:
    """Assemble one vector record: the authored half plus the observed answers."""
    _, raw = op_input(case)
    record: dict[str, Any] = {
        "id": case.id,
        "section": case.section,
        "checklist": list(case.checklist),
        "op": case.op,
        "profile": case.profile,
        "tier": case.tier,
        "expect": case.expect,
        "intent": case.intent,
        "input": _record_input(case, raw, side_file),
    }
    if case.args:
        record["args"] = case.args
    if case.expect == REJECT:
        if case.reason_any is not None:
            record["reason_any"] = list(case.reason_any)
        else:
            record["reason"] = case.reason
    if case.repair_temptation:
        record["repair_temptation"] = case.repair_temptation
    if case.twin:
        record["twin"] = case.twin
    if case.must_differ is not None:
        record["must_differ"] = case.must_differ
    if case.reachable is not None:
        record["reachable"] = case.reachable
    # The union of the op's capability and the case's own. A runner gates on the
    # per-case field, so an op-level capability that never reached a case was inert:
    # every zlib vector was dispatched to a consumer that had said it has no zlib.
    requires = set(case.requires) | set(OP_META[case.op]["requires"])
    if requires:
        record["requires"] = sorted(requires)
    if case.spec_note:
        record["spec_note"] = case.spec_note
    if case.expect in (ACCEPT, VERDICT):
        encoded = canonical_output(observation.output)
        if len(encoded) > OUTPUT_INLINE_LIMIT:
            record["output_sha256"] = hashlib.sha256(encoded).hexdigest()
        else:
            record["output"] = observation.output
    if case.forbidden is not None:
        record["forbidden"] = case.forbidden
    if raw is not None:
        record["x_display"] = display_bytes(raw)
    elif "gen" in case.input:
        record["x_display"] = display_value(assemble_value(case.input["gen"]))
    else:
        record["x_display"] = display_value(case.input["value"])
    record["x_reference"] = (
        {
            "exception": type(observation.exception).__name__,
            "message": str(observation.exception)[:400],
        }
        if case.expect == REJECT
        else None
    )
    return record
