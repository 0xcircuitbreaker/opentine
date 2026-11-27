"""Model-path rules for the ``tine record`` proxy (0.87): names, allowlist, estimates.

A budget policy (:mod:`opentine._budget_policy`) may carry an optional
``model_path`` section::

    {"allow": ["gpt-4o-mini", "claude-sonnet-4*"] | null,
     "aliases": {"fast": "gpt-4o-mini"},
     "judge": {"tokens": 50000, "money_usd": 2.0},
     "max_output_tokens": 32768}

``allow`` lists canonical model names (a trailing ``*`` matches a prefix);
``null`` or absent allows every model. ``judge`` caps the spend of calls tagged
``judge`` or ``scorer``. ``max_output_tokens`` is the output assumed for a
request that names no limit of its own. :func:`canonical` folds a model name
before it is matched: Unicode NFKC, case, whitespace, provider and routing
prefixes (``openai/``, ``models/``, ``us.anthropic.``) and the policy's aliases.

:func:`probe` reads one proxied request and returns the models it names, its
pessimistic token estimate, and why it cannot be checked when it cannot.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any
from urllib.parse import unquote

ROLES = ("judge", "scorer")
DEFAULT_MAX_OUTPUT = 32768
MAX_ENTRIES = 256
MAX_FANOUT = 128
NAME = re.compile(r"^[a-z0-9][a-z0-9._:@/+-]{0,127}$")
_PREFIXES = {"openai", "anthropic", "google", "gemini", "vertex", "vertex_ai", "vertexai",
             "azure", "azure_ai", "deepseek", "xai", "bedrock", "models", "publishers",
             "us", "eu", "apac", "global"}  # fmt: skip
_KEYS = {"allow", "aliases", "judge", "max_output_tokens"}
_OUT_KEYS = ("max_tokens", "max_completion_tokens", "max_output_tokens", "maxOutputTokens")
_FAN_KEYS = ("n", "best_of", "candidateCount", "candidate_count")


class ModelPathError(ValueError):
    """A ``model_path`` section that cannot be used."""


def canonical(name: Any, aliases: dict[str, str] | None = None) -> str:
    """The folded form of model *name*; ``""`` for no usable name."""
    if not isinstance(name, str):
        return ""
    text = "".join(unicodedata.normalize("NFKC", name).casefold().split())
    while True:
        cut = re.match(r"^([a-z_]+)[/.:]", text)
        if not cut or cut.group(1) not in _PREFIXES or len(text) == cut.end():
            break
        text = text[cut.end() :]
    if aliases and text in aliases:
        text = aliases[text]
    return text if NAME.fullmatch(text) else ""


def _entry(value: Any, star: bool) -> str:
    raw = value[:-1] if star and isinstance(value, str) and value.endswith("*") else value
    name = canonical(raw)
    if not name:
        raise ModelPathError(f"{value!r} is not a model name")
    return name + ("*" if star and raw is not value else "")


def section(value: Any) -> dict[str, Any]:
    """The validated ``model_path`` section."""
    if not isinstance(value, dict) or set(value) - _KEYS:
        raise ModelPathError(f"model_path is an object of {', '.join(sorted(_KEYS))}")
    allow = value.get("allow")
    if allow is not None:
        if not isinstance(allow, list) or len(allow) > MAX_ENTRIES:
            raise ModelPathError(f"model_path.allow is a list of at most {MAX_ENTRIES} names")
        allow = sorted({_entry(item, True) for item in allow})
    aliases = value.get("aliases") or {}
    if not isinstance(aliases, dict) or len(aliases) > MAX_ENTRIES:
        raise ModelPathError(f"model_path.aliases maps at most {MAX_ENTRIES} names")
    aliases = {_entry(k, False): _entry(v, False) for k, v in sorted(aliases.items())}
    judge = value.get("judge") or {}
    if not isinstance(judge, dict) or set(judge) - {"tokens", "money_usd"}:
        raise ModelPathError("model_path.judge is an object of tokens, money_usd")
    from opentine._budget_policy import _limit

    caps = {"tokens": _limit("tokens", judge.get("tokens")),
            "money_usd": _limit("money_usd", judge.get("money_usd"))}  # fmt: skip
    most = value.get("max_output_tokens", DEFAULT_MAX_OUTPUT)
    if isinstance(most, bool) or not isinstance(most, int) or not 1 <= most <= 10**9:
        raise ModelPathError("model_path.max_output_tokens is a whole number >= 1")
    return {"allow": allow, "aliases": aliases, "judge": caps, "max_output_tokens": most}


def allowed(name: str, allow: list[str] | None) -> bool:
    if allow is None:
        return True
    if not name:
        return False
    return any(name == a or (a.endswith("*") and name.startswith(a[:-1])) for a in allow)


def widens(old: dict[str, Any] | None, new: dict[str, Any] | None) -> list[str]:
    """What *new* loosens relative to *old* (both validated sections or ``None``)."""
    if old is None:
        return []
    new = new or {"allow": None, "aliases": {}, "judge": {}, "max_output_tokens": 0}
    out = []
    if old["allow"] is not None and (new["allow"] is None
                                     or set(new["allow"]) - set(old["allow"])):  # fmt: skip
        out.append("model_path.allow")
    if any(old["aliases"].get(k) != v for k, v in new["aliases"].items()):  # prices too
        out.append("model_path.aliases")
    for unit, before in old["judge"].items():
        after = new["judge"].get(unit)
        if before is not None and (after is None or after > before):
            out.append("model_path.judge." + unit)
    if new["max_output_tokens"] < old["max_output_tokens"]:
        out.append("model_path.max_output_tokens")
    return out


def _segments(path: str) -> list[str] | None:
    """Lower-case path segments after percent-decoding; ``None`` for a traversal."""
    text = path.split("?", 1)[0].split("#", 1)[0]
    for _ in range(3):
        text = unquote(text)
    parts = [p for p in text.replace("\\", "/").split("/") if p]
    return None if any(p in (".", "..") for p in parts) else [p.casefold() for p in parts]


def _out(request: dict[str, Any], default: int) -> int:
    """Output tokens one request may produce: its own limit (or *default*) times fan-out."""
    places = [request] + [
        c
        for c in (request.get("generationConfig"), request.get("generation_config"))
        if isinstance(c, dict)
    ]
    found = [p.get(k) for p in places for k in _OUT_KEYS if p.get(k) is not None]
    for value in found:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ModelPathError("an output-token limit is not a whole number")
    fans = [p.get(k) for p in places for k in _FAN_KEYS if p.get(k) is not None] or [1]
    for fan in fans:
        if isinstance(fan, bool) or not isinstance(fan, int) or not 1 <= fan <= MAX_FANOUT:
            raise ModelPathError("a request asks for an unsupported number of choices")
    return (max(found) if found else default) * max(fans)


def _batch(dialect: str, body: dict[str, Any]) -> list[dict[str, Any]]:
    if dialect == "anthropic":
        items = body.get("requests")
        items = [i.get("params") if isinstance(i, dict) else None for i in items or [None]]
    else:
        batch = body.get("batch") if isinstance(body.get("batch"), dict) else {}
        found = ((batch.get("input_config") or {}).get("requests") or {}).get("requests")
        items = [i.get("request") if isinstance(i, dict) else None for i in found or [None]]
    if not items or len(items) > 100_000 or not all(isinstance(i, dict) for i in items):
        raise ModelPathError("a batch whose requests are not inline cannot be checked")
    return items


def probe(dialect: str, method: str, path: str, raw: bytes, request: Any,
          default_out: int) -> dict[str, Any]:  # fmt: skip
    """``{"models", "input", "output", "free", "problem"}`` for one request.

    *request* is the parsed JSON body (``None`` when it did not parse). A body that
    cannot be read, a traversal, an upload-based batch or an odd output limit is a
    ``problem``: the caller refuses it whenever a policy is in force."""
    out: dict[str, Any] = {"models": [], "input": len(raw), "output": 0, "free": False,
                           "problem": None}  # fmt: skip
    parts = _segments(path)
    if parts is None:
        return {**out, "problem": "the request path traverses"}
    if not raw:
        return {**out, "free": True}
    if not isinstance(request, dict):
        return {**out, "problem": "the request body is not a JSON object"}
    last = parts[-1] if parts else ""
    mark = {"gemini": "models", "openai": "deployments"}.get(dialect)
    out["models"] += [parts[i + 1].split(":", 1)[0] for i, p in enumerate(parts[:-1]) if p == mark]
    free = last == "count_tokens" or (last.count(":") == 1 and last.endswith(":counttokens"))
    try:
        if "batches" in parts and dialect == "anthropic" or last.endswith(":batchgeneratecontent"):
            items = _batch(dialect, request)
        elif "batches" in parts or "files" in parts or "uploads" in parts:
            raise ModelPathError("an upload-based batch cannot be checked")
        else:
            items = [request]
        for item in items:
            if item.get("model") is not None:
                out["models"].append(str(item["model"]))
            if item.get("models") is not None:  # a gateway's fallback list
                more = item["models"]
                if not isinstance(more, list) or len(more) > MAX_ENTRIES:
                    raise ModelPathError("a fallback model list cannot be checked")
                out["models"] += [str(m) for m in more]
            if not (free or "embed" in last):
                out["output"] += _out(item, default_out)
    except ModelPathError as exc:
        return {**out, "problem": str(exc)}
    out["free"] = free
    return out


__all__ = ["DEFAULT_MAX_OUTPUT", "ModelPathError", "ROLES", "allowed", "canonical", "probe",
           "section", "widens"]  # fmt: skip
