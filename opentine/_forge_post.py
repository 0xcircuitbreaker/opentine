"""The parts every forge shares: the comment text, the HTTP session and the upsert (0.48).

The comment is built from the ``opentine.forge-check`` record alone: counts,
fixed words, validated paths and the bundle's https URL and digest, so nothing
from a run's content, the environment or the token reaches a PR. Paths are
shown as inline code with backticks removed. A token travels only in a request
header to the configured API host; a failure names the HTTP status, never a
header, a body or the token (:class:`ForgeError`).
"""

from __future__ import annotations

import os
from typing import Any

from opentine._forge_check import percent

MARKER = "<!-- opentine-forge-check -->"
NAME = "opentine"
MAX_PAGES = 20
MAX_COMMENT_ROWS = 20
WORDS = {"verified": "verified", "failed": "verification failed", "unverified": "not verified"}


class ForgeError(RuntimeError):
    """A forge call failed; the message names the step and HTTP status only."""


def token(env_name: str) -> str:
    value = os.environ.get(env_name, "")
    if not value.strip():
        raise ForgeError(f"no token: set the {env_name} environment variable")
    return value.strip()


def title(record: dict[str, Any]) -> str:
    share = percent(record["ai"]["share_ppm"])
    return f"OpenTine: {WORDS[record['verify']['state']]}, {share} AI-attributed lines"


def _code(text: str) -> str:
    return "`" + text.replace("`", "'").replace("|", "\\|").replace("\n", " ") + "`"


def summary(record: dict[str, Any]) -> str:
    """The Markdown body shown in a check run, an MR note or a PR comment."""
    ai, verify, bundle = record["ai"], record["verify"], record["bundle"]
    lines = [
        MARKER,
        f"### {title(record)}",
        "",
        "| | |",
        "|---|---|",
        f"| Commit | {_code(record['commit'][:12])} |",
        f"| Project | {_code(record['project_id']) if record['project_id'] else 'none linked'} |",
        f"| AI share | {percent(ai['share_ppm'])} ({ai['ai_lines']} of {ai['total_lines']} "
        "lines at this commit) |",
        f"| Verify | {WORDS[verify['state']]} ({verify['runs']} verify output(s)) |",
    ]
    if bundle["digest"]:
        link = f"[bundle]({bundle['url']}) " if bundle["url"] else ""
        lines.append(f"| Evidence | {link}{_code(bundle['digest'])} |")
    rows = record["overlay"][:MAX_COMMENT_ROWS]
    if rows:
        lines += [
            "",
            "<details><summary>AI-attributed lines in this commit</summary>",
            "",
            "| File | Lines | Run |",
            "|---|---|---|",
        ]
        for row in rows:
            run = _code(row["run"][:16]) if row["run"] else "-"
            lines.append(
                f"| {_code(row['path'])} | {row['start_line']}-{row['end_line']} | {run} |"
            )
        lines += ["", "</details>"]
    if bundle["digest"]:
        lines += [
            "",
            "Verify offline: download the bundle, check `sha256sum` against the digest "
            "above, then run `tine bundle verify FILE` (or `python tine-verify.pyz`).",
        ]
    return "\n".join(lines) + "\n"


def client() -> Any:
    """The HTTP session (tests replace this with a recorded-fixture transport)."""
    import httpx

    return httpx.Client(timeout=30, follow_redirects=False)


def expect(answer: Any, step: str, codes: tuple[int, ...] = (200, 201)) -> Any:
    if answer.status_code not in codes:
        raise ForgeError(f"{step} failed: HTTP {answer.status_code}")
    try:
        return answer.json() if answer.content else None
    except ValueError as exc:
        raise ForgeError(f"{step} failed: the answer is not JSON") from exc


def upsert(
    session: Any,
    *,
    listing: str,
    item: str,
    verb: str,
    headers: dict[str, str],
    body: str,
    mine: Any,
) -> str:
    """Edit this poster's marked comment, else create one: ``created`` or ``updated``."""
    found = None
    for page in range(1, MAX_PAGES + 1):
        params = {"per_page": 100, "page": page, "limit": 100}
        rows = expect(session.get(listing, headers=headers, params=params), "listing comments")
        if not isinstance(rows, list):
            raise ForgeError("listing comments failed: not a list")
        for row in rows:
            if isinstance(row, dict) and str(row.get("body", "")).startswith(MARKER) and mine(row):
                found = row.get("id")
                break
        if found is not None or len(rows) < 100:
            break
    if found is not None:
        answer = session.request(
            verb, item.format(id=int(found)), headers=headers, json={"body": body}
        )
        expect(answer, "editing the comment")
        return "updated"
    expect(session.post(listing, headers=headers, json={"body": body}), "writing the comment")
    return "created"


__all__ = [
    "MARKER",
    "NAME",
    "ForgeError",
    "client",
    "expect",
    "summary",
    "title",
    "token",
    "upsert",
]
