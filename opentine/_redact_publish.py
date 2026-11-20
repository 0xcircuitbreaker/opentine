"""Publication redaction: home paths, email addresses and the local login (Unreleased).

``opentine-redaction/2`` removes credentials from everything stored. A run that
is *published* (``tine bundle create --redacted-public``, ``tine publish hf``)
also names the machine it was recorded on: home directories, the recorder's
login, people's email addresses. This ruleset, recorded as
``opentine-redaction/2+publish/1``, runs after ``/2`` on every object of a
redacted public copy (:mod:`opentine._redacted_derive`):

* ``path``: ``/root``, ``/home/<u>``, ``/Users/<u>``, ``X:\\Users\\<u>`` (also
  ``/`` and JSON-escaped separators), ``~`` and ``~<u>`` become ``<HOME>``; the
  rest of the path is kept.
* ``email``: an address whose domain ends in a known generic or two-letter
  country TLD becomes ``<EMAIL>``, so ``pnpm@10.33.0``, ``icon@2x.png``,
  ``@click.option`` and ``x@w.shape`` are left alone. An scp-style
  ``user@host:path`` or ``ssh://user@host`` names a login, not a mailbox: its
  user becomes ``<USER>`` unless it is a shared service account (``git``, ...).
* ``user``: an ``actor`` / ``writers`` / ``actors`` value equal to this
  machine's real login name becomes ``<USER>``.

Replacements hold no quote or backslash, so JSON stays JSON. Standard library only.
"""

from __future__ import annotations

import getpass
import re
from collections import Counter
from typing import Any

PUBLISH_RULESET = "opentine-redaction/2+publish/1"
HOME, EMAIL, USER = "<HOME>", "<EMAIL>", "<USER>"
#: Logins that name no person: never treated as "the local user".
GENERIC_LOGINS = frozenset({"", "local", "root", "nobody", "unknown", "user", "admin", "system"})
#: Accounts shared by everyone who uses a host; an ssh login with one is not personal.
SERVICE_ACCOUNTS = frozenset(
    {"git", "hg", "svn", "ubuntu", "ec2-user", "centos", "debian", "admin", "root", "deploy"}
)
ACTOR_KEYS = frozenset({"actor", "actors", "writers"})

_SEP = r"(?:\\\\|\\|/)"
_SEG = r"[^\\/\s\"'`:*?<>|,;()\[\]{}]+"
_END = r"(?=[/\\\s\"'`:,;)\]}]|$)"
_PATH = re.compile(
    r"(?:(?<=file://)|(?<![\w.~/\\-]))/(?:root|home/" + _SEG + r"|Users/" + _SEG + r")" + _END
    + r"|(?<![\w])[A-Za-z]:" + _SEP + r"(?i:users|documents and settings)" + _SEP
    + r"(?:" + _SEG + r"(?: " + _SEG + r"){1,3}(?=" + _SEP + r")|" + _SEG + r")" + _END
    + r"|(?<![\w~/\\.-])~(?:[a-z_][a-z0-9_-]{0,31})?(?=[/\\]|$|[\"'`])"
)  # fmt: skip
#: Generic TLDs an address plausibly uses; any other two-letter label is a ccTLD.
_TLDS = frozenset(
    "com net org edu gov mil int io dev app ai info biz xyz cloud tech online site email "
    "mail name pro page blog team tools systems solutions company agency studio design "
    "network digital media news live world global group services support example test "
    "invalid local internal".split()
)
#: Two-letter labels that are far more often file extensions than countries here.
_NOT_CC = frozenset("js ts py md rb go rs sh cs gz xz so pl pm hs kt ml mk rc".split())
_EMAIL = re.compile(
    r"(?<![\w.%+@/-])([A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9_-])?)"
    r"@((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,24}))"
    r"(?![\w-]|\.[A-Za-z0-9])(:)?"
)
_SSH_USER = re.compile(r"(?:(?<=ssh://)|(?<=sftp://))([A-Za-z0-9._-]{1,64})@(?=[A-Za-z0-9])")


def login() -> str | None:
    """This machine's login name, or ``None`` when it names no person."""
    try:
        return real_login(getpass.getuser())
    except Exception:  # noqa: BLE001 - no login name (containers, services)
        return None


def real_login(name: str) -> str | None:
    return None if name.strip().lower() in GENERIC_LOGINS else name


def _tld_ok(tld: str) -> bool:
    tld = tld.lower()
    return tld in _TLDS or (len(tld) == 2 and tld not in _NOT_CC)


def scrub_text(text: str, *, login: str | None) -> tuple[str, Counter[str]]:
    """*text* with homes, addresses and ssh logins replaced, and the counts by kind."""
    counts: Counter[str] = Counter()

    def path(match: re.Match[str]) -> str:
        counts["path"] += 1
        return HOME

    def ssh(match: re.Match[str]) -> str:
        if match.group(1).lower() in SERVICE_ACCOUNTS:
            return match.group(0)
        counts["user"] += 1
        return USER + "@"

    def email(match: re.Match[str]) -> str:
        local, domain, tld, colon = match.groups()
        if not _tld_ok(tld):
            return match.group(0)
        if colon:  # scp-style user@host:path is an ssh login
            if local.lower() in SERVICE_ACCOUNTS:
                return match.group(0)
            counts["user"] += 1
            return f"{USER}@{domain}:"
        counts["email"] += 1
        return EMAIL

    if "/" in text or "\\" in text or "~" in text:
        text = _PATH.sub(path, text)
    if "@" in text:
        text = _EMAIL.sub(email, text)  # first: its lookbehind skips ``ssh://user@``
        text = _SSH_USER.sub(ssh, text)
    return text, +counts


def scrub_bytes(body: bytes, *, login: str | None) -> tuple[bytes, Counter[str]]:
    """A blob's bytes scrubbed as UTF-8 text; bytes that are not UTF-8 are kept."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return body, Counter()
    clean, counts = scrub_text(text, login=login)
    if login is not None and '"' in clean:
        clean = _json_actors(clean, login, counts)
    return (clean.encode("utf-8"), counts) if counts else (body, counts)


_ACTOR_FIELD = re.compile(r'("(?:actor|actors|writers)"\s*:\s*)("[^"\\]*"|\[[^\]]*\])')


def _json_actors(text: str, login: str, counts: Counter[str]) -> str:
    """The actor rule over a JSON blob's text: ``"actor": "<login>"`` and its lists."""
    quoted = '"' + login.replace("\\", "\\\\").replace('"', '\\"') + '"'

    def field(match: re.Match[str]) -> str:
        found = match.group(2).count(quoted)
        if not found:
            return match.group(0)
        counts["user"] += found
        return match.group(1) + match.group(2).replace(quoted, f'"{USER}"')

    return _ACTOR_FIELD.sub(field, text)


def _actor(value: Any, login: str | None, counts: Counter[str]) -> Any:
    if login is not None and isinstance(value, str) and value == login:
        counts["user"] += 1
        return USER
    if isinstance(value, list):
        items = []
        for item in value:  # a loop, not a comprehension: one frame per level
            items.append(_actor(item, login, counts))
        return items
    return value


def scrub_value(value: Any, *, login: str | None) -> tuple[Any, Counter[str]]:
    """A decoded payload scrubbed throughout, and the counts by kind."""
    counts: Counter[str] = Counter()
    return _walk(value, login, counts), +counts


def _walk(value: Any, login: str | None, counts: Counter[str]) -> Any:
    if isinstance(value, str):
        clean, found = scrub_text(value, login=login)
        counts.update(found)
        return clean
    if isinstance(value, list):
        items = []
        for item in value:  # a loop: one frame per nesting level
            items.append(_walk(item, login, counts))
        return items
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, item in value.items():
            clean_key = _walk(key, login, counts) if isinstance(key, str) else key
            if clean_key in out:
                raise ValueError("publication redaction collapsed distinct object keys")
            if key in ACTOR_KEYS:
                item = _actor(item, login, counts)
            out[clean_key] = _walk(item, login, counts)
        return out
    return value


__all__ = [
    "PUBLISH_RULESET",
    "login",
    "real_login",
    "scrub_bytes",
    "scrub_text",
    "scrub_value",
]
