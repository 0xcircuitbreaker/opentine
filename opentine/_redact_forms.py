"""Credentials recognised by the command line or file format that carries them.

A stdlib-only leaf of ``redaction`` (the module line cap). The shapes in
``_redact_shapes`` are vendor token prefixes; these are the places a secret sits
under no recognisable name of its own: ``curl -u user:PW``, ``mysql -pPW``,
``redis-cli -a PW``, a ``.netrc`` ``password`` word, an ``Authorization:`` header
in the middle of a log line, a docker ``"auth"`` blob, ``<password>`` in XML, a
kubeconfig's base64-wrapped private key. Every pattern is anchored on a fixed
literal and every run is bounded, so a scan stays linear in its input.
"""

from __future__ import annotations

import base64
import binascii
import re

from opentine._redact_edits import Step, run, sub_step
from opentine._redact_tails import cli_tail, header_tail, netrc_tail, pwd_tail

_R = b"[REDACTED]"
# A header name mid-line ("12:00:01 DEBUG send: Authorization: Basic ...", "> Cookie:
# ...", "--header=Authorization:..."), or after a literal "\n" escape in a repr'd
# request. The value runs to the end of the line, a quote or a backslash escape.
_INLINE_HEADER = re.compile(
    rb"(?i)(?:(?<![A-Za-z0-9_-])|(?<=\\[nrt]))"
    rb"((?:proxy-)?authorization|set-cookie|cookie)([ \t]*[:=][ \t]*)([^\r\n'\"\\]{1,4096})"
)
# ``MYSQL_PWD=...`` / ``LDAP_BIND_PW=...`` / ``app.db.pwd: ...`` / ``--db-pwd=...``: a
# *prefixed* pwd or pw only, so a shell's own ``PWD=/home/user`` (a working
# directory) is kept. ``REDISCLI_AUTH`` is redis-cli's documented password variable.
# The value may be quoted (``'x'``, ``"x"``, or ``\\"x\\"`` inside a JSON string; the
# quotes are kept) or bare. A bare value is a run of whole escape pairs, so it never
# ends between a backslash and the character it escapes and never takes a raw quote:
# JSON around it stays parseable.
_PWD_NAME = (
    rb"[A-Za-z0-9]{1,64}(?:[_.-][A-Za-z0-9]{1,64}){0,8}[_.-]pwd"
    # A bare "pw" suffix only after "_" or "-" (env and flag names): "host.pw" is a
    # real TLD, and "example.pw:8443/api" is a host and port, not a credential.
    rb"|[A-Za-z0-9]{1,64}(?:[_-][A-Za-z0-9]{1,64}){0,8}[_-]pw"
    rb"|rediscli_auth"
)
# A raw quote opens a value only when a non-space, non-structural character follows
# it, so the closing quote of a JSON string ("MYSQL_PWD=", "b": 1) is never one.
_FIRST = rb"[^\s\"'\\,:;{}\[\]]"
_PWD_VALUE = (
    rb"(?:(?P<qj>\\\")(?P<vj>(?:[^\\\"\r\n]|\\(?!\")[^\"\r\n]){1,512})(?P<cj>\\\")?"
    rb"|(?P<qd>\")(?P<vd>(?=" + _FIRST + rb")(?:[^\"\\\r\n]|\\[^\r\n]){1,512})(?P<cd>\")"
    rb"|(?P<qs>')(?P<vs>[^'\"\\\r\n]{1,512})(?P<cs>')?"
    rb"|(?P<bare>(?:[^\s,;\"'\\]|\\[^\s\"']){1,512}))"
)
_PREFIXED_PWD = re.compile(
    rb"(?i)(?<![A-Za-z0-9_.-])(?P<name>(?:--?)?(?:" + _PWD_NAME + rb"))"
    rb"(?P<sep>[ \t]*[:=][ \t]*)" + _PWD_VALUE
)
# ``--db-pwd x``: a flag takes its value after a space too.
_FLAG_PWD = re.compile(
    rb"(?i)(?<![A-Za-z0-9_.-])(?P<name>--?(?:" + _PWD_NAME + rb"))(?P<sep>[ \t]+)"
    rb"(?![-=:])" + _PWD_VALUE
)
# ``x.pwd:8443/api``: a host label ending ".pwd" glued to a port is a host and port,
# not a credential. Only that shape -- ":" with no space, after a dotted name -- is
# exempt; an assignment (``MYSQL_PWD=2024/x``) or ``key: value`` never is.
_HOST_PORT = re.compile(rb"\d{1,5}(?:/|$)")


def _quoted(match: re.Match[bytes], head: bytes, keys: tuple[tuple[str, str], ...]) -> bytes:
    groups = match.groupdict()
    for opening, closing in keys:
        if groups.get(opening) is not None:
            return head + groups[opening] + _R + (groups[closing] or b"")
    return head + _R


def _prefixed_pwd(match: re.Match[bytes]) -> bytes:
    name, separator, bare = match.group("name", "sep", "bare")
    if separator == b":" and b"." in name and bare is not None and _HOST_PORT.match(bare):
        return match.group(0)
    return _quoted(match, name + separator, (("qj", "cj"), ("qd", "cd"), ("qs", "cs")))


# A CLI password is quoted (``-p'x'``, ``-a "x"``; the quotes are kept) or bare. A
# bare one is a run of whole escape pairs, so it never ends between a backslash and
# the character it escapes. ``mysql -P3307`` is a port: the ``-p`` flag is
# case-sensitive while the program name is not.
# A command starts a word, or follows a literal ``\\n``/``\\t`` escape: in a repr or
# a logged command string ``set -e\\nmysql -px`` has an ``n`` before ``mysql``, so a
# plain ``\\b`` never matched there.
_START = rb"(?:(?<![A-Za-z0-9_-])|(?<=\\[nrt]))"
_QVAL = (
    rb"(?:(?P<q>['\"])(?P<v>[^'\"\r\n]{1,512})(?P=q)"
    rb"|(?P<bare>(?:[^\s'\"\\]|\\[^\s\"']){1,512}))"
)
_CURL_USER = re.compile(
    rb"(?<![A-Za-z0-9_-])(?P<head>-u[ \t]+|--user[ \t=]+)"
    rb"(?:(?P<q>['\"])(?P<user>[^:'\"\r\n]{1,256}:)[^'\"\r\n]{1,512}(?P=q)"
    rb"|(?P<buser>[^\s:'\"]{1,256}:)(?:[^\s'\"\\]|\\[^\s\"']){1,512})"
)
_MYSQL = re.compile(
    rb"(?P<head>" + _START + rb"(?i:mysql(?:dump|admin|import|show)?)\b[^\r\n]{0,512}?[ \t]-p)"
    rb"(?![-\s])" + _QVAL
)
_REDIS = re.compile(
    rb"(?P<head>" + _START + rb"(?i:redis-cli)\b[^\r\n]{0,512}?[ \t]-a[ \t]+)" + _QVAL
)
_DOCKER_LOGIN = re.compile(
    rb"(?P<head>"
    + _START
    + rb"(?i:docker)[ \t]+(?i:login)\b[^\r\n]{0,512}?[ \t](?:-p|--password)[ \t=]+)"
    + _QVAL
)


def _cli(match: re.Match[bytes]) -> bytes:
    quote = match.group("q")
    return match.group("head") + (quote + _R + quote if quote else _R)


def _curl(match: re.Match[bytes]) -> bytes:
    quote = match.group("q")
    if quote:
        return match.group("head") + quote + match.group("user") + _R + quote
    return match.group("head") + match.group("buser") + _R


# A netrc token is quoted (``password "it's p@ss"``, honoured by Python's netrc and
# curl >= 7.84; ``\\"`` when the text sits in a JSON string) or runs to whitespace, a
# quote or a backslash. A raw quote counts only when a non-space, non-structural
# character follows it and its own closing quote comes before the end of the line,
# so the closing quote of a JSON string ("...password ", "b": 1) is never taken for
# an opening one. A JSON-escaped token runs to its own escaped quote, honouring
# netrc's escaped quotes and backslashes, and never past a raw ``"`` (the end of the
# JSON string). An unquoted value never *ends* on ``,;]}``: a closer right after it
# is structure, one inside it is password.
_NETRC_VALUE = (
    rb"(?:(?P<oj>\\\")(?P<bj>(?:\\\\(?:\\\\|\\\")|[^\\\"\r\n]|\\(?!\")[^\"\r\n]){1,512})"
    rb"(?P<cj>\\\")?"
    rb"|(?P<od>\")(?P<bd>(?=" + _FIRST + rb")(?:[^\"\\\r\n]|\\[^\r\n]){1,512})(?P<cd>\")"
    rb"|(?P<os>')(?P<bs>(?=" + _FIRST + rb")(?:[^'\"\\\r\n]|\\[^\"\r\n]){1,512})(?P<cs>')"
    rb"|(?P<bare>[^\s'\"\\]{0,511}[^\s'\"\\,;\]}]))"
)
_NETRC = re.compile(
    rb"(?i)(?P<head>\b(?:login|machine)[ \t]+[^\s'\"\\,;{}\[\]]{1,256}[ \t]+"
    rb"(?:password|passwd)[ \t]+)" + _NETRC_VALUE
)
# On a line of its own (a .netrc file): a quoted token must be the rest of the line
# (closing quote, then only blanks), a bare one the line's only word -- so prose such
# as ``password is required`` or ``Password "must be 8 chars" is the rule`` is kept.
_NETRC_LINE = re.compile(
    rb"(?im)^(?P<head>[ \t]*(?:password|passwd)[ \t]+)"
    rb"(?:(?P<od>\")(?P<bd>(?:[^\"\\\r\n]|\\[^\r\n]){1,1023})(?P<cd>\")"
    rb"|(?P<os>')(?P<bs>(?:[^'\\\r\n]|\\[^\r\n]){1,1023})(?P<cs>')"
    rb"|(?P<bare>\S{1,512}))[ \t]*\r?$"
)
_NETRC_QUOTES = (("oj", "cj"), ("od", "cd"), ("os", "cs"))


def _netrc(match: re.Match[bytes]) -> bytes:
    return _quoted(match, match.group("head"), _NETRC_QUOTES)


_DOCKER_AUTH = re.compile(rb"(?i)([\"']auth[\"'][ \t]*:[ \t]*[\"'])([A-Za-z0-9+/=]{8,4096})([\"'])")
_XML_SECRET = re.compile(
    rb"(?i)(<(password|passwd|secret|token|apikey|api_key|client_secret)>)([^<]{1,4096})(</\2>)"
)
# A password containing "/" ("postgres://u:pa/ss@db"), which the plain userinfo
# shape stops at. The host after "@" must look like a host, and a password that is
# a port followed by a path ("host:8080/@scope") is left alone.
_URL_SLASH_PASSWORD = re.compile(
    rb"(?i)\b([a-z][a-z0-9+.-]{1,20}://[^\s/:@'\"<>]{1,256}:)((?!\d{1,5}/)[^\s@'\"<>]{1,256})"
    rb"(@[A-Za-z0-9.-]{1,253}(?::\d{1,5})?(?=[/?#\s'\"<>]|$))"
)
# base64 of "-----BEGIN": a PEM block wrapped once more (kubeconfig client-key-data),
# on one line or wrapped at any width (``base64`` 76, ``openssl base64`` 64 columns):
# the continuation lines are part of the match, so the whole key goes, not line one.
# A short line counts only with padding, so the word after a key block is kept.
# Line breaks between wrapped base64 lines: real ones, or the ``\\n`` / ``\\r\\n``
# escapes of a key that sits inside a JSON string (tool-call arguments, dumped output).
_BREAK = rb"(?:\r?\n|(?:\\r)?\\n|\\r)"
_B64_PEM = re.compile(
    rb"LS0tLS1CRUdJTi[A-Za-z0-9+/]{16,}={0,2}"
    rb"(?:" + _BREAK + rb"[ \t]{0,64}"
    rb"(?:[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9+/]{2,15}={1,2})"
    rb"(?=[ \t]*(?:" + _BREAK + rb"|['\"]|$)))*"
)
_NOT_B64 = re.compile(rb"[^A-Za-z0-9+/=]")


def _b64_private_key(match: re.Match[bytes]) -> bytes:
    run = match.group(0)
    # Decode the first wrapped line (it holds the whole BEGIN marker at any common
    # width); when it will not decode, redact anyway: the block starts "-----BEGIN".
    first = _NOT_B64.sub(b"", re.split(_BREAK, run, maxsplit=1)[0])
    try:
        decoded = base64.b64decode(first[: len(first) // 4 * 4])
    except (binascii.Error, ValueError):
        return _R
    if b"PRIVATE KEY" in decoded:
        return _R
    # A marker longer than the first line (a narrow wrap): decode the joined body.
    body = _NOT_B64.sub(b"", re.sub(_BREAK, b"", run))
    try:
        joined = base64.b64decode(body[: len(body) // 4 * 4][:256])
    except (binascii.Error, ValueError):
        return _R
    return _R if b"PRIVATE KEY" in joined.split(b"\n", 1)[0] else run


#: A base64-wrapped private key, whole. ``redaction`` runs it first, next to the PEM
#: step: a value rule that took the first wrapped line (``SSH_PRIVATE_KEY=LS0t…``)
#: would leave the continuation lines with no anchor, so the key body survived.
B64_KEY_STEP: Step = sub_step(_B64_PEM, _b64_private_key)

#: ``redact_forms`` as ordered steps (after ``B64_KEY_STEP``), shared with ``redaction``.
FORM_STEPS: list[Step] = [
    sub_step(_INLINE_HEADER, lambda m: m.group(1) + m.group(2) + _R, header_tail),
    sub_step(_PREFIXED_PWD, _prefixed_pwd, pwd_tail),
    sub_step(_FLAG_PWD, _prefixed_pwd, pwd_tail),
    sub_step(_CURL_USER, _curl, cli_tail),
    sub_step(_MYSQL, _cli, cli_tail),
    sub_step(_REDIS, _cli, cli_tail),
    sub_step(_DOCKER_LOGIN, _cli, cli_tail),
    sub_step(_NETRC, _netrc, netrc_tail),
    sub_step(_NETRC_LINE, _netrc),
    sub_step(_DOCKER_AUTH, lambda m: m.group(1) + _R + m.group(3)),
    sub_step(_XML_SECRET, lambda m: m.group(1) + _R + m.group(4)),
    sub_step(_URL_SLASH_PASSWORD, lambda m: m.group(1) + _R + m.group(3)),
]


def redact_forms(value: bytes) -> bytes:
    return run(value, [B64_KEY_STEP, *FORM_STEPS])


__all__ = ["B64_KEY_STEP", "FORM_STEPS", "redact_forms"]
