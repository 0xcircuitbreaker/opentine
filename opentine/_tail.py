"""Follow run events as they become durable: the engine behind ``tine log -f`` and ``GET tail``.

A :class:`Follower` watches a set of run refs. Each :meth:`Follower.poll` reads
the refs, and for every ref whose run grew, yields the new events in order as
``tine-tail/1`` rows. Refs move only after the objects they name are durable
(the write-batch rule), so an event is shown only when its ref already points
past it *and* its bytes are readable; an event whose bytes are not readable yet
is held back and retried on the next poll, never shown.

Every event row carries its own verification status, checked when it is shown:

* ``verified``: the stored bytes hash to the event id, the payload is well
  formed and every object it links (parents, blobs) is present;
* ``unverified``: the bytes hash to the id, but a linked object is not held
  here (a shallow fetch, a purge), so the event is not claimed as verified;
* ``invalid``: the bytes do not decode to the id or the payload is malformed.

A ref whose run no longer extends the run the follower last saw (a rewind, a
forced move) is reported by one ``rewrite`` row, and following continues from
the new tip; the rewritten history is not replayed. A position (:meth:`cursor`)
is a short opaque string, so a client can resume where it stopped.
"""

from __future__ import annotations

import base64
import zlib
from collections.abc import Callable
from typing import Any

from opentine import _json_shallow
from opentine.kernel import KernelError, ObjectEnvelope, canonical_json, validate_links

FORMAT = "tine-tail/1"
RUN_SPACES = ("heads/", "experiments/", "promotions/", "tags/", "remotes/")
MAX_REFS = 1024
MAX_CURSOR = 16_384
MAX_CURSOR_JSON = 256 * 1024
_CURSOR_PREFIX = "c1."
_MISSING = (KeyError, FileNotFoundError, LookupError)


def row(row_type: str, /, **fields: Any) -> dict[str, Any]:
    """One ``tine-tail/1`` row; absent fields are ``null`` so every row has one shape."""
    base: dict[str, Any] = {
        "format": FORMAT,
        "type": row_type,
        "ref": None,
        "run_id": None,
        "index": None,
        "event_id": None,
        "kind": None,
        "status": None,
        "verified": False,
        "time_unix": None,
        "detail": None,
    }
    base.update(fields)
    return base


def check_event(repo: Any, oid: str) -> tuple[str, dict[str, Any]] | None:
    """``(status, payload)`` for a stored event, or ``None`` while its bytes are not readable."""
    try:
        raw = repo.raw(oid)
    except _MISSING:
        return None
    try:
        envelope = ObjectEnvelope.decode(raw, oid)
        if envelope.object_type != "event":
            raise KernelError("not an event")
        payload = envelope.payload()
        validate_links(envelope, None)
    except (KernelError, ValueError, TypeError):
        return "invalid", {}
    try:
        validate_links(envelope, repo._link_exists)
    except (KernelError, ValueError):
        return "unverified", payload
    return "verified", payload


def _run_events(repo: Any, oid: str) -> list[str] | None:
    """The event list of run *oid*, or ``None`` when it is not readable (yet) or not a run."""
    try:
        envelope = ObjectEnvelope.decode(repo.raw(oid), oid)
        events = envelope.payload().get("events") if envelope.object_type == "run" else None
    except (*_MISSING, KernelError, ValueError):
        return None
    if not isinstance(events, list) or not all(isinstance(e, str) for e in events):
        return None
    return events


def encode_cursor(positions: dict[str, tuple[int, str | None]]) -> str:
    data = {name: [count, (last or "")[-12:]] for name, (count, last) in sorted(positions.items())}
    packed = zlib.compress(canonical_json(data), 9)
    return _CURSOR_PREFIX + base64.urlsafe_b64encode(packed).decode().rstrip("=")


def decode_cursor(text: str) -> dict[str, tuple[int, str]]:
    """The positions of a cursor; ``ValueError`` for anything this follower did not write."""
    if not text.startswith(_CURSOR_PREFIX) or len(text) > MAX_CURSOR:
        raise ValueError("not a tail cursor")
    body = text[len(_CURSOR_PREFIX) :]
    try:
        packed = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        inflater = zlib.decompressobj()
        raw = inflater.decompress(packed, MAX_CURSOR_JSON)
        if inflater.unconsumed_tail or not inflater.eof:
            raise ValueError("tail cursor is too large")
        value = _json_shallow.loads(raw.decode("utf-8"), limit=4)
    except (ValueError, zlib.error, UnicodeDecodeError) as exc:
        raise ValueError("not a tail cursor") from exc
    if not isinstance(value, dict) or len(value) > MAX_REFS:
        raise ValueError("not a tail cursor")
    out: dict[str, tuple[int, str]] = {}
    for name, item in value.items():
        ok = isinstance(item, list) and len(item) == 2 and type(item[0]) is int
        if not ok or item[0] < 0 or not isinstance(item[1], str):
            raise ValueError("not a tail cursor")
        out[name] = (item[0], item[1])
    return out


class Follower:
    """New durable events of *names* (or of every run ref, when *names* is ``None``).

    *refs* returns the current ``{name: oid}`` listing; *backlog* events per ref
    already there at the start are shown first; *resume* is a :meth:`cursor`
    string to continue from instead; *allow* may hide objects (a per-object read
    policy): a hidden event is skipped, never shown.
    """

    def __init__(
        self,
        repo: Any,
        refs: Callable[[], dict[str, str]],
        *,
        names: list[str] | None = None,
        backlog: int = 0,
        resume: str | None = None,
        allow: Callable[[str], bool] | None = None,
    ):
        self.repo, self._refs, self._names = repo, refs, names
        self._allow = allow
        self._pos: dict[str, tuple[str | None, int, str | None]] = {}
        if resume is not None:
            for name, (count, tail) in decode_cursor(resume).items():
                self._pos[name] = (None, count, tail or None)
            return
        for name, oid in self._selected().items():
            events = _run_events(repo, oid) or []
            count = max(0, len(events) - max(0, backlog))
            self._pos[name] = (None, count, events[count - 1] if count else None)

    def _selected(self) -> dict[str, str]:
        listing = self._refs()
        if self._names is not None:
            chosen = {n: listing[n] for n in self._names if n in listing}
        else:
            chosen = {n: o for n, o in listing.items() if n.startswith(RUN_SPACES)}
        picked = sorted(n for n, o in chosen.items() if isinstance(o, str) and o.startswith("run:"))
        return {name: chosen[name] for name in picked[:MAX_REFS]}

    def cursor(self) -> str:
        return encode_cursor({n: (count, last) for n, (_, count, last) in self._pos.items()})

    def poll(self, limit: int = 1000) -> list[dict[str, Any]]:
        """Up to *limit* new rows, oldest first per ref; refs in name order."""
        rows: list[dict[str, Any]] = []
        for name, oid in self._selected().items():
            if len(rows) >= limit:
                break
            seen, count, last = self._pos.get(name, (None, 0, None))
            if seen == oid:
                continue
            events = _run_events(self.repo, oid)
            if events is None:
                continue  # the run is not readable yet: the next poll retries
            if count and (
                count > len(events) or not (events[count - 1] or "").endswith(last or "")
            ):
                rows.append(row("rewrite", ref=name, run_id=oid, index=len(events)))
                count = len(events)
            done = True
            while count < len(events):
                if len(rows) >= limit:
                    done = False
                    break
                event = events[count]
                if self._allow is not None and not self._allow(event):
                    count += 1
                    continue
                checked = check_event(self.repo, event)
                if checked is None:
                    done = False  # not durable here yet: never shown, retried next poll
                    break
                status, payload = checked
                time_unix = payload.get("time_unix")
                rows.append(
                    row(
                        "event",
                        ref=name,
                        run_id=oid,
                        index=count,
                        event_id=event,
                        kind=payload.get("kind") if isinstance(payload.get("kind"), str) else None,
                        status=status,
                        verified=status == "verified",
                        time_unix=time_unix if type(time_unix) in (int, float) else None,
                    )
                )
                count += 1
            last = events[count - 1] if count else None
            self._pos[name] = (oid if done else None, count, last)
        return rows


__all__ = ["FORMAT", "MAX_REFS", "Follower", "check_event", "decode_cursor", "encode_cursor", "row"]
