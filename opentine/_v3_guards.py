"""The two rules the compatibility seam must enforce because the kernel does not.

``kernel.validate_links`` and the repository validators constrain only what the
object *graph* depends on: link lists, ``manifests``, an event's numeric metrics,
a run's status. Every other field of an event, run or annotation may hold any
JSON value and still be stored, by design -- that openness is what lets a newer
writer add a field this build round-trips without understanding. Two
consequences land on the seam that turns a compatibility ``Run`` into v3 objects
and back, and both were found as raw interpreter exceptions rather than
refusals:

* Going in, a str the canonical form cannot encode -- an unpaired UTF-16
  surrogate, which ``json.loads`` accepts from any JS-side ``JSON.stringify``
  that sliced a string mid-emoji -- reached the encoder and raised a bare
  ``UnicodeEncodeError`` from inside redaction, naming a byte position in a
  fragment the caller had no way to locate.
* Coming out, a field the validators permit in *any* shape was read as
  ``dict(value or {})`` or ``value.get(key, {}).get(...)``, which rescues
  *absence* and then raises ``TypeError: 'int' object is not iterable`` or
  ``AttributeError: 'NoneType' object has no attribute 'get'`` on a
  present-but-wrong one. That is a loader crash on an object ``fsck`` calls
  healthy, so it takes out every command at once.

Both rules live here so the object writer (``repository.store``), the
compatibility blob writer (``_blob_guard``) and the run loader
(``repository.runs``) cannot drift apart on them -- the asymmetry shape this
release keeps producing is a rule enforced on one side and assumed on the other.
"""

from __future__ import annotations

from typing import Any

from opentine._canon import _redact
from opentine._unicode_text import assert_unicode_text
from opentine.redaction import redact_value


def guarded_redaction(value: Any, *, where: str, redact: bool = True) -> Any:
    """Redact a v3 payload, refusing text no conforming reader could agree on.

    The order is the ``.tine`` writer's own, and it matters. ``_redact`` replaces
    a credential-shaped field's value outright *without* walking into it, so an
    unencodable secret is gone before any encoder sees it and
    ``_graph_serde.save_run`` -> ``assert_loadable`` accepts that run. Checking
    before redaction would refuse the same run here, reintroducing a write-side
    asymmetry between the two formats. ``redact_value`` is the actual raiser --
    it encodes every string it visits -- so the guard sits between the two
    halves: after the shape redaction that may legitimately drop an unencodable
    secret, before the string scrubber that cannot.

    ``redact=False`` (canonical bytes handed straight back, and raw blobs) still
    gets the guard: ``ObjectEnvelope.create`` canonicalizes regardless, and
    ``kernel.canonical_json`` reports only "nesting or Unicode key is invalid"
    with no path. ``bytes`` payloads are opaque by design and the walk skips
    them, so a raw blob of CESU-8 bytes stores unchanged as it always has.

    ``_redact`` runs on both paths because it is also the shared depth bound, and
    the surrogate walk has none: that walk is iterative by design, so a
    self-referential container makes it loop forever instead of raising, where
    ``canonical_json`` refused one immediately. On the unredacted path its result
    is discarded -- ``redact=False`` stores the payload verbatim, so the guard has
    to read the bytes that will actually be written, credential fields included.
    """
    bounded = _redact(value)
    typed = bounded if redact else value
    assert_unicode_text(typed, where=where)
    return redact_value(typed) if redact else typed


def as_mapping(value: Any) -> dict[str, Any]:
    """A copy of ``value`` when it is a mapping, otherwise an empty one.

    The replacement for ``dict(value or {})`` and ``value.get(key, {})`` on any
    field the validators leave unconstrained. A copy, not the original, because
    that is what the ``dict(...)`` calls this replaces promised: ``Step`` mutates
    the mappings it is handed, and handing it the loaded payload's own dict would
    let a step edit the object cache.
    """
    return dict(value) if isinstance(value, dict) else {}


def text_field(*candidates: Any) -> str:
    """The first non-empty ``str`` among ``candidates``, else ``""``.

    The replacement for ``a or b`` on a field the compatibility ``Run`` declares
    as a ``str`` and the v3 validators leave open. ``payload.get("model") or ...``
    rescued an absent or empty value and then handed a ``dict`` or an ``int``
    straight through to ``Run.model_info``, producing a loaded run this build
    could no longer export: ``validate_run_record`` requires ``run_id`` and
    ``metadata.model_info`` to be strings, so ``run.save()`` refused a run the
    repository had just handed back. The ``.tine`` loader already resolves the
    same field this way (``_graph_serde`` falls back unless the name is a str),
    and the two loaders must agree on what a wrong shape means: fall back to the
    next candidate, and leave the raw field itself untouched for whoever wrote it.
    """
    for value in candidates:
        if isinstance(value, str) and value:
            return value
    return ""
