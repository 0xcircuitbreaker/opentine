"""The OpenTine conformance vector suite: authored cases, adapter, generator.

``cases_*`` declares every case *and its disposition* by hand. ``adapter``
answers each case through the reference implementation. ``generate`` fills in
every expected byte string, oid, digest and verdict from that answer and
**refuses to emit** when observation disagrees with the declaration, so a
behaviour change cannot launder itself into a new "correct" vector.
"""
