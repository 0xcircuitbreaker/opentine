"""Linear, bounded visible-text extraction for untrusted HTML."""

from __future__ import annotations

from html.parser import HTMLParser


class _VisibleText(HTMLParser):
    def __init__(self, limit: int):
        super().__init__(convert_charrefs=True)
        self.limit = limit
        self.hidden = 0
        self.parts: list[str] = []
        self.length = 0

    def _append(self, value: str) -> None:
        if self.hidden or self.length >= self.limit:
            return
        value = value[: self.limit - self.length]
        self.parts.append(value)
        self.length += len(value)

    def handle_starttag(self, tag: str, attrs) -> None:
        del attrs
        if tag.casefold() in {"script", "style"}:
            self.hidden += 1
        else:
            self._append(" ")

    def handle_startendtag(self, tag: str, attrs) -> None:
        del tag, attrs
        self._append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() in {"script", "style"} and self.hidden:
            self.hidden -= 1
        else:
            self._append(" ")

    def handle_data(self, data: str) -> None:
        self._append(data)


def visible_text(value: str, limit: int) -> str:
    """Extract visible text in linear time, retaining at most ``limit`` characters."""
    if limit < 1:
        raise ValueError("text output limit must be positive")
    parser = _VisibleText(len(value) + 1)
    parser.feed(value)
    parser.close()
    return " ".join("".join(parser.parts).split())[:limit]
