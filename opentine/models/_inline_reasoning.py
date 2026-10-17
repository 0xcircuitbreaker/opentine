"""Reasoning that a server leaves inline in the answer text.

Many local runtimes return a reasoning model's thinking *inside* ``content``
instead of in ``reasoning_content``: ``<think>…</think>`` (Qwen, DeepSeek-R1,
MiniMax, TGI, llama-cpp-python, llama.cpp ``--reasoning-format none``),
``[THINK]…[/THINK]`` (Magistral), or raw Harmony channels (gpt-oss:
``<|channel|>analysis<|message|>…<|end|>…<|channel|>final<|message|>…``). Recorded
as-is, the thinking became the run's answer text (audit round 3, local research).

Only a *leading* block is split off -- an answer that merely mentions ``<think>``
further down is left alone -- and the split is the same for a whole message and
for a stream fed piece by piece, so ``complete`` and ``stream`` record alike.
"""

from __future__ import annotations

from typing import Any

_PAIRS = (("<think>", "</think>"), ("[THINK]", "[/THINK]"))
_HARMONY_OPEN = "<|channel|>analysis<|message|>"
_HARMONY_CLOSE = "<|end|>"
_HARMONY_FINAL = "<|channel|>final<|message|>"
#: What the stream holds while waiting for Harmony's final channel. Past it the
#: text is treated as the answer (as :func:`split_inline` treats a message with no
#: final channel), so an endless analysis-to-final gap costs bounded memory.
GAP_LIMIT = 64 * 1024
#: Leading whitespace kept before a possible opener; more is collapsed.
_WHITESPACE_LIMIT = 64
#: ``(opener, closer, harmony)`` -- Harmony may arrive with its ``<|start|>`` header.
_OPENERS = (
    *((opener, closer, False) for opener, closer in _PAIRS),
    (_HARMONY_OPEN, _HARMONY_CLOSE, True),
    ("<|start|>assistant" + _HARMONY_OPEN, _HARMONY_CLOSE, True),
)


def _harmony_answer(rest: str) -> str:
    index = rest.find(_HARMONY_FINAL)
    answer = rest[index + len(_HARMONY_FINAL) :] if index >= 0 else rest
    for marker in ("<|return|>", "<|end|>"):
        answer = answer.removesuffix(marker)
    return answer


def split_inline(text: str) -> tuple[str, str]:
    """``(answer, reasoning)`` for a complete message; reasoning is "" if none."""
    if not isinstance(text, str) or not text:
        return text, ""
    stripped = text.lstrip()
    for opener, closer, harmony in _OPENERS:
        if stripped.startswith(opener):
            body = stripped[len(opener) :]
            end = body.find(closer)
            if end < 0:  # unterminated: everything so far is thinking
                return "", body
            rest = body[end + len(closer) :]
            return (_harmony_answer(rest) if harmony else rest).lstrip(), body[:end]
    return text, ""


class InlineReasoningStream:
    """The streaming twin of :func:`split_inline`: feed deltas, get both parts."""

    def __init__(self) -> None:
        self._state = "start"  # start -> thinking -> (harmony gap) -> answer
        self._pending = ""
        self._closer = ""
        self._harmony = False
        self._scanned = 0  # gap text already searched for the final marker

    def feed(self, delta: str) -> tuple[str, str]:
        """``(answer_delta, reasoning_delta)`` for one content delta."""
        if not delta:
            return "", ""
        self._pending += delta
        if self._state == "start":
            head = self._pending.lstrip()
            match = next((item for item in _OPENERS if head.startswith(item[0])), None)
            if match is None:
                if any(item[0].startswith(head) for item in _OPENERS):
                    # Bounded: *head* is a prefix of an opener; whitespace is capped.
                    lead = self._pending[: len(self._pending) - len(head)]
                    self._pending = lead[-_WHITESPACE_LIMIT:] + head
                    return "", ""  # may still become an opener
                self._state = "answer"
            else:
                opener, self._closer, self._harmony = match
                self._pending, self._state = head[len(opener) :], "thinking"
        if self._state == "thinking":
            end = self._pending.find(self._closer)
            if end < 0:
                cut = max(0, len(self._pending) - len(self._closer) + 1)
                reasoning, self._pending = self._pending[:cut], self._pending[cut:]
                return "", reasoning
            reasoning = self._pending[:end]
            self._pending = self._pending[end + len(self._closer) :].lstrip()
            self._state = "gap" if self._harmony else "answer"
            answer = "" if self._harmony else self._take()
            return answer, reasoning
        if self._state == "gap":
            # Search only what is new, plus a marker-length overlap: linear overall.
            start = max(0, self._scanned - len(_HARMONY_FINAL) + 1)
            index = self._pending.find(_HARMONY_FINAL, start)
            if index < 0:
                self._scanned = len(self._pending)
                if len(self._pending) <= GAP_LIMIT:
                    return "", ""
                self._state = "answer"  # no final channel in sight: it is the answer
            else:
                self._pending = self._pending[index + len(_HARMONY_FINAL) :]
                self._state = "answer"
        return self._take(), ""

    def _take(self) -> str:
        # A Harmony answer may end in ``<|return|>``: hold back what could be it.
        keep = len("<|return|>") if self._harmony and self._state == "answer" else 0
        cut = max(0, len(self._pending) - keep)
        taken, self._pending = self._pending[:cut], self._pending[cut:]
        return taken

    def flush(self) -> tuple[str, str]:
        pending, self._pending = self._pending, ""
        if self._state == "start":
            return pending, ""
        if self._state == "thinking":
            return "", pending
        if self._state == "gap" or self._harmony:
            return _harmony_answer(pending), ""
        return pending, ""


def route(
    stream: InlineReasoningStream, text_buffer: Any, reasoning_buffer: Any, text: str, other: str
) -> list[dict[str, str]]:
    """Feed one delta's text (and any structured reasoning) into the two buffers."""
    answer, inline = stream.feed(text) if text else ("", "")
    return _events(text_buffer, reasoning_buffer, answer, other or inline)


def finish(stream: InlineReasoningStream, text_buffer: Any, reasoning_buffer: Any):
    """Flush what the splitter held back at the end of a stream."""
    return _events(text_buffer, reasoning_buffer, *stream.flush())


def _events(text_buffer: Any, reasoning_buffer: Any, answer: str, reasoning: str):
    events: list[dict[str, str]] = []
    if added := text_buffer.add(answer):
        events.append({"type": "text_delta", "text": added})
    if added := reasoning_buffer.add(reasoning):
        events.append({"type": "reasoning_delta", "text": added})
    return events


__all__ = ["InlineReasoningStream", "finish", "route", "split_inline"]
