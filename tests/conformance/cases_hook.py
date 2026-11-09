"""SPEC 8.16 (0.46): the ``opentine-hook/1`` event envelope (docs/spec/hook-1.md).

``hook.normalize`` reads one hook payload -- the generic envelope or a vendor's
own (Claude Code, Codex, Gemini CLI, Antigravity with its ``--event`` hint) --
into the protocol event, or refuses it (``ok: false``). ``hook.respond`` is
what each vendor CLI is answered on stdout at a turn end when steer messages
were delivered: the per-vendor "continue" decision.
"""

from __future__ import annotations

from tests.conformance.cases import VERDICT, Case, Family, V

P = "opentine-hook/1"


def _n(cid: str, intent: str, payload, hint: str | None = None) -> Case:
    return Case(id=f"hook.{cid}", section="8.16", checklist=(8,), op="hook.normalize",
                profile="reader", expect=VERDICT, intent=intent,
                input=V({"payload": payload, "hint": hint}))  # fmt: skip


def _r(cid: str, intent: str, agent: str, steer: list[str]) -> Case:
    return Case(id=f"hook.respond.{cid}", section="8.16", checklist=(8,), op="hook.respond",
                profile="reader", expect=VERDICT, intent=intent,
                input=V({"agent": agent, "steer": steer}))  # fmt: skip


TOOL = {"name": "Bash", "input": {"command": "ls"}, "output": "a\n"}

HOOK = Family(
    "67-hook.json",
    "8.16",
    "hook",
    (
        _n(
            "generic.prompt",
            "the generic envelope, a prompt",
            {"protocol": P, "event": "prompt", "session": "s1", "prompt": "hi", "cwd": "/w"},
        ),
        _n(
            "generic.tool",
            "the generic envelope, a tool call",
            {"protocol": P, "event": "tool", "session": "s1", "tool": TOOL},
        ),
        _n(
            "generic.turn-end",
            "the generic envelope, a turn end",
            {"protocol": P, "event": "turn_end", "session": "s1", "message": "done"},
        ),
        _n(
            "generic.session-end",
            "the generic envelope, a session end",
            {"protocol": P, "event": "session_end", "session": "s1"},
        ),
        _n(
            "generic.unknown-event",
            "an event the protocol does not define is refused",
            {"protocol": P, "event": "pre_tool", "session": "s1"},
        ),
        _n(
            "generic.no-session",
            "an event without a session is refused",
            {"protocol": P, "event": "prompt", "prompt": "hi"},
        ),
        _n(
            "generic.empty-session",
            "an empty session id is refused",
            {"protocol": P, "event": "prompt", "session": ""},
        ),
        _n(
            "generic.session-not-string",
            "a session id that is not a string is refused",
            {"protocol": P, "event": "prompt", "session": 7},
        ),
        _n(
            "generic.session-fallback",
            "an empty `session` falls back to `session_id`",
            {"protocol": P, "event": "prompt", "session": "", "session_id": "s2"},
        ),
        _n(
            "generic.empty-array-session",
            "an empty array is falsy: `session_id` is used",
            {"protocol": P, "event": "prompt", "session": [], "session_id": "s3"},
        ),
        _n(
            "generic.long-session",
            "a session id is cut to 512 code points",
            {"protocol": P, "event": "prompt", "session": "a" * 600},
        ),
        _n(
            "generic.other-protocol",
            "another protocol tag does not name the event",
            {"protocol": "opentine-hook/2", "event": "prompt", "session": "s1"},
        ),
        _n(
            "generic.tool-name-not-string",
            "a non-string tool name is no name",
            {"protocol": P, "event": "tool", "session": "s1", "tool": {"name": 5}},
        ),
        _n(
            "generic.cwd-not-string",
            "a non-string cwd reads as empty",
            {"protocol": P, "event": "prompt", "session": "s1", "cwd": ["/w"]},
        ),
        _n("not-an-object", "a payload that is not an object is refused", ["prompt"]),
        _n(
            "claude.prompt",
            "Claude Code / Codex UserPromptSubmit",
            {
                "hook_event_name": "UserPromptSubmit",
                "session_id": "c1",
                "prompt": "go",
                "cwd": "/repo",
            },
        ),
        _n(
            "claude.tool",
            "Claude Code / Codex PostToolUse",
            {
                "hook_event_name": "PostToolUse",
                "session_id": "c1",
                "tool_name": "Edit",
                "tool_input": {"file_path": "a"},
                "tool_response": {"ok": True},
            },
        ),
        _n(
            "codex.stop",
            "Codex Stop, with last_assistant_message and turn_id",
            {
                "hook_event_name": "Stop",
                "session_id": "x1",
                "turn_id": "t1",
                "last_assistant_message": "done",
                "stop_hook_active": False,
            },
        ),
        _n(
            "claude.session-end",
            "Claude Code SessionEnd",
            {"hook_event_name": "SessionEnd", "session_id": "c1", "reason": "exit"},
        ),
        _n(
            "claude.pre-tool",
            "PreToolUse is not a capture event",
            {"hook_event_name": "PreToolUse", "session_id": "c1", "tool_name": "Bash"},
        ),
        _n(
            "gemini.before-agent",
            "Gemini CLI BeforeAgent is a prompt",
            {"hook_event_name": "BeforeAgent", "session_id": "g1", "prompt": "fix it"},
        ),
        _n(
            "gemini.after-tool",
            "Gemini CLI AfterTool is a tool call",
            {
                "hook_event_name": "AfterTool",
                "session_id": "g1",
                "tool_name": "read_file",
                "tool_input": {"path": "x"},
                "tool_response": {"llmContent": "y"},
            },
        ),
        _n(
            "gemini.after-agent",
            "Gemini CLI AfterAgent (prompt_response) is a turn end",
            {
                "hook_event_name": "AfterAgent",
                "session_id": "g1",
                "prompt": "fix it",
                "prompt_response": "fixed",
                "stop_hook_active": False,
            },
        ),
        _n(
            "hint.event",
            "a payload without its event name takes the --event hint",
            {"session_id": "d1", "prompt": "hi"},
            "UserPromptSubmit",
        ),
        _n(
            "hint.ignored",
            "the hint never overrides a named event",
            {"hook_event_name": "Stop", "session_id": "d1"},
            "UserPromptSubmit",
        ),
        _n(
            "antigravity.prompt",
            "Antigravity PreInvocation, keyed by conversationId",
            {"conversationId": "ag1", "lastUserInput": "hi", "workspacePaths": ["/ws"]},
            "PreInvocation",
        ),
        _n(
            "antigravity.tool",
            "Antigravity PostToolUse, toolCall.name",
            {"conversationId": "ag1", "toolCall": {"name": "run", "args": {}}},
            "PostToolUse",
        ),
        _n(
            "antigravity.no-hint",
            "an Antigravity payload without --event is refused",
            {"conversationId": "ag1", "lastUserInput": "hi"},
        ),
        _r("claude-code", "Claude Code's Stop continues on block", "claude-code", ["more tests"]),
        _r("claude-code.none", "no steer: Claude Code is told to stay quiet", "claude-code", []),
        _r("codex", "Codex's Stop continues on block", "codex", ["more tests"]),
        _r("codex.none", "no steer: Codex gets an empty object", "codex", []),
        _r("gemini", "Gemini CLI's AfterAgent continues on deny", "gemini", ["more tests"]),
        _r("gemini.joined", "several messages are joined by a blank line", "gemini", ["a", "b"]),
        _r("copilot", "Copilot CLI is not steered (recorded only)", "copilot", ["more tests"]),
    ),
)

FAMILIES = (HOOK,)
