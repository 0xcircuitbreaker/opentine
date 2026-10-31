#!/usr/bin/env python3
"""Render the README's animated SVG assets deterministically (stdlib only).

Each asset is a self-contained SVG animated with CSS @keyframes: no scripts,
no external fonts, so GitHub renders it inside an ``<img>`` tag. Terminal
output in the hero mirrors real ``tine run`` / ``tine replay --verify`` output.

    python scripts/render_readme_svgs.py            # write docs/assets/*.svg
    python scripts/render_readme_svgs.py --check    # fail if assets are stale
"""

from __future__ import annotations

import argparse
import random
import sys
from collections.abc import Sequence
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "docs" / "assets"

MONO = "ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'Liberation Mono',monospace"
SANS = "system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
BG, CARD_TOP, CARD_BOT, BORDER = "#080c14", "#111827", "#090d16", "#1f2a3c"
TEXT, MUTED, DIM = "#ecf0f6", "#8b94a5", "#5d677b"
GOLD, GOLD_HI, TEAL, GREEN, BLUE = "#d4a574", "#f1cf9f", "#2dd4bf", "#34d399", "#60a5fa"
EASE = "cubic-bezier(.22,1,.36,1)"

Seg = tuple[str, str]  # (text, color)


def fmt(value: float) -> str:
    return f"{value:.2f}".rstrip("0").rstrip(".")


class Timeline:
    """Collects one keyframe rule per animated element on a shared loop."""

    def __init__(self, loop: float, fade_out: float) -> None:
        self.loop, self.fade_out, self.rules = loop, fade_out, []

    def pct(self, t: float) -> str:
        return fmt(min(max(t / self.loop * 100, 0), 100)) + "%"

    def add(self, frames: Sequence[tuple[float, str]], extra: str = "") -> str:
        name = f"a{len(self.rules)}"
        body = "".join(f"{self.pct(t)}{{{css}}}" for t, css in frames)
        self.rules.append(
            f"@keyframes {name}{{{body}}}"
            f".{name}{{animation:{name} {fmt(self.loop)}s {EASE} infinite;{extra}}}"
        )
        return name

    def show(self, t: float, fade: float = 0.3, dy: float = 0, scale: float = 1) -> str:
        """Hidden until ``t``, eased in over ``fade``, held, then faded at loop end."""
        hidden = "opacity:0"
        if dy or scale != 1:
            hidden += f";transform:translateY({fmt(dy)}px) scale({fmt(scale)})"
        shown = "opacity:1;transform:none"
        out = self.loop - self.fade_out
        extra = "transform-box:fill-box;transform-origin:center" if scale != 1 else ""
        frames = [(0, hidden), (t, hidden), (t + fade, shown), (out, shown), (self.loop, hidden)]
        return self.add(frames, extra)

    def style(self) -> str:
        reduce = "@media (prefers-reduced-motion:reduce){*{animation:none!important}}"
        return "<style>" + "".join(self.rules) + reduce + "</style>"


def text(
    x: float,
    y: float,
    segs: Sequence[Seg],
    *,
    size: float,
    cls: str = "",
    font: str = "m",
    weight: str = "",
    anchor: str = "",
) -> str:
    attrs = f' class="{font} {cls}"'.replace(' "', '"')
    if weight:
        attrs += f' font-weight="{weight}"'
    if anchor:
        attrs += f' text-anchor="{anchor}"'
    spans = "".join(f'<tspan fill="{c}">{escape(s)}</tspan>' for s, c in segs)
    return f'<text x="{fmt(x)}" y="{fmt(y)}" font-size="{fmt(size)}"{attrs}>{spans}</text>'


def document(
    width: int, height: int, title: str, defs: str, body: Sequence[str], style: str
) -> str:
    fonts = f"<style>.m{{font-family:{MONO}}}.s{{font-family:{SANS}}}</style>"
    card = (
        f'<rect width="{width}" height="{height}" rx="18" fill="{BG}"/>'
        f'<rect x="1" y="1" width="{width - 2}" height="{height - 2}" rx="17" '
        f'fill="url(#card)" stroke="{BORDER}"/>'
        f'<rect x="1" y="1" width="{width - 2}" height="{height - 2}" rx="17" fill="url(#halo)"/>'
    )
    base_defs = (
        f'<linearGradient id="card" x1="0" y1="0" x2="0" y2="1"><stop offset="0" '
        f'stop-color="{CARD_TOP}"/><stop offset="1" stop-color="{CARD_BOT}"/></linearGradient>'
        f'<radialGradient id="halo" cx=".5" cy="0" r=".75"><stop offset="0" '
        f'stop-color="{GOLD}" stop-opacity=".10"/><stop offset="1" stop-color="{GOLD}" '
        f'stop-opacity="0"/></radialGradient>'
        f'<filter id="glow" filterUnits="userSpaceOnUse" x="0" y="0" width="{width}" '
        f'height="{height}"><feGaussianBlur stdDeviation="3.5" result="b"/><feMerge>'
        f'<feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>'
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" role="img" aria-label="{escape(title)}">'
        f"<title>{escape(title)}</title><defs>{base_defs}{defs}</defs>{fonts}{style}{card}"
        + "".join(body)
        + "</svg>\n"
    )


# --- hero terminal ---------------------------------------------------------

HERO_RUN = "tine run research.py --save research.tine"
HERO_VERIFY = "tine replay research.tine --verify"


def _tree(branch: str, mark: str, mc: str, digest: str, kind: str, rest: str) -> list[Seg]:
    return [(branch, DIM), (mark + " ", mc), (digest, GOLD), (f" {kind:<6}", mc), (rest, TEXT)]


HERO_RUN_OUT: list[list[Seg]] = [
    [("# Running research.py...", MUTED)],
    [("Saved: ", MUTED), ("research.tine", GOLD)],
    [],
    [
        ("# 770eef0030b2", GOLD),
        ("  model=qwen3  steps=5  cost=$0.0000  ", MUTED),
        ("completed", GREEN),
    ],
    _tree("├── ", "*", BLUE, "b6efae06c71a", "think", ' "Searching."'),
    _tree("├── ", ">", TEAL, "0ab05d8035e9", "tool", " search(query=release readiness)"),
    _tree("├── ", "*", BLUE, "843a9ca7d224", "think", ' "Writing summary."'),
    _tree("├── ", ">", TEAL, "7561e44ca927", "tool", " write_summary(text=ok)"),
    _tree("└── ", "+", GREEN, "39842c149ea8", "done", ' "Saved summary.md"'),
]
HERO_VERIFY_OUT: list[list[Seg]] = [
    [
        ("# Replay verify (cache) ", MUTED),
        ("770eef0030b2", GOLD),
        (" -> ", DIM),
        ("24bdf1c217a2 ", GOLD),
        ("REPRODUCED", GREEN),
    ],
    [("reused 5 recorded steps (expected 5)", TEXT)],
    [("round trip ", MUTED), ("sha256:2c6f5de776d7", GOLD), (" verified", GREEN)],
]


def type_command(
    tl: Timeline,
    x: float,
    y: float,
    command: str,
    start: float,
    rng: random.Random,
    cw: float,
    size: float,
) -> tuple[list[str], float]:
    out = [text(x, y, [("$", GOLD)], size=size, cls=tl.show(start - 0.35, 0.2), weight="600")]
    t = start
    for i, ch in enumerate(command):
        if ch != " ":
            out.append(text(x + (i + 2) * cw, y, [(ch, TEXT)], size=size, cls=tl.show(t, 0.04)))
        t += 0.045 + rng.random() * 0.05 + (0.09 if ch == " " else 0)
    return out, t


def render_hero() -> str:
    width, height, size, lh = 900, 520, 14.5, 23
    cw = size * 0.6
    tl, rng = Timeline(15.0, 0.7), random.Random(20261031)
    x0, y = 40, 104
    body = [
        f'<rect x="20" y="20" width="{width - 40}" height="{height - 40}" rx="12" '
        f'fill="#0b101a" stroke="#243047"/>',
        f'<path d="M20 64h{width - 40}" stroke="#1c2536"/>',
        f'<rect x="21" y="21" width="{width - 42}" height="43" rx="11" fill="#0f1522"/>',
    ]
    for i, color in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        body.append(f'<circle cx="{44 + i * 20}" cy="42" r="6" fill="{color}" opacity=".9"/>')
    body.append(
        text(width / 2, 47, [("opentine — research", MUTED)], size=13, font="s", anchor="middle")
    )
    body.append(text(width - 44, 47, [("portable .tine", GOLD)], size=12, anchor="end"))

    def block(command: str, start: float, lines: list[list[Seg]], y: float) -> tuple[float, float]:
        typed, t = type_command(tl, x0, y, command, start, rng, cw, size)
        body.extend(typed)
        t += 0.45
        for line in lines:
            y += lh
            if line:
                body.append(text(x0, y, line, size=size, cls=tl.show(t, 0.35, dy=6)))
                t += 0.14
        return y, t

    y, t = block(HERO_RUN, 0.8, HERO_RUN_OUT, y)
    y, t = block(HERO_VERIFY, t + 1.0, HERO_VERIFY_OUT, y + lh * 1.6)
    badge_y = y + 34
    badge = tl.show(t + 0.25, 0.6, scale=0.85)
    body.append(
        f'<g class="{badge}"><rect x="{x0}" y="{fmt(badge_y - 19)}" width="372" height="30" '
        f'rx="15" fill="{GOLD}" fill-opacity=".12" stroke="{GOLD}" stroke-opacity=".55"/>'
        f'<path d="M{x0 + 16} {fmt(badge_y - 4)}l5 5 9-10" fill="none" stroke="{GOLD_HI}" '
        f'stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" filter="url(#glow)"/>'
        + text(
            x0 + 40,
            badge_y + 1,
            [("digests intact · zero structural drift", GOLD_HI)],
            size=13.5,
            font="s",
            weight="600",
        )
        + "</g>"
    )
    blink = "blink"
    tl.rules.append("@keyframes blink{50%{opacity:0}}.blink{animation:blink 1s steps(1) infinite}")
    body.append(
        f'<rect class="{blink}" x="{x0}" y="{fmt(badge_y + 22)}" width="{fmt(cw)}" '
        f'height="3" fill="{GOLD}"/>'
    )
    return document(
        width,
        height,
        "tine run captures an agent run; tine replay --verify reproduces it",
        "",
        body,
        tl.style(),
    )


# --- run tree --------------------------------------------------------------

NODE_W, NODE_H = 112, 54
KIND = {"run": GOLD, "think": BLUE, "tool": TEAL, "done": GREEN}


def node(x: float, y: float, kind: str, digest: str, label: str, cls: str) -> str:
    color = KIND[kind]
    return (
        f'<g class="{cls}"><rect x="{fmt(x - NODE_W / 2)}" y="{fmt(y - NODE_H / 2)}" '
        f'width="{NODE_W}" height="{NODE_H}" rx="12" fill="#0d1320" stroke="{color}" '
        f'stroke-opacity=".7"/><rect x="{fmt(x - NODE_W / 2 + 10)}" '
        f'y="{fmt(y - NODE_H / 2)}" width="{NODE_W - 20}" height="2" fill="{color}"/>'
        + text(
            x,
            y - 4,
            [(kind, color), ("  " + digest, GOLD)],
            size=12.5,
            anchor="middle",
            weight="600",
        )
        + text(x, y + 15, [(label, MUTED)], size=11.5, font="s", anchor="middle")
        + "</g>"
    )


def edge(d: str, cls: str, color: str = "#3a4a64", dash: str = "") -> str:
    extra = f' stroke-dasharray="{dash}"' if dash else ""
    return (
        f'<path class="{cls}" d="{d}" pathLength="1" fill="none" stroke="{color}" '
        f'stroke-width="2" stroke-linecap="round"{extra}/>'
    )


def render_tree() -> str:
    width, height = 900, 480
    tl = Timeline(13.0, 0.8)
    body = [
        text(48, 62, [("content-addressed run tree", TEXT)], size=22, font="s", weight="650"),
        text(
            48,
            88,
            [
                (
                    "every step named by digest · fork from any step · replay --verify proves it",
                    MUTED,
                )
            ],
            size=13.5,
            font="s",
        ),
    ]
    main = [
        ("run", "770eef", "research.py"),
        ("think", "b6efae", "plan"),
        ("tool", "0ab05d", "search"),
        ("think", "843a9c", "draft"),
        ("tool", "7561e4", "write_summary"),
        ("done", "39842c", "summary.md"),
    ]
    fork = [
        ("think", "c41f07", "retry plan"),
        ("tool", "9e2b6a", "fetch"),
        ("done", "5d03e8", "summary.md"),
    ]
    xs = [104 + i * 138 for i in range(6)]
    y1, y2 = 186, 318

    def draw_edge(d: str, t: float, color: str = "#3a4a64") -> None:
        draw = [
            (0, "stroke-dashoffset:1;opacity:1"),
            (t, "stroke-dashoffset:1;opacity:1"),
            (t + 0.45, "stroke-dashoffset:0;opacity:1"),
            (tl.loop - tl.fade_out, "stroke-dashoffset:0;opacity:1"),
            (tl.loop, "stroke-dashoffset:0;opacity:0"),
        ]
        body.insert(2, edge(d, tl.add(draw, "stroke-dasharray:1"), color))

    t = 0.5
    for i, (kind, digest, label) in enumerate(main):
        if i:
            draw_edge(f"M{xs[i - 1] + NODE_W / 2} {y1}H{xs[i] - NODE_W / 2}", t - 0.35)
        body.append(node(xs[i], y1, kind, digest, label, tl.show(t, 0.4, dy=8)))
        t += 0.55
    fx = xs[2]
    draw_edge(
        f"M{fx} {y1 + NODE_H / 2}C{fx} {y2 - 10} {fx + 20} {y2} {xs[3] - NODE_W / 2} {y2}", t, GOLD
    )
    body.append(
        text(
            fx - 6,
            y2 + 4,
            [("tine fork", GOLD)],
            size=12,
            anchor="end",
            cls=tl.show(t + 0.1, 0.4),
            weight="600",
        )
    )
    t += 0.6
    for i, (kind, digest, label) in enumerate(fork):
        x = xs[3 + i]
        if i:
            draw_edge(f"M{xs[2 + i] + NODE_W / 2} {y2}H{x - NODE_W / 2}", t - 0.35, GOLD)
        body.append(node(x, y2, kind, digest, label, tl.show(t, 0.4, dy=8)))
        t += 0.55
    t += 0.3
    for y in (y1, y2):
        cx, cy = xs[5] + NODE_W / 2 - 4, y - NODE_H / 2 + 4
        body.append(
            f'<g class="{tl.show(t, 0.5, scale=0.4)}"><circle cx="{cx}" cy="{cy}" r="11" '
            f'fill="{GOLD}" filter="url(#glow)"/><path d="M{cx - 5} {cy}l3.5 3.5 6.5-7" '
            f'fill="none" stroke="#1a1206" stroke-width="2.2" stroke-linecap="round" '
            f'stroke-linejoin="round"/></g>'
        )
        t += 0.25
    bar = tl.show(t + 0.2, 0.5, dy=6)
    body.append(
        f'<g class="{bar}"><rect x="48" y="372" width="{width - 96}" height="40" rx="10" '
        f'fill="{GOLD}" fill-opacity=".08" stroke="{GOLD}" stroke-opacity=".35"/>'
        + text(
            68,
            397,
            [
                ("$ ", GOLD),
                ("tine replay --verify", TEXT),
                ("   →   ", DIM),
                ("REPRODUCED", GREEN),
                ("  ·  digests intact  ·  0 structural drift  ·  parent provenance kept", MUTED),
            ],
            size=13,
        )
        + "</g>"
    )
    for i, (label, color) in enumerate(
        (("think", BLUE), ("tool", TEAL), ("done", GREEN), ("fork", GOLD))
    ):
        x = 48 + i * 104
        body.append(f'<circle cx="{x + 5}" cy="444" r="4.5" fill="{color}"/>')
        body.append(text(x + 16, 448, [(label, MUTED)], size=12.5, font="s"))
    return document(
        width,
        height,
        "OpenTine run tree: fork, retry, and verify without losing provenance",
        "",
        body,
        tl.style(),
    )


# --- harness diagram -------------------------------------------------------

HARNESSES = ["claude-code", "codex", "gemini", "cursor", "kimi-code", "generic + 19 more"]
OUTPUTS = ["replay --verify", "fork · resume", "repo-diff · repo-search", "attest · promote"]


def render_harnesses() -> str:
    width, height = 900, 440
    pulses: list[str] = []
    base: list[str] = []
    rows = [*HARNESSES, "SDK: anthropic·openai·google·ollama"]
    hub_x, hub_y, chip_x = 548, 232, 300

    def link(d: str, delay: float, color: str = GOLD) -> None:
        base.append(f'<path d="{d}" fill="none" stroke="#2a3850" stroke-width="1.5"/>')
        pulses.append(
            f'<path d="{d}" pathLength="1" fill="none" stroke="{color}" stroke-width="2.4" '
            f'stroke-linecap="round" stroke-dasharray=".07 .93" filter="url(#glow)" '
            f'style="animation:flow 2.6s linear {fmt(-delay)}s infinite"/>'
        )

    chips = []
    for i, label in enumerate(rows):
        y = 84 + i * 47
        sdk = i == len(rows) - 1
        w = 292 if sdk else 168
        x = chip_x - w / 2 + (8 if sdk else 0)
        link(f"M142 {hub_y}C200 {hub_y} 190 {y} {x} {y}", i * 0.31, TEAL)
        link(
            f"M{x + w} {y}C{hub_x - 150} {y} {hub_x - 160} {hub_y} {hub_x - 92} {hub_y}",
            1.3 + i * 0.29,
        )
        chips.append(
            f'<rect x="{fmt(x)}" y="{y - 15}" width="{w}" height="30" rx="15" fill="#0e1524" '
            f'stroke="{TEAL if not sdk else BLUE}" stroke-opacity=".55"/>'
            + text(
                x + w / 2, y + 4.5, [(label, TEXT if i < 5 else MUTED)], size=12.5, anchor="middle"
            )
        )
    for i, label in enumerate(OUTPUTS):
        y = 136 + i * 64
        link(
            f"M{hub_x + 92} {hub_y}C{hub_x + 150} {hub_y} {hub_x + 130} {y} 690 {y}",
            0.5 + i * 0.4,
            GREEN,
        )
        chips.append(
            f'<rect x="690" y="{y - 18}" width="186" height="36" rx="10" fill="#0e1524" '
            f'stroke="{GREEN}" stroke-opacity=".5"/>'
            + text(783, y + 4.5, [(label, TEXT)], size=12.5, anchor="middle")
        )
    task = (
        f'<rect x="38" y="{hub_y - 22}" width="104" height="44" rx="22" fill="#121a2b" '
        f'stroke="{MUTED}" stroke-opacity=".6"/>'
        + text(90, hub_y + 5, [("agent task", TEXT)], size=13, font="s", anchor="middle")
    )
    hub = (
        f'<rect class="ring" x="{hub_x - 104}" y="{hub_y - 72}" width="208" height="144" '
        f'rx="26" fill="none" stroke="{GOLD}" stroke-width="1.5"/>'
        f'<rect x="{hub_x - 92}" y="{hub_y - 60}" width="184" height="120" rx="20" '
        f'fill="url(#hub)" stroke="{GOLD_HI}" stroke-opacity=".8" filter="url(#glow)"/>'
        + text(hub_x, hub_y - 6, [(".tine", "#1a1206")], size=34, weight="700", anchor="middle")
        + text(
            hub_x,
            hub_y + 20,
            [("portable file", "#2b1d0c")],
            size=12.5,
            font="s",
            weight="600",
            anchor="middle",
        )
        + text(
            hub_x,
            hub_y + 38,
            [("+ .tine/ repository", "#2b1d0c")],
            size=12.5,
            font="s",
            weight="600",
            anchor="middle",
        )
    )
    labels = [
        text(90, 44, [("capture", MUTED)], size=12, font="s", anchor="middle"),
        text(chip_x, 44, [("tine run --harness …  (25 ship)", MUTED)], size=12, anchor="middle"),
        text(hub_x, 44, [("content-addressed graph", MUTED)], size=12, font="s", anchor="middle"),
        text(783, 44, [("then", MUTED)], size=12, font="s", anchor="middle"),
    ]
    defs = (
        f'<linearGradient id="hub" x1="0" y1="0" x2="1" y2="1"><stop offset="0" '
        f'stop-color="{GOLD_HI}"/><stop offset="1" stop-color="{GOLD}"/></linearGradient>'
    )
    style = (
        "<style>@keyframes flow{from{stroke-dashoffset:1}to{stroke-dashoffset:0}}"
        "@keyframes ring{0%{opacity:.55;transform:scale(.96)}100%{opacity:0;"
        "transform:scale(1.12)}}.ring{transform-box:fill-box;transform-origin:center;"
        "animation:ring 2.6s cubic-bezier(.22,1,.36,1) infinite}"
        "@media (prefers-reduced-motion:reduce){*{animation:none!important}}</style>"
    )
    return document(
        width,
        height,
        "Harnesses and SDKs record into a portable .tine file "
        "and .tine/ repository, then replay, fork, diff and attest",
        defs,
        [*labels, *base, *pulses, task, *chips, hub],
        style,
    )


RENDERERS = {
    "readme-hero-terminal.svg": render_hero,
    "readme-run-tree.svg": render_tree,
    "readme-harnesses.svg": render_harnesses,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output-dir", type=Path, default=ASSETS)
    parser.add_argument("--check", action="store_true", help="fail if assets are stale")
    args = parser.parse_args()
    stale = []
    for name, render in RENDERERS.items():
        path, content = args.output_dir / name, render()
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                stale.append(name)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
        print(f"{path}  {len(content.encode()):,} bytes")
    if stale:
        print("stale README assets: " + ", ".join(stale), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
