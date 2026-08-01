#!/usr/bin/env python3
"""Render deterministic README GIF assets with Pillow only."""

from __future__ import annotations

import argparse
import math
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

Color = tuple[int, int, int]
Point = tuple[float, float]
Segment = tuple[str, Color]
Line = Sequence[Segment]

HERO_SIZE = (900, 500)
TREE_SIZE = (900, 480)
MAX_EXPECTED_GIF_BYTES = 2_500_000

BG = (8, 12, 20)
CARD = (13, 18, 29)
CARD_2 = (18, 25, 38)
PANEL = (11, 15, 24)
BORDER = (42, 54, 74)
MUTED = (139, 148, 165)
TEXT = (236, 240, 246)
DIM = (93, 103, 123)
GOLD = (212, 165, 116)
AMBER = (245, 158, 11)
TEAL = (45, 212, 191)
GREEN = (52, 211, 153)
RED = (248, 81, 73)
BLUE = (96, 165, 250)
BLACK = (0, 0, 0)


def blend(a: Color, b: Color, amount: float) -> Color:
    return (
        round(a[0] + (b[0] - a[0]) * amount),
        round(a[1] + (b[1] - a[1]) * amount),
        round(a[2] + (b[2] - a[2]) * amount),
    )


def make_palette_image() -> Image.Image:
    colors: list[Color] = [
        BG,
        CARD,
        CARD_2,
        PANEL,
        BORDER,
        MUTED,
        TEXT,
        DIM,
        GOLD,
        AMBER,
        TEAL,
        GREEN,
        RED,
        BLUE,
        BLACK,
        (255, 255, 255),
    ]

    colors.extend((value, value, value) for value in range(0, 256, 6))
    for accent in (GOLD, AMBER, TEAL, GREEN, RED, BLUE):
        colors.extend(blend(BG, accent, amount / 24) for amount in range(1, 25))
    colors.extend(blend(CARD, TEXT, amount / 32) for amount in range(1, 33))

    unique: list[Color] = []
    for color in colors:
        if color not in unique:
            unique.append(color)
        if len(unique) == 256:
            break

    while len(unique) < 256:
        unique.append(BG)

    palette = Image.new("P", (1, 1))
    palette.putpalette([channel for color in unique for channel in color])
    return palette


PALETTE = make_palette_image()


def quantize(frame: Image.Image) -> Image.Image:
    return frame.convert("RGB").quantize(palette=PALETTE, dither=Image.Dither.NONE)


def font(size: int, *, mono: bool = False, bold: bool = False) -> ImageFont.ImageFont:
    if mono:
        candidates = [
            "/usr/share/fonts/truetype/noto/NotoSansMono-Regular.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        ]
    elif bold:
        candidates = [
            "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        ]
    else:
        candidates = [
            "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        ]

    for candidate in candidates:
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, size)
    return ImageFont.load_default()


MONO = font(16, mono=True)
BODY_SMALL = font(14)
BODY_BOLD = font(18, bold=True)
TITLE = font(21, bold=True)


def text_width(draw: ImageDraw.ImageDraw, text: str, text_font: ImageFont.ImageFont) -> int:
    return round(draw.textlength(text, font=text_font))


def draw_segmented_line(
    draw: ImageDraw.ImageDraw,
    xy: tuple[int, int],
    line: Line,
    text_font: ImageFont.ImageFont,
) -> int:
    x, y = xy
    for text, color in line:
        draw.text((x, y), text, font=text_font, fill=color)
        x += text_width(draw, text, text_font)
    return x


def command_line(command: str) -> Line:
    return [("$ ", GOLD), (command, TEXT)]


def hero_states() -> Iterable[tuple[list[Line], bool, int]]:
    run_command = "tine run research.py"
    run_output: list[Line] = [
        [("# a7f3c2", GOLD), (" research.py", TEXT), ("  steps=5  completed", GREEN)],
        [("|-- # 9a12 plan", MUTED), ('    "scope sources and checks"', DIM)],
        [("|-- > 31fd tool", TEAL), ('    web.search(query="release readiness")', TEXT)],
        [("|-- > 77be tool", TEAL), ('    fs.write(path="summary.md")', TEXT)],
        [("`-- + f29c done", GREEN), ('    "saved docs/research-summary.md"', TEXT)],
        [("saved run ", MUTED), ("a7f3c2", GOLD), (" to .tine_runs/a7f3c2.tine", MUTED)],
    ]
    verify_command = "tine replay a7f3c2 --verify"
    verify_output: list[Line] = [
        [("verifying ", MUTED), ("a7f3c2", GOLD), ("  re-deriving 5 steps", DIM)],
        [("|-- ", DIM), ("model", BLUE), ("  qwen3        digest matches", TEXT)],
        [("|-- ", DIM), ("tool ", TEAL), ("  search       digest matches", TEXT)],
        [("|-- ", DIM), ("tool ", TEAL), ("  fs.write     digest matches", TEXT)],
        [("`-- ", DIM), ("done ", GREEN), ("  reproduced   0 structural drift", TEXT)],
    ]

    char_counts = [0, 2, 5, 8, 11, 14, 17, len(run_command)]
    for count in char_counts:
        yield [command_line(run_command[:count])], True, 70

    lines = [command_line(run_command)]
    for count in range(1, len(run_output) + 1):
        yield lines + run_output[:count], False, 120

    yield lines + run_output, False, 450

    base = lines + run_output + [[]]
    char_counts = [0, 4, 8, 12, 16, 20, 24, len(verify_command)]
    for count in char_counts:
        yield base + [command_line(verify_command[:count])], True, 70

    lines = base + [command_line(verify_command)]
    for count in range(1, len(verify_output) + 1):
        yield lines + verify_output[:count], False, 125

    yield lines + verify_output, False, 900


def draw_terminal_frame(lines: list[Line], show_cursor: bool) -> Image.Image:
    image = Image.new("RGB", HERO_SIZE, BG)
    draw = ImageDraw.Draw(image)

    outer = (35, 34, HERO_SIZE[0] - 35, HERO_SIZE[1] - 34)
    draw.rounded_rectangle((41, 42, outer[2] + 6, outer[3] + 8), radius=22, fill=BLACK)
    draw.rounded_rectangle(outer, radius=22, fill=CARD, outline=BORDER, width=2)

    header = (35, 34, HERO_SIZE[0] - 35, 82)
    draw.rounded_rectangle(header, radius=22, fill=CARD_2)
    draw.rectangle((35, 62, HERO_SIZE[0] - 35, 82), fill=CARD_2)
    for index, color in enumerate((RED, AMBER, GREEN)):
        x = 62 + index * 24
        draw.ellipse((x, 53, x + 12, 65), fill=color)
    draw.text((142, 49), "opentine / run provenance", font=BODY_SMALL, fill=MUTED)
    draw.rounded_rectangle((694, 48, 826, 68), radius=10, outline=(54, 68, 91), width=1)
    draw.text((710, 49), "portable .tine", font=BODY_SMALL, fill=GOLD)

    body = (57, 98, HERO_SIZE[0] - 57, HERO_SIZE[1] - 48)
    draw.rounded_rectangle(body, radius=14, fill=PANEL, outline=(25, 34, 51), width=1)

    x = 82
    y = 118
    line_height = 24
    cursor_end = x
    cursor_y = y
    for index, line in enumerate(lines):
        if not line:
            y += line_height
            continue
        cursor_end = draw_segmented_line(draw, (x, y), line, MONO)
        cursor_y = y
        if index == 0 or (line and line[0][0] == "$ "):
            draw.line((x, y + 22, cursor_end, y + 22), fill=(20, 27, 40), width=1)
        y += line_height

    if show_cursor:
        draw.rectangle((cursor_end + 3, cursor_y + 4, cursor_end + 10, cursor_y + 20), fill=GOLD)

    return image


@dataclass(frozen=True)
class TreeNode:
    key: str
    title: str
    detail: str
    center: tuple[int, int]
    border: Color
    fill: Color


@dataclass(frozen=True)
class TreeEdge:
    key: str
    points: tuple[Point, ...]
    color: Color


NODES: tuple[TreeNode, ...] = (
    TreeNode("root", "root run", "#a7f3c2", (115, 250), GOLD, (31, 24, 20)),
    TreeNode("model", "model", "plan", (295, 155), BLUE, (17, 27, 43)),
    TreeNode("tool", "tool", "search", (475, 155), TEAL, (13, 34, 36)),
    TreeNode("error", "error", "edit failed", (675, 155), RED, (43, 20, 22)),
    TreeNode("fork", "fork", "step 2", (475, 350), AMBER, (41, 31, 13)),
    TreeNode("retry", "retry", "inspect", (675, 350), TEAL, (13, 34, 36)),
    TreeNode("done", "done", "verified", (775, 250), GREEN, (15, 38, 29)),
)

EDGES: tuple[TreeEdge, ...] = (
    TreeEdge("root-model", ((170, 233), (240, 184)), GOLD),
    TreeEdge("model-tool", ((360, 155), (410, 155)), BLUE),
    TreeEdge("tool-error", ((540, 155), (610, 155)), TEAL),
    TreeEdge("tool-fork", ((475, 191), (475, 314)), AMBER),
    TreeEdge("fork-retry", ((540, 350), (610, 350)), AMBER),
    TreeEdge("retry-done", ((720, 328), (748, 287)), GREEN),
)

REVEAL_ORDER: tuple[tuple[str, str], ...] = (
    ("node", "root"),
    ("edge", "root-model"),
    ("node", "model"),
    ("edge", "model-tool"),
    ("node", "tool"),
    ("edge", "tool-error"),
    ("node", "error"),
    ("edge", "tool-fork"),
    ("node", "fork"),
    ("edge", "fork-retry"),
    ("node", "retry"),
    ("edge", "retry-done"),
    ("node", "done"),
)


def draw_arrowhead(draw: ImageDraw.ImageDraw, start: Point, end: Point, color: Color) -> None:
    angle = math.atan2(end[1] - start[1], end[0] - start[0])
    length = 12
    spread = 0.55
    left = (
        end[0] - length * math.cos(angle - spread),
        end[1] - length * math.sin(angle - spread),
    )
    right = (
        end[0] - length * math.cos(angle + spread),
        end[1] - length * math.sin(angle + spread),
    )
    draw.polygon([end, left, right], fill=color)


def path_length(points: Sequence[Point]) -> float:
    return sum(math.dist(points[index], points[index + 1]) for index in range(len(points) - 1))


def draw_path(
    draw: ImageDraw.ImageDraw,
    points: Sequence[Point],
    color: Color,
    *,
    progress: float,
    width: int = 5,
) -> None:
    progress = max(0.0, min(1.0, progress))
    if progress <= 0:
        return

    total = path_length(points)
    remaining = total * progress
    last_drawn_start = points[0]
    last_drawn_end = points[0]
    for index in range(len(points) - 1):
        start = points[index]
        end = points[index + 1]
        segment_length = math.dist(start, end)
        if remaining >= segment_length:
            draw.line((start, end), fill=color, width=width)
            remaining -= segment_length
            last_drawn_start = start
            last_drawn_end = end
            continue

        amount = 0 if segment_length == 0 else remaining / segment_length
        partial = (
            start[0] + (end[0] - start[0]) * amount,
            start[1] + (end[1] - start[1]) * amount,
        )
        draw.line((start, partial), fill=color, width=width)
        last_drawn_start = start
        last_drawn_end = partial
        break

    if progress >= 1.0:
        draw_arrowhead(draw, last_drawn_start, last_drawn_end, color)


def draw_node(draw: ImageDraw.ImageDraw, node: TreeNode, *, active: bool = False) -> None:
    x, y = node.center
    w, h = 124, 68
    bbox = (x - w // 2, y - h // 2, x + w // 2, y + h // 2)
    shadow = (bbox[0] + 4, bbox[1] + 5, bbox[2] + 4, bbox[3] + 5)
    draw.rounded_rectangle(shadow, radius=14, fill=BLACK)
    if active:
        glow = (bbox[0] - 5, bbox[1] - 5, bbox[2] + 5, bbox[3] + 5)
        draw.rounded_rectangle(glow, radius=18, outline=blend(node.border, TEXT, 0.35), width=3)
    draw.rounded_rectangle(bbox, radius=14, fill=node.fill, outline=node.border, width=2)

    title_bbox = draw.textbbox((0, 0), node.title, font=BODY_BOLD)
    detail_bbox = draw.textbbox((0, 0), node.detail, font=BODY_SMALL)
    title_width = title_bbox[2] - title_bbox[0]
    detail_width = detail_bbox[2] - detail_bbox[0]
    draw.text((x - title_width / 2, y - 23), node.title, font=BODY_BOLD, fill=TEXT)
    draw.text((x - detail_width / 2, y + 3), node.detail, font=BODY_SMALL, fill=MUTED)


def tree_timeline() -> Iterable[tuple[set[str], set[str], tuple[str, str] | None, float, int]]:
    completed_nodes: set[str] = set()
    completed_edges: set[str] = set()

    for kind, key in REVEAL_ORDER:
        if kind == "node":
            completed_nodes.add(key)
            yield set(completed_nodes), set(completed_edges), (kind, key), 1.0, 180
            continue

        for progress in (0.3, 0.65, 1.0):
            yield set(completed_nodes), set(completed_edges), (kind, key), progress, 90
        completed_edges.add(key)

    for _ in range(3):
        yield set(completed_nodes), set(completed_edges), None, 1.0, 500


def draw_tree_frame(
    completed_nodes: set[str],
    completed_edges: set[str],
    active: tuple[str, str] | None,
    progress: float,
) -> Image.Image:
    image = Image.new("RGB", TREE_SIZE, BG)
    draw = ImageDraw.Draw(image)

    draw.rounded_rectangle((28, 24, TREE_SIZE[0] - 28, TREE_SIZE[1] - 24), radius=24, fill=CARD)
    draw.rounded_rectangle((46, 44, TREE_SIZE[0] - 46, TREE_SIZE[1] - 44), radius=18, fill=PANEL)
    draw.text((70, 62), "content-addressed run tree", font=TITLE, fill=TEXT)
    draw.text(
        (70, 92),
        "fork, retry, and verify without losing provenance",
        font=BODY_SMALL,
        fill=MUTED,
    )

    for edge in EDGES:
        if edge.key in completed_edges:
            draw_path(draw, edge.points, edge.color, progress=1.0)
        elif active == ("edge", edge.key):
            draw_path(draw, edge.points, edge.color, progress=progress)

    for node in NODES:
        if node.key in completed_nodes:
            draw_node(draw, node, active=active == ("node", node.key))

    legend_y = 410
    legend = (("main chain", GOLD), ("fork branch", AMBER), ("verified outcome", GREEN))
    x = 70
    for label, color in legend:
        draw.rounded_rectangle((x, legend_y, x + 18, legend_y + 18), radius=5, fill=color)
        draw.text((x + 28, legend_y - 1), label, font=BODY_SMALL, fill=MUTED)
        x += 210

    return image


def save_gif(frames: Sequence[Image.Image], durations: Sequence[int], path: Path) -> None:
    paletted = [quantize(frame) for frame in frames]
    path.parent.mkdir(parents=True, exist_ok=True)
    paletted[0].save(
        path,
        save_all=True,
        append_images=paletted[1:],
        duration=list(durations),
        loop=0,
        disposal=2,
        optimize=False,
    )


def render_hero(output_dir: Path) -> Path:
    frames: list[Image.Image] = []
    durations: list[int] = []
    for lines, show_cursor, duration in hero_states():
        frames.append(draw_terminal_frame(lines, show_cursor))
        durations.append(duration)

    output = output_dir / "readme-hero-terminal.gif"
    save_gif(frames, durations, output)
    return output


def render_tree(output_dir: Path) -> Path:
    frames: list[Image.Image] = []
    durations: list[int] = []
    for completed_nodes, completed_edges, active, progress, duration in tree_timeline():
        frames.append(draw_tree_frame(completed_nodes, completed_edges, active, progress))
        durations.append(duration)

    output = output_dir / "readme-run-tree.gif"
    save_gif(frames, durations, output)
    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/assets"),
        help="Directory for generated README GIFs.",
    )
    parser.add_argument(
        "--max-size",
        type=int,
        default=MAX_EXPECTED_GIF_BYTES,
        help="Warn when any generated GIF exceeds this many bytes.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    outputs = [render_hero(args.output), render_tree(args.output)]
    for output in outputs:
        size = output.stat().st_size
        print(f"{output} {size:,} bytes")
        if size > args.max_size:
            print(
                f"warning: {output} is larger than expected ({size:,} > {args.max_size:,})",
                file=sys.stderr,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
