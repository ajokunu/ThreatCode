"""Grid-aware orthogonal edge routing and label placement for the SVG diagram.

The diagram lays nodes out on a strict grid: every swim lane shares the same
column pitch, so the gaps between columns form vertical channels and the gaps
between rows form horizontal channels. Routes only travel through those
channels, which keeps them from crossing unrelated node boxes.
"""

from __future__ import annotations

import itertools
import math
from collections.abc import Hashable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Literal

Point = tuple[float, float]
Side = Literal["top", "bottom", "left", "right"]
Shape = Literal["rect", "diamond", "cylinder"]

# Cylinder cap height, matching the datastore shape drawn by the renderer
CYLINDER_RY = 6.0

# Port spreading along a node side
_PORT_SPACING = 20.0
# Minimum distance between ports of different routes on facing sides of a column
_FACING_PORT_SEP = 6.0
# Share of half the node width (or height) the ports of one side may use. Wide spans keep the
# arrowheads of a busy node apart; a diamond narrows towards its tips, so it gets less
_PORT_SPAN = {"rect": 0.8, "cylinder": 0.8, "diamond": 0.5}

# Track spreading inside a channel
_TRACK_SPACING = 10.0
_TRACK_MIN_SEP = 30.0
# Channels with more tracks than this keep greedy order instead of a full search
_TRACK_SEARCH_MAX = 7
# The full search costs permutations x runs squared, so a channel crowded with runs keeps the
# greedy order as well
_TRACK_SEARCH_RUNS_MAX = 24

# Label placement: the most positions tried on one route, whatever its length
MAX_CANDIDATES = 64
# Edge of one cell of the spatial index, in pixels: a little under a node
_INDEX_CELL = 64.0

_CORNER_RADIUS = 6.0
_NEST_KEY = 1e6
_UP = -1
_DOWN = 1
_SELF_LOOP_REACH = 14.0


@dataclass(frozen=True)
class Rect:
    """Axis-aligned rectangle."""

    x: float
    y: float
    w: float
    h: float

    @property
    def right(self) -> float:
        return self.x + self.w

    @property
    def bottom(self) -> float:
        return self.y + self.h

    @property
    def cx(self) -> float:
        return self.x + self.w / 2

    @property
    def cy(self) -> float:
        return self.y + self.h / 2

    def expand(self, pad: float) -> Rect:
        return Rect(self.x - pad, self.y - pad, self.w + pad * 2, self.h + pad * 2)

    def intersects(self, other: Rect) -> bool:
        return (
            self.x < other.right
            and other.x < self.right
            and self.y < other.bottom
            and other.y < self.bottom
        )

    def contains(self, other: Rect) -> bool:
        return (
            self.x <= other.x
            and self.y <= other.y
            and other.right <= self.right
            and other.bottom <= self.bottom
        )

    def intersects_segment(self, a: Point, b: Point) -> bool:
        """Return True when segment a-b passes through the rectangle interior."""
        # Liang-Barsky clipping against the open rectangle
        x0, y0 = a
        dx = b[0] - x0
        dy = b[1] - y0
        t0, t1 = 0.0, 1.0
        for p, q in (
            (-dx, x0 - self.x),
            (dx, self.right - x0),
            (-dy, y0 - self.y),
            (dy, self.bottom - y0),
        ):
            if p == 0:
                if q <= 0:
                    return False
                continue
            t = q / p
            if p < 0:
                t0 = max(t0, t)
            else:
                t1 = min(t1, t)
            if t0 >= t1:
                return False
        return True


class SpatialIndex:
    """Uniform-grid index over rectangles and tagged segments.

    A label candidate only needs the rectangles and route segments near it, so each item is
    filed under the cells its bounding box covers and a query reads just the cells the candidate
    covers.
    That keeps placement near linear in the number of routes where a flat list made it quadratic.
    Items come back in insertion order, so output never depends on hashing.
    """

    def __init__(self, cell: float = _INDEX_CELL) -> None:
        self._cell = cell
        self._rects: list[Rect] = []
        self._segments: list[tuple[Point, Point, Hashable]] = []
        self._rect_cells: dict[tuple[int, int], list[int]] = {}
        self._segment_cells: dict[tuple[int, int], list[int]] = {}

    def __len__(self) -> int:
        return len(self._rects) + len(self._segments)

    def _cells(self, x0: float, y0: float, x1: float, y1: float) -> Iterable[tuple[int, int]]:
        c = self._cell
        for cx in range(math.floor(x0 / c), math.floor(x1 / c) + 1):
            for cy in range(math.floor(y0 / c), math.floor(y1 / c) + 1):
                yield (cx, cy)

    def add_rect(self, rect: Rect) -> None:
        idx = len(self._rects)
        self._rects.append(rect)
        for cell in self._cells(rect.x, rect.y, rect.right, rect.bottom):
            self._rect_cells.setdefault(cell, []).append(idx)

    def add_segment(self, a: Point, b: Point, tag: Hashable = None) -> None:
        idx = len(self._segments)
        self._segments.append((a, b, tag))
        for cell in self._cells(min(a[0], b[0]), min(a[1], b[1]), max(a[0], b[0]), max(a[1], b[1])):
            self._segment_cells.setdefault(cell, []).append(idx)

    def add_route(self, points: Sequence[Point], tag: Hashable = None) -> None:
        for a, b in zip(points, points[1:], strict=False):
            self.add_segment(a, b, tag)

    def rects_near(self, area: Rect) -> list[Rect]:
        """Every indexed rectangle whose bounding box shares a cell with ``area``."""
        found: set[int] = set()
        for cell in self._cells(area.x, area.y, area.right, area.bottom):
            found.update(self._rect_cells.get(cell, ()))
        return [self._rects[i] for i in sorted(found)]

    def segments_near(self, area: Rect) -> list[tuple[Point, Point, Hashable]]:
        """Every indexed segment whose bounding box shares a cell with ``area``."""
        found: set[int] = set()
        for cell in self._cells(area.x, area.y, area.right, area.bottom):
            found.update(self._segment_cells.get(cell, ()))
        return [self._segments[i] for i in sorted(found)]


@dataclass(frozen=True)
class GridNode:
    """A node placed on the layout grid."""

    id: str
    col: int
    row: int
    rect: Rect
    shape: Shape


@dataclass(frozen=True)
class Grid:
    """Routing grid derived from the diagram layout.

    ``channels[r]`` is the usable y band below global row ``r``; ``gaps[g]`` is
    the usable x band of the column gap to the left of column ``g`` (the last
    entry is the gap to the right of the final column). ``keep_out[r]`` is a y
    band inside channel ``r`` that tracks must skip, such as a lane border.
    """

    nodes: dict[str, GridNode]
    channels: list[tuple[float, float]]
    gaps: list[tuple[float, float]]
    keep_out: dict[int, tuple[float, float]] = field(default_factory=dict)


@dataclass
class _Plan:
    src: GridNode
    tgt: GridNode
    src_side: Side
    tgt_side: Side
    channel_1: int | None = None
    gap: int | None = None
    channel_2: int | None = None
    src_port: Point = (0.0, 0.0)
    tgt_port: Point = (0.0, 0.0)
    track_1: float = 0.0
    track_2: float = 0.0
    gap_track: float = 0.0


def route_edges(grid: Grid, pairs: list[tuple[str, str]]) -> dict[tuple[str, str], list[Point]]:
    """Compute an orthogonal polyline for each (source, target) pair."""
    plans: dict[tuple[str, str], _Plan] = {}
    loops: dict[tuple[str, str], list[Point]] = {}
    occupied = {(n.col, n.row) for n in grid.nodes.values()}
    for key in pairs:
        src = grid.nodes.get(key[0])
        tgt = grid.nodes.get(key[1])
        if src is None or tgt is None or key in plans or key in loops:
            continue
        if src.id == tgt.id:
            loops[key] = _self_loop(src)
            continue
        plans[key] = _plan(grid, src, tgt, occupied)

    _assign_ports(grid, plans)
    _assign_channel_tracks(grid, plans)
    _assign_gap_tracks(grid, plans)

    routes = {key: _simplify(_polyline(grid, plan)) for key, plan in plans.items()}
    routes.update(loops)
    return routes


def _plan(grid: Grid, src: GridNode, tgt: GridNode, occupied: set[tuple[int, int]]) -> _Plan:
    if src.row == tgt.row:
        if abs(src.col - tgt.col) == 1:
            if tgt.col > src.col:
                return _Plan(src, tgt, "right", "left")
            return _Plan(src, tgt, "left", "right")
        # Non-adjacent nodes in one row: dip into the channel below the row
        return _Plan(src, tgt, "bottom", "bottom", channel_1=src.row)

    down = tgt.row > src.row
    src_side: Side = "bottom" if down else "top"
    tgt_side: Side = "top" if down else "bottom"
    near_src = src.row if down else src.row - 1
    near_tgt = tgt.row - 1 if down else tgt.row
    lo, hi = sorted((src.row, tgt.row))
    between = range(lo + 1, hi)

    if _column_clear(occupied, tgt.col, between):
        return _Plan(src, tgt, src_side, tgt_side, channel_1=near_src)
    if _column_clear(occupied, src.col, between):
        return _Plan(src, tgt, src_side, tgt_side, channel_1=near_tgt)

    if tgt.col > src.col:
        gap = src.col + 1
    elif tgt.col < src.col:
        gap = src.col
    else:
        gap = src.col + 1 if src.col + 1 < len(grid.gaps) else src.col
    return _Plan(src, tgt, src_side, tgt_side, channel_1=near_src, gap=gap, channel_2=near_tgt)


def _column_clear(occupied: set[tuple[int, int]], col: int, rows: range) -> bool:
    return all((col, r) not in occupied for r in rows)


def _gap_center(grid: Grid, gap: int) -> float:
    lo, hi = grid.gaps[gap]
    return (lo + hi) / 2


def _assign_ports(grid: Grid, plans: dict[tuple[str, str], _Plan]) -> None:
    """Spread the endpoints that share a node side so arrows do not overlap."""
    by_side: dict[tuple[str, Side], list[tuple[float, tuple[str, str], bool]]] = {}
    for key, plan in plans.items():
        for is_src in (True, False):
            node = plan.src if is_src else plan.tgt
            other = plan.tgt if is_src else plan.src
            side = plan.src_side if is_src else plan.tgt_side
            if side in ("left", "right"):
                toward = other.rect.cy
            elif plan.gap is not None:
                toward = _gap_center(grid, plan.gap)
            elif plan.src_side == plan.tgt_side:
                # Same-row dips nest: the nearest partner takes the outermost port
                # (paired with the innermost track), so loops wrap without crossing
                direction = 1.0 if other.rect.cx > node.rect.cx else -1.0
                dist = abs(other.rect.cx - node.rect.cx)
                toward = node.rect.cx + direction * (_NEST_KEY - dist)
            else:
                toward = other.rect.cx
            by_side.setdefault((node.id, side), []).append((toward, key, is_src))

    cells = {(n.col, n.row): n.id for n in grid.nodes.values()}
    placed: dict[tuple[str, Side], list[tuple[float, tuple[str, str]]]] = {}
    for node_id, side in sorted(
        by_side, key=lambda k: (grid.nodes[k[0]].row, grid.nodes[k[0]].col, k[1])
    ):
        node = grid.nodes[node_id]
        ends = sorted(by_side[(node_id, side)], key=lambda e: (e[0], e[1]))
        horizontal = side in ("top", "bottom")
        half = (node.rect.w if horizontal else node.rect.h) / 2
        span = half * _PORT_SPAN[node.shape]
        n = len(ends)
        spacing = min(_PORT_SPACING, 2 * span / (n - 1)) if n > 1 else 0.0
        offsets = [(i - (n - 1) / 2) * spacing for i in range(n)]
        keys = [key for _, key, _ in ends]

        # Ports on the facing side of the vertically adjacent node share the channel
        # between them; nudge ours so stubs of different routes are never collinear.
        facing: list[tuple[float, tuple[str, str]]] = []
        if horizontal:
            other_row = node.row + 1 if side == "bottom" else node.row - 1
            other_side: Side = "top" if side == "bottom" else "bottom"
            other_id = cells.get((node.col, other_row))
            if other_id is not None:
                facing = placed.get((other_id, other_side), [])
        offsets = _nudge(offsets, keys, facing, span, max(spacing, _PORT_SPACING))
        placed[(node_id, side)] = list(zip(offsets, keys, strict=True))

        for offset, (_, key, is_src) in zip(offsets, ends, strict=True):
            port = _outline_point(node, side, offset)
            if is_src:
                plans[key].src_port = port
            else:
                plans[key].tgt_port = port


def _nudge(
    offsets: list[float],
    keys: list[tuple[str, str]],
    facing: list[tuple[float, tuple[str, str]]],
    span: float,
    step: float,
) -> list[float]:
    """Shift a side's ports until none sits on a facing port of a different route."""

    def clashes(shift: float) -> bool:
        return any(
            abs(off + shift - f_off) < _FACING_PORT_SEP
            for off, key in zip(offsets, keys, strict=True)
            for f_off, f_key in facing
            if f_key != key
        )

    if not facing or not clashes(0.0):
        return offsets
    limit = span * 1.5
    for shift in (step / 2, -step / 2, step, -step, step * 1.5, -step * 1.5):
        if max(abs(o + shift) for o in offsets) <= limit and not clashes(shift):
            return [o + shift for o in offsets]
    return offsets


def _outline_point(node: GridNode, side: Side, offset: float) -> Point:
    """Point on the node outline at ``offset`` from the center of ``side``."""
    r = node.rect
    if side in ("top", "bottom"):
        x = r.cx + offset
        sign = -1.0 if side == "top" else 1.0
        if node.shape == "diamond":
            inset = (r.h / 2) * (abs(offset) / (r.w / 2))
            return (x, r.cy + sign * (r.h / 2 - inset))
        if node.shape == "cylinder":
            rx = r.w / 2
            cap = CYLINDER_RY * math.sqrt(max(0.0, 1 - (offset / rx) ** 2))
            if side == "top":
                return (x, r.y + CYLINDER_RY - cap)
            return (x, r.bottom - CYLINDER_RY + cap)
        return (x, r.y if side == "top" else r.bottom)

    y = r.cy + offset
    sign = -1.0 if side == "left" else 1.0
    if node.shape == "diamond":
        inset = (r.w / 2) * (abs(offset) / (r.h / 2))
        return (r.cx + sign * (r.w / 2 - inset), y)
    return (r.x if side == "left" else r.right, y)


@dataclass(frozen=True)
class _Run:
    """A horizontal run in a channel and the vertical stubs leaving its ends."""

    lo: float
    hi: float
    key: tuple[str, str]
    which: int
    stubs: tuple[tuple[float, int], ...]  # (x, _UP or _DOWN)


def _assign_channel_tracks(grid: Grid, plans: dict[tuple[str, str], _Plan]) -> None:
    """Give each horizontal run its own y track inside its channel."""
    runs: dict[int, list[_Run]] = {}
    for key, plan in plans.items():
        if plan.channel_1 is None:
            continue
        xs = plan.src_port[0]
        xt = plan.tgt_port[0]
        src_stub = (xs, _UP if plan.src_side == "bottom" else _DOWN)
        tgt_stub = (xt, _DOWN if plan.tgt_side == "top" else _UP)
        if plan.gap is None:
            run = _Run(min(xs, xt), max(xs, xt), key, 1, (src_stub, tgt_stub))
            runs.setdefault(plan.channel_1, []).append(run)
        else:
            xg = _gap_center(grid, plan.gap)
            assert plan.channel_2 is not None
            down = plan.src_side == "bottom"
            run_1 = _Run(min(xs, xg), max(xs, xg), key, 1, (src_stub, (xg, _DOWN if down else _UP)))
            run_2 = _Run(min(xg, xt), max(xg, xt), key, 2, ((xg, _UP if down else _DOWN), tgt_stub))
            runs.setdefault(plan.channel_1, []).append(run_1)
            runs.setdefault(plan.channel_2, []).append(run_2)

    for channel, items in runs.items():
        colors = _color_intervals([(r.lo, r.hi, r.key, r.which) for r in items])
        n = max(colors) + 1
        slots = _spread_tracks(grid.channels[channel], list(range(n)), grid.keep_out.get(channel))
        order = _least_crossing_order(items, colors, slots)
        for run, color in zip(items, colors, strict=True):
            pos = slots[order[color]]
            if run.which == 1:
                plans[run.key].track_1 = pos
            else:
                plans[run.key].track_2 = pos


def _least_crossing_order(runs: list[_Run], colors: list[int], slots: list[float]) -> list[int]:
    """Map each track color to a slot so stubs cross as few runs as possible."""
    n = len(slots)
    identity = list(range(n))
    if n < 2 or n > _TRACK_SEARCH_MAX or len(runs) > _TRACK_SEARCH_RUNS_MAX:
        return identity

    def crossings(order: tuple[int, ...] | list[int]) -> int:
        ys = [slots[order[c]] for c in colors]
        count = 0
        for i, a in enumerate(runs):
            for j, b in enumerate(runs):
                if i == j or a.key == b.key:
                    continue
                for x, direction in b.stubs:
                    if a.lo + 0.5 < x < a.hi - 0.5:
                        above = ys[i] < ys[j]
                        if (direction == _UP and above) or (direction == _DOWN and not above):
                            count += 1
        return count

    best = identity
    best_count = crossings(identity)
    for perm in itertools.permutations(identity):
        if best_count == 0:
            break
        count = crossings(perm)
        if count < best_count:
            best, best_count = list(perm), count
    return best


def _assign_gap_tracks(grid: Grid, plans: dict[tuple[str, str], _Plan]) -> None:
    """Give each vertical run through a column gap its own x track."""
    runs: dict[int, list[tuple[float, float, tuple[str, str], int]]] = {}
    for key, plan in plans.items():
        if plan.gap is None:
            continue
        lo, hi = sorted((plan.track_1, plan.track_2))
        runs.setdefault(plan.gap, []).append((lo, hi, key, 0))

    for gap, items in runs.items():
        positions = _spread_tracks(grid.gaps[gap], _color_intervals(items))
        for (_, _, key, _), pos in zip(items, positions, strict=True):
            plans[key].gap_track = pos


def _color_intervals(items: list[tuple[float, float, tuple[str, str], int]]) -> list[int]:
    """Greedy interval coloring: overlapping runs get distinct track indices."""
    order = sorted(range(len(items)), key=lambda i: (items[i][0], items[i][1], items[i][2]))
    track_ends: list[float] = []
    colors = [0] * len(items)
    for i in order:
        lo, hi = items[i][0], items[i][1]
        for t, end in enumerate(track_ends):
            if end + _TRACK_MIN_SEP <= lo:
                track_ends[t] = hi
                colors[i] = t
                break
        else:
            colors[i] = len(track_ends)
            track_ends.append(hi)
    return colors


def _spread_tracks(
    band: tuple[float, float],
    colors: list[int],
    keep_out: tuple[float, float] | None = None,
) -> list[float]:
    """Spread track indices evenly over the band, skipping the keep-out zone."""
    lo, hi = band
    pieces = [(lo, hi)]
    if keep_out is not None and lo < keep_out[0] and keep_out[1] < hi:
        pieces = [(lo, keep_out[0]), (keep_out[1], hi)]
    usable = sum(b - a for a, b in pieces)
    n = max(colors, default=0) + 1
    spacing = min(_TRACK_SPACING, usable / (n - 1)) if n > 1 else 0.0
    start = (usable - spacing * (n - 1)) / 2

    def place(dist: float) -> float:
        for a, b in pieces:
            if dist <= b - a:
                return a + dist
            dist -= b - a
        return hi

    return [place(start + c * spacing) for c in colors]


def _polyline(grid: Grid, plan: _Plan) -> list[Point]:
    ps = plan.src_port
    pt = plan.tgt_port
    if plan.channel_1 is None:
        # Side-to-side between adjacent columns; jog in the gap if ports differ
        mx = (ps[0] + pt[0]) / 2
        return [ps, (mx, ps[1]), (mx, pt[1]), pt]
    if plan.gap is None:
        y = plan.track_1
        return [ps, (ps[0], y), (pt[0], y), pt]
    xg = plan.gap_track
    return [
        ps,
        (ps[0], plan.track_1),
        (xg, plan.track_1),
        (xg, plan.track_2),
        (pt[0], plan.track_2),
        pt,
    ]


def _self_loop(node: GridNode) -> list[Point]:
    r = node.rect
    x = r.right + _SELF_LOOP_REACH
    top = (r.right, r.cy - 8) if node.shape != "diamond" else _outline_point(node, "right", -8)
    bottom = (r.right, r.cy + 8) if node.shape != "diamond" else _outline_point(node, "right", 8)
    return [top, (x, top[1]), (x, bottom[1]), bottom]


def _simplify(points: list[Point]) -> list[Point]:
    """Drop repeated points and merge collinear runs."""
    out: list[Point] = []
    for p in points:
        if (
            out
            and math.isclose(out[-1][0], p[0], abs_tol=0.5)
            and math.isclose(out[-1][1], p[1], abs_tol=0.5)
        ):
            continue
        out.append(p)
    i = 1
    while i < len(out) - 1:
        a, b, c = out[i - 1], out[i], out[i + 1]
        cross = (b[0] - a[0]) * (c[1] - b[1]) - (b[1] - a[1]) * (c[0] - b[0])
        if abs(cross) < 0.5:
            out.pop(i)
        else:
            i += 1
    return out


def polyline_to_path(points: list[Point], radius: float = _CORNER_RADIUS) -> str:
    """Render a polyline as an SVG path with rounded corners."""
    if not points:
        return ""
    parts = [f"M{points[0][0]:.1f},{points[0][1]:.1f}"]
    for i in range(1, len(points) - 1):
        a, b, c = points[i - 1], points[i], points[i + 1]
        len_in = math.dist(a, b)
        len_out = math.dist(b, c)
        r = min(radius, len_in / 2, len_out / 2)
        if r < 0.5:
            parts.append(f"L{b[0]:.1f},{b[1]:.1f}")
            continue
        p_in = (b[0] + (a[0] - b[0]) * r / len_in, b[1] + (a[1] - b[1]) * r / len_in)
        p_out = (b[0] + (c[0] - b[0]) * r / len_out, b[1] + (c[1] - b[1]) * r / len_out)
        parts.append(f"L{p_in[0]:.1f},{p_in[1]:.1f}")
        parts.append(f"Q{b[0]:.1f},{b[1]:.1f} {p_out[0]:.1f},{p_out[1]:.1f}")
    last = points[-1]
    parts.append(f"L{last[0]:.1f},{last[1]:.1f}")
    return " ".join(parts)


def route_segments(points: list[Point]) -> list[tuple[Point, Point]]:
    return list(zip(points, points[1:], strict=False))


def point_at_half_length(points: list[Point]) -> Point:
    """Point halfway along a polyline, measured by length."""
    return _sample(points, sum(math.dist(a, b) for a, b in route_segments(points)) / 2)[0]


def _sample(points: list[Point], s: float) -> tuple[Point, bool]:
    """Point at arc length ``s`` and whether its segment is vertical."""
    for a, b in route_segments(points):
        seg = math.dist(a, b)
        if seg > 0 and s <= seg:
            t = s / seg
            return (a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t), abs(b[0] - a[0]) < 0.5
        s -= seg
    return points[-1], False


def place_on_route(
    points: list[Point],
    size: tuple[float, float],
    obstacles: SpatialIndex | Sequence[Rect],
    bounds: Rect,
    avoid: SpatialIndex | Sequence[tuple[Point, Point]],
    end_clearance: float = 14.0,
    step: float = 4.0,
    avoid_pad: float = 4.0,
    skip_tag: Hashable = None,
    max_candidates: int = MAX_CANDIDATES,
) -> Rect | None:
    """Find a spot on the route for a ``size`` box that clears every obstacle.

    Candidates are centered on the route. Among the collision-free ones the
    closest to the route's midpoint wins, with penalties for sitting on a
    vertical run or covering other routes' segments.

    ``obstacles`` and ``avoid`` may be plain lists or ``SpatialIndex`` objects; the index lets a
    candidate look at nearby items only.
    Segments in ``avoid`` tagged ``skip_tag`` (the route being labelled) do not count.
    At most ``max_candidates`` positions are tried however long the route is: a longer route
    gets a coarser step.
    """
    w, h = size
    total = sum(math.dist(a, b) for a, b in route_segments(points))
    if total <= 0:
        return None
    mid = total / 2
    obstacle_index = _rect_index(obstacles)
    avoid_index = _segment_index(avoid)
    lo = min(end_clearance, mid)
    span = total - 2 * lo
    if span > 0 and span / step > max_candidates:
        step = span / max_candidates
    best: tuple[float, Rect] | None = None
    s = lo
    while s <= total - lo + 1e-6:
        (px, py), vertical = _sample(points, s)
        rect = Rect(px - w / 2, py - h / 2, w, h)
        here = s
        s += step
        if not bounds.contains(rect):
            continue
        if any(rect.intersects(o) for o in obstacle_index.rects_near(rect)):
            continue
        padded = rect.expand(avoid_pad)
        covered = sum(
            1
            for a, b, tag in avoid_index.segments_near(padded)
            if (skip_tag is None or tag != skip_tag) and padded.intersects_segment(a, b)
        )
        score = abs(here - mid) + covered * 40.0 + (30.0 if vertical else 0.0)
        if best is None or score < best[0]:
            best = (score, rect)
    return best[1] if best else None


def _rect_index(obstacles: SpatialIndex | Sequence[Rect]) -> SpatialIndex:
    if isinstance(obstacles, SpatialIndex):
        return obstacles
    index = SpatialIndex()
    for rect in obstacles:
        index.add_rect(rect)
    return index


def _segment_index(avoid: SpatialIndex | Sequence[tuple[Point, Point]]) -> SpatialIndex:
    if isinstance(avoid, SpatialIndex):
        return avoid
    index = SpatialIndex()
    for a, b in avoid:
        index.add_segment(a, b)
    return index
