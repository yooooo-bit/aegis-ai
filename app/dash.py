"""Aggregation and chart geometry for the overview dashboard (pure Python, no JS chart library)."""
import math
from collections import Counter
from datetime import datetime
from urllib.parse import urlparse

ORDER = ["Critical", "High", "Medium", "Low", "Requires verification"]
SHORT = {"Requires verification": "Needs verification"}
# Severity uses the fixed status palette; "needs verification" takes a neutral violet.
COLORS = {
    "Critical": "#d03b3b",
    "High": "#ec835a",
    "Medium": "#fab219",
    "Low": "#0ca30c",
    "Requires verification": "#9085e9",
}

# Trend chart canvas (SVG user units)
W, H = 720, 240
X0, X1, Y0, Y1 = 44, W - 90, 16, H - 34


def component_of(url: str) -> str:
    return urlparse(url or "").path or "/"


def _date_label(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso)
        return f"{dt.strftime('%b')} {dt.day}"
    except (TypeError, ValueError):
        return ""


def build_donut(counts: Counter) -> dict:
    r = 70
    circ = 2 * math.pi * r
    total = sum(counts.values())
    live = [label for label in ORDER if counts.get(label)]
    gap = 2.0 if len(live) > 1 else 0.0  # 2px surface gap between segments
    segments, offset = [], 0.0
    for label in live:
        n = counts[label]
        length = n / total * circ
        segments.append({
            "label": SHORT.get(label, label), "count": n, "color": COLORS[label],
            "dash": f"{max(length - gap, 0.5):.2f} {circ:.2f}", "offset": f"{-offset:.2f}",
        })
        offset += length
    return {"r": r, "segments": segments, "total": total}


def _smooth(points):
    if len(points) < 2:
        return ""
    d = f"M{points[0][0]:.1f},{points[0][1]:.1f}"
    for (xa, ya), (xb, yb) in zip(points, points[1:]):
        cx = (xa + xb) / 2
        d += f" C{cx:.1f},{ya:.1f} {cx:.1f},{yb:.1f} {xb:.1f},{yb:.1f}"
    return d


def build_trend(rows: list) -> dict:
    n = len(rows)
    top = int(math.ceil(max([r["total"] for r in rows] + [4]) / 4) * 4)

    def x_at(i):
        return (X0 + X1) / 2 if n == 1 else X0 + (X1 - X0) * i / (n - 1)

    def y_at(v):
        return Y1 - (Y1 - Y0) * v / top

    pts_total = [(x_at(i), y_at(r["total"])) for i, r in enumerate(rows)]
    pts_urgent = [(x_at(i), y_at(r["urgent"])) for i, r in enumerate(rows)]
    line_total, line_urgent = _smooth(pts_total), _smooth(pts_urgent)
    area_total = ""
    if line_total:
        area_total = f"{line_total} L{pts_total[-1][0]:.1f},{Y1} L{pts_total[0][0]:.1f},{Y1} Z"

    points = []
    for i, r in enumerate(rows):
        label = f"Assessment #{r['id']}" + (f" · {_date_label(r['started_at'])}" if r.get("started_at") else "")
        points.append({
            "x": round(pts_total[i][0], 1), "ty": round(pts_total[i][1], 1), "uy": round(pts_urgent[i][1], 1),
            "label": label, "id": r["id"], "date": _date_label(r.get("started_at")),
            "total": r["total"], "urgent": r["urgent"],
        })

    end_total_y = pts_total[-1][1] if n else 0
    end_urgent_y = pts_urgent[-1][1] if n else 0
    if n and abs(end_total_y - end_urgent_y) < 14:  # keep the two end labels apart
        end_urgent_y = end_total_y + 14

    return {
        "w": W, "h": H, "x0": X0, "x1": X1, "y0": Y0, "y1": Y1, "n": n,
        "grid": [{"y": round(y_at(top * k / 4), 1), "label": int(top * k / 4)} for k in range(5)],
        "xlabels": [{"x": p["x"], "text": f"#{p['id']}"} for i, p in enumerate(points) if n <= 8 or i % 2 == 0],
        "line_total": line_total, "line_urgent": line_urgent, "area_total": area_total,
        "points": points, "end_total_y": round(end_total_y, 1), "end_urgent_y": round(end_urgent_y, 1),
    }


def _bars(counter: Counter, k: int = 3) -> list:
    items = counter.most_common(k)
    peak = items[0][1] if items else 1
    return [{"label": label, "count": count, "pct": max(round(count / peak * 100), 4)} for label, count in items]


def build_dashboard(findings, trend_rows) -> dict:
    counts = Counter(f["priority_label"] for f in findings)
    comps = Counter(component_of(f["url"]) for f in findings)
    types = Counter(f["title"] for f in findings)
    return {
        "donut": build_donut(counts),
        "legend": [{"label": SHORT.get(l, l), "count": counts.get(l, 0), "color": COLORS[l]} for l in ORDER],
        "trend": build_trend([dict(r) for r in trend_rows]),
        "components": {"total": len(comps), "top": _bars(comps)},
        "types": {"total": len(types), "top": _bars(types)},
    }
