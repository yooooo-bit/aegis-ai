"""Builds the 3D attack-surface graph: target -> components (URL paths) <-> finding types."""
import re
from urllib.parse import urlparse

COLORS = {
    "Critical": "#d03b3b",
    "High": "#ec835a",
    "Medium": "#fab219",
    "Low": "#0ca30c",
    "Requires verification": "#9085e9",
}
TARGET_COLOR = "#4f7cff"


def _clean(text: str, limit: int = 320) -> str:
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def _path(url: str) -> str:
    return urlparse(url or "").path or "/"


def build_graph(target: str, findings, max_components: int = 40) -> dict:
    # Group findings by component (URL path) and by finding type (title).
    by_path, by_title = {}, {}
    for f in findings:
        by_path.setdefault(_path(f["url"]), []).append(f)
        by_title.setdefault(f["title"], []).append(f)

    def top(items):
        return max(items, key=lambda f: f["priority_score"])

    # Keep the most serious components so the scene stays readable.
    ranked = sorted(by_path.items(), key=lambda kv: (-top(kv[1])["priority_score"], -len(kv[1])))
    kept = dict(ranked[:max_components])

    nodes = [{
        "id": "target", "label": target, "group": "target", "color": TARGET_COLOR, "val": 14,
        "detail": f"Assessment target. {len(findings)} findings across {len(by_path)} components.",
    }]
    links = []
    used_titles = set()

    for path, items in kept.items():
        best = top(items)
        nodes.append({
            "id": f"c:{path}", "label": path, "group": "component",
            "color": COLORS.get(best["priority_label"], "#8b96b0"),
            "val": 2 + min(len(items), 12),
            "detail": f"{len(items)} finding(s). Highest priority: {best['priority_label']} ({best['priority_score']}).",
        })
        links.append({"source": "target", "target": f"c:{path}"})
        for title in {f["title"] for f in items}:
            used_titles.add(title)
            links.append({"source": f"c:{path}", "target": f"f:{title}"})

    for title in used_titles:
        items = by_title[title]
        best = top(items)
        nodes.append({
            "id": f"f:{title}", "label": title, "group": "finding",
            "color": COLORS.get(best["priority_label"], "#8b96b0"),
            "val": 3 + min(len(items), 10),
            "detail": f"{best['priority_label']} ({best['priority_score']}) · {len(items)} occurrence(s). "
                      f"{_clean(best['description'])} Fix: {_clean(best['solution'], 220) or 'no guidance provided.'}",
        })

    return {
        "nodes": nodes,
        "links": links,
        "meta": {"components_shown": len(kept), "components_total": len(by_path), "finding_types": len(used_titles)},
    }
