"""AI analysis layer.

Two sources, both stored in the `analyses` table and always labelled in the UI:

1. rules  - deterministic knowledge-base text (always available, no model needed).
2. ollama - optional local LLM. It sees ONLY the stored finding fields, must answer in JSON, and its
            output is rejected if it mentions CVE/CWE ids or URLs that are not in the scan data.

AI output is advisory. It never creates, removes or changes a finding.
"""
import html
import json
import re
import threading
from collections import Counter

import requests

from app import db, knowledge, settings
from app.dash import component_of

PROGRESS = {}          # scan_id -> {"running", "done", "total", "rejected", "error"}
_lock = threading.Lock()
FIELDS = ("explanation", "impact", "remediation")


def clean(text, limit: int = 600) -> str:
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = re.sub(r"\s+", " ", html.unescape(text)).strip()
    return text[:limit] + ("..." if len(text) > limit else "")


def valid_cwe(cwe) -> bool:
    return bool(cwe) and str(cwe) not in ("0", "-1")


def group_findings(findings) -> list:
    """Group related findings (same CWE, or same title when there is no CWE) and rank by priority."""
    groups = {}
    for f in findings:
        if valid_cwe(f["cwe"]):
            key, cwe = f"cwe-{f['cwe']}", str(f["cwe"])
        else:
            key, cwe = "title-" + re.sub(r"[^a-z0-9]+", "-", (f["title"] or "").lower()).strip("-"), ""
        groups.setdefault(key, {"key": key, "cwe": cwe, "items": []})["items"].append(f)

    out = []
    for g in groups.values():
        items = g["items"]
        titles = Counter(f["title"] for f in items)
        g.update(
            title=titles.most_common(1)[0][0],
            titles=sorted(titles),
            top=max(items, key=lambda f: f["priority_score"]),
            count=len(items),
            locations=sorted({component_of(f["url"]) for f in items}),
        )
        out.append(g)
    out.sort(key=lambda g: (-g["top"]["priority_score"], -g["count"]))
    return out


# ---------------------------------------------------------------- rules layer
def rules_analysis(g: dict) -> dict:
    entry = knowledge.lookup(g["cwe"], g["title"])
    best = g["top"]
    scanner_fix = clean(best["solution"], 300)
    if entry:
        explanation, impact, fix = entry["explain"], entry["impact"], entry["fix"]
        if scanner_fix:
            fix += " Scanner suggestion: " + scanner_fix
    else:
        explanation = clean(best["description"]) or f"The scanner reported '{g['title']}'."
        impact = "The impact depends on how this component is used. Confirm the issue manually before rating the business risk."
        fix = scanner_fix or "The scanner gave no remediation guidance. Research the finding name and its CWE reference."
    shown = g["locations"][:5]
    more = len(g["locations"]) - len(shown)
    where = ", ".join(shown) + (f" and {more} more" if more > 0 else "")
    explanation += f" Reported {g['count']} time(s) at: {where}."
    return {"explanation": explanation, "impact": impact, "remediation": fix}


def generate_rules(scan_id: int, overwrite: bool = False) -> int:
    """Create rules-based analyses for every finding group. Returns how many were written."""
    existing = db.get_analyses(scan_id)
    written = 0
    for g in group_findings(db.get_findings(scan_id)):
        if g["key"] in existing and not overwrite:
            continue
        a = rules_analysis(g)
        db.upsert_analysis(scan_id, g["key"], "rules", a["explanation"], a["impact"], a["remediation"])
        written += 1
    return written


# ----------------------------------------------------------------- Ollama layer
def _source_text(g: dict) -> str:
    """Everything the model is allowed to rely on, lowercased, for grounding checks."""
    parts = [g["title"], *g["titles"], g["cwe"]]
    for f in g["items"]:
        parts += [f["title"], f["url"], f["param"], f["description"], f["solution"], f["evidence"], f["risk"]]
    return " ".join(str(p) for p in parts if p).lower()


def build_prompt(g: dict) -> str:
    best = g["top"]
    facts = {
        "finding_name": g["title"],
        "cwe": g["cwe"] or "none",
        "scanner_risk": best["risk"],
        "scanner_confidence": best["confidence"],
        "occurrences": g["count"],
        "locations": g["locations"][:8],
        "scanner_description": clean(best["description"], 700),
        "scanner_solution": clean(best["solution"], 500),
    }
    return (
        "You help a junior penetration tester understand automated scanner output.\n"
        "Use ONLY the facts in the JSON below. Do not mention any vulnerability, CVE or CWE identifier, "
        "software version or URL that is not in the facts. Do not claim the issue is confirmed or exploitable; "
        "it is scanner output that still needs manual verification.\n"
        'Reply with a JSON object with exactly these string keys: "explanation" (what it is, in simple words, '
        'max 3 sentences), "impact" (possible business impact, max 2 sentences), "remediation" (practical fix '
        "steps, max 3 sentences).\n\nFACTS:\n" + json.dumps(facts, indent=2)
    )


def verify_grounding(data, g: dict) -> tuple:
    """Return (ok, reasons). Rejects output that is malformed or invents identifiers/URLs."""
    reasons = []
    if not isinstance(data, dict):
        return False, ["the model did not return a JSON object"]
    for key in FIELDS:
        if not isinstance(data.get(key), str) or not data[key].strip():
            reasons.append(f"missing '{key}'")
    if reasons:
        return False, reasons

    blob = " ".join(data[k] for k in FIELDS)
    source = _source_text(g)
    for cve in set(re.findall(r"CVE-\d{4}-\d{4,}", blob, re.I)):
        if cve.lower() not in source:
            reasons.append(f"{cve.upper()} is not in the scan data")
    for num in set(re.findall(r"CWE[- ]?(\d+)", blob, re.I)):
        if num != g["cwe"] and f"cwe-{num}" not in source:
            reasons.append(f"CWE-{num} is not in the scan data")
    for url in set(re.findall(r"https?://[^\s\"')<>]+", blob)):
        if url.rstrip(".,;").lower() not in source:
            reasons.append(f"URL {url[:50]} is not in the scan data")
    return (not reasons), reasons


def check_ollama() -> str:
    """Raise RuntimeError with a friendly message if Ollama or the model is unavailable."""
    url, model = settings.get("ollama_url").rstrip("/"), settings.get("ollama_model")
    try:
        r = requests.get(f"{url}/api/tags", timeout=5)
        r.raise_for_status()
        names = [m.get("name", "") for m in r.json().get("models", [])]
    except (requests.RequestException, ValueError) as exc:
        raise RuntimeError(f"Cannot reach Ollama at {url}. Is it running? ({exc.__class__.__name__})") from exc
    if model not in names and f"{model}:latest" not in names:
        raise RuntimeError(f"Model '{model}' is not installed in Ollama. Run: ollama pull {model}")
    return model


def ollama_analysis(g: dict) -> dict:
    url, model = settings.get("ollama_url").rstrip("/"), settings.get("ollama_model")
    r = requests.post(
        f"{url}/api/generate",
        json={"model": model, "prompt": build_prompt(g), "stream": False, "format": "json",
              "options": {"temperature": 0.2}},
        timeout=180,
    )
    r.raise_for_status()
    return json.loads(r.json()["response"])


def start_enhancement(scan_id: int) -> bool:
    with _lock:
        if PROGRESS.get(scan_id, {}).get("running"):
            return False
        PROGRESS[scan_id] = {"running": True, "done": 0, "total": 0, "rejected": 0, "error": None}
    threading.Thread(target=_enhance, args=(scan_id,), daemon=True).start()
    return True


def _enhance(scan_id: int):
    prog = PROGRESS[scan_id]
    try:
        model = check_ollama()
        groups = group_findings(db.get_findings(scan_id))
        prog["total"] = len(groups)
        db.audit("analysis_started", "", f"scan_id={scan_id} model={model}")
        for g in groups:
            try:
                data = ollama_analysis(g)
                ok, reasons = verify_grounding(data, g)
            except (requests.RequestException, ValueError, KeyError) as exc:
                ok, reasons, data = False, [f"model call failed: {exc.__class__.__name__}"], None
            if ok:
                db.upsert_analysis(scan_id, g["key"], "ollama", data["explanation"][:900],
                                   data["impact"][:700], data["remediation"][:900], 1, model, None)
            else:
                prog["rejected"] += 1
                db.set_analysis_note(scan_id, g["key"], "Local AI output rejected: " + "; ".join(reasons))
            prog["done"] += 1
        db.audit("analysis_completed", "", f"scan_id={scan_id} groups={len(groups)} rejected={prog['rejected']}")
    except Exception as exc:  # keep rules-based results; show the reason on the page
        prog["error"] = str(exc)
    finally:
        prog["running"] = False
