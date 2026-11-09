"""Rule-based risk prioritization (Phase 3 starter).

Score (0-100) = severity + exposure + CIA impact + fix availability.
Low-confidence findings are labelled 'Requires verification' instead of being
presented as confirmed.
"""
from app import settings

SEVERITY_POINTS = {"High": 50, "Medium": 30, "Low": 12, "Informational": 3}

# Rough CIA impact by CWE id (extend this table as you learn more).
CIA_BY_CWE = {
    "79": 15,    # XSS
    "89": 25,    # SQL injection
    "22": 20,    # Path traversal
    "200": 15,   # Information exposure
    "209": 10,   # Error message info leak
    "284": 20,   # Improper access control
    "352": 15,   # CSRF
    "693": 8,    # Protection mechanism failure (missing headers)
    "1021": 8,   # Clickjacking
    "16": 8,     # Configuration
    "614": 8,    # Cookie flags
    "1275": 6,   # SameSite
}


def score_finding(f: dict) -> dict:
    score = SEVERITY_POINTS.get(f["risk"], 3)
    score += 15 if settings.get_bool("internet_exposed") else 5
    score += CIA_BY_CWE.get(str(f.get("cwe")), 5)
    score += 10 if (f.get("solution") or "").strip() else 0
    score = min(score, 100)

    if f.get("confidence") in ("Low", "False Positive"):
        label = "Requires verification"
    elif score >= 70:
        label = "Critical"
    elif score >= 50:
        label = "High"
    elif score >= 30:
        label = "Medium"
    else:
        label = "Low"

    f["priority_score"] = score
    f["priority_label"] = label
    return f
