"""Assessment report: data assembly (shared by the HTML page and the PDF) and PDF rendering."""
import io
from collections import Counter
from datetime import datetime, timezone
from xml.sax.saxutils import escape

import config
from app import ai, dash, db, settings
from app.dash import component_of

ORDER = dash.ORDER
COLORS = dash.COLORS
SHORT = dash.SHORT

LIMITATIONS = [
    "Results are automated scanner output from OWASP ZAP. They are not confirmed exploits and must be verified manually before remediation decisions are made.",
    "Automated scanning cannot find every vulnerability, especially business-logic flaws and issues behind authentication that the scanner could not reach.",
    "Priority scores are rule-based estimates built from scanner severity, exposure, impact and fix availability. They are a triage aid, not a formal risk rating.",
    "Explanations labelled as AI-assisted are advisory. They were checked against the scan data but do not add evidence.",
]


def pdf_available() -> bool:
    try:
        import reportlab  # noqa: F401
        return True
    except ImportError:
        return False


def _join(names: list) -> str:
    if len(names) <= 1:
        return "".join(names)
    return ", ".join(names[:-1]) + " and " + names[-1]


def _retest(scan, findings):
    prev = db.get_previous_scan(scan)
    if not prev:
        return None

    def keys(rows):
        return {(f["title"], component_of(f["url"]), f["param"] or "") for f in rows}

    old, new = keys(db.get_findings(prev["id"])), keys(findings)
    return {
        "previous_id": prev["id"],
        "previous_date": (prev["started_at"] or "")[:10],
        "fixed": len(old - new),
        "new": len(new - old),
        "persisting": len(old & new),
        "fixed_titles": sorted({k[0] for k in old - new})[:10],
        "new_titles": sorted({k[0] for k in new - old})[:10],
    }


def build_report(scan_id: int) -> dict:
    scan = db.get_scan(scan_id)
    findings = db.get_findings(scan_id)
    analyses = db.get_analyses(scan_id)
    groups = ai.group_findings(findings)
    counts = Counter(f["priority_label"] for f in findings)
    total = len(findings)
    urgent = counts.get("Critical", 0) + counts.get("High", 0)
    verify = counts.get("Requires verification", 0)
    components = {component_of(f["url"]) for f in findings}

    started = (scan["started_at"] or "").replace("T", " ")[:19]
    summary = (
        f"AEGIS AI ran a {scan['mode']} automated security assessment of {scan['target']}. "
        f"The scanner reported {total} finding{'s' if total != 1 else ''}, which AEGIS AI grouped into "
        f"{len(groups)} issue type{'s' if len(groups) != 1 else ''} across {len(components)} "
        f"component{'s' if len(components) != 1 else ''}. "
    )
    summary += (
        f"{urgent} finding{'s are' if urgent != 1 else ' is'} prioritised as Critical or High and should be reviewed first. "
        if urgent else "No findings reached Critical or High priority. "
    )
    if verify:
        summary += f"{verify} finding{'s are' if verify != 1 else ' is'} marked 'Requires verification' because the scanner reported low confidence. "
    if groups:
        summary += f"The most significant issue types are {_join([g['title'] for g in groups[:3]])}. "
    summary += "All results are automated scanner output and must be verified manually before remediation decisions are made."

    issues = []
    for i, g in enumerate(groups, 1):
        best = g["top"]
        a = analyses.get(g["key"])
        evidence = next((f["evidence"] for f in g["items"] if f["evidence"]), "")
        issues.append({
            "n": i, "title": g["title"], "priority": best["priority_label"], "score": best["priority_score"],
            "risk": best["risk"], "confidence": best["confidence"], "cwe": g["cwe"], "count": g["count"],
            "locations": g["locations"][:8], "more_locations": max(len(g["locations"]) - 8, 0),
            "description": ai.clean(best["description"], 700), "evidence": ai.clean(evidence, 300),
            "scanner_solution": ai.clean(best["solution"], 400),
            "analysis": None if a is None else {
                "source": a["source"], "model": a["model"], "explanation": a["explanation"],
                "impact": a["impact"], "remediation": a["remediation"], "note": a["note"],
            },
        })

    duration = ""
    try:
        if scan["finished_at"]:
            secs = int((datetime.fromisoformat(scan["finished_at"]) - datetime.fromisoformat(scan["started_at"])).total_seconds())
            duration = f"{secs // 60}m {secs % 60}s"
    except (TypeError, ValueError):
        pass

    return {
        "scan": dict(scan),
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "started": started,
        "duration": duration,
        "org": settings.get("org_name"),
        "tester": settings.get("tester_name"),
        "total": total,
        "counts": [(SHORT.get(label, label), counts.get(label, 0), COLORS[label]) for label in ORDER],
        "summary": summary,
        "issues": issues,
        "retest": _retest(scan, findings),
        "allowed": sorted(config.ALLOWED_TARGETS),
        "limitations": LIMITATIONS,
        "chain_ok": db.verify_audit_chain(),
        "hashed": sum(1 for f in findings if f["evidence_hash"]),
    }


# --------------------------------------------------------------------------- PDF
_SIMPLE = str.maketrans({
    "\u2192": "->", "\u2190": "<-", "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
    "\u2013": "-", "\u2014": "-", "\u2026": "...", "\u2022": "-", "\u00a0": " ",
})


def _t(value) -> str:
    """Escape for reportlab Paragraph; swap common symbols for plain ones the built-in Helvetica font can draw."""
    text = str(value if value is not None else "").translate(_SIMPLE)
    return escape(text.encode("latin-1", "replace").decode("latin-1"))


def build_pdf(report: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    ink, muted, line, accent = (colors.HexColor(c) for c in ("#111827", "#6b7280", "#e5e7eb", "#2f5fe0"))
    base = getSampleStyleSheet()["Normal"]
    S = {
        "body": ParagraphStyle("body", parent=base, fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=ink),
        "small": ParagraphStyle("small", parent=base, fontName="Helvetica", fontSize=8.5, leading=11.5, textColor=muted),
        "cell": ParagraphStyle("cell", parent=base, fontName="Helvetica", fontSize=8.5, leading=11.5, textColor=ink, wordWrap="CJK"),
        "label": ParagraphStyle("label", parent=base, fontName="Helvetica-Bold", fontSize=8, leading=11, textColor=muted),
        "title": ParagraphStyle("title", parent=base, fontName="Helvetica-Bold", fontSize=24, leading=28, textColor=ink),
        "h1": ParagraphStyle("h1", parent=base, fontName="Helvetica-Bold", fontSize=14, leading=18, textColor=accent, spaceBefore=16, spaceAfter=6, keepWithNext=1),
        "h2": ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=ink),
        "pill": ParagraphStyle("pill", parent=base, fontName="Helvetica-Bold", fontSize=8.5, leading=11, alignment=1),
    }
    W = A4[0] - 36 * mm
    P = lambda text, style="body": Paragraph(_t(text), S[style])

    def pill(label: str):
        hexcol = COLORS.get(label, "#9085e9")
        dark = label == "Medium"
        st = ParagraphStyle("p", parent=S["pill"], textColor=colors.HexColor("#111827") if dark else colors.white)
        return Paragraph(_t(SHORT.get(label, label)), st), colors.HexColor(hexcol)

    def grid(rows, widths, header=True):
        t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
        style = [
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, line),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]
        if header:
            style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6"))]
        t.setStyle(TableStyle(style))
        return t

    story = []
    scan = report["scan"]

    # Title block
    story += [P("Security Assessment Report", "title"), Spacer(1, 4),
              P(scan["target"], "h2"), Spacer(1, 10)]
    meta = [
        [P("ASSESSMENT", "label"), P(f"#{scan['id']} ({scan['mode']} scan)"), P("DATE", "label"), P(report["started"] + " UTC")],
        [P("PREPARED BY", "label"), P(report["tester"] or "-"), P("ORGANISATION", "label"), P(report["org"] or "-")],
        [P("GENERATED", "label"), P(report["generated"]), P("TOOL", "label"), P("AEGIS AI with OWASP ZAP")],
    ]
    mt = Table(meta, colWidths=[28 * mm, W / 2 - 28 * mm, 28 * mm, W / 2 - 28 * mm])
    mt.setStyle(TableStyle([("LINEABOVE", (0, 0), (-1, 0), 1.2, accent), ("LINEBELOW", (0, -1), (-1, -1), 0.4, line),
                            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                            ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(mt)

    # 1. Executive summary
    story += [P("1. Executive summary", "h1"), P(report["summary"])]
    heads, vals = [], []
    for label, n, hexcol in report["counts"]:
        heads.append(P(label.upper(), "label"))
        vals.append(Paragraph(f'<font size="18"><b>{n}</b></font>', S["body"]))
    ct = Table([heads, vals], colWidths=[W / len(heads)] * len(heads))
    cs = [("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
          ("BOX", (0, 0), (-1, -1), 0.4, line), ("INNERGRID", (0, 0), (-1, -1), 0.4, line)]
    for i, (_, _, hexcol) in enumerate(report["counts"]):
        cs.append(("LINEABOVE", (i, 0), (i, 0), 3, colors.HexColor(hexcol)))
    ct.setStyle(TableStyle(cs))
    story += [Spacer(1, 8), ct]

    # 2. Scope and methodology
    story += [P("2. Scope and methodology", "h1"),
              P(f"Target: {scan['target']}. Authorized targets configured in AEGIS AI: {', '.join(report['allowed'])}. "
                f"Scan type: {scan['mode']}. Duration: {report['duration'] or 'n/a'}."),
              Spacer(1, 4),
              P("Method: the target was loaded and crawled with the OWASP ZAP spider, ZAP's passive scanner analysed every response"
                + (", and the active scanner sent test requests to the target." if scan["mode"] == "active" else ".")
                + " Findings were normalised, grouped, and prioritised by AEGIS AI using scanner severity, exposure, "
                  "confidentiality/integrity/availability impact and fix availability.")]

    # 3. Findings summary
    story.append(P("3. Findings summary", "h1"))
    rows = [[P("#", "label"), P("ISSUE", "label"), P("PRIORITY", "label"), P("COUNT", "label"), P("CWE", "label")]]
    pill_styles = []
    for k, it in enumerate(report["issues"], start=1):
        para, col = pill(it["priority"])
        rows.append([P(it["n"], "cell"), P(it["title"], "cell"), para, P(it["count"], "cell"), P(f"CWE-{it['cwe']}" if it["cwe"] else "-", "cell")])
        pill_styles.append(("BACKGROUND", (2, k), (2, k), col))
    if len(rows) == 1:
        rows.append([P("", "cell"), P("No findings were reported.", "cell"), "", "", ""])
    ft = grid(rows, [10 * mm, W - 10 * mm - 36 * mm - 14 * mm - 22 * mm, 36 * mm, 14 * mm, 22 * mm])
    ft.setStyle(TableStyle(pill_styles))
    story.append(ft)

    # 4. Detailed findings
    pending = [P("4. Detailed findings", "h1")]  # kept together with the first finding so it is never stranded
    for it in report["issues"]:
        para, col = pill(it["priority"])
        head = Table([[P(f"{it['n']}. {it['title']}", "h2"), para]], colWidths=[W - 34 * mm, 34 * mm])
        head.setStyle(TableStyle([("BACKGROUND", (1, 0), (1, 0), col), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                  ("LINEBELOW", (0, 0), (-1, 0), 0.6, line), ("TOPPADDING", (0, 0), (-1, -1), 5),
                                  ("BOTTOMPADDING", (0, 0), (-1, -1), 5), ("LEFTPADDING", (0, 0), (0, 0), 0)]))
        where = ", ".join(it["locations"]) + (f" and {it['more_locations']} more" if it["more_locations"] else "")
        details = [
            ("Priority", f"{it['priority']} (score {it['score']}/100). Scanner risk: {it['risk']}, confidence: {it['confidence']}."),
            ("Occurrences", f"{it['count']} at: {where}"),
            ("CWE", f"CWE-{it['cwe']}" if it["cwe"] else "Not provided"),
            ("Scanner description", it["description"] or "-"),
        ]
        if it["evidence"]:
            details.append(("Evidence", it["evidence"]))
        a = it["analysis"]
        if a:
            if a["source"] == "ollama":
                tag = f"AI-assisted ({a['model']}), checked against scan data"
            else:
                tag = "Knowledge-base explanation"
            details += [(f"Explanation [{tag}]", a["explanation"]), ("Possible impact", a["impact"]), ("Recommended remediation", a["remediation"])]
        elif it["scanner_solution"]:
            details.append(("Recommended remediation", it["scanner_solution"]))
        drows = [[P(k.upper(), "label"), P(v, "cell")] for k, v in details]
        dt = Table(drows, colWidths=[34 * mm, W - 34 * mm])
        dt.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 3),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 3), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
        story += [KeepTogether(pending + [head, dt]), Spacer(1, 10)]
        pending = []
    story += pending + ([P("No findings were reported.")] if pending else [])

    # 5. Retest
    rt = report["retest"]
    story.append(P("5. Retest results", "h1"))
    if rt:
        story.append(P(f"Compared with assessment #{rt['previous_id']} of the same target ({rt['previous_date']}): "
                       f"{rt['fixed']} issue(s) no longer reported, {rt['new']} new, {rt['persisting']} still present. "
                       "Matching uses the finding name, component and parameter."))
        if rt["fixed_titles"]:
            story += [Spacer(1, 3), P("No longer reported: " + "; ".join(rt["fixed_titles"]), "small")]
        if rt["new_titles"]:
            story += [Spacer(1, 3), P("Newly reported: " + "; ".join(rt["new_titles"]), "small")]
    else:
        story.append(P("No earlier completed assessment of this target exists yet. Run another assessment after remediation to see fixed, new and persisting findings here."))

    # 6. Limitations
    story.append(P("6. Limitations", "h1"))
    for text in report["limitations"]:
        story += [P("- " + text), Spacer(1, 2)]

    # Appendix
    story += [P("Appendix A. Evidence integrity", "h1"),
              P(f"{report['hashed']} of {report['total']} findings carry a SHA-256 evidence hash taken when they were stored. "
                f"The scan audit log hash chain was {'verified intact' if report['chain_ok'] else 'NOT intact (entries were modified)'} when this report was generated.")]

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(muted)
        canvas.drawString(18 * mm, 10 * mm, "AEGIS AI  |  Security Assessment Report  |  Confidential")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm,
                            bottomMargin=18 * mm, title=f"AEGIS AI report - scan {scan['id']}", author="AEGIS AI")
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
