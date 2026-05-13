"""
reports/report_generator.py
-----------------------------
Generates a PDF compliance report using ReportLab (free, no cloud).
Run: python reports/report_generator.py
"""

import sqlite_utils
import pandas as pd
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Table, TableStyle,
    Spacer, HRFlowable,
)

DB_PATH    = "sentinel.db"
OUTPUT_PDF = f"reports/SentinelAI_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#E24B4A"),
    "HIGH":     colors.HexColor("#EF9F27"),
    "MEDIUM":   colors.HexColor("#378ADD"),
    "LOW":      colors.HexColor("#1D9E75"),
}

OWASP_DESCRIPTIONS = {
    "A01": ("Broken Access Control",           "Restrictions on authenticated users are not properly enforced."),
    "A02": ("Cryptographic Failures",          "Failures related to cryptography that expose sensitive data."),
    "A03": ("Injection",                       "User-supplied data is not validated or sanitized."),
    "A04": ("Insecure Design",                 "Missing or ineffective security controls in the design phase."),
    "A05": ("Security Misconfiguration",       "Insecure default configurations or incomplete setups."),
    "A06": ("Vulnerable and Outdated Components", "Using components with known vulnerabilities."),
    "A07": ("Identification & Auth Failures",  "Weaknesses in authentication allow credential-based attacks."),
    "A08": ("Software & Data Integrity Failures", "Code and data integrity not verified — deserialization flaws."),
    "A09": ("Security Logging & Monitoring",   "Insufficient logging prevents breach detection."),
    "A10": ("Server-Side Request Forgery",     "Server fetches a remote resource from attacker-controlled URL."),
}

def generate():
    db = sqlite_utils.Database(DB_PATH)
    tables = db.table_names()

    reqs    = pd.DataFrame(db["requests"].rows) if "requests" in tables else pd.DataFrame()
    threats = pd.DataFrame(db["threats"].rows)  if "threats"  in tables else pd.DataFrame()

    doc    = SimpleDocTemplate(OUTPUT_PDF, pagesize=A4,
                               leftMargin=2*cm, rightMargin=2*cm,
                               topMargin=2*cm,  bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []

    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=20, spaceAfter=6)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=14, spaceAfter=4)
    h3 = ParagraphStyle("h3", parent=styles["Heading3"], fontSize=11, spaceAfter=2)
    body_style = styles["BodyText"]
    body_style.fontSize = 9

    # ── Cover ──────────────────────────────────────────────────────────────────
    story.append(Paragraph("SentinelAI — Security Assessment Report", h1))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y %H:%M UTC')}", body_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.4*cm))

    # ── Executive Summary ──────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", h2))
    total_req    = len(reqs)
    total_threats= len(threats)
    critical_ct  = len(threats[threats.severity == "CRITICAL"]) if not threats.empty else 0
    high_ct      = len(threats[threats.severity == "HIGH"])     if not threats.empty else 0

    summary_data = [
        ["Metric", "Value"],
        ["Total requests monitored", str(total_req)],
        ["Total threats detected",   str(total_threats)],
        ["Critical threats",         str(critical_ct)],
        ["High threats",             str(high_ct)],
        ["Unique OWASP categories",  str(threats["owasp_id"].nunique()) if not threats.empty else "0"],
    ]
    t = Table(summary_data, colWidths=[9*cm, 6*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1,  0), colors.HexColor("#2C2C2A")),
        ("TEXTCOLOR",   (0, 0), (-1,  0), colors.white),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#F1EFE8"), colors.white]),
        ("GRID",        (0, 0), (-1, -1), 0.25, colors.HexColor("#D3D1C7")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.5*cm))

    # ── OWASP Category Breakdown ───────────────────────────────────────────────
    story.append(Paragraph("OWASP Top 10 Coverage", h2))

    for owasp_id, (name, description) in OWASP_DESCRIPTIONS.items():
        category_threats = (
            threats[threats.owasp_id == owasp_id] if not threats.empty else pd.DataFrame()
        )
        count = len(category_threats)
        label = f"{owasp_id}: {name} — {count} finding(s)"
        story.append(Paragraph(label, h3))
        story.append(Paragraph(description, body_style))

        if count > 0:
            rows = [["Severity", "Threat Type", "Detail"]]
            for _, row in category_threats.head(10).iterrows():
                sev   = str(row.get("severity", ""))
                ttype = str(row.get("threat_type", ""))[:60]
                detail= str(row.get("detail", ""))[:80]
                rows.append([sev, ttype, detail])

            ct = Table(rows, colWidths=[2.5*cm, 6*cm, 8*cm])
            ct.setStyle(TableStyle([
                ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#444441")),
                ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
                ("FONTSIZE",    (0, 0), (-1,-1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.HexColor("#F1EFE8"), colors.white]),
                ("GRID",        (0, 0), (-1,-1), 0.25, colors.HexColor("#D3D1C7")),
                ("LEFTPADDING", (0, 0), (-1,-1), 6),
            ]))
            story.append(ct)
        story.append(Spacer(1, 0.3*cm))

    doc.build(story)
    print(f"✅ Report saved to: {OUTPUT_PDF}")

if __name__ == "__main__":
    generate()
