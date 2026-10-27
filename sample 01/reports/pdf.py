"""PDF generator for Website Security Posture & Phishing Reports using ReportLab.

Generates in-memory streaming PDFs with zero file system persistence.
"""
from __future__ import annotations

import io
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether


def clean(value: object, limit: int = 1200) -> str:
    """Safely escape and truncate report text for XML-based flowables."""
    return escape(str(value or "")[:limit])


def build_report_pdf(report: dict) -> bytes:
    """Build a concise, beautifully styled PDF in memory; no data is persisted."""
    checks = report.get("checks")
    if not isinstance(checks, list) or len(checks) > 30:
        raise ValueError("The report format is invalid.")

    buffer = io.BytesIO()

    # Premium Modern Cybersecurity Palette
    dark_primary = colors.HexColor("#0B132B")
    accent_emerald = colors.HexColor("#10B981")
    accent_amber = colors.HexColor("#F59E0B")
    accent_crimson = colors.HexColor("#EF4444")
    card_bg = colors.HexColor("#F8FAFC")
    border_color = colors.HexColor("#E2E8F0")
    ink_color = colors.HexColor("#0F172A")
    muted_color = colors.HexColor("#64748B")

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.white,
        alignment=0,
        spaceAfter=0,
    ))
    styles.add(ParagraphStyle(
        name="ReportSub",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#CBD5E1"),
    ))
    styles.add(ParagraphStyle(
        name="SectionHead",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=dark_primary,
        spaceBefore=8,
        spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        name="CardTitle",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        textColor=dark_primary,
        spaceAfter=2,
    ))
    styles.add(ParagraphStyle(
        name="SmallBody",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        textColor=muted_color,
    ))
    styles.add(ParagraphStyle(
        name="EvidenceBody",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        textColor=ink_color,
    ))
    styles.add(ParagraphStyle(
        name="FieldLabel",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=7,
        leading=9,
        textColor=muted_color,
        spaceBefore=3,
    ))
    styles.add(ParagraphStyle(
        name="ScoreBig",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=accent_emerald,
    ))

    story = []
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    target = clean(report.get("target", "Unknown target"), 220)
    assessed = clean(report.get("assessed_at", "Not provided"), 80)

    # Header Banner
    header = Table([
        [
            Paragraph("🛡️ Website Security Posture & Phishing Report", styles["ReportTitle"]),
            Paragraph(f"<b>TARGET:</b> {target}<br/><b>ASSESSED:</b> {assessed}", styles["ReportSub"]),
        ]
    ], colWidths=[105 * mm, 65 * mm])
    header.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), dark_primary),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5 * mm),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5 * mm),
        ("TOPPADDING", (0, 0), (-1, -1), 5 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5 * mm),
    ]))
    story += [header, Spacer(1, 4 * mm)]

    # Score & Posture Summary Box
    score_val = summary.get("score")
    score_text = "N/A" if score_val is None else f"{clean(score_val, 10)}/100"
    badge_label = clean(summary.get("badge", summary.get("label", "Assessment Completed")), 120)

    summary_box = Table([
        [
            [
                Paragraph(score_text, styles["ScoreBig"]),
                Paragraph("Weighted Posture Score", styles["SmallBody"]),
            ],
            [
                Paragraph(f"<b>Status: {badge_label}</b>", styles["CardTitle"]),
                Paragraph(
                    f"{clean(summary.get('completed', 0), 8)} of {clean(summary.get('total', 0), 8)} checks completed. "
                    "Unknown and not-applicable checks are excluded from failure penalties.",
                    styles["SmallBody"],
                ),
                Paragraph("This snapshot represents a passive, non-intrusive configuration audit.", styles["SmallBody"]),
            ],
        ]
    ], colWidths=[45 * mm, 125 * mm])
    summary_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), card_bg),
        ("BOX", (0, 0), (-1, -1), 0.8, border_color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4 * mm),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4 * mm),
        ("TOPPADDING", (0, 0), (-1, -1), 3 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3 * mm),
    ]))
    story += [summary_box, Spacer(1, 3 * mm)]

    # Threat Intelligence Findings
    story.append(Paragraph("🔍 Phishing & Known-Threat Intelligence", styles["SectionHead"]))
    lookup = report.get("threat_lookup") if isinstance(report.get("threat_lookup"), dict) else {}
    lookup_status = lookup.get("status", "unknown")
    lookup_title = {
        "match": "⚠️ Known Threat Match Found",
        "no_match": "✅ No Known Threat Match Found",
        "unknown": "ℹ️ Threat Lookup Could Not Be Completed",
    }.get(lookup_status, "Threat Lookup Incomplete")
    
    lookup_text = clean(lookup.get("evidence", "No threat lookup data was included."), 700)
    if lookup_status == "no_match":
        lookup_text += " This does not prove the website is genuine or phishing-free."
    if isinstance(lookup.get("threat_types"), list) and lookup["threat_types"]:
        lookup_text += " Detected threat types: " + clean(", ".join(map(str, lookup["threat_types"][:10])), 200) + "."

    intel_table = Table([[
        [
            Paragraph(f"<b>{clean(lookup_title, 100)}</b>", styles["CardTitle"]),
            Paragraph(lookup_text, styles["EvidenceBody"]),
            Paragraph(
                f"<font color='#64748B'>Provider: {clean(lookup.get('provider', 'Google Safe Browsing'), 100)} · "
                "Passive reputation lookup only.</font>",
                styles["SmallBody"],
            ),
        ]
    ]], colWidths=[170 * mm])
    intel_bg = (
        colors.HexColor("#FEF2F2") if lookup_status == "match"
        else colors.HexColor("#F0FDF4") if lookup_status == "no_match"
        else colors.HexColor("#F8FAFC")
    )
    intel_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), intel_bg),
        ("BOX", (0, 0), (-1, -1), 0.6, border_color),
        ("LEFTPADDING", (0, 0), (-1, -1), 4 * mm),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4 * mm),
        ("TOPPADDING", (0, 0), (-1, -1), 3 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3 * mm),
    ]))
    story += [intel_table, Spacer(1, 3 * mm)]

    # Detailed Findings Section
    story.append(Paragraph("📋 Security Control Findings", styles["SectionHead"]))
    colors_by_status = {
        "present": (colors.HexColor("#ECFDF5"), accent_emerald, "PASSED"),
        "not_present": (colors.HexColor("#FFFBEB"), accent_amber, "NEEDS ATTENTION"),
        "not_applicable": (colors.HexColor("#F1F5F9"), muted_color, "N/A"),
        "unknown": (colors.HexColor("#F1F5F9"), muted_color, "UNCHECKED"),
    }

    for item in checks:
        if not isinstance(item, dict):
            continue
        status = item.get("status", "unknown")
        bg, accent, badge = colors_by_status.get(status, colors_by_status["unknown"])

        head = Table([
            [
                Paragraph(clean(item.get("title", "Untitled Check"), 150), styles["CardTitle"]),
                Paragraph(f"<b>{badge}</b>", styles["SmallBody"]),
            ]
        ], colWidths=[125 * mm, 40 * mm])
        head.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 0), (1, 0), "RIGHT"),
            ("BACKGROUND", (1, 0), (1, 0), bg),
            ("BOX", (1, 0), (1, 0), 0.5, accent),
            ("LEFTPADDING", (1, 0), (-1, -1), 2 * mm),
            ("RIGHTPADDING", (1, 0), (-1, -1), 2 * mm),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5 * mm),
        ]))

        parts = [
            head,
            Paragraph(f"Category: {clean(item.get('category', ''), 80)}", styles["SmallBody"]),
            Paragraph("Observed Evidence", styles["FieldLabel"]),
            Paragraph(clean(item.get("evidence", "No evidence available.")), styles["EvidenceBody"]),
        ]
        if item.get("impact"):
            parts.extend([
                Paragraph("Potential Security Impact", styles["FieldLabel"]),
                Paragraph(clean(item["impact"]), styles["EvidenceBody"]),
            ])
        if item.get("remediation"):
            parts.extend([
                Paragraph("Recommended Remediation Action", styles["FieldLabel"]),
                Paragraph(clean(item["remediation"]), styles["EvidenceBody"]),
            ])
        parts.append(
            Paragraph(f"Confidence: {clean(item.get('confidence', 'High'), 40)}", styles["SmallBody"])
        )

        card = Table([[parts]], colWidths=[170 * mm])
        card.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.6, border_color),
            ("LINEBEFORE", (0, 0), (0, 0), 3, accent),
            ("LEFTPADDING", (0, 0), (-1, -1), 3.5 * mm),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3.5 * mm),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5 * mm),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5 * mm),
        ]))
        story += [KeepTogether(card), Spacer(1, 2 * mm)]

    # Limitations & Legal Notice
    story.append(Paragraph("⚠️ Limitations and Interpretation", styles["SectionHead"]))
    story.append(Paragraph(
        clean(report.get("limitations", "Passive single-response review only."), 1000),
        styles["SmallBody"],
    ))
    story.append(Spacer(1, 1.5 * mm))
    story.append(Paragraph(
        "A missing header alone is not proof of exploitability. HTTPS encrypts traffic in transit "
        "but does not guarantee that a site represents a legitimate, trusted organization. "
        "Always verify suspicious domains through independent official channels.",
        styles["SmallBody"],
    ))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(border_color)
        canvas.line(18 * mm, 14 * mm, A4[0] - 18 * mm, 14 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(muted_color)
        canvas.drawString(18 * mm, 9 * mm, "Website Security Posture Checker | Non-Intrusive Passive Assessment")
        canvas.drawRightString(A4[0] - 18 * mm, 9 * mm, f"Page {doc.page}")
        canvas.restoreState()

    SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=14 * mm,
        bottomMargin=18 * mm,
        title="Website Security Posture Report",
    ).build(story, onFirstPage=footer, onLaterPages=footer)

    return buffer.getvalue()
