"""Handles all FastAPI + ElevenLabs calls. Falls back to mock if unavailable."""

import os
import time
import json
import requests
import urllib3
from io import BytesIO
from dotenv import load_dotenv

from mock_data import MOCK_ALERTS, MOCK_COPILOT_RESPONSE

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
USE_MOCK = os.getenv("USE_MOCK", "true").lower() == "true"
ELEVENLABS_API_KEY = os.getenv("ELEVENLABS_API_KEY", "")
ELEVENLABS_VOICE_ID = os.getenv("ELEVENLABS_VOICE_ID", "EXAVITQu4vr4xnSDxMaL")

TIMEOUT = 10


# ============================================================
# HEALTH
# ============================================================

def get_health():
    if USE_MOCK:
        return {"status": "mock-ok"}
    try:
        r = requests.get(f"{API_BASE_URL}/health", timeout=TIMEOUT, verify=False)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"status": "unreachable", "error": str(e)}


# ============================================================
# ALERTS
# ============================================================

def get_alerts():
    if USE_MOCK:
        return MOCK_ALERTS, None
    try:
        r = requests.get(
            f"{API_BASE_URL}/api/alerts", timeout=TIMEOUT, verify=False
        )
        r.raise_for_status()
        return r.json(), None
    except Exception as e:
        return [], str(e)


# ============================================================
# PARSE LOGS
# ============================================================

def parse_logs(uploaded_file):
    if USE_MOCK:
        return {"parsed_events": [], "note": "mock parse (no backend)"}, None
    try:
        files = {"file": (uploaded_file.name, uploaded_file.getvalue())}
        r = requests.post(
            f"{API_BASE_URL}/api/logs/parse",
            files=files,
            timeout=TIMEOUT,
            verify=False,
        )
        r.raise_for_status()
        return r.json(), None
    except Exception as e:
        return None, str(e)


# ============================================================
# DETECTION
# ============================================================

def run_detection():
    if USE_MOCK:
        return {"alerts": MOCK_ALERTS}, None
    try:
        r = requests.post(
            f"{API_BASE_URL}/api/detect", timeout=TIMEOUT, verify=False
        )
        r.raise_for_status()
        return r.json(), None
    except Exception as e:
        return None, str(e)


# ============================================================
# AI COPILOT
# ============================================================

def analyze_alert(alert):
    if USE_MOCK:
        time.sleep(0.6)
        return MOCK_COPILOT_RESPONSE, None
    try:
        r = requests.post(
            f"{API_BASE_URL}/api/copilot/analyze",
            json=alert,
            timeout=30,
            verify=False,
        )
        r.raise_for_status()
        return r.json(), None
    except Exception as e:
        return None, str(e)


# ============================================================
# STATUS UPDATE
# ============================================================

def update_alert_status(alert_id, status):
    if USE_MOCK:
        return {"alert_id": alert_id, "status": status}, None
    try:
        r = requests.patch(
            f"{API_BASE_URL}/api/alerts/{alert_id}/status",
            json={"status": status},
            timeout=TIMEOUT,
            verify=False,
        )
        r.raise_for_status()
        return r.json(), None
    except Exception as e:
        return None, str(e)


# ============================================================
# ELEVENLABS — VOICE BRIEFING
# ============================================================

def generate_voice_briefing(text: str):
    if not ELEVENLABS_API_KEY or ELEVENLABS_API_KEY.startswith("yahan"):
        return None, "missing_api_key"

    try:
        url = (
            f"https://api.elevenlabs.io/v1/text-to-speech/"
            f"{ELEVENLABS_VOICE_ID}"
        )
        headers = {
            "xi-api-key": ELEVENLABS_API_KEY,
            "Content-Type": "application/json",
            "Accept": "audio/mpeg",
        }
        payload = {
            "text": text,
            "model_id": "eleven_turbo_v2_5",
            "voice_settings": {
                "stability": 0.5,
                "similarity_boost": 0.75,
            },
        }
        r = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=30,
            verify=False,
        )
        if r.status_code != 200:
            return None, f"ElevenLabs error {r.status_code}: {r.text[:200]}"
        return r.content, None
    except Exception as e:
        return None, str(e)


# ============================================================
# EXPORT — Markdown
# ============================================================

def build_markdown_report(alert: dict, ai_analysis: dict = None) -> str:
    lines = []
    lines.append(f"# SOC Alert Report — {alert.get('rule_name', 'Unknown')}\n")
    lines.append(f"**Alert ID**: `{alert.get('alert_id', 'N/A')}`\n")
    lines.append(f"**Severity**: {alert.get('severity', 'N/A')}  ")
    lines.append(f"**Risk Score**: {alert.get('risk_score', 'N/A')}/100\n")
    lines.append(f"**Host**: {alert.get('host', 'N/A')}  ")
    lines.append(f"**Source IP**: {alert.get('source_ip', 'N/A')}  ")
    lines.append(f"**User**: {alert.get('username', 'N/A')}\n")
    lines.append(
        f"**Time Window**: {alert.get('first_seen', '?')} → "
        f"{alert.get('last_seen', '?')} "
        f"({alert.get('time_window_seconds', '?')}s, "
        f"{alert.get('event_count', '?')} events)\n"
    )
    lines.append("---\n")
    lines.append("## Evidence\n")
    for e in alert.get("evidence", []):
        lines.append(f"- `{e.get('timestamp')}` — {e.get('message')}")
    lines.append("")

    if ai_analysis:
        lines.append("---\n")
        lines.append("## AI Investigation Guidance\n")
        lines.append(f"**Summary**: {ai_analysis.get('alert_summary', '')}\n")
        lines.append(f"**Assessment**: {ai_analysis.get('assessment', '')}\n")
        lines.append("### Observed Evidence")
        for item in ai_analysis.get("observed_evidence", []):
            lines.append(f"- {item}")
        lines.append("\n### Investigation Checklist")
        for item in ai_analysis.get("investigation_checklist", []):
            lines.append(f"- {item}")
        lines.append(
            f"\n**Recommended Disposition**: "
            f"{ai_analysis.get('recommended_disposition', '')}"
        )

    lines.append("\n---\n")
    lines.append("*Generated by AI SOC Copilot*\n")
    return "\n".join(lines)


# ============================================================
# EXPORT — JSON
# ============================================================

def build_json_report(alert: dict, ai_analysis: dict = None) -> str:
    report = {
        "alert": alert,
        "ai_analysis": ai_analysis if ai_analysis else None,
        "generated_by": "AI SOC Copilot",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    return json.dumps(report, indent=2, default=str)


# ============================================================
# EXPORT — PDF
# ============================================================

def build_pdf_report(alert: dict, ai_analysis: dict = None) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        PageBreak,
    )

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Title"],
        fontSize=20,
        textColor=colors.HexColor("#0c4a6e"),
        spaceAfter=6,
    )
    heading_style = ParagraphStyle(
        "HeadingStyle",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=colors.HexColor("#0891b2"),
        spaceAfter=8,
        spaceBefore=12,
    )
    subheading_style = ParagraphStyle(
        "SubHeadingStyle",
        parent=styles["Heading3"],
        fontSize=11,
        textColor=colors.HexColor("#4f46e5"),
        spaceAfter=4,
        spaceBefore=8,
    )
    body_style = ParagraphStyle(
        "BodyStyle",
        parent=styles["BodyText"],
        fontSize=10,
        textColor=colors.HexColor("#1e293b"),
        leading=14,
    )

    story = []

    story.append(Paragraph("🛡️ SOC Alert Report", title_style))
    story.append(
        Paragraph(
            f"<i>Generated by AI SOC Copilot · "
            f"{time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}</i>",
            body_style,
        )
    )
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("Alert Overview", heading_style))

    summary_data = [
        ["Rule Name", alert.get("rule_name", "N/A")],
        ["Alert ID", alert.get("alert_id", "N/A")],
        ["Severity", alert.get("severity", "N/A")],
        ["Risk Score", f"{alert.get('risk_score', 'N/A')}/100"],
        ["Host", alert.get("host") or "—"],
        ["Source IP", alert.get("source_ip") or "—"],
        ["User", alert.get("username") or "—"],
        ["Event Count", str(alert.get("event_count", "N/A"))],
        ["Time Window", f"{alert.get('time_window_seconds', '?')}s"],
        ["First Seen", alert.get("first_seen", "N/A")],
        ["Last Seen", alert.get("last_seen", "N/A")],
        ["Status", alert.get("status", "N/A")],
    ]

    summary_table = Table(summary_data, colWidths=[4 * cm, 12 * cm])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e0f2fe")),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#0c4a6e")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("Evidence", heading_style))
    evidence = alert.get("evidence", [])
    if evidence:
        evidence_data = [["Timestamp", "Message"]]
        for e in evidence:
            evidence_data.append(
                [e.get("timestamp", ""), e.get("message", "")]
            )
        ev_table = Table(evidence_data, colWidths=[4.5 * cm, 11.5 * cm])
        ev_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0891b2")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("FONTNAME", (0, 1), (-1, -1), "Courier"),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#94a3b8")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(ev_table)
    else:
        story.append(Paragraph("<i>No evidence recorded.</i>", body_style))

    if ai_analysis:
        story.append(PageBreak())
        story.append(Paragraph("AI Investigation Guidance", heading_style))
        story.append(
            Paragraph(
                f"<b>Summary:</b> {ai_analysis.get('alert_summary', '')}",
                body_style,
            )
        )
        story.append(Spacer(1, 0.3 * cm))
        story.append(
            Paragraph(
                f"<b>Assessment:</b> {ai_analysis.get('assessment', '')}",
                body_style,
            )
        )
        story.append(Paragraph("Observed Evidence", subheading_style))
        for item in ai_analysis.get("observed_evidence", []):
            story.append(Paragraph(f"• {item}", body_style))
        story.append(Paragraph("Investigation Checklist", subheading_style))
        for item in ai_analysis.get("investigation_checklist", []):
            story.append(Paragraph(f"☐ {item}", body_style))
        story.append(Spacer(1, 0.3 * cm))
        story.append(
            Paragraph(
                f"<b>Recommended Disposition:</b> "
                f"{ai_analysis.get('recommended_disposition', '')}",
                body_style,
            )
        )

    story.append(Spacer(1, 0.5 * cm))
    story.append(
        Paragraph(
            "<i>This report was auto-generated. "
            "AI analysis is based on supplied evidence only.</i>",
            body_style,
        )
    )

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes


# ============================================================
# HISTORICAL TRENDS
# ============================================================

def get_historical_trends():
    if USE_MOCK:
        return {
            "hours": [
                "00", "01", "02", "03", "04", "05", "06", "07",
                "08", "09", "10", "11", "12", "13", "14", "15",
                "16", "17", "18", "19", "20", "21", "22", "23",
            ],
            "alerts": [1, 0, 0, 1, 0, 0, 2, 3, 1, 5, 2, 4, 3, 6, 4, 2,
                       3, 1, 2, 0, 1, 2, 1, 1],
            "critical": [0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 1, 1, 1, 2, 1, 0,
                         1, 0, 1, 0, 0, 1, 0, 0],
        }, None
    try:
        r = requests.get(
            f"{API_BASE_URL}/api/trends", timeout=TIMEOUT, verify=False
        )
        r.raise_for_status()
        return r.json(), None
    except Exception as e:
        return None, str(e)