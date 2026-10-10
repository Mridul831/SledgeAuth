"""Handles AI + ElevenLabs calls. Multi-provider: Backend(Ollama) → Ollama → Fallback.

No Gemini — all AI calls are local Ollama only.
"""

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
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:1b")

TIMEOUT = 15


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
# ALERTS — robust dict/list handling
# ============================================================

def _safe_alerts_list(data):
    """Extract alerts list from various backend response shapes."""
    if isinstance(data, dict):
        alerts = data.get("alerts", [])
    elif isinstance(data, list):
        alerts = data
    else:
        return []
    return [a for a in alerts if isinstance(a, dict)]


def get_alerts():
    if USE_MOCK:
        return MOCK_ALERTS, None
    try:
        r = requests.get(
            f"{API_BASE_URL}/api/alerts", timeout=TIMEOUT, verify=False
        )
        r.raise_for_status()
        data = r.json()
        alerts = _safe_alerts_list(data)
        return alerts, None
    except Exception as e:
        return [], str(e)


# ============================================================
# PARSE LOGS
# ============================================================

def parse_logs(uploaded_file):
    if USE_MOCK:
        return {
            "events": [
                {"event_type": "login_failure", "username": "root",
                 "source_ip": "203.0.113.42", "host": "fin-ws-04",
                 "timestamp": "2026-10-10T09:12:00Z"},
                {"event_type": "login_failure", "username": "root",
                 "source_ip": "203.0.113.42", "host": "fin-ws-04",
                 "timestamp": "2026-10-10T09:12:45Z"},
                {"event_type": "login_failure", "username": "root",
                 "source_ip": "203.0.113.42", "host": "fin-ws-04",
                 "timestamp": "2026-10-10T09:13:30Z"},
            ],
            "parsed_count": 3,
            "error_count": 0,
        }, None
    try:
        files = {"file": (uploaded_file.name, uploaded_file.getvalue())}
        r = requests.post(
            f"{API_BASE_URL}/api/logs/parse",
            files=files,
            timeout=TIMEOUT,
            verify=False,
        )
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, dict):
            return {"events": [], "parsed_count": 0, "error_count": 0}, None
        events = data.get("events", [])
        events = [e for e in events if isinstance(e, dict)]
        data["events"] = events
        return data, None
    except Exception as e:
        return None, str(e)


# ============================================================
# DETECTION — takes events and returns alerts
# ============================================================

def run_detection(events=None):
    if USE_MOCK:
        return {
            "alerts": MOCK_ALERTS,
            "total_events_processed": len(events) if events else 47,
            "detection_time_ms": 128,
        }, None
    try:
        payload = {"events": events or []}
        r = requests.post(
            f"{API_BASE_URL}/api/detect",
            json=payload,
            timeout=TIMEOUT,
            verify=False,
        )
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, dict):
            return {"alerts": []}, None
        alerts = _safe_alerts_list(data)
        data["alerts"] = alerts
        return data, None
    except Exception as e:
        return None, str(e)


# ============================================================
# AI PROMPT BUILDER
# ============================================================

def _build_ai_prompt(alert: dict) -> str:
    evidence_lines = "\n".join(
        f"- {e.get('timestamp')}: {e.get('message')}"
        for e in alert.get("evidence", [])[:5]
        if isinstance(e, dict)
    )
    if not evidence_lines:
        evidence_lines = "(no structured evidence)"

    return f"""You are a SOC analyst. Analyze this alert. Respond in JSON only.

ALERT:
- Rule: {alert.get('rule_name')}
- Severity: {alert.get('severity')}
- Risk: {alert.get('risk_score')}/100
- Host: {alert.get('host')}
- Source IP: {alert.get('source_ip')}
- User: {alert.get('username')}
- Events: {alert.get('event_count')} in {alert.get('time_window_seconds')}s

EVIDENCE:
{evidence_lines}

Return JSON with these exact keys:
{{
  "alert_summary": "one complete sentence describing the alert",
  "assessment": "one complete sentence explaining the likely meaning",
  "observed_evidence": ["short fact 1", "short fact 2", "short fact 3"],
  "investigation_checklist": ["short step 1", "short step 2", "short step 3"],
  "recommended_disposition": "full sentence like: escalate to a human analyst for review"
}}

Rules:
- Use only the evidence above.
- Write full sentences for summary and assessment.
- Return JSON only, no markdown, no explanations outside JSON.
"""


def _parse_ai_json(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        parts = text.split("```")
        if len(parts) >= 2:
            text = parts[1]
            if text.startswith("json"):
                text = text[4:]
    text = text.strip()
    if text.endswith("```"):
        text = text[:-3].strip()
    return json.loads(text)


# ============================================================
# PROVIDER 1 — BACKEND (FastAPI + Ollama)
# ============================================================

def _analyze_via_backend(alert: dict):
    """Backend uses Ollama. Reject fallback so frontend can retry."""
    try:
        r = requests.post(
            f"{API_BASE_URL}/api/copilot/analyze",
            json={"alert": alert},
            timeout=60,
            verify=False,
        )
        r.raise_for_status()
        result = r.json()
        if not isinstance(result, dict):
            return None, "backend: invalid response"
        if result.get("fallback_used") is True:
            return None, "backend: fallback — trying next provider"
        result["ai_fallback"] = False
        result["ai_provider"] = "backend"
        return result, None
    except Exception as e:
        return None, f"backend: {e}"


# ============================================================
# PROVIDER 2 — OLLAMA (Local LLM, direct from frontend)
# ============================================================

def _analyze_via_ollama(alert: dict):
    try:
        import ollama as ollama_client
    except ImportError:
        return None, "ollama: python package not installed"

    try:
        prompt = _build_ai_prompt(alert)
        client = ollama_client.Client(host=OLLAMA_HOST)
        response = client.chat(
            model=OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={
                "temperature": 0.3,
                "num_predict": 500,
                "num_ctx": 2048,
                "top_k": 20,
                "top_p": 0.9,
            },
            format="json",
            keep_alive="10m",
        )
        text = response["message"]["content"]
        result = _parse_ai_json(text)
        result["ai_fallback"] = False
        result["ai_provider"] = "ollama"
        return result, None
    except Exception as e:
        return None, f"ollama: {e}"


# ============================================================
# PROVIDER 3 — DETERMINISTIC FALLBACK (last resort)
# ============================================================

def _analyze_fallback(alert: dict):
    evidence = alert.get("evidence", [])
    return {
        "alert_summary": (
            f"{alert.get('event_count', 0)} "
            f"{alert.get('event_type', 'events')} recorded from "
            f"{alert.get('source_ip', 'unknown source')} targeting "
            f"{alert.get('username', 'unknown user')}."
        ),
        "assessment": (
            f"This pattern is consistent with a possible "
            f"{alert.get('rule_name', 'security event').lower()}. "
            f"Assessment based on supplied evidence only."
        ),
        "observed_evidence": [
            f"{len(evidence)} events in a "
            f"{alert.get('time_window_seconds', '?')}s window.",
            f"Source IP: {alert.get('source_ip', 'N/A')}.",
            f"Target host: {alert.get('host', 'N/A')}.",
        ],
        "investigation_checklist": [
            "Verify whether the source IP is internal or external.",
            "Check if any successful login followed the failures.",
            "Review firewall/IDS logs for the same source IP.",
            "Confirm the targeted account is not locked out.",
        ],
        "recommended_disposition": (
            "Escalate to a human analyst for review. "
            "Do not auto-block or disable accounts."
        ),
        "ai_fallback": True,
        "ai_provider": "fallback",
    }


# ============================================================
# MAIN ENTRY — Backend (Ollama) → Ollama direct → Fallback
# ============================================================

def analyze_alert(alert):
    """
    Cascade:
      1. Backend  (FastAPI → Ollama)
      2. Ollama   (direct from frontend, in case backend fails)
      3. Deterministic fallback (last resort)

    No Gemini. All AI is local Ollama.
    """
    if not USE_MOCK:
        result, err = _analyze_via_backend(alert)
        if result:
            return result, None

    result, err = _analyze_via_ollama(alert)
    if result:
        return result, None

    return _analyze_fallback(alert), None


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
            "voice_settings": {"stability": 0.5, "similarity_boost": 0.75},
        }
        r = requests.post(
            url, json=payload, headers=headers, timeout=30, verify=False
        )
        if r.status_code != 200:
            return None, f"ElevenLabs error {r.status_code}: {r.text[:200]}"
        return r.content, None
    except Exception as e:
        return None, str(e)


# ============================================================
# HELPER — Safely format evidence
# ============================================================

def _format_evidence_lines(evidence):
    lines = []
    for e in evidence or []:
        if isinstance(e, dict):
            ts = e.get("timestamp", "—")
            msg = e.get("message", "—")
            lines.append((str(ts), str(msg)))
        else:
            lines.append(("—", str(e)))
    return lines


# ============================================================
# EXPORT — Markdown (single alert)
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
    for ts, msg in _format_evidence_lines(alert.get("evidence", [])):
        lines.append(f"- `{ts}` — {msg}")
    lines.append("")

    if ai_analysis:
        provider = ai_analysis.get("ai_provider", "unknown")
        lines.append("---\n")
        lines.append(f"## AI Investigation Guidance _(provider: {provider})_\n")
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
# EXPORT — JSON (single alert)
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
# EXPORT — PDF (single alert)
# ============================================================

def build_pdf_report(alert: dict, ai_analysis: dict = None) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    )

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=2 * cm, leftMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle", parent=styles["Title"], fontSize=20,
        textColor=colors.HexColor("#0c4a6e"), spaceAfter=6,
    )
    heading_style = ParagraphStyle(
        "HeadingStyle", parent=styles["Heading2"], fontSize=14,
        textColor=colors.HexColor("#0891b2"), spaceAfter=8, spaceBefore=12,
    )
    subheading_style = ParagraphStyle(
        "SubHeadingStyle", parent=styles["Heading3"], fontSize=11,
        textColor=colors.HexColor("#4f46e5"), spaceAfter=4, spaceBefore=8,
    )
    body_style = ParagraphStyle(
        "BodyStyle", parent=styles["BodyText"], fontSize=10,
        textColor=colors.HexColor("#1e293b"), leading=14,
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
        ["Rule Name", str(alert.get("rule_name", "N/A"))],
        ["Alert ID", str(alert.get("alert_id", "N/A"))],
        ["Severity", str(alert.get("severity", "N/A"))],
        ["Risk Score", f"{alert.get('risk_score', 'N/A')}/100"],
        ["Host", str(alert.get("host") or "—")],
        ["Source IP", str(alert.get("source_ip") or "—")],
        ["User", str(alert.get("username") or "—")],
        ["Event Count", str(alert.get("event_count", "N/A"))],
        ["Time Window", f"{alert.get('time_window_seconds', '?')}s"],
        ["First Seen", str(alert.get("first_seen", "N/A"))],
        ["Last Seen", str(alert.get("last_seen", "N/A"))],
        ["Status", str(alert.get("status", "N/A"))],
    ]
    summary_table = Table(summary_data, colWidths=[4 * cm, 12 * cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e0f2fe")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#0c4a6e")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("Evidence", heading_style))
    evidence = alert.get("evidence", [])
    if evidence:
        evidence_data = [["Timestamp", "Message"]]
        for ts, msg in _format_evidence_lines(evidence):
            evidence_data.append([ts, msg])
        ev_table = Table(evidence_data, colWidths=[4.5 * cm, 11.5 * cm])
        ev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0891b2")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("FONTNAME", (0, 1), (-1, -1), "Courier"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#94a3b8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(ev_table)

    if ai_analysis:
        story.append(PageBreak())
        provider = ai_analysis.get("ai_provider", "unknown")
        story.append(
            Paragraph(f"AI Investigation Guidance ({provider})", heading_style)
        )
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
# HISTORICAL TRENDS — real backend + mock fallback
# ============================================================

def get_historical_trends():
    if not USE_MOCK:
        try:
            r = requests.get(
                f"{API_BASE_URL}/api/trends", timeout=TIMEOUT, verify=False
            )
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, dict) and "hours" in data:
                    return data, None
        except Exception:
            pass

    return {
        "hours": [f"{h:02d}" for h in range(24)],
        "alerts": [1, 0, 0, 1, 0, 0, 2, 3, 1, 5, 2, 4, 3, 6, 4, 2,
                   3, 1, 2, 0, 1, 2, 1, 1],
        "critical": [0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 1, 1, 1, 2, 1, 0,
                     1, 0, 1, 0, 0, 1, 0, 0],
    }, None


# ============================================================
# BULK EXPORT — ALL ALERTS
# ============================================================

def build_all_alerts_markdown(alerts: list, ai_results: dict = None) -> str:
    """Build a markdown report for ALL alerts."""
    lines = []
    lines.append("# 🛡️ AI SOC Copilot — Full Alert Report\n")
    lines.append(
        f"**Generated**: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}  "
    )
    lines.append(f"**Total Alerts**: {len(alerts)}\n")
    lines.append("## Summary\n")
    lines.append("| # | Rule | Severity | Score | Host | Source IP | Status |")
    lines.append("|---|------|----------|-------|------|-----------|--------|")
    for i, a in enumerate(alerts, 1):
        lines.append(
            f"| {i} | {a.get('rule_name', '-')} | {a.get('severity', '-')} | "
            f"{a.get('risk_score', '-')} | {a.get('host', '-')} | "
            f"{a.get('source_ip', '-')} | {a.get('status', '-')} |"
        )
    lines.append("")
    lines.append("---\n")
    lines.append("## Alert Details\n")
    for i, a in enumerate(alerts, 1):
        lines.append(f"### {i}. {a.get('rule_name', 'Unknown')}\n")
        lines.append(f"- **Alert ID**: `{a.get('alert_id', 'N/A')}`")
        lines.append(f"- **Severity**: {a.get('severity', 'N/A')}")
        lines.append(f"- **Risk Score**: {a.get('risk_score', 'N/A')}/100")
        lines.append(f"- **Host**: {a.get('host', 'N/A')}")
        lines.append(f"- **Source IP**: {a.get('source_ip', 'N/A')}")
        lines.append(f"- **User**: {a.get('username', 'N/A')}")
        lines.append(f"- **Events**: {a.get('event_count', 'N/A')}")
        lines.append(f"- **Status**: {a.get('status', 'N/A')}\n")
        evidence = a.get("evidence", [])
        if evidence:
            lines.append("**Evidence:**")
            for e in evidence:
                if isinstance(e, dict):
                    lines.append(
                        f"- `{e.get('timestamp', '—')}` — {e.get('message', '—')}"
                    )
                else:
                    lines.append(f"- {e}")
            lines.append("")
    lines.append("\n---\n")
    lines.append("*Generated by AI SOC Copilot*\n")
    return "\n".join(lines)


def build_all_alerts_json(alerts: list) -> str:
    """Build a JSON export for ALL alerts."""
    report = {
        "generated_by": "AI SOC Copilot",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_alerts": len(alerts),
        "alerts": alerts,
    }
    return json.dumps(report, indent=2, default=str)


def build_all_alerts_pdf(alerts: list) -> bytes:
    """Build a PDF summary report for ALL alerts."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    )

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=2 * cm, leftMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "T", parent=styles["Title"], fontSize=22,
        textColor=colors.HexColor("#0c4a6e"), spaceAfter=8,
    )
    heading_style = ParagraphStyle(
        "H", parent=styles["Heading2"], fontSize=14,
        textColor=colors.HexColor("#0891b2"), spaceAfter=8, spaceBefore=12,
    )
    body_style = ParagraphStyle(
        "B", parent=styles["BodyText"], fontSize=10,
        textColor=colors.HexColor("#1e293b"), leading=14,
    )

    story = []
    story.append(Paragraph("🛡️ SOC Alert Report — Full Summary", title_style))
    story.append(
        Paragraph(
            f"<i>Generated by AI SOC Copilot · "
            f"{time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())} · "
            f"{len(alerts)} alerts</i>",
            body_style,
        )
    )
    story.append(Spacer(1, 0.4 * cm))

    story.append(Paragraph("Alert Summary", heading_style))
    summary_data = [["#", "Rule", "Severity", "Score", "Host", "Source IP"]]
    for i, a in enumerate(alerts, 1):
        summary_data.append([
            str(i),
            str(a.get("rule_name", "-"))[:30],
            str(a.get("severity", "-")),
            str(a.get("risk_score", "-")),
            str(a.get("host", "-"))[:15],
            str(a.get("source_ip", "-"))[:15],
        ])
    summary_table = Table(
        summary_data,
        colWidths=[1 * cm, 5 * cm, 2 * cm, 1.5 * cm, 3 * cm, 3.5 * cm],
    )
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0891b2")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#94a3b8")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(summary_table)

    story.append(PageBreak())
    story.append(Paragraph("Alert Details", heading_style))

    for i, a in enumerate(alerts, 1):
        story.append(
            Paragraph(
                f"<b>{i}. {a.get('rule_name', 'Unknown')}</b> "
                f"— {a.get('severity', '-')} ({a.get('risk_score', '-')}/100)",
                body_style,
            )
        )
        story.append(
            Paragraph(
                f"Host: {a.get('host', '-')} · "
                f"IP: {a.get('source_ip', '-')} · "
                f"User: {a.get('username', '-')} · "
                f"Events: {a.get('event_count', '-')}",
                body_style,
            )
        )
        story.append(Spacer(1, 0.2 * cm))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes