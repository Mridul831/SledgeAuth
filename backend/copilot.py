"""
Member 3 — AI Copilot endpoint.
Uses local Ollama LLM (offline). No cloud dependencies.
"""
import json
import os

from fastapi import APIRouter, HTTPException

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    ollama = None
    OLLAMA_AVAILABLE = False

from .schemas import CopilotAnalyzeRequest, CopilotAnalyzeResponse

router = APIRouter()

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:1b")


def _build_prompt(alert) -> str:
    """Build the prompt for Ollama from a structured alert."""
    evidence = getattr(alert, "evidence", []) or []
    evidence_lines = []
    for e in evidence[:5]:
        if isinstance(e, dict):
            ts = e.get("timestamp", "—")
            msg = e.get("message", "—")
            evidence_lines.append(f"- {ts}: {msg}")
        else:
            evidence_lines.append(f"- {e}")
    evidence_text = "\n".join(evidence_lines) if evidence_lines else "(no evidence)"

    return f"""You are a SOC analyst. Analyze this security alert. Respond in JSON only.

ALERT:
- Rule: {getattr(alert, 'rule_name', 'Unknown')}
- Severity: {getattr(alert, 'severity', 'Unknown')}
- Risk: {getattr(alert, 'risk_score', 0)}/100
- Host: {getattr(alert, 'host', 'N/A')}
- Source IP: {getattr(alert, 'source_ip', 'N/A')}
- User: {getattr(alert, 'username', 'N/A')}
- Events: {getattr(alert, 'event_count', 0)} in {getattr(alert, 'time_window_seconds', 0)}s

EVIDENCE:
{evidence_text}

Return JSON with these exact keys:
{{
  "alert_summary": "one complete sentence describing the alert",
  "assessment": "one complete sentence explaining the likely meaning",
  "observed_evidence": ["short fact 1", "short fact 2"],
  "investigation_checklist": ["short step 1", "short step 2"],
  "recommended_disposition": "full sentence like: escalate to a human analyst for review"
}}

Rules:
- Use only the evidence above.
- Write full sentences for summary and assessment.
- Return JSON only. No markdown, no explanations outside JSON.
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


@router.post("/api/copilot/analyze", response_model=CopilotAnalyzeResponse)
async def analyze_alert(request: CopilotAnalyzeRequest):
    """
    AI Copilot endpoint — uses local Ollama LLM.
    Falls back to a deterministic response if Ollama is unavailable.
    """
    alert = request.alert

    # Try Ollama (local)
        # Try Ollama (local)
    if not OLLAMA_AVAILABLE:
        raise Exception("Ollama not installed on this server")

    try:
        client = ollama.Client(host=OLLAMA_HOST)
        prompt = _build_prompt(alert)

        response = client.chat(
            model=OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={
                "temperature": 0.3,
                "num_predict": 500,
                "num_ctx": 2048,
            },
            format="json",
            keep_alive="10m",
        )

        text = response["message"]["content"]
        result = _parse_ai_json(text)

        return CopilotAnalyzeResponse(
            alert_summary=result.get("alert_summary", ""),
            assessment=result.get("assessment", ""),
            observed_evidence=result.get("observed_evidence", []),
            investigation_checklist=result.get("investigation_checklist", []),
            recommended_disposition=result.get("recommended_disposition", ""),
            fallback_used=False,
            error=None,
        )

    except Exception as e:
        # Deterministic fallback if Ollama fails
        evidence = getattr(alert, "evidence", []) or []
        return CopilotAnalyzeResponse(
            alert_summary=(
                f"{getattr(alert, 'event_count', 0)} events recorded from "
                f"{getattr(alert, 'source_ip', 'unknown source')}."
            ),
            assessment=(
                f"Pattern consistent with a possible "
                f"{getattr(alert, 'rule_name', 'security event').lower()}."
            ),
            observed_evidence=[
                f"{len(evidence)} events in a "
                f"{getattr(alert, 'time_window_seconds', '?')}s window.",
                f"Source IP: {getattr(alert, 'source_ip', 'N/A')}.",
            ],
            investigation_checklist=[
                "Verify whether the source IP is internal or external.",
                "Check if any successful login followed the failures.",
                "Review firewall/IDS logs for the same source IP.",
            ],
            recommended_disposition=(
                "Escalate to a human analyst for review. "
                "Do not auto-block or disable accounts."
            ),
            fallback_used=True,
            error=f"Ollama unavailable: {str(e)[:150]}",
        )