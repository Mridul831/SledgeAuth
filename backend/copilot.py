import os
import json
import httpx
from fastapi import APIRouter, HTTPException
from .schemas import CopilotAnalyzeRequest, CopilotAnalyzeResponse

router = APIRouter()

# Get API key from environment (loaded via python-dotenv in main.py or OS env)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"

# --- Guardrails and System Prompt ---
SYSTEM_PROMPT = """You are a SOC Level 1 AI assistant. Your job is to explain security alerts to a human analyst.

STRICT RULES:
1. Use ONLY the supplied alert evidence. Do NOT invent IPs, events, counts, timestamps, commands, or findings.
2. If a fact is absent from the evidence, explicitly say "Not available" instead of guessing.
3. Describe brute force as a "possibility consistent with the pattern", not a confirmed attacker.
4. Return ONLY valid JSON. No markdown formatting, no explanations outside the JSON.
5. The JSON must have exactly these keys: 'alert_summary', 'assessment', 'observed_evidence', 'investigation_checklist', 'recommended_disposition'.
6. 'observed_evidence' must be a list of strings derived directly from the alert's evidence.
7. 'investigation_checklist' must be a list of safe, manual investigation steps for the analyst. Do not suggest automated blocking or destructive actions.
"""

def generate_fallback_response(alert, error_msg: str) -> CopilotAnalyzeResponse:
    """
    Deterministic fallback when LLM is unavailable.
    Never pretends the LLM succeeded.
    """
    return CopilotAnalyzeResponse(
        alert_summary=f"Alert '{alert.rule_name}' triggered on host {alert.host} involving {alert.event_count} events from {alert.source_ip or 'unknown IP'}.",
        assessment=(
            f"The pattern is consistent with a potential {alert.rule_name.lower().replace('_', ' ')}. "
            f"However, no automated confirmation can be made without manual review. "
            f"Risk score is {alert.risk_score} ({alert.severity})."
        ),
        observed_evidence=alert.evidence,
        investigation_checklist=[
            f"Verify firewall and VPN logs for source IP: {alert.source_ip or 'unknown'}.",
            "Check if the targeted user accounts show any successful logins during this window.",
            "Review host endpoint logs for any suspicious processes or privilege escalations.",
            "Correlate with threat intelligence feeds for the source IP."
        ],
        recommended_disposition="Escalate to Tier 2 for manual investigation.",
        fallback_used=True,
        error=error_msg
    )

@router.post("/api/copilot/analyze", response_model=CopilotAnalyzeResponse)
async def analyze_alert(request: CopilotAnalyzeRequest):
    """
    Member 3's AI Copilot endpoint.
    Sends structured evidence to the LLM and returns a validated response.
    """
    alert = request.alert

    # 1. Check for API Key (Fallback if missing)
    if not OPENAI_API_KEY or OPENAI_API_KEY.startswith("sk-your"):
        return generate_fallback_response(alert, "LLM provider unavailable: Missing or invalid API key.")

    # 2. Build the User Prompt with only necessary evidence
    user_prompt = f"""
    Please analyze the following security alert:
    
    Rule Name: {alert.rule_name}
    Host: {alert.host}
    Source IP: {alert.source_ip or 'Not available'}
    Event Count: {alert.event_count}
    Severity: {alert.severity}
    Risk Score: {alert.risk_score}
    Timestamps: {alert.timestamp}
    Event Type: {alert.event_type}
    
    Evidence List:
    {json.dumps(alert.evidence, indent=2)}
    
    Remember: Return ONLY valid JSON matching the requested schema.
    """

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "gpt-4o-mini", # Fast, cheap, and supports JSON mode
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.2 # Low temperature for factual consistency
    }

    # 3. Call the LLM
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                OPENAI_API_URL,
                headers=headers,
                json=payload,
                timeout=15.0
            )
            response.raise_for_status()
            
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            
            # 4. Parse and validate the JSON
            parsed_json = json.loads(content)
            
            # Ensure required keys exist
            required_keys = ["alert_summary", "assessment", "observed_evidence", "investigation_checklist", "recommended_disposition"]
            for key in required_keys:
                if key not in parsed_json:
                    raise ValueError(f"LLM response missing required key: {key}")

            # 5. Return validated response
            return CopilotAnalyzeResponse(
                alert_summary=parsed_json["alert_summary"],
                assessment=parsed_json["assessment"],
                observed_evidence=parsed_json["observed_evidence"],
                investigation_checklist=parsed_json["investigation_checklist"],
                recommended_disposition=parsed_json["recommended_disposition"],
                fallback_used=False,
                error=None
            )

    except httpx.TimeoutException:
        return generate_fallback_response(alert, "LLM provider unavailable: Request timed out.")
    except httpx.HTTPStatusError as e:
        return generate_fallback_response(alert, f"LLM provider error: HTTP {e.response.status_code}")
    except json.JSONDecodeError:
        return generate_fallback_response(alert, "LLM provider error: Returned malformed JSON.")
    except Exception as e:
        return generate_fallback_response(alert, f"Unexpected error during AI analysis: {str(e)}")