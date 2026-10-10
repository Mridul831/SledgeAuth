cat > backend/copilot.py <<'EOF'
import json
import os

from fastapi import APIRouter, HTTPException
from openai import APITimeoutError, APIConnectionError, APIStatusError
from openai import OpenAI, RateLimitError
from pydantic import ValidationError

from backend.prompts import SYSTEM_PROMPT
from backend.schemas import CopilotAnalyzeRequest, CopilotAnalyzeResponse


router = APIRouter()
MODEL_NAME = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")


def deterministic_analysis(alert):
    """Return explicitly labelled fallback guidance without inventing facts."""
    evidence = list(alert.evidence or [])

    return CopilotAnalyzeResponse(
        alert_summary=(
            f"Alert {alert.alert_id}: {alert.rule_name} "
            f"on host {alert.host}; severity {alert.severity.value}, "
            f"risk score {alert.risk_score}/100."
        ),
        assessment=(
            "AI analysis is unavailable. This assessment is limited to "
            "the fields supplied in the alert and does not establish "
            "malicious intent."
        ),
        observed_evidence=evidence,
        investigation_checklist=[
            "Review the original events associated with this alert.",
            "Verify the event timestamps, source, and affected host.",
            "Correlate with relevant authentication and system logs.",
            "Follow your organization's incident response procedures."
        ],
        recommended_disposition=(
            "Review and investigate according to the alert severity "
            "and your organization's incident response policy."
        ),
        fallback_used=True,
        error="AI analysis is unavailable; deterministic fallback used."
    )


@router.post(
    "/api/copilot/analyze",
    response_model=CopilotAnalyzeResponse
)
def analyze_alert(request: CopilotAnalyzeRequest):
    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        raise HTTPException(
            status_code=503,
            detail="AI analysis is unavailable: OPENAI_API_KEY is not configured."
        )

    alert_data = request.alert.model_dump(mode="json")

    try:
        client = OpenAI(
            api_key=api_key,
            timeout=15.0,
            max_retries=0
        )

        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": json.dumps(alert_data)
                }
            ],
            response_format={"type": "json_object"}
        )

        content = response.choices[0].message.content
        if not content:
            raise ValueError("The AI returned an empty response.")

        result = json.loads(content)

        required = {
            "alert_summary",
            "assessment",
            "observed_evidence",
            "investigation_checklist",
            "recommended_disposition"
        }

        if not required.issubset(result):
            raise ValueError("The AI response is missing required fields.")

        result["fallback_used"] = False
        result["error"] = None

        return CopilotAnalyzeResponse.model_validate(result)

    except (
        APITimeoutError,
        APIConnectionError,
        APIStatusError,
        RateLimitError,
        ValidationError,
        ValueError,
        json.JSONDecodeError
    ) as exc:
        # Contract requires 503 when AI is unavailable.
        raise HTTPException(
            status_code=503,
            detail=f"AI analysis is unavailable: {type(exc).__name__}."
        ) from exc
EOF