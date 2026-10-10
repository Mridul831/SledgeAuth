from fastapi import APIRouter
from .schemas import CopilotAnalyzeRequest, CopilotAnalyzeResponse

router = APIRouter()

@router.post("/api/copilot/analyze", response_model=CopilotAnalyzeResponse)
async def analyze_alert(request: CopilotAnalyzeRequest):
    """
    Member 3's AI Copilot endpoint.
    Currently a safe placeholder that returns a fallback response.
    """
    # Extract alert details
    alert = request.alert
    
    # Fallback response (simulating what Member 3 will build)
    return CopilotAnalyzeResponse(
        alert_summary=f"Analysis for alert {alert.alert_id} on host {alert.host}.",
        assessment="This is a placeholder analysis. The LLM integration is currently under development.",
        observed_evidence=alert.evidence,
        investigation_checklist=[
            "Verify the source IP in the SIEM.",
            "Check if the targeted user accounts are active.",
            "Review recent firewall logs for this IP."
        ],
        recommended_disposition="Escalate to Tier 2 for manual review.",
        fallback_used=True,
        error="LLM provider not yet configured."
    )
