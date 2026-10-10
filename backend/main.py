"""
SledgeAuth - FastAPI backend.
"""
from typing import Dict

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError

from .parser import parse_auth_logs
from .detection import (
    detect_brute_force,
    detect_privileged_activity,
)
from .schemas import (
    Alert,
    AlertsResponse,
    DetectRequest,
    DetectResponse,
    HealthResponse,
    LogParseRequest,
    NormalizedEventResponse,
    StatusUpdateRequest,
)

# Safely import the copilot router so the backend doesn't crash if Member 3 is still working
try:
    from .copilot import router as copilot_router
except ImportError:
    copilot_router = None

app = FastAPI(
    title="SledgeAuth - AI Security SOC Copilot",
    description="Backend API for Linux authentication log ingestion and security detection.",
    version="0.1.0",
)

# Register Member 3's copilot endpoints if the file exists
if copilot_router:
    app.include_router(copilot_router)

# Allow local frontends (React on 5173, Streamlit on 8501) to communicate with this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8501",
        "http://127.0.0.1:8501",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Temporary in-memory alert storage for the prototype.
ALERTS: Dict[str, Alert] = {}

MAX_LOG_BYTES = 2 * 1024 * 1024  # 2 MB


@app.get("/")
async def root():
    """Welcome endpoint for the API."""
    return {"message": "Welcome to the SledgeAuth API. Go to /docs for the interactive UI."}


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Return backend health information."""
    return HealthResponse()


@app.post(
    "/api/logs/parse",
    response_model=NormalizedEventResponse,
)
async def parse_logs(request: Request) -> NormalizedEventResponse:
    """
    Accept either:
    1. multipart/form-data containing a .log file named 'file'
    2. application/json containing {"content": "raw log text"}
    """
    content_type = request.headers.get("content-type", "").lower()
    content: str

    if "multipart/form-data" in content_type:
        try:
            form = await request.form()
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Unable to read multipart form data.") from exc

        uploaded_file = form.get("file")

        if uploaded_file is None or not hasattr(uploaded_file, "filename") or not hasattr(uploaded_file, "read"):
            raise HTTPException(status_code=400, detail="A log file must be supplied in the 'file' field.")

        filename = uploaded_file.filename or ""

        if not filename.lower().endswith(".log"):
            await uploaded_file.close()
            raise HTTPException(status_code=400, detail="Only .log files are supported.")

        try:
            raw_bytes = await uploaded_file.read(MAX_LOG_BYTES + 1)
        finally:
            await uploaded_file.close()

        if len(raw_bytes) > MAX_LOG_BYTES:
            raise HTTPException(status_code=413, detail="Log file exceeds the 2 MB size limit.")

        try:
            content = raw_bytes.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=400, detail="Log file must contain valid UTF-8 text.") from exc

    elif "application/json" in content_type:
        try:
            payload = await request.json()
            parse_request = LogParseRequest.model_validate(payload)
        except (ValueError, ValidationError) as exc:
            raise HTTPException(status_code=400, detail="Invalid JSON request. Supply a string 'content' field.") from exc

        if parse_request.content is None:
            raise HTTPException(status_code=400, detail="The 'content' field is required.")

        content = parse_request.content

        if len(content.encode("utf-8")) > MAX_LOG_BYTES:
            raise HTTPException(status_code=413, detail="Log content exceeds the 2 MB size limit.")

    else:
        raise HTTPException(status_code=415, detail="Use application/json or multipart/form-data.")

    events, error_count = parse_auth_logs(content)

    return NormalizedEventResponse(
        events=events,
        parsed_count=len(events),
        error_count=error_count,
    )


@app.post("/api/detect", response_model=DetectResponse)
def run_detection(request: DetectRequest) -> DetectResponse:
    """
    Run the deterministic detection rules on normalized events.
    Member 2 owns the detection functions and their scoring logic.
    """
    brute_force_alerts = detect_brute_force(request.events)
    privileged_alerts = detect_privileged_activity(request.events)

    detected_alerts = brute_force_alerts + privileged_alerts

    validated_alerts = [
        alert if isinstance(alert, Alert) else Alert.model_validate(alert)
        for alert in detected_alerts
    ]

    # Keep alert retrieval and status updates synchronized with detection.
    for alert in validated_alerts:
        ALERTS[alert.alert_id] = alert

    return DetectResponse(alerts=validated_alerts)


@app.get("/api/alerts", response_model=AlertsResponse)
async def get_alerts() -> AlertsResponse:
    """Return alerts currently available in the shared in-memory store."""
    return AlertsResponse(alerts=list(ALERTS.values()))


@app.patch(
    "/api/alerts/{alert_id}/status",
    response_model=Alert,
)
async def update_alert_status(
    alert_id: str,
    payload: StatusUpdateRequest,
) -> Alert:
    """Update an existing alert's analyst-controlled status."""
    alert = ALERTS.get(alert_id)

    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' was not found.")

    updated_alert = alert.model_copy(update={"status": payload.status})
    ALERTS[alert_id] = updated_alert

    return updated_alert