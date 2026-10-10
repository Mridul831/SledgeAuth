from datetime import datetime
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, HttpUrl
from enum import Enum

# ===== Normalized Event =====
class EventType(str, Enum):
    LOGIN_FAILURE = "login_failure"
    LOGIN_SUCCESS = "login_success"
    PRIVILEGE_CHANGE = "privilege_change"
    OTHER = "other"

class NormalizedEvent(BaseModel):
    timestamp: datetime
    host: str
    event_type: EventType
    username: Optional[str] = None
    source_ip: Optional[str] = None
    message: str
    raw_log: Optional[str] = None

# ===== Alert =====
class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class AlertStatus(str, Enum):
    OPEN = "Open"
    INVESTIGATING = "Investigating"
    ESCALATED = "Escalated"
    CLOSED = "Closed"

class Alert(BaseModel):
    alert_id: str
    timestamp: datetime
    host: str
    rule_name: str
    event_type: EventType
    source_ip: Optional[str] = None
    event_count: int
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    evidence: List[str]
    ai_summary: Optional[str] = None
    investigation_checklist: List[str] = []
    mitre_attack: Optional[str] = None
    status: AlertStatus = AlertStatus.OPEN

# ===== API Request/Response =====
class LogParseRequest(BaseModel):
    content: Optional[str] = None  # raw log text
    # file upload handled via multipart, not this model

class NormalizedEventResponse(BaseModel):
    events: List[NormalizedEvent]
    parsed_count: int
    error_count: int

class DetectRequest(BaseModel):
    events: List[NormalizedEvent]

class DetectResponse(BaseModel):
    alerts: List[Alert]

class AlertsResponse(BaseModel):
    alerts: List[Alert]

class CopilotAnalyzeRequest(BaseModel):
    alert: Alert

class CopilotAnalyzeResponse(BaseModel):
    alert_summary: str
    assessment: str
    observed_evidence: List[str]
    investigation_checklist: List[str]
    recommended_disposition: str
    fallback_used: bool = False
    error: Optional[str] = None

class StatusUpdateRequest(BaseModel):
    status: AlertStatus

class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "0.1.0"
