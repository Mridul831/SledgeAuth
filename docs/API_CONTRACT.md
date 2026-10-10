# API Contract - AI Security SOC Copilot

**Version:** 0.1.0 | **Status:** FROZEN for parallel development

---

## Endpoints

| Method | Path | Owner | Description |
|--------|------|-------|-------------|
| GET | `/health` | M1 | Health check |
| POST | `/api/logs/parse` | M1 | Parse uploaded log file/text |
| POST | `/api/detect` | M2 | Generate alerts from normalized events |
| GET | `/api/alerts` | M1/M2 | Retrieve all alerts |
| POST | `/api/copilot/analyze` | M3 | AI investigation guidance |
| PATCH | `/api/alerts/{alert_id}/status` | M1/M4 | Update alert status |
| GET | `/docs` | - | Swagger UI |

---

## Request/Response Schemas

### GET /health
**Response:** `HealthResponse` (200)

### POST /api/logs/parse
**Content-Type:** `multipart/form-data` (file) OR `application/json` (text)
**Request (multipart):** `file` (UploadFile, .log)
**Request (JSON):** `{ "content": "raw log text..." }`
**Response:** `NormalizedEventResponse` (200) / 400 validation error

### POST /api/detect
**Request:** `DetectRequest` - `{ "events": [NormalizedEvent, ...] }`
**Response:** `DetectResponse` - `{ "alerts": [Alert, ...] }` (200)

### GET /api/alerts
**Response:** `AlertsResponse` - `{ "alerts": [Alert, ...] }` (200)

### POST /api/copilot/analyze
**Request:** `CopilotAnalyzeRequest` - `{ "alert": Alert }`
**Response:** `CopilotAnalyzeResponse` (200) / 503 if AI unavailable

### PATCH /api/alerts/{alert_id}/status
**Request:** `StatusUpdateRequest` - `{ "status": "Investigating" }`
**Response:** Updated `Alert` (200) / 404 not found

---

## Shared Enums (MUST MATCH EXACTLY)

```python
EventType: login_failure | login_success | privilege_change | other
Severity: Low | Medium | High | Critical
AlertStatus: Open | Investigating | Escalated | Closed
Field Name Rules
- snake_case for all JSON fields
- ISO 8601 UTC timestamps: 2026-10-09T12:00:00Z
- source_ip is null (not empty string) when unavailable
- risk_score integer 0-100 inclusive
- evidence array of human-readable strings
Error Format
{ "detail": "Human-readable error message" }
