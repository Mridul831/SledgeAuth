import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")

def check_health():
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=3)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

def parse_logs(content: str):
    try:
        response = requests.post(
            f"{API_BASE_URL}/api/logs/parse",
            json={"content": content},
            timeout=10
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"Failed to parse logs: {e}")

def detect_threats(events: list):
    try:
        response = requests.post(
            f"{API_BASE_URL}/api/detect",
            json={"events": events},
            timeout=10
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"Failed to run detection: {e}")

def get_alerts():
    try:
        response = requests.get(f"{API_BASE_URL}/api/alerts", timeout=5)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException:
        return None

def update_alert_status(alert_id: str, new_status: str):
    try:
        response = requests.patch(
            f"{API_BASE_URL}/api/alerts/{alert_id}/status",
            json={"status": new_status},
            timeout=5
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"Failed to update status: {e}")

def analyze_alert(alert: dict):
    try:
        response = requests.post(
            f"{API_BASE_URL}/api/copilot/analyze",
            json={"alert": alert},
            timeout=20  # AI calls can take a bit longer
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"Failed to get AI analysis: {e}")