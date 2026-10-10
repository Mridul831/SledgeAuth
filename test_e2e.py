import requests

BASE_URL = "http://127.0.0.1:8000"

# 1. Parse the suspicious log
with open("sample_data/suspicious_auth.log", "r") as f:
    log_content = f.read()

parse_resp = requests.post(f"{BASE_URL}/api/logs/parse", json={"content": log_content})
events = parse_resp.json()["events"]
print(f"Parsed {len(events)} events.")

# 2. Run detection
detect_resp = requests.post(f"{BASE_URL}/api/detect", json={"events": events})
alerts = detect_resp.json()["alerts"]
print(f"Generated {len(alerts)} alerts.")

# 3. Print the alert
for alert in alerts:
    print(f"Alert: {alert['rule_name']} | Score: {alert['risk_score']} | Severity: {alert['severity']}")