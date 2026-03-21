import requests
import json

# Change this to 8001 based on your current terminal output!
URL = "http://localhost:8001/v1/gatekeeper/evaluate"

payload = {
    "environment": "prod",
    "severity_weight": 0.5,
    "public_exposure": 1,         # Triggers OPA Policy
    "privilege_level": 1,
    "encryption_disabled": 0,
    "port_risk": 0.3,
    "history_incidents": 0,
    "mitre_tactic_score": 0.6     # Triggers AI Score
}

print(f"📡 Sending final validation request to {URL}...")
try:
    response = requests.post(URL, json=payload)
    print("\n✅ API Response Received:")
    print(json.dumps(response.json(), indent=4))
except Exception as e:
    print(f"❌ Connection Error: {e}")