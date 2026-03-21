import requests
import json

url = "http://localhost:8000/v1/gatekeeper/evaluate"

# TEST CASE: Production deployment with Public Exposure
# This violates the OPA Rego rule even if the AI score is low.
data = {
    "environment": "prod",
    "severity_weight": 0.2,
    "public_exposure": 1,         # <--- Triggers OPA Deny
    "privilege_level": 1,
    "encryption_disabled": 0,
    "port_risk": 0.1,
    "history_incidents": 0,
    "mitre_tactic_score": 0.2
}

print(f"📡 Sending payload to Gatekeeper API...")
response = requests.post(url, json=data)

if response.status_code == 200:
    print("\n✅ Response Received:")
    print(json.dumps(response.json(), indent=4))
else:
    print(f"❌ Error: {response.status_code}")