import os
import requests
import sys

def scan_project():
    print("🔍 Starting Automatic Security Scan...")
    
    # 1. Automatic Environment Discovery
    # If we are on the 'main' or 'prod' branch, we assume Production
    ref = os.getenv('GITHUB_REF', '')
    env = "prod" if "main" in ref or "prod" in ref else "dev"
    
    # 2. Automatic Feature Extraction
    # We check if a Dockerfile exists and if it has 'EXPOSE 80' (Public)
    public_exposure = 0
    if os.path.exists("Dockerfile"):
        with open("Dockerfile", "r") as f:
            content = f.read()
            if "EXPOSE" in content or "0.0.0.0" in content:
                public_exposure = 1

    # 3. Setting the AI Risk Score based on findings
    # In a real project, this would be a sum of vulnerabilities found
    mitre_score = 0.95 if env == "prod" and public_exposure == 1 else 0.05

    payload = {
        "environment": env,
        "public_exposure": public_exposure,
        "mitre_tactic_score": mitre_score,
        "encryption_disabled": 0
    }
    
    print(f"📡 Automatic Payload Generated: {payload}")
    
    # 4. Send to Gatekeeper
    try:
        response = requests.post("http://localhost:8001/v1/gatekeeper/evaluate", json=payload)
        if response.status_code == 403:
            print("❌ GATEKEEPER BLOCK: Security risk detected!")
            sys.exit(1) # This fails the GitHub Action
        else:
            print("✅ GATEKEEPER ALLOW: Deployment is safe.")
    except Exception as e:
        print(f"⚠️ Connection Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    scan_project()