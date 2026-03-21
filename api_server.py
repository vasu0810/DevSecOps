import sys
import os
import uvicorn
import requests
import json
from fastapi import FastAPI, Response, status 

# --- 🛠️ 1. DOCKER PATH RESOLUTION ---
# This ensures Python can see the 'core_ai' folder inside the container
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR)

# --- 🛠️ 2. SAFE IMPORTS ---
try:
    from core_ai.risk_engine import evaluate_deployment
    from core_ai.logger_service import log_security_decision
    from core_ai.explainable_ai import explain_decision
    print("✅ Core AI modules loaded successfully.")
except ImportError as e:
    print(f"❌ Critical Module Import Error: {e}")
    # Default behavior so the server doesn't 500-crash if a file is missing
    def evaluate_deployment(x): return {"risk_score": 0.8, "threshold": 0.5}

OPA_URL = os.getenv("OPA_URL", "http://opa-service:8181/v1/data/policy/allow")

app = FastAPI(title="Hybrid Gatekeeper Stage 15")

@app.get("/")
async def root():
    return {"status": "Online", "mode": "CI-CD-Enforcement"}

# --- 🛡️ HYBRID POLICY LOGIC ---
def run_hybrid_checks(data, ai_score, threshold):
    violations = []
    
    # Python Policy
    if data.get('encryption_disabled') == 1:
        violations.append("PY_DENY: Encryption disabled.")
        
    if data.get('environment') == 'prod' and data.get('public_exposure') == 1:
        violations.append("PY_DENY: Public exposure forbidden in Production.")
    
    # OPA Policy
    try:
        opa_resp = requests.post(OPA_URL, json={"input": data}, timeout=3)
        if opa_resp.status_code == 200 and opa_resp.json().get("result") is False:
            violations.append("OPA_DENY: Governance rejection.")
    except Exception:
        print("⚠️ OPA Service unreachable.")

    # AI Risk Policy
    if ai_score > threshold:
        violations.append(f"AI_BLOCK: Risk score {ai_score:.2f} too high.")
        
    return {"allow": len(violations) == 0, "violations": violations}

# --- 🌐 EVALUATION ENDPOINT ---
@app.post("/v1/gatekeeper/evaluate")
async def evaluate(payload: dict, response: Response):
    try:
        # 1. AI Inference (Wrapped to prevent 500 error)
        try:
            ai_result = evaluate_deployment(payload)
            ai_score = ai_result.get('risk_score', 0.5)
            threshold = ai_result.get('threshold', 0.5)
        except Exception:
            ai_score, threshold = 0.9, 0.5 # Default to high risk if engine fails

        # 2. Hybrid Decision
        gov_result = run_hybrid_checks(payload, ai_score, threshold)
        final_decision = "BLOCK" if not gov_result['allow'] else "ALLOW"
        
        # 3. Log the decision
        try:
            log_security_decision(payload, {"decision": final_decision})
        except: pass

        # --- 🚀 ENFORCEMENT ---
        if final_decision == "BLOCK":
            # This is what stops the GitHub Action
            response.status_code = status.HTTP_403_FORBIDDEN
            return {"verdict": "BLOCK", "violations": gov_result['violations']}

        return {"verdict": "ALLOW", "score": ai_score}

    except Exception as e:
        # THE 500-ERROR KILLER: Any global crash becomes a 403.
        print(f"🔥 System Error: {e}")
        response.status_code = status.HTTP_403_FORBIDDEN
        return {"verdict": "BLOCK", "error": "Internal Processing Error"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)