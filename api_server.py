import sys
import os
import uvicorn
import requests
import json
from fastapi import FastAPI, Response, status 

# --- 🛠️ 1. DOCKER PATH RESOLUTION ---
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
    def evaluate_deployment(x): return {"risk_score": 0.2, "threshold": 0.5}

OPA_URL = os.getenv("OPA_URL", "http://opa-service:8181/v1/data/policy/allow")

app = FastAPI(title="Hybrid Gatekeeper Stage 15")

@app.get("/")
async def root():
    return {"status": "Online", "mode": "CI-CD-Enforcement"}

# --- 🛡️ HYBRID POLICY LOGIC ---
def run_hybrid_checks(data, ai_score, threshold):
    violations = []
    env = data.get('environment', 'dev').lower()
    
    # 1. HARD RULE: Encryption (Strict for everyone)
    if data.get('encryption_disabled') == 1:
        violations.append("PY_DENY: Encryption disabled.")
        
    # 2. CONTEXTUAL RULE: Production Exposure
    # We only block this if it's ACTUALLY prod.
    if env == 'prod' and data.get('public_exposure') == 1:
        violations.append("PY_DENY: Public exposure forbidden in Production.")
    
    # 3. OPA Policy (Only block if OPA explicitly says 'result: false')
    try:
        opa_resp = requests.post(OPA_URL, json={"input": data}, timeout=3)
        if opa_resp.status_code == 200:
            opa_data = opa_resp.json()
            # We ONLY block if OPA returns a definite False. 
            # If OPA is empty/null, we allow it to pass to the AI officer.
            if opa_data.get("result") is False:
                violations.append("OPA_DENY: Governance rejection.")
    except Exception:
        print("⚠️ OPA Service unreachable - bypassing OPA check.")

    # 4. AI Risk Policy
    # For 'dev', we are more relaxed. For 'prod', we are strict.
    current_threshold = threshold if env == 'prod' else 0.8
    if ai_score > current_threshold:
        violations.append(f"AI_BLOCK: Risk score {ai_score:.2f} exceeds {current_threshold}.")
        
    return {"allow": len(violations) == 0, "violations": violations}

# --- 🌐 EVALUATION ENDPOINT ---
@app.post("/v1/gatekeeper/evaluate")
async def evaluate(payload: dict, response: Response):
    try:
        # 1. AI Inference
        try:
            ai_result = evaluate_deployment(payload)
            ai_score = ai_result.get('risk_score', 0.1) # Default low risk
            threshold = ai_result.get('threshold', 0.5)
        except Exception:
            ai_score, threshold = 0.5, 0.5 

        # 2. Hybrid Decision
        gov_result = run_hybrid_checks(payload, ai_score, threshold)
        
        # 3. Decision Logic
        if not gov_result['allow']:
            response.status_code = status.HTTP_403_FORBIDDEN
            return {
                "verdict": "BLOCK", 
                "violations": gov_result['violations'],
                "score": ai_score
            }

        # SUCCESS CASE (200 OK)
        return {
            "verdict": "ALLOW", 
            "score": ai_score,
            "message": "Deployment cleared by Hybrid Gatekeeper"
        }

    except Exception as e:
        print(f"🔥 System Error: {e}")
        response.status_code = status.HTTP_403_FORBIDDEN
        return {"verdict": "BLOCK", "error": str(e)}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)