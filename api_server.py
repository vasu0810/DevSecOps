import sys
import os
import uvicorn
import requests
import json
from fastapi import FastAPI, Response, status 

# Ensure core_ai modules are recognized
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from core_ai.risk_engine import evaluate_deployment
    from core_ai.logger_service import log_security_decision
    from core_ai.explainable_ai import explain_decision
except ImportError as e:
    print(f"❌ Critical Module Import Error: {e}")

# Service discovery for Docker networking
OPA_URL = os.getenv("OPA_URL", "http://opa-service:8181/v1/data/policy/allow")

app = FastAPI(
    title="Hybrid AI-DevSecOps Gatekeeper", 
    description="M.Tech Final Stage 15: Full CI/CD Enforcement",
    version="1.5.0"
)

# --- 🏠 ROOT ENDPOINT ---
@app.get("/", tags=["Health"])
async def root():
    return {
        "status": "Online",
        "mode": "CI-CD-Enforcement-Active",
        "stage": "15_FINAL",
        "documentation": "/docs"
    }

# --- 🛡️ GOVERNANCE LOGIC ---
def opa_policy_check(data, ai_score, threshold):
    violations = []
    
    if data.get('encryption_disabled') == 1:
        violations.append("PY_DENY: Encryption disabled.")
        
    if data.get('environment') == 'prod' and data.get('public_exposure') == 1:
        violations.append("PY_DENY: Public exposure forbidden in Production.")
    
    try:
        opa_resp = requests.post(OPA_URL, json={"input": data}, timeout=2)
        if opa_resp.status_code == 200:
            result = opa_resp.json().get("result", False)
            if result is False: 
                violations.append("OPA_DENY: External policy container rejected this.")
    except Exception:
        print("⚠️ Warning: OPA Service unreachable.")

    if ai_score > threshold:
        violations.append(f"AI_BLOCK: Risk score {ai_score:.4f} exceeds threshold.")
        
    return {"allow": len(violations) == 0, "violations": violations}

# --- 🌐 EVALUATION ENDPOINT ---
@app.post("/v1/gatekeeper/evaluate")
async def evaluate(payload: dict, response: Response):
    # 1. AI Inference
    ai_result = evaluate_deployment(payload)
    ai_score, threshold = ai_result['risk_score'], ai_result['threshold']
    
    # 2. Hybrid Policy Check
    gov_result = opa_policy_check(payload, ai_score, threshold)
    
    # 3. Final Verdict
    final_decision = "BLOCK" if not gov_result['allow'] else "ALLOW"
    reason = " | ".join(gov_result['violations']) if not gov_result['allow'] else "Passed"
    
    # 4. Log and Explain
    log_security_decision(payload, {"decision": final_decision, "reason": reason})
    if final_decision == "BLOCK" and ai_score > threshold:
        explain_decision(payload)

    # --- 🚀 STAGE 15 ENFORCEMENT ---
    # Returning 403 Forbidden tells GitHub Actions to FAIL the build
    if final_decision == "BLOCK":
        response.status_code = status.HTTP_403_FORBIDDEN

    return {
        "verdict": final_decision,
        "compliance_status": "COMPLIANT" if final_decision == "ALLOW" else "NON-COMPLIANT",
        "ai_metrics": {"score": round(ai_score, 4), "threshold": threshold},
        "violations": gov_result['violations'],
        "pipeline_action": "STOP_DEPLOYMENT" if final_decision == "BLOCK" else "CONTINUE_DEPLOYMENT"
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)