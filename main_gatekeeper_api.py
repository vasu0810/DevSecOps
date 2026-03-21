from fastapi import FastAPI, HTTPException
import uvicorn
import sys
import os

# Ensure the core_ai folder is recognized
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core_ai.risk_engine import evaluate_deployment
from core_ai.logger_service import log_security_decision
from core_ai.explainable_ai import explain_decision

app = FastAPI(title="AI-DevSecOps OPA Hybrid Gatekeeper")

def simulate_opa_rest_call(input_data, ai_score, threshold):
    """
    Simulates the Rego logic from Stage 11:
    POST /v1/data/devsecops/deny
    """
    deny_reasons = []
    
    # Rule 1: Encryption disabled
    if input_data.get('encryption_disabled') == 1:
        deny_reasons.append("OPA_DENY: Encryption must be enabled.")
        
    # Rule 2: Public exposure in Prod
    if input_data.get('environment') == 'prod' and input_data.get('public_exposure') == 1:
        deny_reasons.append("OPA_DENY: Public exposure strictly forbidden in Production.")
        
    # Rule 3: AI Risk threshold check (Mapped from Rego)
    if ai_score > threshold:
        deny_reasons.append(f"AI_RISK_DENY: Score {ai_score:.4f} exceeds safety threshold.")

    return {
        "allow": len(deny_reasons) == 0,
        "violations": deny_reasons
    }

@app.post("/v1/gatekeeper/evaluate")
async def gatekeeper_service(payload: dict):
    print(f"\n📥 Incoming Deployment Request: {payload.get('environment', 'Unknown').upper()}")
    print("-" * 60)

    # STEP 1: AI Risk Evaluation (Probabilistic)
    ai_result = evaluate_deployment(payload)
    ai_score = ai_result['risk_score']
    ai_threshold = ai_result['threshold']

    # STEP 2: OPA Policy Evaluation (Deterministic REST simulation)
    opa_result = simulate_opa_rest_call(payload, ai_score, ai_threshold)

    # STEP 3: Final Decision Logic
    # IF (AI score > threshold) OR (OPA deny) THEN BLOCK
    is_blocked = not opa_result['allow']
    final_verdict = "BLOCK" if is_blocked else "ALLOW"

    # STEP 4: SHAP Explanation (If AI contributed to the risk)
    if is_blocked and ai_score > 0.5:
        print("🔍 AI detected high risk. Generating SHAP explanation...")
        explain_decision(payload)

    # STEP 5: Audit Logging (Stage 11)
    log_reason = " | ".join(opa_result['violations']) if is_blocked else "Passed all security gates."
    log_security_decision(payload, {"decision": final_verdict, "reason": log_reason})

    print(f"⚖️ FINAL SYSTEM VERDICT: {final_verdict}")
    print("-" * 60)

    return {
        "verdict": final_verdict,
        "ai_analysis": {
            "risk_score": round(ai_score, 4),
            "threshold": ai_threshold
        },
        "opa_governance": {
            "status": "Success",
            "violations": opa_result['violations']
        },
        "compliance": "NON-COMPLIANT" if is_blocked else "COMPLIANT"
    }

if __name__ == "__main__":
    print("🔥 Starting OPA Hybrid Gatekeeper API on http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)