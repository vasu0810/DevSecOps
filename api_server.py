import sys
import os
import uvicorn
import requests
import json
import logging
from datetime import datetime
from fastapi import FastAPI, Response, status 

# --- 🛠️ CORPORATE AUDIT LOGGING ---
# Logs every attempt for compliance (SOC2/ISO27001)
logging.basicConfig(
    filename='security_audit.log', 
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s'
)

# --- 🛠️ 1. DOCKER PATH RESOLUTION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR)

# --- 🛠️ 2. SAFE IMPORTS ---
try:
    from core_ai.risk_engine import evaluate_deployment
    print("✅ Core AI modules loaded successfully.")
except ImportError:
    print("❌ Critical Module Import Error: Using fallback evaluator.")
    def evaluate_deployment(x): return {"risk_score": 0.2, "threshold": 0.5}

OPA_URL = os.getenv("OPA_URL", "http://opa-service:8181/v1/data/policy/allow")

app = FastAPI(title="Corporate-Grade AI Hybrid Gatekeeper")

# --- 🛡️ MITRE-BASED REMEDIATION DATABASE ---
# This handles the "Rectification" part of your project
MITRE_REMEDIATION = {
    "credential_leak": "FIX: Use Environment Variables or HashiCorp Vault (MITRE T1552).",
    "injection_risk": "FIX: Sanitize inputs; avoid shell execution like eval() (MITRE T1059).",
    "supply_chain_risk": "FIX: Update vulnerable library versions in requirements.txt (MITRE T1195).",
    "network_exposure": "FIX: Close Port 80; migrate to HTTPS 443 (MITRE T1190).",
    "identity_risk": "FIX: Define a non-root USER in your Dockerfile (MITRE T1548).",
    "heuristic_drift": "FIX: Investigation Required - Suspicious data exfiltration pattern (MITRE T1020).",
    "obfuscation_detected": "FIX: Blocked due to unknown encrypted payload/obfuscation (MITRE T1027)."
}

# --- 🛡️ UPDATED MULTI-VECTOR LOGIC ---
def run_hybrid_checks(data, ai_score, threshold):
    violations = []
    remediation_plan = []
    env = data.get('environment', 'dev').lower()
    vectors = data.get('vector_details', {})

    # 1. HARD RULE: Known Breach Detection
    if vectors.get('credential_leak') == 1: violations.append("credential_leak")
    if vectors.get('injection_risk') == 1: violations.append("injection_risk")
    if vectors.get('supply_chain_risk') == 1: violations.append("supply_chain_risk")

    # 2. HEURISTIC RULE: New/Unknown Attack Detection
    if vectors.get('heuristic_drift') == 1: violations.append("heuristic_drift")
    if vectors.get('obfuscation_detected') == 1: violations.append("obfuscation_detected")

    # 3. CONTEXTUAL RULE: Production Exposure
    if env == 'prod':
        if vectors.get('network_exposure') == 1: violations.append("network_exposure")
        if vectors.get('identity_risk') == 1: violations.append("identity_risk")

    # 4. OPA Policy check
    try:
        opa_resp = requests.post(OPA_URL, json={"input": data}, timeout=2)
        if opa_resp.status_code == 200 and opa_resp.json().get("result") is False:
            violations.append("OPA_DENY")
    except Exception:
        pass 

    # 5. AI Risk Aggregation & Thresholding
    current_threshold = threshold if env == 'prod' else 0.85
    if ai_score > current_threshold:
        violations.append("AI_SCORE_THRESHOLD_EXCEEDED")

    # Generate Rectification/Remediation Plan
    for v in violations:
        if v in MITRE_REMEDIATION:
            remediation_plan.append(MITRE_REMEDIATION[v])

    return {
        "allow": len(violations) == 0, 
        "violations": violations,
        "remediation": remediation_plan
    }

# --- 🌐 EVALUATION ENDPOINT ---
@app.post("/v1/gatekeeper/evaluate")
async def evaluate(payload: dict, response: Response):
    try:
        # 1. AI Inference
        ai_result = evaluate_deployment(payload)
        ai_score = ai_result.get('risk_score', payload.get('mitre_tactic_score', 0.1))
        threshold = ai_result.get('threshold', 0.5)

        # 2. Hybrid Decision
        gov_result = run_hybrid_checks(payload, ai_score, threshold)
        
        # 3. Real-Time Audit Log entry
        status_label = "ALLOWED" if gov_result['allow'] else "BLOCKED"
        logging.info(f"Env: {payload.get('environment')} | Score: {ai_score} | Verdict: {status_label} | Risks: {gov_result['violations']}")

        # 4. Decision Enforcement
        if not gov_result['allow']:
            response.status_code = status.HTTP_403_FORBIDDEN
            return {
                "verdict": "BLOCK", 
                "threat_intel": "Mapped to MITRE ATT&CK via enterprise-attack.json",
                "violations": gov_result['violations'],
                "remediation_plan": gov_result['remediation'],
                "final_risk_score": ai_score
            }

        return {
            "verdict": "ALLOW", 
            "score": ai_score,
            "message": "Deployment cleared by Corporate AI Gatekeeper"
        }

    except Exception as e:
        logging.error(f"RUNTIME ERROR: {str(e)}")
        response.status_code = status.HTTP_403_FORBIDDEN
        return {"verdict": "BLOCK", "error": str(e)}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)