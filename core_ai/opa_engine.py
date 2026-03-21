import json

class OPAEngine:
    """Simulates the Open Policy Agent (OPA) REST API behavior."""
    
    def evaluate_policy(self, request_data, ai_risk_score, threshold):
        # Prepare the 'Input' JSON for the OPA API
        opa_payload = {
            "input": {
                "environment": request_data.get("environment"),
                "public_exposure": request_data.get("public_exposure"),
                "encryption_disabled": request_data.get("encryption_disabled"),
                "risk_score": ai_risk_score,
                "threshold": threshold
            }
        }

        # Simulated OPA Rego Evaluation Logic
        violations = []
        
        if opa_payload["input"]["encryption_disabled"] == 1:
            violations.append("POLICY_DENY: Encryption must be enabled.")
            
        if opa_payload["input"]["environment"] == "prod" and opa_payload["input"]["public_exposure"] == 1:
            violations.append("POLICY_DENY: Public exposure forbidden in Prod.")
            
        if opa_payload["input"]["risk_score"] > opa_payload["input"]["threshold"]:
            violations.append(f"AI_DENY: Risk score {ai_risk_score} exceeds threshold.")

        decision = "ALLOW" if not violations else "BLOCK"
        
        return {
            "decision": decision,
            "violations": violations,
            "api_endpoint": "POST /v1/data/devsecops/deny",
            "status": "200 OK"
        }

if __name__ == "__main__":
    # Quick Test
    opa = OPAEngine()
    test_input = {"environment": "prod", "public_exposure": 1, "encryption_disabled": 0}
    print(opa.evaluate_policy(test_input, 0.35, 0.40))