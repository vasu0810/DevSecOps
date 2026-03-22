import yaml
import os
import sys

# 1. Add current directory to path so core_ai can be found
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

try:
    from core_ai.risk_engine import evaluate_deployment
    from core_ai.explainable_ai import explain_decision
    from core_ai.logger_service import log_security_decision
except ImportError as e:
    print(f"❌ Import Error: {e}")
    sys.exit(1)

def load_governance_policies():
    """Load Hard-Coded YAML Rules from governance folder"""
    policy_path = os.path.join(current_dir, "governance", "policy.yaml")
    if not os.path.exists(policy_path):
        policy_path = os.path.join(current_dir, "policy.yaml") 
    
    if not os.path.exists(policy_path):
        return []
        
    try:
        with open(policy_path, 'r') as file:
            data = yaml.safe_load(file)
            return data.get('policies', [])
    except Exception:
        return []

def check_deterministic_rules(request, policies):
    """Evaluate Hard Rules without using dangerous eval()"""
    vectors = request.get('vector_details', {})
    for policy in policies:
        try:
            condition_key = policy.get('condition_key')
            if condition_key in vectors and vectors[condition_key] == 1:
                # Example: Hard block in production for specific violations
                if request['environment'] == "prod":
                    return {
                        "decision": "BLOCK",
                        "reason": policy['reason'],
                        "policy_name": policy['name'],
                        "type": "GOVERNANCE_VIOLATION"
                    }
        except Exception as e:
            print(f"Error in policy {policy['name']}: {e}")
    return None

def main_gatekeeper(request):
    """The Hybrid Gatekeeper Logic: Governance + AI"""
    print(f"\n🛡️  STARTING SECURITY EVALUATION [{request['environment'].upper()}]")
    print("=" * 60)

    # --- SAFETY FIX: Ensure required keys exist to avoid KeyErrors ---
    request.setdefault('severity_weight', 0.1)
    request.setdefault('public_exposure', 0)
    request.setdefault('privilege_level', 0)
    request.setdefault('encryption_disabled', 0)
    request.setdefault('port_risk', 0.1)
    request.setdefault('history_incidents', 0)
    request.setdefault('mitre_tactic_score', 0.0)

    # --- STEP 1: GOVERNANCE CHECK (Hard Rules) ---
    policies = load_governance_policies()
    hard_block = check_deterministic_rules(request, policies)

    if hard_block:
        print(f"🛑 [GOVERNANCE] BLOCK")
        print(f"Reason: {hard_block['reason']}")
        log_security_decision(request, hard_block)
        return hard_block

    # --- STEP 2: AI RISK CHECK ---
    print("✅ No governance violations. Consulting AI Risk Engine...")
    ai_result = evaluate_deployment(request)
    
    if ai_result['decision'] == "BLOCK":
        print(f"🛑 [AI ENGINE] BLOCK (Risk Score: {ai_result['risk_score']})")
        # --- STEP 3: EXPLAINABILITY ---
        print("\n🔍 SHAP Analysis (AI Reasoning):")
        explain_decision(request)
    else:
        print(f"✅ [AI ENGINE] ALLOW (Risk Score: {ai_result['risk_score']})")

    # --- STEP 4: AUDIT LOGGING ---
    log_security_decision(request, ai_result)
    return ai_result

if __name__ == "__main__":
    # Test Scenario representing a typical scan request
    test_request = {
        "environment": "dev",
        "severity_weight": 0.2,
        "mitre_tactic_score": 0.20,
        "vector_details": {
            "identity_risk": 1,
            "injection_risk": 0
        }
    }

    final_verdict = main_gatekeeper(test_request)
    print("\n" + "=" * 60)
    print(f"FINAL SYSTEM VERDICT: {final_verdict['decision']}")
    print("=" * 60)