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
    print(f" Import Error: {e}")
    print("Make sure logger_service.py, risk_engine.py, and explainable_ai.py are inside 'core_ai' folder.")
    sys.exit(1)

def load_governance_policies():
    """Stage 10: Load Hard-Coded YAML Rules"""
    policy_path = os.path.join(current_dir, "governance", "policy.yaml")
    
    if not os.path.exists(policy_path):
        # Check root if governance folder is missing
        policy_path = os.path.join(current_dir, "policy.yaml") 
        
    if not os.path.exists(policy_path):
        print(" Warning: No policy.yaml found. Proceeding with AI only.")
        return []
        
    with open(policy_path, 'r') as file:
        data = yaml.safe_load(file)
        return data.get('policies', [])

def check_deterministic_rules(request, policies):
    """Stage 10: Evaluate Hard Rules (Deterministic)"""
    for policy in policies:
        try:
            # Eval evaluates the 'condition' string against request variables
            if eval(policy['condition'], {"__builtins__": {}}, request):
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
    """The Hybrid Gatekeeper Logic"""
    print(f"\n STARTING SECURITY EVALUATION [{request['environment'].upper()}]")
    print("=" * 60)

    # --- STEP 1: GOVERNANCE CHECK (YAML) ---
    policies = load_governance_policies()
    hard_block = check_deterministic_rules(request, policies)

    if hard_block:
        print(f" [GOVERNANCE] BLOCK")
        print(f" Reason: {hard_block['reason']}")
        log_security_decision(request, hard_block)
        return hard_block

    # --- STEP 2: AI RISK CHECK (RANDOM FOREST) ---
    print(" No governance violations. Consulting AI Risk Engine...")
    ai_result = evaluate_deployment(request)
    
    if ai_result['decision'] == "BLOCK":
        print(f" [AI ENGINE] BLOCK (Risk Score: {ai_result['risk_score']})")
        
        # --- STEP 3: EXPLAINABILITY (SHAP) ---
        print("\n SHAP Analysis (Why AI Blocked This):")
        explain_decision(request)
    else:
        print(f"[AI ENGINE] ALLOW (Risk Score: {ai_result['risk_score']})")

    # --- STEP 4: AUDIT LOGGING ---
    log_security_decision(request, ai_result)
    
    return ai_result

if __name__ == "__main__":
    # Test Scenario: Violates Hard Rule (Public Exposure in Prod)
    test_request = {
        "environment": "prod",
        "severity_weight": 0.2,       # AI might think this is low risk...
        "public_exposure": 1,         # ...but the YAML Policy says NO.
        "privilege_level": 1,
        "encryption_disabled": 0,
        "port_risk": 0.1,
        "history_incidents": 0,
        "mitre_tactic_score": 0.3
    }

    final_verdict = main_gatekeeper(test_request)
    print("\n" + "=" * 60)
    print(f"FINAL SYSTEM VERDICT: {final_verdict['decision']}")
    print("=" * 60)