import yaml
import os
import sys
import re

# 1. Setup paths for core_ai modules
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

try:
    from core_ai.risk_engine import evaluate_deployment
    from core_ai.explainable_ai import explain_decision
    from core_ai.logger_service import log_security_decision
except ImportError as e:
    print(f"❌ Import Error: {e}")
    sys.exit(1)

def auto_analyze_vulnerabilities():
    """IDENTIFIES ALL SECURITY BREACHES (ROOT, PORTS, SECRETS, HEURISTICS)"""
    print("🔎 Starting Heuristic & Multi-Layer Breach Analysis...")
    
    # Complete Data Schema to prevent AI Risk Engine KeyErrors
    profile = {
        "identity_risk": 0,
        "public_exposure": 0,
        "privilege_level": 0,
        "encryption_disabled": 0,
        "port_risk": 0.1,
        "history_incidents": 0,
        "mitre_score": 0.10,
        "severity": 0.1,
        "env": "dev"
    }

    if not os.path.exists("Dockerfile"):
        print("⚠️ No Dockerfile found. Proceeding with safe defaults.")
        return profile

    with open("Dockerfile", "r") as f:
        lines = f.readlines()
        
        for line in lines:
            clean_line = line.strip().lower()
            if not clean_line or clean_line.startswith("#"):
                continue

            # --- LAYER 1: BREACH - Unauthorized ROOT (Identity Risk) ---
            if "user root" in clean_line:
                print("🚨 BREACH: Unauthorized ROOT Privileges detected!")
                profile["identity_risk"] = 1
                profile["privilege_level"] = 1
                profile["mitre_score"] = max(profile["mitre_score"], 0.85)

            # --- LAYER 2: BREACH - Unsecured API Keys/Secrets (Credential Risk) ---
            # Pattern catches API_KEY=..., PASSWORD=..., or AWS_KEY=...
            secret_pattern = r"(?i)(api_key|secret|password|token|aws_access_key)[\s:=]+['\"]?([a-zA-Z0-9\-_]{16,})['\"]?"
            if re.search(secret_pattern, clean_line):
                print(f"🚨 BREACH: Unsecured API Key/Secret found in line -> {clean_line.split('=')[0]}...")
                profile["encryption_disabled"] = 1
                profile["mitre_score"] = max(profile["mitre_score"], 0.95) # Highest risk from CSV T1552.001

            # --- LAYER 3: BREACH - Dangerous Port Exposure (Network Risk) ---
            if "expose" in clean_line:
                if any(p in clean_line for p in ["22", "23", "3389", "445"]):
                    print(f"🚨 BREACH: Dangerous Port Exposure ({clean_line})!")
                    profile["public_exposure"] = 1
                    profile["port_risk"] = 0.95
                    profile["mitre_score"] = max(profile["mitre_score"], 0.90)

            # --- LAYER 4: HEURISTIC ALERT - Malicious Execution (Zero-Day Risk) ---
            # Detects suspicious downloads or piping to shell
            if re.search(r"(curl|wget|git clone).*(http|https|ftp)", clean_line) or "| bash" in clean_line:
                print(f"⚠️ HEURISTIC ALERT: Suspicious behavioral pattern detected!")
                profile["history_incidents"] = 1 
                profile["mitre_score"] = max(profile["mitre_score"], 0.80)

    # Escalation Logic: If any breach is found, escalate environment to PROD
    if profile["mitre_score"] > 0.5:
        profile["env"] = "prod"
        profile["severity"] = max(profile["severity"], 0.9)
        
    return profile

def main_gatekeeper(request):
    print(f"\n🛡️  SECURITY EVALUATION GATEWAY [{request['environment'].upper()}]")
    print("=" * 60)

    # Consult AI Hybrid Risk Engine
    print("✅ Running AI Hybrid Risk Assessment...")
    ai_result = evaluate_deployment(request)
    
    if ai_result['decision'] == "BLOCK":
        print(f"🛑 [AI ENGINE] BLOCK (Risk Score: {ai_result['risk_score']})")
        explain_decision(request) # Triggers SHAP Explainability
    else:
        print(f"✅ [AI ENGINE] ALLOW (Risk Score: {ai_result['risk_score']})")

    log_security_decision(request, ai_result)
    return ai_result

if __name__ == "__main__":
    # 1. Automatic Breach Analysis
    findings = auto_analyze_vulnerabilities()

    # 2. Build the request dictionary for the Risk Engine
    test_request = {
        "environment": findings["env"],
        "severity_weight": findings["severity"],
        "public_exposure": findings["public_exposure"],
        "privilege_level": findings["privilege_level"],
        "encryption_disabled": findings["encryption_disabled"],
        "port_risk": findings["port_risk"],
        "history_incidents": findings["history_incidents"],
        "mitre_tactic_score": findings["mitre_score"],
        "vector_details": {
            "identity_risk": findings["identity_risk"],
            "injection_risk": 0
        }
    }

    # 3. Final AI Evaluation
    final_verdict = main_gatekeeper(test_request)
    
    print("\n" + "=" * 60)
    print(f"FINAL SYSTEM VERDICT: {final_verdict['decision']}")
    print("=" * 60)

    # 4. Exit for GitHub Actions (1 = FAIL/RED, 0 = PASS/GREEN)
    sys.exit(1 if final_verdict['decision'] == "BLOCK" else 0)