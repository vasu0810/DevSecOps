import joblib
import pandas as pd
import os

# Stage 8 Configuration: Environment-specific risk thresholds
# Lower threshold means stricter security (Common in Enterprise)
THRESHOLDS = {
    "dev": 0.85,
    "staging": 0.65,
    "prod": 0.40
}

def load_ai_model():
    """Loads the trained .pkl model from the models directory."""
    model_path = os.path.join("models", "ai_risk_model.pkl")
    
    # Path alignment for different execution contexts
    if not os.path.exists(model_path):
        model_path = os.path.join("..", "models", "ai_risk_model.pkl")
    
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"❌ AI Model not found at {model_path}. Please run train_model.py first.")
    
    return joblib.load(model_path)

def evaluate_deployment(deployment_data):
    """
    Predicts risk probability and makes a decision based on environment thresholds.
    
    deployment_data: Dictionary containing deployment features
    """
    model = load_ai_model()
    
    # 1. Identify Environment and Threshold
    env = deployment_data.get('environment', 'dev').lower()
    threshold = THRESHOLDS.get(env, 0.50) # Default to 0.50 if env unknown
    
    # 2. Prepare Input for AI Model
    # Note: Model expects 'env_prod' (1 for prod, 0 otherwise) instead of 'environment' string
    input_df = pd.DataFrame([{
        'env_prod': 1 if env == 'prod' else 0,
        'severity_weight': deployment_data['severity_weight'],
        'public_exposure': deployment_data['public_exposure'],
        'privilege_level': deployment_data['privilege_level'],
        'encryption_disabled': deployment_data['encryption_disabled'],
        'port_risk': deployment_data['port_risk'],
        'history_incidents': deployment_data['history_incidents'],
        'mitre_tactic_score': deployment_data['mitre_tactic_score']
    }])

    # 3. Predict Probability (Class 1 is 'Risk/Block')
    # predict_proba returns [prob_allow, prob_block]
    risk_probability = model.predict_proba(input_df)[0][1]
    
    # 4. Final Decision Logic
    decision = "BLOCK" if risk_probability > threshold else "ALLOW"
    
    return {
        "environment": env,
        "risk_score": round(float(risk_probability), 4),
        "threshold": threshold,
        "decision": decision
    }

if __name__ == "__main__":
    # --- SIMULATING A DEPLOYMENT REQUEST ---
    # Scenario: A high-risk production deployment
    request = {
        "environment": "prod",
        "severity_weight": 0.85,
        "public_exposure": 1,
        "privilege_level": 3,
        "encryption_disabled": 1,
        "port_risk": 0.9,
        "history_incidents": 4,
        "mitre_tactic_score": 0.92
    }
    
    print("🚀 Incoming Deployment Request detected...")
    result = evaluate_deployment(request)
    
    print("\n--- 🛡️ AI Risk Engine Evaluation ---")
    print(f"Target Environment : {result['environment'].upper()}")
    print(f"AI Risk Probability: {result['risk_score']}")
    print(f"Safety Threshold   : {result['threshold']}")
    print(f"Final Action       : {result['decision']}")
    print("------------------------------------\n")