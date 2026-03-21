import joblib
import pandas as pd
import shap
import os
import numpy as np

def explain_decision(deployment_data):
    # 1. Load the Model
    model_path = os.path.join("models", "ai_risk_model.pkl")
    if not os.path.exists(model_path):
        model_path = os.path.join("..", "models", "ai_risk_model.pkl")
    
    model = joblib.load(model_path)

    # 2. Prepare the Input Data
    env = deployment_data.get('environment', 'dev').lower()
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

    # 3. Initialize SHAP Explainer
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(input_df)

    # --- THE FIX ---
    # Random Forest returns a list of two arrays [Allow_values, Block_values]
    # We take the values for Class 1 (Block)
    if isinstance(shap_values, list):
        # Access index 1 for 'Block' class, then first row [0]
        current_shap_values = shap_values[1][0]
    else:
        # Some versions of SHAP return a 3D array; we handle that here
        current_shap_values = shap_values[0, :, 1] if len(shap_values.shape) == 3 else shap_values[0]

    # 4. Map and Print
    feature_importance = dict(zip(input_df.columns, current_shap_values))
    sorted_importance = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)

    print("\n --- AI EXPLANATION (SHAP) ---")
    print("Top factors contributing to this RISK decision:")
    
    for feature, score in sorted_importance[:3]:
        impact = "INCREASED RISK" if score > 0 else "REDUCED RISK"
        print(f"-> {feature}: {impact} (Score: {score:.4f})")
    
    return sorted_importance

if __name__ == "__main__":
    test_request = {
        "environment": "prod",
        "severity_weight": 0.85,
        "public_exposure": 1,
        "privilege_level": 3,
        "encryption_disabled": 1,
        "port_risk": 0.9,
        "history_incidents": 4,
        "mitre_tactic_score": 0.92
    }

    from risk_engine import evaluate_deployment
    result = evaluate_deployment(test_request)
    print(f"Decision: {result['decision']} (Risk Probability: {result['risk_score']})")

    explain_decision(test_request)