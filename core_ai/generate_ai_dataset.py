import pandas as pd
import numpy as np
import os

def generate_threat_aware_dataset(num_records=5000):
    # --- ALIGNMENT: ALWAYS USE processed_data FOLDER ---
    output_dir = "processed_data"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    # Check for Stage 3 output in processed_data
    mitre_file = os.path.join(output_dir, "mitre_tactic_score.csv")
    if os.path.exists(mitre_file):
        mitre_scores = pd.read_csv(mitre_file)["mitre_tactic_score"].values
        print(f"✅ Loaded Stage 3 scores from {mitre_file}")
    else:
        # Fallback if Stage 3 wasn't run or saved elsewhere
        mitre_scores = [0.1, 0.5, 0.9]
        print("⚠️ Warning: mitre_tactic_score.csv not found, using default scores.")

    data = {
        "environment": np.random.choice(["dev", "staging", "prod"], num_records),
        "severity_weight": np.random.uniform(0.1, 1.0, num_records),
        "public_exposure": np.random.choice([0, 1], num_records),
        "privilege_level": np.random.choice([1, 2, 3], num_records),
        "encryption_disabled": np.random.choice([0, 1], num_records),
        "port_risk": np.random.uniform(0.0, 1.0, num_records),
        "history_incidents": np.random.randint(0, 10, num_records),
        "mitre_tactic_score": np.random.choice(mitre_scores, num_records)
    }
    
    df = pd.DataFrame(data)
    output_path = os.path.join(output_dir, "devsecops_ai_dataset_5000.csv")
    df.to_csv(output_path, index=False)
    print(f"✅ Stage 4 & 5 Complete: Created {output_path}")

if __name__ == "__main__":
    generate_threat_aware_dataset()