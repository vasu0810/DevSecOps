import json
import pandas as pd
import os

# Updated to use your local dataset path
DATASET_PATH = "./data/json_inputs/enterprise-attack.json"

def extract_patterns():
    if not os.path.exists(DATASET_PATH):
        print(f"Error: Could not find {DATASET_PATH}")
        return

    with open(DATASET_PATH, "r") as f:
        data = json.load(f)

    techniques = []
    # Goal: Extract adversarial tactics & techniques [cite: 10]
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            ext_refs = obj.get("external_references", [{}])
            technique_id = ext_refs[0].get("external_id", "N/A")
            
            # Identify High-Impact techniques (Execution/Initial Access) [cite: 17]
            tactics = [p.get("phase_name") for p in obj.get("kill_chain_phases", [])]
            impact = "High" if any(t in tactics for t in ["execution", "initial-access"]) else "Medium"
            
            techniques.append({
                "technique_id": technique_id,
                "name": obj.get("name"),
                "impact": impact
            })

    df = pd.DataFrame(techniques)
    df.to_csv("important_attack_patterns.csv", index=False)
    print(f"Stage 1 & 2 Complete: Extracted {len(df)} patterns [cite: 12, 16]")

if __name__ == "__main__":
    extract_patterns()