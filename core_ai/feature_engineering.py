import pandas as pd
import os
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

def perform_feature_engineering():
    # Look for the dataset specifically in the processed_data folder
    input_path = os.path.join("processed_data", "devsecops_ai_dataset_5000.csv")
    
    if not os.path.exists(input_path):
        print(f"❌ Error: {input_path} not found. Run generate_ai_dataset.py first.")
        return

    df = pd.read_csv(input_path)
    
    # 1. Encoding & Normalization
    le = LabelEncoder()
    df['env_encoded'] = le.fit_transform(df['environment'])
    df['env_prod'] = (df['environment'] == 'prod').astype(int) # Critical production flag

    scaler = MinMaxScaler()
    cols = ['severity_weight', 'port_risk', 'history_incidents', 'mitre_tactic_score']
    df[cols] = scaler.fit_transform(df[cols])

    # Save to the same folder
    output_path = os.path.join("processed_data", "engineered_devsecops_data.csv")
    df.to_csv(output_path, index=False)
    print(f"✅ Stage 6 Complete: Saved to {output_path}")

if __name__ == "__main__":
    perform_feature_engineering()