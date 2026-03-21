import pandas as pd

def generate_scores():
    # Load the patterns extracted in Stage 2 [cite: 16]
    df = pd.read_csv("important_attack_patterns.csv")

    # Weighted tactics by severity: High = 0.9, Medium = 0.5 
    df["mitre_tactic_score"] = df["impact"].apply(lambda x: 0.9 if x == "High" else 0.5)
    
    df.to_csv("mitre_tactic_score.csv", index=False)
    print("Stage 3 Complete: Generated mitre_tactic_score.csv [cite: 22]")

if __name__ == "__main__":
    generate_scores()