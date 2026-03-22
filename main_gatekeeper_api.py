from fastapi import FastAPI
import uvicorn
from main_gatekeeper import main_gatekeeper

app = FastAPI(title="AI-DevSecOps Hybrid Gatekeeper API")

@app.post("/v1/gatekeeper/evaluate")
async def gatekeeper_service(payload: dict):
    # Pass incoming request directly to the core gatekeeper logic
    result = main_gatekeeper(payload)
    
    # Standardized response for scanner.py or GitHub Actions
    return {
        "verdict": result.get('decision', 'BLOCK'),
        "ai_analysis": {
            "risk_score": result.get('risk_score', 0.0),
            "threshold": result.get('threshold', 0.3)
        },
        "compliance": "NON-COMPLIANT" if result.get('decision') == "BLOCK" else "COMPLIANT"
    }

if __name__ == "__main__":
    # Port 8000 is used by default in your scanner.py configuration
    # Troubleshooting: If [Errno 10048] occurs, kill the existing process
    print("🔥 Starting OPA Hybrid Gatekeeper API on http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)