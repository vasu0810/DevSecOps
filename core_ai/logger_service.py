import logging
import os
from datetime import datetime

# Setup the log directory
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

log_file = os.path.join(log_dir, "gatekeeper_audit.log")

# Configure Logging
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s'
)

def log_security_decision(request, result):
    """Writes the final decision to the audit trail for compliance."""
    env = request.get('environment', 'unknown').upper()
    decision = result.get('decision', 'UNKNOWN')
    
    # Identify if it was a Policy Block or an AI Block
    reason = result.get('reason', f"AI Risk Score: {result.get('risk_score', 'N/A')}")
    
    log_entry = f"ENV: {env} | VERDICT: {decision} | DETAILS: {reason}"
    logging.info(log_entry)
    print(f"📝 Decision synced to audit log: {log_file}")