# --- NEGATIVE TEST TRIGGER ---
FROM python:3.9-slim

# Rule Violation: Running as Root (High Identity Risk)
USER root 

# Add a fake "malicious" script to trigger the scanner
RUN echo "os.system('rm -rf /')" > exploit.py

WORKDIR /app
COPY . .