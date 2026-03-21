FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# 1. Copy requirements first (for faster builds)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2. IMPORTANT: Copy EVERYTHING (including core_ai, models, and governance folders)
COPY . .

# 3. Set Python Path so it can find your modules
ENV PYTHONPATH=/app

# Start the server
CMD ["python", "api_server.py"]