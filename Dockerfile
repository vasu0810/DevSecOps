FROM python:3.9-slim
# Create a security user
RUN useradd -m appuser
WORKDIR /app
COPY . .
# Fix: Switch from root to appuser
USER appuser
CMD ["python", "api_server.py"]