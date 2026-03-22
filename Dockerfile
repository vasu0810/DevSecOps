FROM python:3.9-slim
USER python
# This line will be caught by the new Layer 2 regex
ENV CLOUD_API_KEY="AIzaSyA1234567890-ExampleKey"