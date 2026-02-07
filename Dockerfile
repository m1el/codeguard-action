FROM python:3.11-slim

LABEL maintainer="GuardSpine <support@guardspine.io>"
LABEL org.opencontainers.image.source="https://github.com/DNYoussef/codeguard-action"
LABEL org.opencontainers.image.description="AI-aware code governance with verifiable evidence bundles"

# Install git for diff operations
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /action

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root runtime user
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin app

# Copy action code
COPY src/ ./src/
COPY rubrics/ ./rubrics/
COPY entrypoint.py .
RUN chown -R app:app /action
USER app

# Set entrypoint
ENTRYPOINT ["python", "/action/entrypoint.py"]
