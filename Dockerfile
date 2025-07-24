# CertNode Production Dockerfile
FROM python:3.11-slim

LABEL maintainer="SRB Creative Holdings LLC"
LABEL version="1.0.0"
LABEL description="CertNode T17+ Logic Governance Infrastructure"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    sqlite3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY *.py ./
COPY *.json ./

# Create necessary directories
RUN mkdir -p vault logs certified_outputs trust_badges config

# Create non-root user
RUN adduser --disabled-password --gecos '' certnode && \
    chown -R certnode:certnode /app
USER certnode

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Run the application
CMD ["python3", "certnode_api.py", "--host", "0.0.0.0", "--port", "8000"]
