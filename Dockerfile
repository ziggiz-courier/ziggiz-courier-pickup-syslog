# ---- Base image with Python and system deps ----
FROM python:3.13.3-alpine3.21 AS base

# Set environment variables for Python
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VERSION=^2

# ---- Builder image for installing dependencies ----
FROM base AS builder

WORKDIR /app

# Install Poetry and Git in a single layer
RUN apk add --no-cache git && \
    pip install --no-cache-dir "poetry"

# Copy only dependency files for better caching
COPY pyproject.toml poetry.lock* README.md LICENSE /tmp/
COPY ziggiz_courier_pickup_syslog /tmp/ziggiz_courier_pickup_syslog

# Install dependencies (no dev)
RUN cd /tmp && poetry install --only main

# ---- Final image ----
FROM base

WORKDIR /app

# Copy installed dependencies from builder
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --from=builder /app /app

# Compile .pyc files at build time for faster startup
RUN python -m compileall -q .

# Set the entrypoint (adjust as needed)
CMD ["python", "-m", "ziggiz_courier_pickup_syslog"]
