FROM python:3.11-slim AS builder

WORKDIR /build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cargo \
    libssl-dev \
    libpq-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip wheel --wheel-dir /wheels --no-binary cryptography -r requirements.txt

FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

# Install runtime-only system dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Install only prebuilt wheels from the disposable builder stage.
# Also upgrade base-image packaging tooling to clear known CVEs
# (wheel CVE-2026-24049, setuptools-vendored jaraco.context CVE-2026-23949).
COPY requirements.txt .
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --upgrade "wheel>=0.46.2" "setuptools>=80.9.0" \
    && pip install --no-cache-dir --no-index --find-links=/wheels -r requirements.txt \
    && rm -rf /wheels

# Copy runtime code only. Tests, backup servers, local data, and generated
# artifacts never enter the final image context.
COPY app ./app
COPY worker.py ./worker.py

# Create non-root user and its writable local-development key mount point.
RUN useradd -m -u 1000 appuser \
    && mkdir -p /run/oidc \
    && chown -R appuser:appuser /app /run/oidc
USER appuser

# Expose port
EXPOSE 8000

# Command will be overridden in docker-compose
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]