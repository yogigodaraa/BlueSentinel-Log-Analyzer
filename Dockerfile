# ───────────────────────────────────────────────────────────────────
# BlueSentinel — slim image for the FastAPI service.
#
# Skips torch/transformers by default (they're big). Enable them with:
#   docker build --build-arg EXTRAS=llm -t bluesentinel .
# ───────────────────────────────────────────────────────────────────

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install build deps only for stages that need them
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

# ───────────────────────────────────────────────────────────────────
# Copy & install package
# ───────────────────────────────────────────────────────────────────
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

# Install with only the API-essential deps (skip torch/transformers).
# If you need the full detector stack, `pip install -e ".[eval]"`.
RUN pip install --no-cache-dir \
    "numpy>=1.26" "pandas>=2.1" "pydantic>=2.5" "loguru>=0.7" \
    "drain3>=0.9.11" "scikit-learn>=1.3" "joblib>=1.3" \
    "PyYAML>=6" "fastapi>=0.110" "uvicorn[standard]>=0.27" \
 && pip install --no-cache-dir -e . --no-deps

# ───────────────────────────────────────────────────────────────────
# Runtime
# ───────────────────────────────────────────────────────────────────
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "bluesentinel.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
