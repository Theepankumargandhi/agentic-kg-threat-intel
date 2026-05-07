# ============================================================
# Agentic Knowledge Graph Reasoning Engine
# Production Dockerfile — python:3.11-slim base
# ============================================================

# --------------- Stage 1: dependency builder ---------------
FROM python:3.11-slim AS builder

# System-level build tools needed for some Python packages
# (e.g. grpcio, numpy, chromadb native extensions)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy requirements first so Docker can cache this layer separately
# from the application code layer — pip install only re-runs when
# requirements.txt actually changes.
COPY requirements.txt .

RUN pip install --upgrade pip --no-cache-dir \
    && pip install --no-cache-dir --prefix=/install -r requirements.txt

# --------------- Stage 2: production runtime ---------------
FROM python:3.11-slim AS runtime

LABEL maintainer="tgandhi1107@gmail.com"
LABEL org.opencontainers.image.title="Agentic Knowledge Graph Reasoning Engine"
LABEL org.opencontainers.image.description="Cybersecurity / MITRE ATT&CK knowledge graph with LangGraph agents"
LABEL org.opencontainers.image.source="https://github.com/theepan/agentic-knowledge-graph"

# Runtime system deps only (no build tools in final image)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy pre-built Python packages from builder stage
COPY --from=builder /install /usr/local

# ---- Non-root user for security ----
RUN groupadd --gid 1001 appgroup \
    && useradd --uid 1001 --gid appgroup --shell /bin/bash \
       --create-home appuser

# Working directory inside the container
WORKDIR /app

# Create data directory for ChromaDB and grant ownership before
# switching user so we don't need root at runtime
RUN mkdir -p /app/data/chroma \
    && chown -R appuser:appgroup /app

# Copy application source — done AFTER installing deps so source
# changes don't invalidate the (expensive) pip install layer
COPY --chown=appuser:appgroup . .

# Switch to non-root user
USER appuser

# Expose the FastAPI port
EXPOSE 8000

# Health check: poll /api/v1/health every 30 s; allow 10 s start period
# before the first check; fail after 3 consecutive misses.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Default environment values (overridable at runtime / docker-compose)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CHROMA_PATH=/app/data/chroma

# Entrypoint: production uvicorn with a single worker per container
# (scale horizontally via replicas, not threads)
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "1", \
     "--loop", "uvloop", \
     "--http", "httptools", \
     "--log-level", "info", \
     "--access-log"]
