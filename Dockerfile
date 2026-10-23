# ─── Stage 1: Build Dependencies ──────────────────────────────────────────────
FROM python:3.11-slim AS builder

# Install build dependencies for any C-extension wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy only dependency manifests first for better layer caching
COPY pyproject.toml ./
COPY src/ ./src/

# Install into a prefix we can copy cleanly to the runtime stage
RUN pip install --no-cache-dir --prefix=/install -e .


# ─── Stage 2: Runtime Image ──────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="DevOps Auditor Agent"
LABEL org.opencontainers.image.description="Autonomous AI agent for DevOps repository auditing"
LABEL org.opencontainers.image.source="https://github.com/AHSANooo/repo-auditor-agent"
LABEL org.opencontainers.image.licenses="MIT"

# Install git (required for cloning target repos and running git log)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system --add safe.directory '*'

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Copy source code
COPY --from=builder /build/src /app/src
COPY agent.py tools.py /app/

WORKDIR /app

# Create a non-root user for security (principle of least privilege)
RUN groupadd --gid 1001 auditor && \
    useradd --uid 1001 --gid auditor --shell /bin/bash --create-home auditor && \
    # Give auditor write access to /reports for output files
    mkdir -p /reports && chown auditor:auditor /reports

USER auditor

# Default output directory inside the container
VOLUME ["/reports"]

# Health check — verify the CLI is importable
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from devops_auditor.cli import main; print('ok')" || exit 1

ENTRYPOINT ["python", "agent.py"]
CMD ["--help"]
