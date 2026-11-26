# syntax=docker/dockerfile:1

# Pin base image by SHA-256 digest before production use:
#   docker buildx imagetools inspect python:3.12-slim
FROM python:3.12-slim@sha256:REPLACE_WITH_VERIFIED_DIGEST AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY secscan ./secscan
COPY secscan_ui ./secscan_ui

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir ".[ui]"

FROM python:3.12-slim@sha256:REPLACE_WITH_VERIFIED_DIGEST AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    SECSCAN_REPORTS_DIR="/reports" \
    SECSCAN_DATA_DIR="/data"

# Create fixed non-root user (override at runtime with HOST_UID:HOST_GID via Compose)
RUN groupadd --gid 10001 secscanui \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin secscanui \
    && mkdir -p /reports /data /app \
    && chown 10001:10001 /data

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /build/secscan /app/secscan
COPY --from=builder /build/secscan_ui /app/secscan_ui

USER 10001:10001
EXPOSE 8080

CMD ["waitress-serve", "--host=0.0.0.0", "--port=8080", "--call", "secscan_ui.app:create_app"]
