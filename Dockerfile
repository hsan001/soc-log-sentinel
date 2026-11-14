# Multi-stage non-root Dockerfile for SOC Log Sentinel
# Stage 1: Build & wheels
FROM python:3.11-slim-bookworm AS builder

WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip build wheel \
    && pip wheel --no-cache-dir --no-deps --wheel-dir /build/wheels -r requirements.txt || true

# Stage 2: Minimal non-root runtime
FROM python:3.11-slim-bookworm AS runner

ARG APP_USER=sentinel
ARG APP_UID=10001
ARG APP_GID=10001

RUN groupadd --gid "${APP_GID}" "${APP_USER}" \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" --shell /sbin/nologin --create-home "${APP_USER}"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=${APP_USER}:${APP_USER} . /app

USER 10001:10001

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["python", "-m", "sentinel.cli"]
CMD ["--help"]
