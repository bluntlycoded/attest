# The service. The console is a separate deploy (see DEPLOY.md) because it is
# a static-ish Next app and this is a stateful process holding a SQLite file.
FROM python:3.12-slim

WORKDIR /app

# Copy metadata first so the dependency layer survives source edits.
COPY pyproject.toml README.md ./
COPY attest ./attest
COPY service ./service

RUN pip install --no-cache-dir -e ".[service]"

# SQLite lives here. Mount a volume at /app/data on any host that recycles the
# container filesystem, or every restart starts from an empty fleet.
ENV ATTEST_DB=/app/data/attest.db
RUN mkdir -p /app/data

# ATTEST_BOOTSTRAP_KEY is deliberately not defaulted. The service refuses every
# request without a valid token, and a Dockerfile-supplied default key would be
# a published credential on every deploy that forgot to override it.
EXPOSE 8317

CMD ["sh", "-c", "uvicorn service.app:app --host 0.0.0.0 --port ${PORT:-8317}"]
