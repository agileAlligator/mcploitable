# mcploitable — a collection of deliberately vulnerable MCP servers.
# The container is the trust boundary: a successful RCE/exfiltration is contained
# to this image's fake data, not your host. Run it isolated (see compose).
FROM python:3.12-slim

# Don't write .pyc, unbuffered stdio (MCP uses stdio transport).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 lowpriv

# Drop to an unprivileged user — even container-local RCE shouldn't be root.
USER lowpriv

# No default server: each is its own console script (mail-assistant/analytics-bi/
# account-recovery/plugin-hub/memo-assistant/ops-orchestrator/calc). docker-compose.yml
# sets the entrypoint per service; for a bare run, name one, e.g.:
#   docker run -i --rm mcploitable:latest mail-assistant
