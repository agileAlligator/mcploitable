# mcploitable — deliberately vulnerable MCP server.
# The container is the trust boundary: a successful RCE/exfiltration is contained
# to this image's fake sandbox, not your host. Run it isolated (see compose).
FROM python:3.12-slim

# Don't write .pyc, unbuffered stdio (MCP uses stdio transport).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MCPLOITABLE_LEVEL=insecure

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 lowpriv

# Drop to an unprivileged user — even container-local RCE shouldn't be root.
USER lowpriv

# stdio MCP server. Launch with `docker run -i --rm ...` so the client can talk
# to it over stdin/stdout.
ENTRYPOINT ["mcploitable"]
