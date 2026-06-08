"""A collection of deliberately vulnerable — but ordinary-looking — MCP servers.

Each module is a standalone server that presents as a normal, mundane tool. The
vulnerabilities are latent and unannounced: the servers don't know they're
targets, there are no flags, hints, or difficulty toggles. A successful exploit
is observed by its effect (data that actually leaves, code that actually runs),
not credited by the server.

See ``docs/SERVERS.md`` for what each one demonstrates. For authorized security
research and training only — run isolated, never against real systems.
"""

from __future__ import annotations

# Display/registration name -> dotted module path (each exposes ``main`` + ``mcp``).
SERVERS = {
    "helpdesk-ASI01": "mcploitable.servers.helpdesk",
    "analytics-ASI02": "mcploitable.servers.analytics",
    "ops-assistant-ASI03": "mcploitable.servers.ops_assistant",
    "toolhub-ASI04": "mcploitable.servers.toolhub",
    "calc-service-ASI05": "mcploitable.servers.calc_service",
}
