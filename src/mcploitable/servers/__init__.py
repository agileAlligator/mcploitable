"""A collection of deliberately vulnerable — but ordinary-looking — MCP servers.

Each module is a standalone server that presents as a normal, mundane tool. The
vulnerabilities are latent and unannounced: the servers don't know they're
targets, there are no flags, hints, or difficulty toggles. A successful exploit
is observed by its effect (data that actually leaves, code that actually runs),
not credited by the server.

See ``docs/operator/SERVERS.md`` (maintainer-only) for what each one demonstrates. For authorized security
research and training only — run isolated, never against real systems.
"""

from __future__ import annotations

# Display/registration name -> dotted module path (each exposes ``main`` + ``mcp``).
SERVERS = {
    "mail-assistant": "mcploitable.servers.mail",            # ASI01 indirect injection
    "analytics-bi": "mcploitable.servers.analytics",         # ASI02 tool misuse
    "account-recovery": "mcploitable.servers.recovery",      # ASI03 identity/privilege abuse
    "plugin-hub": "mcploitable.servers.toolhub",             # ASI04 agentic supply chain
    "calc": "mcploitable.servers.calc_service",              # ASI05 unexpected code execution
    "memo-assistant": "mcploitable.servers.memory",          # ASI06 memory/context poisoning
    "ops-orchestrator": "mcploitable.servers.orchestrator",  # ASI07 insecure agent-to-agent
}
