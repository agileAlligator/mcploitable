"""mcploitable — a collection of deliberately vulnerable MCP servers.

WARNING: This software intentionally contains security vulnerabilities. Each
server presents as an ordinary tool but harbours a latent flaw, so defenders,
red-teamers, and developers can study how MCP / agentic systems get compromised.
Run it ONLY inside an isolated sandbox (the bundled Docker image). NEVER expose
it to an untrusted network or connect it to real credentials, data, or systems.

The vulnerabilities map to the OWASP Top 10 for Agentic Applications (Agentic
Security Initiative, "ASI") 2026 — see the ASI tag in each server's name.
"""

__version__ = "0.2.0"
