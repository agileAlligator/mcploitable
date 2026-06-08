"""mcploitable — a deliberately vulnerable MCP server for agentic-security training.

WARNING: This software intentionally contains security vulnerabilities. It exists
so that defenders, red-teamers, and developers can practice attacking and hardening
MCP / agentic systems in a controlled lab. Run it ONLY inside an isolated sandbox
(the bundled Docker image). NEVER expose it to an untrusted network or connect it
to real credentials, data, or systems.

Vulnerability scenarios are mapped to the OWASP Top 10 for Agentic Applications
(Agentic Security Initiative, "ASI") 2026.
"""

__version__ = "0.1.0"
