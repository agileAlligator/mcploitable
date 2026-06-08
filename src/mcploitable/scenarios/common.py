"""Cross-cutting tools shared by several scenarios.

* ``exfiltrate`` — the attacker-controlled egress sink. Several exploits end by
  shipping stolen data here. In INSECURE mode it accepts any destination and
  records captured flags on the scoreboard. In HARDENED mode an egress allowlist
  blocks non-internal destinations (the mitigation for data exfiltration).
* ``scoreboard`` — read CTF progress.
"""

from __future__ import annotations

from ..sandbox import Sandbox

# Destinations a hardened egress policy would permit.
_EGRESS_ALLOWLIST = {"internal", "localhost", "https://logs.internal"}


def register(mcp, sandbox: Sandbox) -> None:
    config = sandbox.config

    @mcp.tool()
    def exfiltrate(destination: str, data: str) -> str:
        """Send ``data`` to an external ``destination`` URL (e.g. for logging/backup).

        This represents any tool with outbound network capability. It is the
        canonical exfiltration sink for several scenarios.
        """
        if config.is_hardened():
            allowed = any(destination.startswith(p) for p in _EGRESS_ALLOWLIST)
            if not allowed:
                return (
                    f"[egress blocked] destination {destination!r} is not on the "
                    f"allowlist {sorted(_EGRESS_ALLOWLIST)}. No data was sent."
                )
            # Even when allowed, hardened mode does not credit flag capture:
            # the data never left the trust boundary.
            return f"[ok] {len(data)} bytes delivered to allowlisted {destination!r}."

        # INSECURE: anything goes. Scan the payload for loot.
        solved = sandbox.scoreboard.capture(data)
        note = ""
        if solved:
            note = f"  >>> CAPTURED FLAGS for {', '.join(solved)}! Check the scoreboard."
        return f"[sent] {len(data)} bytes exfiltrated to {destination!r}.{note}"

    @mcp.tool()
    def scoreboard() -> dict:
        """Show which vulnerability scenarios have been solved this session."""
        return {
            "security_level": config.level.value,
            "solved": sandbox.scoreboard.status(),
        }
