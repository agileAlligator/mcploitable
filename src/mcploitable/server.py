"""mcploitable MCP server entrypoints.

mcploitable ships as **one server per vulnerability** — each demonstrates a
single OWASP ASI scenario in isolation, with its own tools, scoreboard, and
``insecure``/``hardened`` toggle. A combined server (all scenarios at once) is
also available for convenience and for the test suite.

Run a single-vuln server (stdio transport):

    mcploitable-asi01        # Agent Goal Hijack only
    mcploitable-asi05        # Unexpected Code Execution only

Run the combined server (all scenarios):

    mcploitable

Security level: MCPLOITABLE_LEVEL=insecure|hardened  (default: insecure)
"""

from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP

from .config import Config, SecurityLevel
from .sandbox import FLAGS, Sandbox
from .scenarios import SCENARIOS, register_selected
from .scenarios.base import ScenarioMeta

_COMBINED_BANNER = (
    "mcploitable — DELIBERATELY VULNERABLE MCP server for security training. "
    "Mapped to the OWASP Top 10 for Agentic Applications (ASI 2026). "
    "Run only in an isolated sandbox; never expose it or wire it to real systems."
)


def _scenario_banner(meta: ScenarioMeta) -> str:
    return (
        f"mcploitable:{meta.id} — DELIBERATELY VULNERABLE MCP server demonstrating a "
        f"SINGLE OWASP ASI vulnerability: {meta.id} {meta.name}. {meta.summary} "
        "Run only in an isolated sandbox; never expose it or wire it to real systems."
    )


def _build(name: str, instructions: str, keys, config: Config | None) -> tuple[FastMCP, Sandbox]:
    """Core builder: a FastMCP server carrying the scenarios named in ``keys``."""
    config = config or Config()

    # Stage the RCE flag in the real process environment so that genuine code
    # execution (ASI05) — and only that — can read it back.
    os.environ.setdefault("MCPLOITABLE_RCE_FLAG", FLAGS["ASI05"])

    mcp = FastMCP(name, instructions=instructions)
    sandbox = Sandbox(config)
    metas = register_selected(mcp, sandbox, keys)

    @mcp.tool()
    def list_scenarios() -> list[dict]:
        """List the vulnerability scenario(s) this server exposes, with exploit hints."""
        return [
            {
                "id": m.id,
                "name": m.name,
                "summary": m.summary,
                "exploit_hint": m.exploit_hint,
                "hardened_behavior": m.hardened_behavior,
            }
            for m in metas
        ]

    @mcp.tool()
    def get_security_level() -> str:
        """Return the current security level (insecure or hardened)."""
        return config.level.value

    @mcp.tool()
    def set_security_level(level: str) -> str:
        """Set the security level: 'insecure' (vulnerable) or 'hardened' (mitigated).

        Note: tool *descriptions* (ASI04 descriptor poisoning) are fixed at server
        startup and are not affected by a runtime change.
        """
        try:
            new = config.set_level(SecurityLevel(level.strip().lower()))
        except ValueError:
            return f"[error] unknown level {level!r}; use 'insecure' or 'hardened'."
        return f"security level set to {new.value}."

    @mcp.tool()
    def reset_sandbox() -> str:
        """Re-seed the fake world and clear the scoreboard."""
        sandbox.reset()
        return "sandbox reset."

    return mcp, sandbox


def build_scenario_server(key: str, config: Config | None = None) -> tuple[FastMCP, Sandbox]:
    """Build a server demonstrating exactly one vulnerability (``key`` = 'asi01' …)."""
    if key not in SCENARIOS:
        raise KeyError(f"unknown scenario {key!r}; known: {sorted(SCENARIOS)}")
    meta = SCENARIOS[key].META
    return _build(f"mcploitable-{key}", _scenario_banner(meta), [key], config)


def build_server(config: Config | None = None) -> tuple[FastMCP, Sandbox]:
    """Build the combined server with every scenario registered."""
    return _build("mcploitable", _COMBINED_BANNER, list(SCENARIOS), config)


def main() -> None:
    """Entrypoint for the combined ``mcploitable`` server."""
    mcp, _ = build_server()
    mcp.run()


def _run_scenario(key: str) -> None:
    mcp, _ = build_scenario_server(key)
    mcp.run()


# Per-vulnerability console-script entrypoints (see pyproject [project.scripts]).
def asi01() -> None:  # Agent Goal Hijack
    _run_scenario("asi01")


def asi02() -> None:  # Tool Misuse & Exploitation
    _run_scenario("asi02")


def asi03() -> None:  # Identity & Privilege Abuse
    _run_scenario("asi03")


def asi04() -> None:  # Agentic Supply Chain
    _run_scenario("asi04")


def asi05() -> None:  # Unexpected Code Execution (RCE)
    _run_scenario("asi05")


if __name__ == "__main__":
    main()
