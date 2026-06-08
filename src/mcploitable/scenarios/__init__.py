"""Vulnerability scenario registry.

Each scenario module exposes ``register(mcp, sandbox)`` and (except ``common``)
a ``META`` describing the vulnerability. The ``SCENARIOS`` map keys each module
by its short id (``asi01`` …) so a server can register all of them (combined
mode) or just one (per-vuln mode). ``common`` carries the shared exfiltration
sink + scoreboard and is registered into every server.
"""

from __future__ import annotations

from ..sandbox import Sandbox
from . import (
    asi01_goal_hijack,
    asi02_tool_misuse,
    asi03_identity_abuse,
    asi04_supply_chain,
    asi05_code_execution,
    common,
)
from .base import ScenarioMeta

# Ordered map: short key -> scenario module. The key (e.g. "asi01") names the
# per-vuln server and its console-script entrypoint.
SCENARIOS = {
    "asi01": asi01_goal_hijack,
    "asi02": asi02_tool_misuse,
    "asi03": asi03_identity_abuse,
    "asi04": asi04_supply_chain,
    "asi05": asi05_code_execution,
}

ALL_META: list[ScenarioMeta] = [m.META for m in SCENARIOS.values()]


def register_selected(mcp, sandbox: Sandbox, keys) -> list[ScenarioMeta]:
    """Register the shared tools plus the scenarios named in ``keys``.

    Returns the META for each registered scenario (used by ``list_scenarios``).
    """
    common.register(mcp, sandbox)  # shared exfiltrate sink + scoreboard, always
    metas: list[ScenarioMeta] = []
    for key in keys:
        module = SCENARIOS[key]
        module.register(mcp, sandbox)
        metas.append(module.META)
    return metas


def register_all(mcp, sandbox: Sandbox) -> list[ScenarioMeta]:
    """Register the shared tools and every scenario (combined mode)."""
    return register_selected(mcp, sandbox, SCENARIOS.keys())
