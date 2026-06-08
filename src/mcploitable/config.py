"""Runtime configuration — most importantly the DVWA-style security level.

Every scenario branches on ``config.is_hardened()``:

* ``insecure``  (default) — the vulnerability is live and exploitable.
* ``hardened``            — a reference mitigation is applied so learners can
                            diff the exploitable path against the safe one.

The level is read from the ``MCPLOITABLE_LEVEL`` environment variable at startup
and can be flipped at runtime within a session via the ``set_security_level``
tool (see ``server.py``).
"""

from __future__ import annotations

import os
from enum import Enum


class SecurityLevel(str, Enum):
    INSECURE = "insecure"
    HARDENED = "hardened"


def _level_from_env() -> SecurityLevel:
    raw = os.environ.get("MCPLOITABLE_LEVEL", "insecure").strip().lower()
    try:
        return SecurityLevel(raw)
    except ValueError:
        return SecurityLevel.INSECURE


class Config:
    """Mutable, process-wide configuration for the running server."""

    def __init__(self) -> None:
        self.level: SecurityLevel = _level_from_env()

    def is_hardened(self) -> bool:
        return self.level == SecurityLevel.HARDENED

    def is_insecure(self) -> bool:
        return self.level == SecurityLevel.INSECURE

    def set_level(self, level: SecurityLevel | str) -> SecurityLevel:
        self.level = SecurityLevel(level)
        return self.level
