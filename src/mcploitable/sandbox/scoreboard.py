"""A tiny CTF-style scoreboard tracking which scenarios have been solved.

The shared exfiltration sink and a few scenario-specific success checks call
``capture()`` with whatever data an exploit managed to move. Any flag strings
found are recorded as solved.
"""

from __future__ import annotations

from .secrets import FLAGS


class Scoreboard:
    def __init__(self) -> None:
        # scenario id -> unix timestamp of first capture
        self._solved: dict[str, float] = {}
        self._monotonic = 0.0

    def _now(self) -> float:
        # Avoid wall-clock nondeterminism issues in tests; monotonic counter.
        self._monotonic += 1.0
        return self._monotonic

    def capture(self, data: str) -> list[str]:
        """Scan exfiltrated text for any flags and mark them solved.

        Returns the list of scenario ids newly solved by this call.
        """
        newly: list[str] = []
        if not data:
            return newly
        for scenario_id, flag in FLAGS.items():
            if flag in data and scenario_id not in self._solved:
                self._solved[scenario_id] = self._now()
                newly.append(scenario_id)
        return newly

    def mark_solved(self, scenario_id: str) -> bool:
        """Directly mark a scenario solved (for non-exfil success conditions)."""
        if scenario_id not in self._solved:
            self._solved[scenario_id] = self._now()
            return True
        return False

    def is_solved(self, scenario_id: str) -> bool:
        return scenario_id in self._solved

    def status(self) -> dict[str, bool]:
        return {sid: (sid in self._solved) for sid in FLAGS}
