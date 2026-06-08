"""The contained 'fake world' that exploits act upon.

Nothing here touches the real host. The filesystem is an in-memory dict, the
database is an in-memory SQLite instance, and every secret/credential is fake.
This is what keeps mcploitable's blast radius inside the container: a successful
RCE or exfiltration steals *these* fake artifacts, not your real ones.
"""

from __future__ import annotations

from ..config import Config
from .database import Database
from .documents import DocumentStore
from .scoreboard import Scoreboard
from .secrets import FLAGS, SecretsVault


class Sandbox:
    """Aggregates the shared fake-world singletons handed to every scenario."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.secrets = SecretsVault()
        self.scoreboard = Scoreboard()
        self.db = Database()
        self.docs = DocumentStore()

    def reset(self) -> None:
        """Re-seed the fake world (handy between training runs)."""
        self.secrets = SecretsVault()
        self.scoreboard = Scoreboard()
        self.db = Database()
        self.docs = DocumentStore()


__all__ = ["Sandbox", "Database", "DocumentStore", "Scoreboard", "SecretsVault", "FLAGS"]
