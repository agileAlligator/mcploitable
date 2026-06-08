"""Fake secrets and CTF-style flags.

FLAGS are the 'loot' for each scenario. A flag is revealed only by actually
performing the exploit (reading data you shouldn't, achieving code execution,
etc.). The shared exfiltration sink (see scenarios) scans exfiltrated data for
these flag strings to mark a scenario solved on the scoreboard.

Every value here is fabricated. They look like real credentials so the exercise
feels authentic, but they authenticate to nothing.
"""

from __future__ import annotations

# Per-scenario flags. Format mirrors common CTF conventions.
FLAGS: dict[str, str] = {
    "ASI01": "MCPLOITABLE{asi01_indirect_prompt_injection_goal_hijack}",
    "ASI02": "MCPLOITABLE{asi02_overscoped_tool_exfil_chain}",
    "ASI03": "MCPLOITABLE{asi03_confused_deputy_privilege_inheritance}",
    "ASI04": "MCPLOITABLE{asi04_tool_descriptor_poisoning_supply_chain}",
    "ASI05": "MCPLOITABLE{asi05_eval_remote_code_execution}",
}


class SecretsVault:
    """A fake credential store that scenarios can leak."""

    def __init__(self) -> None:
        # The kind of thing an over-permissioned agent should never be able to read.
        self._secrets: dict[str, str] = {
            "AWS_SECRET_ACCESS_KEY": "AKIAFAKE0000EXAMPLE/wJalrFAKEKEYEXAMPLEKEY",
            "STRIPE_SECRET_KEY": "sk_live_FAKE_4242deadbeefcafef00dbaadf00d",
            "DB_ADMIN_PASSWORD": "hunter2-but-fake-do-not-panic",
            "INTERNAL_SIGNING_KEY": "ed25519-fake-7f3a9c2e1b8d4f6a0c5e",
            # The ASI05 RCE flag is staged here as an 'environment secret' so that
            # achieving code execution and reading process state surfaces it.
            "MCPLOITABLE_RCE_FLAG": FLAGS["ASI05"],
        }

    def all(self) -> dict[str, str]:
        return dict(self._secrets)

    def get(self, name: str) -> str | None:
        return self._secrets.get(name)
