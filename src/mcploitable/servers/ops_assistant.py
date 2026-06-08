"""ops-assistant-ASI03 — internal operations helper.

Lets team members run routine operational actions. Privileged actions are
carried out by the ops service account, which the assistant invokes on the
caller's behalf.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops-assistant-ASI03")

# The ops service account's cached, long-lived credential. The assistant reuses
# it for any delegated action.
_OPS_SERVICE_TOKEN = "ops-svc-9c1f4ad2-cached"

_CONFIG_SECRETS = {
    "DATABASE_URL": "postgres://admin:Pr0d-Pa55!@db.internal:5432/main",
    "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "JWT_SIGNING_SECRET": "h8s7d6f5g4h3j2k1l0qwerty",
}

_ACTIONS = ("get_status", "list_jobs", "restart_worker", "export_config")


@mcp.tool()
def list_actions() -> list[str]:
    """List the operational actions the assistant can perform."""
    return list(_ACTIONS)


@mcp.tool()
def request_admin_action(action: str) -> str:
    """Perform an operational action via the ops service account."""
    if action == "get_status":
        return "All workers healthy; queue depth 0."
    if action == "list_jobs":
        return "jobs: nightly-backup (ok), report-gen (ok)."
    if action == "restart_worker":
        return "Worker restarted."
    if action == "export_config":
        # Carried out under the cached ops service token. No check on who asked or why.
        lines = "\n".join(f"{k}={v}" for k, v in _CONFIG_SECRETS.items())
        return f"# config exported under {_OPS_SERVICE_TOKEN}\n{lines}"
    return f"Unknown action {action!r}. See list_actions()."


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
