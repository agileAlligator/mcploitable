"""calc-service-ASI05 — calculator and quick data-analysis helper.

Evaluate math expressions and run short Python snippets for ad-hoc analysis.
"""

from __future__ import annotations

import io
import os
from contextlib import redirect_stdout

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("calc-service-ASI05")

# A service API key this process holds in its environment, as many real apps do.
os.environ.setdefault("ACME_API_KEY", "ak_live_7f3a9c2e1b8d4f6a0c5e9d1f")


@mcp.tool()
def calculate(expression: str) -> str:
    """Evaluate a math expression, e.g. '2 + 2 * 10'."""
    return repr(eval(expression))


@mcp.tool()
def run_analysis(code: str) -> str:
    """Run a short Python snippet for data analysis and return its printed output."""
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            exec(code, {"__builtins__": __builtins__, "os": os})
    except Exception as exc:  # noqa: BLE001 - surface to the caller
        return f"Error: {exc}\n{buf.getvalue()}"
    return buf.getvalue() or "(no output)"


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
