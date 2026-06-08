"""ASI05 — Unexpected Code Execution (RCE).

A "calculator"/"data analysis" agent exposes tools that evaluate expressions and
run scripts. INSECURE uses eval()/exec() on untrusted input — genuine arbitrary
code execution. The blast radius is the container only, but it is real RCE: you
can import os, read the environment, touch the (fake) filesystem, etc. The RCE
flag is staged in the process environment, so reading it proves code execution.

HARDENED: ``evaluate`` uses an AST-restricted arithmetic interpreter (no names,
calls, attribute access, or imports); ``run_script`` is disabled entirely.
"""

from __future__ import annotations

import ast
import io
import operator
import os
from contextlib import redirect_stdout

from ..sandbox import Sandbox
from .base import ScenarioMeta

META = ScenarioMeta(
    id="ASI05",
    name="Unexpected Code Execution (RCE)",
    summary="Untrusted input reaches eval()/exec(), yielding arbitrary code execution.",
    exploit_hint=(
        "evaluate(\"__import__('os').environ['MCPLOITABLE_RCE_FLAG']\") — or "
        "run_script('import os; print(os.environ)') — to read the staged flag."
    ),
    hardened_behavior=(
        "evaluate() is an AST-restricted arithmetic-only interpreter; run_script() "
        "is disabled."
    ),
)

# Operators permitted by the hardened arithmetic evaluator.
_SAFE_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.FloorDiv: operator.floordiv,
}
_SAFE_UNARYOPS = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def _safe_eval(node: ast.AST):
    """Evaluate a numeric expression AST, rejecting anything dangerous."""
    if isinstance(node, ast.Expression):
        return _safe_eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _SAFE_BINOPS:
        return _SAFE_BINOPS[type(node.op)](_safe_eval(node.left), _safe_eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _SAFE_UNARYOPS:
        return _SAFE_UNARYOPS[type(node.op)](_safe_eval(node.operand))
    raise ValueError("only arithmetic over numeric literals is allowed")


def register(mcp, sandbox: Sandbox) -> None:
    config = sandbox.config

    @mcp.tool()
    def evaluate(expression: str) -> str:
        """Evaluate a math expression for the user (e.g. '2 + 2 * 10')."""
        if config.is_hardened():
            try:
                tree = ast.parse(expression, mode="eval")
                return str(_safe_eval(tree))
            except Exception as exc:  # noqa: BLE001 - surface to the learner
                return f"[rejected] {exc}"

        # INSECURE: arbitrary code execution.
        result = eval(expression)  # noqa: S307 - intentional vulnerability
        text = repr(result)
        sandbox.scoreboard.capture(text)
        return text

    @mcp.tool()
    def run_script(code: str) -> str:
        """Run a short Python snippet for data analysis and return its stdout."""
        if config.is_hardened():
            return "[disabled] arbitrary script execution is turned off in hardened mode."

        # INSECURE: exec arbitrary code, capturing stdout.
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                exec(code, {"__builtins__": __builtins__, "os": os})  # noqa: S102
        except Exception as exc:  # noqa: BLE001
            return f"[error] {exc}\n{buf.getvalue()}"
        out = buf.getvalue()
        sandbox.scoreboard.capture(out)
        return out or "[no output]"
