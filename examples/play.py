"""Interactive driver — exercise a vulnerable server in-process, no MCP client
or Docker needed.

Run (pick a server by short name: mail, analytics, recovery, toolhub, calc, memory, orchestrator):
    PYTHONPATH=src python3 examples/play.py analytics

Commands:
    list                       list the server's tools (with descriptions)
    call <tool> [json-args]    call a tool, e.g.  call get_ticket {"ticket_id":1}
    help                       show this help
    quit                       exit

You can also pipe a script of commands in:
    PYTHONPATH=src python3 examples/play.py analytics < commands.txt
"""

from __future__ import annotations

import asyncio
import importlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

_ALIASES = {
    "mail": "mcploitable.servers.mail",
    "analytics": "mcploitable.servers.analytics",
    "recovery": "mcploitable.servers.recovery",
    "toolhub": "mcploitable.servers.toolhub",
    "calc": "mcploitable.servers.calc_service",
    "memory": "mcploitable.servers.memory",
    "orchestrator": "mcploitable.servers.orchestrator",
}

HELP = __doc__.split("Commands:", 1)[1]


def _text(res) -> str:
    if isinstance(res, tuple):
        res = res[0]
    seq = res if isinstance(res, (list, tuple)) else [res]
    return "\n".join(getattr(c, "text", str(c)) for c in seq)


async def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in _ALIASES:
        print(f"usage: play.py <{'|'.join(_ALIASES)}>", file=sys.stderr)
        raise SystemExit(2)
    mcp = importlib.import_module(_ALIASES[sys.argv[1]]).mcp
    print(f"driving '{mcp.name}'. Type 'help' for commands, 'quit' to exit.\n")

    loop = asyncio.get_event_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        cmd, _, rest = line.partition(" ")
        cmd = cmd.lower()
        try:
            if cmd in ("quit", "exit"):
                break
            elif cmd == "help":
                print(HELP)
            elif cmd == "list":
                for t in await mcp.list_tools():
                    print(f"- {t.name}: {(t.description or '').splitlines()[0] if t.description else ''}")
            elif cmd == "call":
                tool, _, arg_str = rest.partition(" ")
                args = json.loads(arg_str) if arg_str.strip() else {}
                print(_text(await mcp.call_tool(tool, args)))
            else:
                print(f"unknown command {cmd!r}; type 'help'.")
        except Exception as exc:  # surface tool/parse errors
            print(f"[error] {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    asyncio.run(main())
