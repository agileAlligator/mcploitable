"""Interactive driver for mcploitable — exercise the server with no MCP client
or Docker needed. It builds the server in-process and lets you call tools.

Run:
    PYTHONPATH=src python3 examples/play.py                 # insecure (default)
    MCPLOITABLE_LEVEL=hardened PYTHONPATH=src python3 examples/play.py

Commands:
    list                       list available tools
    scenarios                  show scenario catalogue + exploit hints
    call <tool> [json-args]    call a tool, e.g.  call fetch_ticket {"ticket_id":"ticket-1002"}
    score                      show the CTF scoreboard
    level <insecure|hardened>  switch security level at runtime
    reset                      re-seed the sandbox
    help                       show this help
    quit                       exit

You can also pipe a script of commands in:
    PYTHONPATH=src python3 examples/play.py < commands.txt
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

# Make the package importable without setting PYTHONPATH.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcploitable.server import build_server  # noqa: E402


def _text(res) -> str:
    if isinstance(res, tuple):
        res = res[0]
    seq = res if isinstance(res, (list, tuple)) else [res]
    return "\n".join(getattr(c, "text", str(c)) for c in seq)


HELP = __doc__.split("Commands:", 1)[1]


async def main() -> None:
    mcp, _ = build_server()
    print("mcploitable interactive driver. Type 'help' for commands, 'quit' to exit.\n")

    loop = asyncio.get_event_loop()
    while True:
        try:
            line = await loop.run_in_executor(None, sys.stdin.readline)
        except (EOFError, KeyboardInterrupt):
            break
        if not line:  # EOF (piped input ended)
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
                names = sorted(t.name for t in await mcp.list_tools())
                print("\n".join(names))
            elif cmd == "scenarios":
                print(_text(await mcp.call_tool("list_scenarios", {})))
            elif cmd == "score":
                print(_text(await mcp.call_tool("scoreboard", {})))
            elif cmd == "level":
                print(_text(await mcp.call_tool("set_security_level", {"level": rest.strip()})))
            elif cmd == "reset":
                print(_text(await mcp.call_tool("reset_sandbox", {})))
            elif cmd == "call":
                tool, _, arg_str = rest.partition(" ")
                args = json.loads(arg_str) if arg_str.strip() else {}
                print(_text(await mcp.call_tool(tool, args)))
            else:
                print(f"unknown command {cmd!r}; type 'help'.")
        except Exception as exc:  # surface tool/parse errors to the learner
            print(f"[error] {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    asyncio.run(main())
