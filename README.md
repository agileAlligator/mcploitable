# mcploitable

**A deliberately vulnerable MCP server for agentic-security training — the
"Metasploitable" of the Model Context Protocol.**

mcploitable is an intentionally insecure [MCP](https://modelcontextprotocol.io)
server you can attack in a lab to learn how agentic systems get compromised. Its
vulnerability scenarios map directly to the **[OWASP Top 10 for Agentic
Applications (ASI) 2026](https://genai.owasp.org)**. Like DVWA or Juice Shop, but
for tool-using AI agents and the MCP layer they run on.

> [!WARNING]
> This software is **intentionally vulnerable**. One scenario achieves **real
> code execution**. Run it **only** inside the bundled, network-isolated Docker
> container. **Never** expose it to an untrusted network, and **never** connect
> it to real credentials, data, or systems. Everything it "leaks" is fake.

## One server per vulnerability

mcploitable ships as **a separate MCP server for each scenario** — every server
demonstrates exactly one OWASP ASI vulnerability, with only that scenario's tools
plus the shared exfiltration sink and scoreboard. Register just the ones you want
to train on.

| Server / command | Scenario |
|------------------|----------|
| `mcploitable-asi01` | ASI01 — Agent Goal Hijack |
| `mcploitable-asi02` | ASI02 — Tool Misuse & Exploitation |
| `mcploitable-asi03` | ASI03 — Identity & Privilege Abuse |
| `mcploitable-asi04` | ASI04 — Agentic Supply Chain |
| `mcploitable-asi05` | ASI05 — Unexpected Code Execution (RCE) |

A combined `mcploitable` command (all scenarios in one server) is also available
for convenience.

## What's inside

Each scenario ships in two modes via a DVWA-style toggle
(`MCPLOITABLE_LEVEL=insecure|hardened`, or the `set_security_level` tool):

* **`insecure`** — the vulnerability is live and exploitable.
* **`hardened`** — a reference mitigation is applied, so you can diff the
  exploitable path against the safe one.

| ASI | Scenario | Vulnerability | Key tools |
|-----|----------|---------------|-----------|
| **ASI01** | Agent Goal Hijack | Indirect prompt injection in fetched content | `fetch_ticket`, `read_internal_note`, `exfiltrate` |
| **ASI02** | Tool Misuse & Exploitation | Over-scoped SQL + email chained to exfiltrate | `query_database`, `send_email` |
| **ASI03** | Identity & Privilege Abuse | Confused-deputy privilege inheritance | `delegate_to_admin`, `issue_task_token` |
| **ASI04** | Agentic Supply Chain | Tool-descriptor poisoning + malicious registry | `search_tool_registry`, `install_tool`, `get_weather` |
| **ASI05** | Unexpected Code Execution (RCE) | `eval`/`exec` on untrusted input | `evaluate`, `run_script` |

A CTF-style **scoreboard** tracks progress: each successful exploit captures a
`MCPLOITABLE{...}` flag. Check it with the `scoreboard` tool.

## Quick start (Docker — recommended)

```bash
docker compose build
docker compose run --rm -T asi01      # one stdio MCP server per vuln, fully isolated
docker compose run --rm -T asi05      # … swap asi0N for the scenario you want
```

Each compose service runs with **no network**, a **read-only filesystem**,
**dropped capabilities**, and as a **non-root user** — so even the real RCE
scenario stays boxed inside the container.

### Connect an MCP client

Point your MCP client (Claude Desktop, etc.) at one container per vuln. Example
client config registering all five:

```json
{
  "mcpServers": {
    "mcploitable-asi01": {
      "command": "docker",
      "args": ["compose", "-f", "/path/to/mcploitable/docker-compose.yml",
               "run", "--rm", "-T", "asi01"]
    },
    "mcploitable-asi05": {
      "command": "docker",
      "args": ["compose", "-f", "/path/to/mcploitable/docker-compose.yml",
               "run", "--rm", "-T", "asi05"]
    }
  }
}
```

## Local run (development only)

```bash
pip install -e ".[dev]"
mcploitable-asi01                    # single-vuln stdio server, insecure by default
MCPLOITABLE_LEVEL=hardened mcploitable-asi01
mcploitable                          # combined server (all scenarios)
pytest                               # exploit/mitigation test suite
```

> Running outside the container removes the network/filesystem isolation. Only do
> this on a throwaway dev machine.

## How to use it

1. Start the server and connect an MCP client/agent.
2. Call `list_scenarios` for the catalogue, ASI mappings, and exploit hints.
3. Drive the agent (or call tools directly) to exploit a scenario; capture its flag.
4. Check `scoreboard`. Then flip to `hardened` and watch the same attack fail.
5. Read [`docs/SCENARIOS.md`](docs/SCENARIOS.md) for full walkthroughs and the
   mitigation rationale behind each hardened mode.

## Disclaimer

For **authorized** security education, training, and research only. You are
responsible for running it safely and legally. The maintainers accept no
liability for misuse. See [`docs/SCENARIOS.md`](docs/SCENARIOS.md) and `LICENSE`.
