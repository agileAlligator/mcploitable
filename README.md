# mcploitable

**A collection of deliberately vulnerable MCP servers — the "Metasploitable" of
the Model Context Protocol.**

mcploitable is a set of ordinary-looking [MCP](https://modelcontextprotocol.io)
servers — a helpdesk, an analytics assistant, a plugin manager, a calculator —
that each quietly harbour one real vulnerability. Point an agent at them in a
lab and watch how agentic systems get compromised. The flaws map to the **[OWASP
Top 10 for Agentic Applications (ASI) 2026](https://genai.owasp.org)**.

> [!WARNING]
> These servers are **intentionally vulnerable**. One achieves **real code
> execution**. Run them **only** inside the bundled, network-isolated Docker
> containers. **Never** expose them to an untrusted network, and **never**
> connect them to real credentials, data, or systems. Everything they "leak" is
> fake.

## Design: the servers don't know they're targets

Unlike a CTF range, these servers carry **no self-awareness**: no scoreboard, no
capture flags, no "exploit hint" tool, no insecure/hardened switch. Each presents
as a mundane, believable tool with innocent descriptions. The vulnerability is
**latent** — you discover and trigger it, and success is observed by its *effect*
(data that actually leaves, code that actually runs), not credited by the server.
The only tell is the `ASI##` tag in each server's name, kept so you can map a
server to its vulnerability class.

| Server | Looks like | Latent vulnerability (ASI) |
|--------|-----------|----------------------------|
| `helpdesk-ASI01` | Customer-support assistant | **ASI01** Agent Goal Hijack — a ticket body smuggles instructions (indirect prompt injection) |
| `analytics-ASI02` | NL analytics over a database | **ASI02** Tool Misuse — `run_query` takes arbitrary SQL; chain with email to exfiltrate |
| `ops-assistant-ASI03` | Internal ops helper | **ASI03** Identity & Privilege Abuse — confused deputy runs privileged actions on a cached cred |
| `toolhub-ASI04` | Plugin/tool manager | **ASI04** Supply Chain — poisoned tool description + unsigned install-hook backdoor |
| `calc-service-ASI05` | Calculator / data analysis | **ASI05** Unexpected Code Execution — `eval`/`exec` on input |

See [`docs/SERVERS.md`](docs/SERVERS.md) for each server's tools, where the flaw
lives, and how to observe a successful exploit.

## Quick start (Docker — recommended)

```bash
docker compose build
docker compose run --rm -T helpdesk     # one isolated stdio server per vuln
docker compose run --rm -T calc         # … swap the service: helpdesk|analytics|ops|toolhub|calc
```

Each compose service runs with **no network**, a **read-only filesystem**,
**dropped capabilities**, and as a **non-root user** — so even the real code
execution stays boxed inside the container.

## Register in Claude Code (or any MCP client)

The bundled `install.sh` builds the image and registers all five servers:

```bash
./install.sh                 # Docker-isolated (recommended)
./install.sh --local         # local console scripts, no Docker (unsandboxed)
./install.sh --uninstall     # remove them
```

Or wire a client up by hand — one container per server:

```json
{
  "mcpServers": {
    "helpdesk-ASI01": {
      "command": "docker",
      "args": ["compose", "-f", "/path/to/mcploitable/docker-compose.yml",
               "run", "--rm", "-T", "helpdesk"]
    }
  }
}
```

## Local run (development only)

```bash
pip install -e ".[dev]"
helpdesk-ASI01                                    # a single stdio server
PYTHONPATH=src python3 examples/play.py helpdesk  # drive it in-process, no client
pytest                                            # PoC test suite
```

> Running outside the container removes the network/filesystem isolation. Only do
> this on a throwaway dev machine.

## Disclaimer

For **authorized** security education, training, and research only. You are
responsible for running it safely and legally. The maintainers accept no
liability for misuse. See [`docs/SERVERS.md`](docs/SERVERS.md) and `LICENSE`.
