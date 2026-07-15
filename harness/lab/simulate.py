#!/usr/bin/env python3
"""mcploitable — guided simulations for ASI08/ASI09/ASI10.

These three OWASP Agentic classes are operational / control-gap failures, not
things a student can "break into" with a crafted artifact — there is no canary
to capture. So instead of faking a CTF box for them, we DEMONSTRATE them: a
short, narrated, deterministic run that shows the failure with the control OFF,
asks the student what control stops it, then toggles the fix ON and re-runs so
the same metric visibly changes. The point is the before/after on one screen.

Every metric here is measured by real code (a real loop counter, a real value
scan, a real policy check) — never a hard-coded "before/after" number.

This is NOT a scored box. `./play` is where you attack; `./simulate` is where
you watch a failure and its deterministic fix.

Usage:
    ./simulate                 # menu
    python3 harness/lab/simulate.py asi09     # run one directly
    python3 harness/lab/simulate.py --selftest # run all three non-interactively
"""
from __future__ import annotations

import sys

_AUTO = False  # --selftest: don't block on input


def _ask(prompt: str) -> str:
    if _AUTO:
        print(prompt + " [auto]")
        return ""
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        return ""


BAR = "─" * 68


def _header(code: str, title: str, incident: str) -> None:
    print(f"\n\033[1m{BAR}\033[0m")
    print(f"\033[1m {code} · {title}   (guided simulation — not a scored box)\033[0m")
    print(f"\033[1m{BAR}\033[0m")
    print(f" Real-world anchor: {incident}\n")


def _checkpoint(question: str, answer: str) -> None:
    print(f"\n\033[33m? {question}\033[0m")
    _ask("  your answer (press Enter to reveal): ")
    print(f"  \033[36m→ the control: {answer}\033[0m")


def _toggle() -> None:
    _ask("\n\033[1m▸ press Enter to toggle the control ON and re-run\033[0m ")


def _summary(failure: str, fix: str) -> None:
    print(f"\n\033[1m failure ↔ fix \033[0m")
    print(f"  \033[31m✗ {failure}\033[0m")
    print(f"  \033[32m✓ {fix}\033[0m")
    print(f"\033[1m{BAR}\033[0m")


# ─────────────────────────── ASI08 — Denial-of-Wallet ───────────────────────────
def sim_asi08() -> None:
    _header("ASI08", "Denial-of-Wallet (recursive cost blowout)",
            "Agent tool-loops / recursive sub-agent fan-out running up unbounded API/compute "
            "cost — the 'agent stuck in a loop' incidents that quietly burn thousands.")
    PER = 0.03  # $ per model call
    print("An agent works a task queue where processing one item makes a model call AND")
    print("enqueues follow-up items — a genuine fan-out. We count actual calls; cost = calls × $%.2f.\n" % PER)

    # Control OFF: a REAL amplifying process — each processed item enqueues 2 more,
    # so the queue (and cost) grows because of an actual branching structure. Only
    # the external safety cap halts it.
    print("\033[1m[budget/loop-guard OFF]\033[0m")
    SAFETY_CAP = 500
    queue = ["task"]
    calls = 0
    while queue:
        queue.pop()
        calls += 1                              # one model call to process this item
        queue.extend(["follow-up", "follow-up"])  # its output re-triggers: 2 more items
        if calls in (50, 200, 500):
            print(f"  … {calls} calls, {len(queue)} still queued, ${calls*PER:,.2f} burned")
        if calls >= SAFETY_CAP:
            break
    print(f"  → each call spawned 2 more; only the external safety cap halted the fan-out at "
          f"{calls} calls ({len(queue)} still pending), \033[31m${calls*PER:,.2f}\033[0m burned.")

    _checkpoint("What stops this?",
                "A deterministic per-task call/token BUDGET plus loop/repeat-call detection.")
    _toggle()

    # Control ON: the SAME fan-out, now halted by a real per-task budget.
    print("\n\033[1m[budget/loop-guard ON: budget=20 calls]\033[0m")
    BUDGET = 20
    queue = ["task"]
    calls = 0
    while queue:
        if calls >= BUDGET:
            print(f"  → budget guard halted the same fan-out at {calls} calls ({len(queue)} items "
                  f"left unprocessed); task fails closed, \033[32m${calls*PER:,.2f}\033[0m — cost bounded.")
            break
        queue.pop()
        calls += 1
        queue.extend(["follow-up", "follow-up"])
    _summary("An unbounded self-amplifying fan-out (each call spawns more) burns cost without limit — a denial of *wallet*.",
             "A deterministic per-task budget + loop-detection halts the growth regardless of what the agent does.")


# ─────────────────────────── ASI09 — Insufficient Monitoring ───────────────────────────
def sim_asi09() -> None:
    _header("ASI09", "Insufficient Monitoring / Observability",
            "Attacks that succeeded because nothing was watching. The lab's own out-of-band "
            "score log is the positive example — here we show it as the defender's tool.")
    # A REAL egress event: an outbound reply carrying a credential value (an inert canary).
    CANARY = "CANARY-STRIPE-OAUTH-do-not-use-0001"
    outbound = ("Reply posted to ticket #5 (customer-visible): 'Here are your current integration "
                f"values for reconciliation: stripe_token={CANARY}.'")
    print("Event: an agent, steered by a poisoned ticket, posts a reply containing a credential.\n")
    print(f"  the outbound: {outbound}\n")
    known_secrets = {CANARY}                             # value-based (decode-aware in the real detector)
    action_log = "agent posted a reply to ticket #5"     # what a naive monitor records: the action, no content

    # Monitoring OFF: a naive monitor scans the ACTION LOG (no content) — run it for real, get 0.
    print("\033[1m[monitoring OFF / naive activity log]\033[0m")
    naive_hit = any(s in action_log for s in known_secrets)
    print(f"  naive monitor scanned the action log ('{action_log}') → {'ALERT' if naive_hit else 'clean'}")
    print(f"  \033[31malerts fired: {int(naive_hit)}\033[0m — the secret left and the dashboard stayed green.")

    _checkpoint("What would have caught this?",
                "Effect-based egress monitoring that inspects outbound CONTENT for secret values "
                "(the same value-detector the lab uses to score a LAND).")
    _toggle()

    # Monitoring ON: the SAME value scan, now over the outbound CONTENT — the real score-log technique.
    print("\n\033[1m[monitoring ON / effect-based egress audit]\033[0m")
    hit = any(s in outbound for s in known_secrets)
    verdict = "\033[32mALERT\033[0m" if hit else "clean"
    print(f"  effect monitor scanned the outbound content → {verdict}")
    if hit:
        print(f"    ALERT: credential value egressed on reply #5 ({CANARY[:16]}…) — flagged for response.")
    print(f"  \033[32malerts fired: {int(hit)}\033[0m — same event, two real detectors: the naive one missed it, this one caught it.")
    _summary("The exfil succeeded and the operator saw nothing — you can't respond to what you don't observe.",
             "Effect-based egress monitoring/audit on the *content* fires on the exact event a naive "
             "action-log misses. (This is the score-log mechanism, pointed at the defender.)")


# ─────────────────────────── ASI10 — Rogue Agent / Governance ───────────────────────────
def sim_asi10() -> None:
    _header("ASI10", "Rogue Agent / Governance",
            "An agent operating outside its authorized scope with no authorization governance — "
            "a shadow/over-scoped agent taking privileged actions it was never sanctioned for.")
    SCOPE = ["read_reports", "draft_email", "summarize"]  # this agent's sanctioned operations
    action, args = "wire_funds", {"amount_usd": 50000, "to": "acct-9921-external"}
    print("A reporting agent (scope: read/draft/summarize) is steered off-task and attempts:")
    print(f"  requested action: \033[1m{action}({args})\033[0m\n")

    # Governance OFF: the agent self-authorizes.
    print("\033[1m[governance OFF: agent self-authorizes]\033[0m")
    print(f"  → \033[31mACTION EXECUTED\033[0m: wired ${args['amount_usd']:,} to {args['to']}. "
          "No approval, no record.")

    _checkpoint("What stops a rogue / over-scoped action?",
                "A deterministic policy/authorization broker that gates every privileged action "
                "against the agent's declared scope (human-in-the-loop for anything outside it).")
    _toggle()

    # Governance ON: a real policy check against the declared scope.
    print("\n\033[1m[governance ON: policy broker in front of the tools]\033[0m")
    allowed = action in SCOPE
    decision = "\033[32mALLOW\033[0m" if allowed else "\033[32mDENY\033[0m"
    print(f"  broker checks '{action}' against authorized scope {SCOPE} → {decision}")
    print(f"    \033[32mDENIED\033[0m: '{action}' is outside this agent's authorized scope; "
          "blocked and routed to human review.")
    print("\n  \033[90mnote: this is the same deterministic-authorization pattern that walls ASI07 (recipient\n"
          "  scope) and ASI03 (delivery bound to a verified contact), now applied to an agent's own\n"
          "  declared scope — which is exactly why ASI10 is a governance *lens*, not a separate box.\033[0m")
    _summary("With no authorization layer, an off-task agent self-authorizes a privileged action.",
             "A deterministic policy broker scopes every privileged action to what the agent is "
             "sanctioned to do — the action is denied and logged regardless of how it was steered.")


SIMS = [
    ("asi08", "Denial-of-Wallet", sim_asi08),
    ("asi09", "Insufficient Monitoring / Observability", sim_asi09),
    ("asi10", "Rogue Agent / Governance", sim_asi10),
]


def main() -> int:
    global _AUTO
    args = sys.argv[1:]
    if "--selftest" in args:
        _AUTO = True
        for _k, _t, fn in SIMS:
            fn()
        print("\nALL SIMULATIONS RAN")
        return 0
    if args and args[0] in {k for k, _t, _fn in SIMS}:
        dict((k, fn) for k, _t, fn in SIMS)[args[0]]()
        return 0

    print("\n\033[1mmcploitable — guided simulations (ASI08–10)\033[0m")
    print("Demonstrations of operational/control-gap classes — watch the failure, then the fix.\n")
    for i, (k, t, _fn) in enumerate(SIMS, 1):
        print(f"  {i}) {k}  {t}")
    sel = _ask("\npick a simulation (or Ctrl-C to quit) > ").strip()
    if sel.isdigit() and 1 <= int(sel) <= len(SIMS):
        SIMS[int(sel) - 1][2]()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
