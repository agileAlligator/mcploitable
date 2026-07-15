# Simulations — ASI08, ASI09, ASI10 (`./simulate`)

The five boxes (ASI01–05) and the two later boxes (ASI06 memory poisoning, ASI07
agent-to-agent) are **breakable challenges**: a real incident reduced to a canary
you capture by crafting one untrusted artifact, scored server-side across an
L0→L3 control ladder.

The remaining three OWASP Agentic Top-10 classes are a **different kind of
failure**, and this lab is honest about that rather than forcing a box for them:

| class | why it isn't a breakable box |
|---|---|
| **ASI08 — Denial-of-Wallet** | Success is "burned N tokens / looped forever," not a captured secret. There's no canary and no artifact to craft — it's a resource-metering failure. |
| **ASI09 — Insufficient Monitoring** | This is a *defender-capability gap*, not an attacker-exploitable channel. There's nothing to "break into" — monitoring is what *detects* the other classes. |
| **ASI10 — Rogue Agents / Governance** | The broadest, most organizational class. Any narrow technical carve-out collapses into ASI03 (identity) or ASI07 (authority). |

A two-plane, capture-the-canary CTF is the wrong instrument for these. So instead
of faking a box, they ship as **guided simulations**: run `./simulate`, pick one,
and you get a short narrated run that

1. **shows the failure** with the control OFF — and a **real, measured metric**
   (a live cost counter, an alert count, an authorization decision) makes the
   harm concrete;
2. **asks you** what control stops it;
3. **toggles the fix ON and re-runs** so the same metric visibly changes.

The metrics are computed by real code — a genuine fan-out process whose call
count grows because each call enqueues more (ASI08), a real value scan run over
both the naive action-log and the outbound content (ASI09), a real scope check
(ASI10) — never a hard-coded before/after. Each simulation ends by naming the
failure and its **deterministic** fix, reinforcing the lab's thesis even where
the class isn't a scored box: **the durable defense is a deterministic control (a
budget, effect-based egress monitoring, a policy broker) — not hoping the agent
behaves.**

Notes:
- **Why no live model.** These run as deterministic code, not against a pinned
  agent, on purpose: the before/after is then trustworthy and reproducible — it
  changes because real control code runs, not because of model luck.
- **ASI09 shows one facet.** Effect-based egress monitoring is *a* faithful slice
  of observability, not the whole class (which also spans dwell time, audit
  trails, anomaly detection, and incident response).
- **ASI10 is deliberately a re-use.** Its control is the same
  deterministic-authorization pattern that walls ASI07 (recipient scope) and
  ASI03 (delivery bound to a verified contact), applied to an agent's own
  declared scope. That reuse *is* the governance lesson — and exactly why ASI10
  is a lens over the other classes rather than a separate box.

```
./simulate            # menu
./simulate asi09      # run one directly
```

These are demonstrations, not scored challenges. `./play` is where you attack;
`./simulate` is where you watch a failure and its fix.
