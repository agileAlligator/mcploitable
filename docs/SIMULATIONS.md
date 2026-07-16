# Simulations — ASI08, ASI09, ASI10 (guided, in `./play`)

The five boxes (ASI01–05) and the two later boxes (ASI06 memory poisoning, ASI07
agent-to-agent) are **breakable challenges**: a real incident reduced to a canary
you capture by crafting one untrusted artifact, scored server-side across an
L0→L3 control ladder.

The remaining three OWASP Agentic Top-10 classes are a **different kind of
failure**, and this lab is honest about that rather than forcing a box for them:

| class | why it isn't a breakable box |
|---|---|
| **ASI08 — Cascading Failures** | The failure is a single fault propagating across a multi-agent chain, not a secret one artifact captures. There's no canary — the harm is systemic, best shown as a before/after on how far a fault spreads. |
| **ASI09 — Human-Agent Trust Exploitation** | The "victim" is a human's decision, made because they over-trust a fluent agent — not a server-side canary. There's nothing to "break into"; the failure is a trust judgement, shown as a decision before/after. |
| **ASI10 — Rogue Agents** | A compromised/misaligned agent deviating from its intended scope — an organizational/authorization failure whose fix is a policy broker, shown as an allow/deny before/after rather than a captured flag. |

A two-plane, capture-the-canary CTF is the wrong instrument for these. So instead
of faking a box, they ship as **guided simulations**: in `./play`, pick one from
the box menu, and you get a short narrated run that

1. **shows the failure** with the control OFF — and a **real, measured metric**
   (how far a fault propagates down an agent chain, whether a human approval
   flips, an authorization decision) makes the harm concrete;
2. **asks you** what control stops it;
3. **toggles the fix ON and re-runs** so the same metric visibly changes.

The metrics are computed by real code — a real multi-agent chain where one
compromised planner step is executed by every downstream agent until a validation
gate contains it (ASI08), a real decision that flips when it's gated on
independent verification of a trusted agent's claim rather than the claim itself
(ASI09), a real scope check (ASI10) — never a hard-coded before/after. Each
simulation ends by naming the failure and its **deterministic** fix, reinforcing
the lab's thesis even where the class isn't a scored box: **the durable defense is
a deterministic control (inter-agent validation / a circuit breaker, independent
verification of an agent's claims, a policy broker) — not hoping the agent
behaves.**

Notes:
- **Why no live model.** These run as deterministic code, not against a pinned
  agent, on purpose: the before/after is then trustworthy and reproducible — it
  changes because real control code runs, not because of model luck.
- **ASI09 shows one facet.** The trust-exploitation surface is broad (social
  engineering, emotional manipulation, over-reliance on a confident agent); the
  sim shows the core failure — a consequential decision keyed on a trusted
  agent's assertion instead of on independent verification.
- **ASI10 is deliberately a re-use.** Its control is the same
  deterministic-authorization pattern that walls ASI07 (recipient scope) and
  ASI03 (delivery bound to a verified contact), applied to an agent's own
  declared scope. That reuse *is* the governance lesson — and exactly why ASI10
  is a lens over the other classes rather than a separate box.

```
./play                # pick a simulation (asi08/asi09/asi10) from the box menu
```

These are demonstrations, not scored challenges. `./play` is where you attack the
seven boxes, and — from the same menu — where you watch these three failures and
their deterministic fixes.
