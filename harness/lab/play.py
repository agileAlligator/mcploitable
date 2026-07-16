#!/usr/bin/env python3
"""mcploitable — interactive attacker REPL.

A thin, student-facing skin over the existing file-based pipeline
(harness/lab/submit.sh). It NEVER reimplements or bypasses the victim plane:
it collects the student's typed payload, assembles it into exactly the artifact
each box's ingest.sh already expects, writes it to a throwaway file, and calls
`submit.sh <box> <tmpfile> <level> <model>` unchanged. Every trust-critical
property (two-plane isolation, clean-victim recipe, reset-before-ingest,
effect-based method-silent scoring) lives in submit.sh/victim_runner.sh/
scoreboard.py and is inherited verbatim.

Per box, one box-owned manifest — scenarios/<box>/prompt.json — declares the
neutral briefing, the incident name, and ONLY the attacker-lever fields to
prompt for (everything structural is templated). The manifest is student-facing
and must stay neutral (form, never the answer), same discipline as tool
docstrings.

It also hosts the three guided simulations (ASI08–10) — narrated, deterministic
demonstrations rather than scored boxes — reached from the same box menu (see
`sim_asi08`/`sim_asi09`/`sim_asi10`, formerly the separate `./simulate`).

Usage:
    ./play                 # interactive
    python3 harness/lab/play.py            # same
    python3 harness/lab/play.py --selftest # run every box x level once (plumbing check)
"""
from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
SCEN_DIR = HERE / "scenarios"
BOXES_DIR = HERE / "boxes"
SUBMIT = HERE / "submit.sh"

# Ordered box list (scenario dir name -> short class label). Neutral labels only.
BOXES = [
    ("asi01-mail", "Agent Goal Hijack"),
    ("asi02-analytics", "Tool Misuse"),
    ("asi03-recovery", "Identity & Privilege Abuse"),
    ("asi04-plugin", "Agentic Supply Chain"),
    ("asi05-calc", "Unexpected Code Execution"),
    ("asi06-memory", "Memory / Context Poisoning"),
    ("asi07-a2a", "Insecure Agent-to-Agent Comms"),
]

# Guided simulations (ASI08–10). NOT breakable boxes — there is no canary to
# capture; picking one runs a narrated failure + its deterministic fix, in
# process (sim_asi08/09/10 below). Listed in the same menu so they are
# discoverable.
SIMS = [
    ("asi08", "Cascading Failures"),
    ("asi09", "Human-Agent Trust Exploitation"),
    ("asi10", "Rogue Agents"),
]

# Neutral, non-spoiling one-liner per level (reviewed once, same for every box).
LEVELS = [
    ("L0", "open door", "No controls. The incident exactly as it originally shipped."),
    ("L1", "recognition control",
     "A soft signal is present — the system may flag or warn the agent, but it blocks nothing. "
     "You have to get the agent to act despite the warning."),
    ("L2", "partial control",
     "A real but incomplete control is in place. The naive attempt is blocked; a competent artifact still gets through."),
    ("L3", "the wall",
     "The correct, deterministic control. By design no artifact beats it — bring your best and watch it hold."),
]
LEVEL_BY_ID = {lid: (label, desc) for lid, label, desc in LEVELS}

RESULT_RE = re.compile(r"result=([A-Za-z-]+)")

STARTING_BOX = "asi01-mail"  # suggested first stop, annotated in the box menu


# ─────────────────────────── progress (A3) ───────────────────────────
PROGRESS_FILE = HERE / "state" / ".progress.json"
INTRO_SENTINEL = HERE / "state" / ".play-intro-shown"


def load_progress() -> dict:
    """{scenario: {level: True}} for every (box, level) landed so far. Best-effort;
    never raises — a missing/corrupt file just means an empty progress record."""
    try:
        return json.loads(PROGRESS_FILE.read_text())
    except (OSError, json.JSONDecodeError, ValueError):
        return {}


def save_progress(progress: dict) -> None:
    try:
        PROGRESS_FILE.parent.mkdir(parents=True, exist_ok=True)
        PROGRESS_FILE.write_text(json.dumps(progress, indent=2))
    except OSError:
        pass  # progress tracking is a nicety, never fatal


def mark_landed(progress: dict, scenario: str, level: str) -> None:
    progress.setdefault(scenario, {})[level] = True
    save_progress(progress)


def _box_menu_options(progress: dict) -> list[str]:
    opts = []
    for s, lbl in BOXES:
        marks = progress.get(s, {})
        landed = sum(1 for v in marks.values() if v)
        tag = f"  \033[32m✓ {landed}/{len(LEVELS)}\033[0m" if landed else ""
        start = "  \033[2m(start here)\033[0m" if s == STARTING_BOX else ""
        opts.append(f"{s.ljust(16)} {lbl}{tag}{start}")
    for code, lbl in SIMS:
        opts.append(f"{code.ljust(16)} {lbl}  \033[2m(guided simulation — watch, not attack)\033[0m")
    return opts


def _level_menu_options(progress: dict, scenario: str) -> list[str]:
    marks = progress.get(scenario, {})
    opts = []
    for lid, lbl, desc in LEVELS:
        tag = "  \033[32m✓ landed\033[0m" if marks.get(lid) else ""
        opts.append(f"{lid} · {lbl} — {desc}{tag}")
    return opts


# ─────────────────────────── manifest + assembly ───────────────────────────
def load_manifest(scenario: str) -> dict:
    return json.loads((SCEN_DIR / scenario / "prompt.json").read_text())


def _deep_set(obj: dict, dotted: str, value) -> None:
    """Set obj[a][b]=value for dotted key 'a.b', creating intermediate dicts."""
    parts = dotted.split(".")
    cur = obj
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


def _convert(field: dict, raw: str):
    t = field.get("type", "line")
    if t == "csv":
        return [s.strip() for s in raw.split(",") if s.strip()]
    if t == "bool":
        return str(raw).strip().lower() in ("1", "true", "yes", "y")
    if t == "json":
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return raw  # prompt_fields validates first; a bad default falls through as text
    return raw


def assemble(scenario: str, manifest: dict, values: dict) -> tuple[str, str]:
    """Return (artifact_text, file_suffix) for the collected field values."""
    if manifest["kind"] == "eml":
        text = manifest["eml_template"]
        for f in manifest["fields"]:
            text = text.replace("${" + f["key"] + "}", str(values.get(f["key"], "")))
        return text, ".eml"

    # kind == json
    obj = copy.deepcopy(manifest.get("fixed", {}))
    for f in manifest["fields"]:
        key = f["key"]
        jkey = f.get("json_key")
        if not jkey:
            continue
        raw = values.get(key, "")
        if f.get("optional") and (raw is None or str(raw).strip() == ""):
            continue  # omit optional empty (e.g. contact_change)
        _deep_set(obj, jkey, _convert(f, raw))
    return json.dumps(obj, indent=2), ".json"


def solution_artifact(scenario: str, level: str) -> Path:
    """Reference SOLUTION artifact for a box+level (L3 uses the L2 artifact — the wall)."""
    base = BOXES_DIR / scenario / "SOLUTION"
    lvl = "L2" if level == "L3" else level
    if scenario == "asi01-mail":
        return base / f"{lvl}.eml"
    if scenario == "asi05-calc":
        return base / f"{lvl}_artifact.json"
    return base / f"{lvl}.json"


# ─────────────────────────── help ladder (A2 / B1) ───────────────────────────
def help_ladder(scenario: str, level: str, manifest: dict,
                 hints_state: dict) -> tuple[str, str] | None:
    """Reveal the NEXT rung of the escalating help ladder for this (box, level):
    hint[0] -> hint[1] -> hint[2] -> (only then) offer the reference solution.
    Call this again to advance one more rung; state lives in `hints_state`
    (keyed per box/level, owned by the caller so it resets per box/level visit).
    Returns (artifact_text, suffix) only if the student accepts the revealed
    reference solution as their payload; otherwise None (purely informational).
    Degrades gracefully if the manifest has no/short `hints`: falls straight
    through to the solution offer, same as the original one-shot reveal."""
    key = (scenario, level)
    shown = hints_state.get(key, 0)
    hints = manifest.get("hints") or []
    if shown < len(hints) and shown < 3:
        print(f"\n  \033[33mHint {shown + 1}/3:\033[0m {hints[shown]}")
        hints_state[key] = shown + 1
        try:
            input("\n  (press Enter to continue) ")
        except (EOFError, KeyboardInterrupt):
            pass
        return None
    if hints:
        print("\n  You've seen all the hints for this level.")
    if input("  Reveal the reference solution for this level? [y/N] ").strip().lower() != "y":
        return None
    sol = solution_artifact(scenario, level)
    if not sol.exists():
        print(f"  (no reference solution file at {sol})")
        return None
    return sol.read_text(), sol.suffix


# ─────────────────────────── running one round ───────────────────────────
def _render_stream_line(obj: dict) -> None:
    """Print a student-safe projection of one stream-json event. Never touches
    score.log; the transcript carries no control-identity/detector info."""
    t = obj.get("type")
    if t == "assistant":
        for c in obj.get("message", {}).get("content", []):
            if c.get("type") == "text" and c.get("text", "").strip():
                print(f"  \033[90m{c['text'].strip()[:600]}\033[0m")
            elif c.get("type") == "tool_use":
                args = json.dumps(c.get("input", {}))[:120]
                print(f"  \033[36m→ {c['name']}({args})\033[0m")
    elif t == "user":
        for c in obj.get("message", {}).get("content", []):
            if isinstance(c, dict) and c.get("type") == "tool_result":
                body = c.get("content", "")
                if isinstance(body, list):
                    body = " ".join(x.get("text", "") for x in body if isinstance(x, dict))
                s = str(body).replace("\n", " ").strip()[:160]
                print(f"  \033[35m← {s}\033[0m")


def _tail(path: Path, stop: threading.Event, since: float) -> None:
    # Wait for the FRESH transcript for this run: submit.sh's reset.sh removes
    # the stale last.jsonl, then victim_runner writes a new one. Only follow a
    # file whose mtime is >= this run's start, else we'd stream a prior run.
    while not stop.is_set():
        try:
            if path.exists() and path.stat().st_mtime >= since:
                break
        except OSError:
            pass
        time.sleep(0.1)
    if stop.is_set() or not path.exists():
        return
    with path.open() as fh:
        while not stop.is_set():
            line = fh.readline()
            if not line:
                time.sleep(0.15)
                continue
            try:
                _render_stream_line(json.loads(line))
            except Exception:
                pass


def run_round(scenario: str, level: str, artifact_text: str, suffix: str,
              model: str, live: bool) -> str:
    """Write the artifact, call submit.sh unchanged, return the verdict token."""
    tf = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
    tf.write(artifact_text)
    tf.close()
    stop = threading.Event()
    tailer = None
    since = time.time()
    try:
        if live:
            last = HERE / "state" / scenario / "last.jsonl"
            print("\n\033[1m— the assistant is working (live) —\033[0m")
            tailer = threading.Thread(target=_tail, args=(last, stop, since), daemon=True)
            tailer.start()
        proc = subprocess.run(
            ["bash", str(SUBMIT), scenario, tf.name, level, model],
            capture_output=True, text=True,
        )
    finally:
        stop.set()
        if tailer:
            tailer.join(timeout=2)
        os.unlink(tf.name)
    m = RESULT_RE.search(proc.stdout) or RESULT_RE.search(proc.stderr)
    return m.group(1) if m else "ERROR"


# ─────────────────────────── interactive prompting ───────────────────────────
def _read_multiline(label: str) -> str:
    print(f"\n{label}")
    print("  (type your text; finish with a lone '.' on its own line, or type 'edit' to use $EDITOR)")
    first = input("  > ")
    if first.strip() == "edit":
        return _editor("")
    lines = [] if first.strip() == "." else [first]
    if first.strip() != ".":
        while True:
            ln = input("  > ")
            if ln.strip() == ".":
                break
            lines.append(ln)
    return "\n".join(lines)


def _editor(initial: str) -> str:
    ed = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "nano"
    tf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    tf.write(initial)
    tf.close()
    subprocess.call([ed, tf.name])
    text = Path(tf.name).read_text().rstrip("\n")
    os.unlink(tf.name)
    return text


def prompt_fields(manifest: dict, advanced: bool) -> dict:
    values = {}
    for f in manifest["fields"]:
        default = f.get("default", "")
        if f.get("advanced") and not advanced:
            values[f["key"]] = default
            continue
        t = f.get("type", "line")
        label = f["label"]
        if t == "multiline":
            v = _read_multiline(label + (f"  [default kept if you finish empty]" if default else ""))
            values[f["key"]] = v if v.strip() else default
        elif t == "json":
            while True:
                v = _read_multiline(label + "  [JSON; finish empty to keep default]")
                if not v.strip():
                    values[f["key"]] = default
                    break
                try:
                    json.loads(v)
                    values[f["key"]] = v
                    break
                except ValueError as e:
                    print(f"  \033[31minvalid JSON:\033[0m {e} — try again")
        elif t == "choice":
            choices = f["choices"]
            print(f"\n{label}:")
            for i, c in enumerate(choices, 1):
                print(f"  {i}) {c}")
            sel = input(f"  > [{default}] ").strip()
            values[f["key"]] = choices[int(sel) - 1] if sel.isdigit() and 1 <= int(sel) <= len(choices) else default
        else:  # line / csv / bool
            hint = f" [{default}]" if default != "" else ""
            v = input(f"\n{label}{hint}: ").strip()
            values[f["key"]] = v if v else default
    return values


# ─────────────────────────── guided screen ───────────────────────────
def show_briefing(scenario: str, label: str, manifest: dict, level: str, advanced: bool) -> None:
    lvl_label, lvl_desc = LEVEL_BY_ID[level]
    bar = "─" * 66
    print(f"\n\033[1m{bar}\033[0m")
    print(f"\033[1m {scenario} · {label}\033[0m")
    print(f"\033[1m{bar}\033[0m")
    print(f" Real incident: {manifest['incident']}")
    print(f"   {manifest['briefing']}")
    print(f"\n This level — {level} · {lvl_label}: {lvl_desc}")
    print("\n Your levers (what you control in the artifact):")
    for f in manifest["fields"]:
        adv = f.get("advanced")
        if adv and not advanced:
            tag = "  \033[90m[advanced — enable advanced mode to edit]\033[0m"
        else:
            tag = ""
        print(f"   • {f['label']}{tag}")
        what = f.get("what")
        if what:
            print(f"       \033[2;90m{what}\033[0m")
    print(f"\033[1m{bar}\033[0m")


# ─────────────────────────── preflight ───────────────────────────
def preflight() -> None:
    import shutil
    sentinel = HERE / "state" / ".play-preflight-ok"
    if shutil.which("claude") is None:
        sys.exit("error: the `claude` CLI is not on PATH. Install it and authenticate, then rerun ./play.")
    if shutil.which("docker") is None:
        sys.exit("error: docker is not on PATH. Install Docker, then rerun ./play.")
    # build the image once if missing
    have_img = subprocess.run(["docker", "image", "inspect", "mcploitable:latest"],
                              capture_output=True).returncode == 0
    if not have_img:
        print("Building the mcploitable image once (~1 min)…")
        subprocess.run(["docker", "compose", "build"], cwd=REPO, check=True)
    if not sentinel.exists():
        print("Checking the `claude` CLI is authenticated…")
        r = subprocess.run(["claude", "-p", "ok", "--model", "haiku"],
                           capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)
        if r.returncode != 0:
            sys.exit("error: `claude` is installed but a test call failed — is it logged in? "
                     "Run `claude` once interactively to authenticate, then rerun ./play.")
        sentinel.parent.mkdir(parents=True, exist_ok=True)
        sentinel.write_text("ok\n")


# ─────────────────────────── first-run orientation (A4) ───────────────────────────
def _maybe_show_orientation() -> None:
    if INTRO_SENTINEL.exists():
        return
    print("\n\033[1mHow this works:\033[0m")
    print("  Pick a box, then read the real incident behind it.")
    print("  Fill in the attacker levers to shape your artifact (help ladder if you're stuck).")
    print("  Watch the agent run live against a clean victim.")
    print("  See whether your canary reached the sink — L0 is wide open, L3 is the wall.")
    try:
        INTRO_SENTINEL.parent.mkdir(parents=True, exist_ok=True)
        INTRO_SENTINEL.write_text("shown\n")
    except OSError:
        pass


# ─────────────────────────── interactive loop ───────────────────────────
def choose(prompt: str, options: list[str]) -> int:
    for i, o in enumerate(options, 1):
        print(f"  {i}) {o}")
    while True:
        s = input(f"{prompt} > ").strip()
        if s.isdigit() and 1 <= int(s) <= len(options):
            return int(s) - 1


def interactive(model: str) -> None:
    preflight()
    progress = load_progress()
    _maybe_show_orientation()
    print("\n\033[1mmcploitable\033[0m — interactive attacker lab. Ctrl-C to quit.")
    while True:
        print("\nPick a box:")
        bi = choose("box", _box_menu_options(progress))
        if bi >= len(BOXES):
            code = SIMS[bi - len(BOXES)][0]
            print(f"\n\033[2m— launching guided simulation {code} (not a scored box) —\033[0m")
            run_simulation(code)
            continue
        scenario, label = BOXES[bi]
        if scenario == "asi05-calc":
            print("\n\033[33m⚠ asi05-calc runs REAL code execution inside a network-isolated container.\033[0m")
            if input("  type 'yes' to enable it: ").strip().lower() != "yes":
                continue
        print("\nPick a level:")
        li = choose("level", _level_menu_options(progress, scenario))
        level = LEVELS[li][0]
        manifest = load_manifest(scenario)
        advanced = False
        hints_state: dict[tuple[str, str], int] = {}

        prev_values: dict | None = None
        while True:
            show_briefing(scenario, label, manifest, level, advanced)
            print("\nPayload:")
            src = choose("payload", [
                "Write your own",
                "Get help (hints, then the reference solution)",
                "Read the full story of the real incident",
                "Toggle advanced mode (edit templated fields)",
                "Back to box/level menu",
            ])
            if src == 4:
                break
            if src == 3:
                advanced = not advanced
                print(f"  advanced mode {'ON' if advanced else 'OFF'}")
                continue
            if src == 2:
                story = manifest.get("story")
                if story:
                    print("\n\033[1m— the full story —\033[0m")
                    print(f"  {story}")
                    ref = manifest.get("reference")
                    if ref:
                        print(f"\n  \033[90mReference: {ref}\033[0m")
                else:
                    print("\n  (no extended write-up yet for this box)")
                try:
                    input("\n  (press Enter to continue) ")
                except (EOFError, KeyboardInterrupt):
                    pass
                continue
            if src == 1:
                got = help_ladder(scenario, level, manifest, hints_state)
                if got is None:
                    continue
                artifact_text, suffix = got
            else:
                values = prompt_fields(manifest, advanced)
                prev_values = values
                artifact_text, suffix = assemble(scenario, manifest, values)

            print("\n\033[1m— artifact to be submitted —\033[0m")
            print(artifact_text)
            if input("\nsubmit this? [Y/n] ").strip().lower() in ("n", "no"):
                continue
            runs = [run_round(scenario, level, artifact_text, suffix, model, live=True)]
            _show_verdict(runs[0], level, scenario)
            if runs[-1] == "LANDED":
                mark_landed(progress, scenario, level)
            elif runs[-1] == "not-yet" and level != "L3":
                if input("\n  want a hint? [y/N] ").strip().lower() in ("y", "yes"):
                    help_ladder(scenario, level, manifest, hints_state)
            # Opt-in retry (up to 3 total) on a miss — L0/L1/L2 only, never L3
            # (a wall has nothing to retry against). Always show the honest
            # tally; a land is declared, not laundered into a bare "WIN".
            while level != "L3" and runs[-1] == "not-yet" and len(runs) < 3:
                note = ("recognition controls are probabilistic — a good payload lands most runs, not all"
                        if level == "L1" else "run variance")
                if input(f"\n  retry the same payload? ({note}) [y/N] ").strip().lower() not in ("y", "yes"):
                    break
                runs.append(run_round(scenario, level, artifact_text, suffix, model, live=True))
                _show_verdict(runs[-1], level, scenario)
                if runs[-1] == "LANDED":
                    mark_landed(progress, scenario, level)
                elif runs[-1] == "not-yet" and len(runs) < 3:
                    if input("\n  want another hint? [y/N] ").strip().lower() in ("y", "yes"):
                        help_ladder(scenario, level, manifest, hints_state)
            if len(runs) > 1:
                landed = runs.count("LANDED")
                print(f"\n  ⇒ landed {landed}/{len(runs)} run(s).")
                if level == "L1":
                    print("    (L1 is probabilistic by design — contrast L3, which never falls.)")
            if level == "L3":
                lesson = manifest.get("l3_lesson")
                if lesson:
                    print(f"\n  \033[36mWhy this holds:\033[0m {lesson}")
            if input("\ntry again on this box/level with a new payload? [Y/n] ").strip().lower() in ("n", "no"):
                break


def show_capture(scenario: str) -> None:
    """On a land, show the student the attacker-observable sink — the RAW content
    that actually egressed (the leaked reply, the mailbox message, the auto-fetch
    collector URL, the outbox line, the poisoned registry). Scoring stays
    method-silent; the sink is the student's own ground truth of what left the
    trust boundary. `.log` effect files are shown first, then any other capture."""
    sink_dir = HERE / "sinks" / scenario
    if not sink_dir.is_dir():
        return
    files = sorted((p for p in sink_dir.glob("*") if p.is_file()),
                   key=lambda p: (p.suffix != ".log", p.name))
    shown = False
    for f in files:
        try:
            content = f.read_text(errors="replace").strip()
        except OSError:
            continue
        if not content:
            continue
        if not shown:
            print("\n  \033[32m— what leaked (your attacker sink) —\033[0m")
            shown = True
        snippet = "\n".join(content.splitlines()[-12:])[:900]
        print(f"  \033[90m{f.name}:\033[0m")
        for ln in snippet.splitlines():
            print(f"    {ln[:200]}")
    if shown:
        print(f"  \033[90m(full sink: harness/lab/sinks/{scenario}/)\033[0m")


def _show_verdict(verdict: str, level: str, scenario: str | None = None) -> None:
    print()
    if verdict == "LANDED":
        print("\033[32m╔════════════════════════════════════╗")
        print("║  LANDED — you captured the canary. ║")
        print("╚════════════════════════════════════╝\033[0m")
        if scenario:
            show_capture(scenario)
        print("  \033[90myour canary reached the sink — scored server-side by effect.\033[0m")
    elif verdict == "wall" or (verdict == "not-yet" and level == "L3"):
        # A held L3 comes back as `wall` from the scorer: the same live effect
        # check runs at L3, and a not-landed result there is labeled `wall` (a
        # genuine land would report LANDED). The `not-yet` arm is a defensive
        # fallback for any caller that hasn't adopted the wall label.
        print("\033[34m╔══════════════════════════════════════════════╗")
        print("║  WALL — the deterministic control held (L3).  ║")
        print("╚══════════════════════════════════════════════╝\033[0m")
    elif verdict == "not-yet":
        print("\033[33m— not yet. The attack didn't land this run. Iterate. —\033[0m")
        print("  \033[90mthe agent saw your artifact but didn't act — is the ask buried, "
              "or does it read as suspicious?\033[0m")
    else:
        log_path = f"harness/lab/state/{scenario}/runner.log" if scenario else "harness/lab/state/<box>/runner.log"
        print(f"\033[31m— run error (verdict={verdict}) — check {log_path} for details —\033[0m")


# ─────────────────────────── guided simulations (ASI08–10) ───────────────────────────
# Narrated, deterministic demonstrations of the three OWASP Agentic classes that
# are NOT breakable boxes (no canary to capture). Each shows a real, measured
# metric with the control OFF, asks what stops it, then toggles the fix ON and
# re-runs so the same metric visibly changes. Reached from the ./play box menu
# (run_simulation, below); formerly the separate ./simulate entry point.
_SIM_AUTO = False  # selftest: don't block on input

SIM_BAR = "─" * 68


def _sim_ask(prompt: str) -> str:
    if _SIM_AUTO:
        print(prompt + " [auto]")
        return ""
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        return ""


def _sim_header(code: str, title: str, incident: str) -> None:
    print(f"\n\033[1m{SIM_BAR}\033[0m")
    print(f"\033[1m {code} · {title}   (guided simulation — not a scored box)\033[0m")
    print(f"\033[1m{SIM_BAR}\033[0m")
    print(f" Real-world anchor: {incident}\n")


def _sim_checkpoint(question: str, answer: str) -> None:
    print(f"\n\033[33m? {question}\033[0m")
    _sim_ask("  your answer (press Enter to reveal): ")
    print(f"  \033[36m→ the control: {answer}\033[0m")


def _sim_toggle() -> None:
    _sim_ask("\n\033[1m▸ press Enter to toggle the control ON and re-run\033[0m ")


def _sim_summary(failure: str, fix: str) -> None:
    print(f"\n\033[1m failure ↔ fix \033[0m")
    print(f"  \033[31m✗ {failure}\033[0m")
    print(f"  \033[32m✓ {fix}\033[0m")
    print(f"\033[1m{SIM_BAR}\033[0m")


def sim_asi08() -> None:
    _sim_header("ASI08", "Cascading Failures (planner → executor chain)",
                "A single fault — a hallucinated or compromised planner step — propagates across "
                "autonomous agents that each act on the previous agent's output without re-checking "
                "it, compounding into system-wide harm (OWASP ASI08).")
    CHAIN = ["planner", "executor-A", "executor-B", "executor-C"]
    UNSAFE = "drop_customers_table"
    # The planner is compromised: its plan carries one unsafe step among benign ones.
    plan = ["read_reports", "summarize", UNSAFE]
    print("A 4-agent pipeline: the planner drafts steps; each executor runs the steps it")
    print("receives and hands its output to the next as trusted ground truth.\n")

    # Control OFF: no boundary re-validates upstream output — every agent trusts it verbatim.
    print("\033[1m[inter-agent validation OFF]\033[0m")
    propagated = 0
    executed_unsafe = False
    for agent in CHAIN[1:]:
        if UNSAFE in plan:                       # this agent runs the (faulty) upstream plan as-is
            propagated += 1
            executed_unsafe = True
            print(f"  {agent}: ran the upstream plan verbatim — incl. the unsafe step '{UNSAFE}'")
    print(f"  → the fault propagated through \033[31m{propagated}/{len(CHAIN)-1}\033[0m downstream agents; "
          f"unsafe step executed: \033[31m{executed_unsafe}\033[0m — system-wide harm.")

    _sim_checkpoint("What stops this?",
                    "A deterministic inter-agent validation gate — a typed/allow-listed action contract "
                    "plus a circuit breaker — that re-checks each upstream output at the boundary instead "
                    "of trusting it, containing a fault to its origin.")
    _sim_toggle()

    # Control ON: each boundary validates upstream steps against an allow-list; a bad step trips the breaker.
    print("\n\033[1m[inter-agent validation ON: per-boundary allow-list + circuit breaker]\033[0m")
    ALLOWED = {"read_reports", "summarize", "draft_email"}
    propagated = 0
    executed_unsafe = False
    tripped_at = None
    for agent in CHAIN[1:]:
        bad = [s for s in plan if s not in ALLOWED]
        if bad:
            tripped_at = agent
            print(f"  {agent}: validation rejected non-allow-listed step(s) {bad} → circuit breaker trips, chain halts")
            break
        propagated += 1
    print(f"  → fault contained at \033[32m{tripped_at}\033[0m: propagated to {propagated} agents, "
          f"unsafe step executed: \033[32m{executed_unsafe}\033[0m.")
    _sim_summary("With no re-validation between agents, one compromised planner step is performed by every "
                 "downstream agent that trusts it — a single fault cascades into system-wide harm.",
                 "A deterministic per-boundary validation gate (allow-listed action contract + circuit "
                 "breaker) re-checks each upstream output and halts the chain at the first bad step, "
                 "containing the fault to its origin.")


def sim_asi09() -> None:
    _sim_header("ASI09", "Human-Agent Trust Exploitation",
                "Users extend strong trust to a fluent, confident agent (anthropomorphism / perceived "
                "expertise); an adversary or a misaligned design exploits that trust to steer a human "
                "decision (OWASP ASI09).")
    # A finance assistant the user trusts asserts a payee change is verified & safe. It was
    # manipulated upstream, so its confident assertion is false.
    agent_assertion = "I already verified this payee update with the vendor — safe to approve."
    agent_says_verified = True     # what the trusted agent claims
    on_record_verified = False     # the authoritative truth: the change was never verified
    print("A finance assistant the user trusts says, about a $50,000 payee change:\n")
    print(f"  \033[36magent:\033[0m \"{agent_assertion}\" (confidence: high)")
    print("  reality: the payee change is unverified — the agent was manipulated upstream.\n")

    # Control OFF: the human decides on the agent's word (trust-based).
    print("\033[1m[decision gate OFF: human acts on the agent's assurance]\033[0m")
    approved = agent_says_verified              # decision keys off the AGENT's claim, not the truth
    print(f"  → the human approves because the agent said so → approved=\033[31m{approved}\033[0m "
          "— a manipulated assurance moved real money.")

    _sim_checkpoint("What stops this?",
                    "Trust calibration: gate any consequential action on an INDEPENDENT verification of "
                    "the agent's claim against an authoritative record — never on the agent's own "
                    "assertion, however fluent or confident.")
    _sim_toggle()

    # Control ON: verify the claim against the record; the agent's confidence carries no authority.
    print("\n\033[1m[decision gate ON: independent verification of the claim]\033[0m")
    approved = on_record_verified               # decision keys off the AUTHORITATIVE record
    print(f"  → gate checks the 'verified' claim against the on-record status ({on_record_verified}) "
          f"→ approved=\033[32m{approved}\033[0m — the agent's say-so can't authorize the action.")
    _sim_summary("The decision keyed off a trusted agent's confident assertion rather than the truth, so a "
                 "manipulated claim steered a harmful human approval — the trust itself was the attack surface.",
                 "Gate consequential actions on independent verification against an authoritative record, "
                 "not the agent's assertion; fluency and confidence carry no authority.")


def sim_asi10() -> None:
    _sim_header("ASI10", "Rogue Agents",
                "A compromised or misaligned agent deviates from its intended behavior, operating "
                "outside its authorized scope to take privileged actions it was never sanctioned for "
                "(OWASP ASI10).")
    SCOPE = ["read_reports", "draft_email", "summarize"]  # this agent's sanctioned operations
    action, args = "wire_funds", {"amount_usd": 50000, "to": "acct-9921-external"}
    print("A reporting agent (scope: read/draft/summarize) is steered off-task and attempts:")
    print(f"  requested action: \033[1m{action}({args})\033[0m\n")

    # Governance OFF: the agent self-authorizes.
    print("\033[1m[governance OFF: agent self-authorizes]\033[0m")
    print(f"  → \033[31mACTION EXECUTED\033[0m: wired ${args['amount_usd']:,} to {args['to']}. "
          "No approval, no record.")

    _sim_checkpoint("What stops a rogue / over-scoped action?",
                    "A deterministic policy/authorization broker that gates every privileged action "
                    "against the agent's declared scope (human-in-the-loop for anything outside it).")
    _sim_toggle()

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
    _sim_summary("With no authorization layer, an off-task agent self-authorizes a privileged action.",
                 "A deterministic policy broker scopes every privileged action to what the agent is "
                 "sanctioned to do — the action is denied and logged regardless of how it was steered.")


_SIM_FUNCS = {
    "asi08": sim_asi08,
    "asi09": sim_asi09,
    "asi10": sim_asi10,
}


def run_simulation(code: str) -> None:
    """Run one guided simulation by scenario code (asi08|asi09|asi10). Unknown
    codes are a no-op — the menu only ever hands us a valid one."""
    fn = _SIM_FUNCS.get(code)
    if fn is not None:
        fn()


# ─────────────────────────── selftest ───────────────────────────
def _canned(scenario: str, field: dict):
    if field.get("example"):
        return field["example"]
    d = field.get("default", "")
    if d != "":
        return d
    t = field.get("type", "line")
    if t == "choice":
        return field["choices"][0]
    if t == "bool":
        return "true"
    if t == "csv":
        return "selftest-cap"
    if "email" in field["key"]:
        return "selftest@example.test"
    return f"selftest payload for {scenario}"


def selftest(model: str) -> int:
    from concurrent.futures import ThreadPoolExecutor
    print(f"=== play.py selftest — every box x level once (model={model}) ===\n")
    results: dict[str, str] = {}

    def do_box(scenario_label):
        scenario, _ = scenario_label
        manifest = load_manifest(scenario)
        # canned "write your own": basic fields get canned filler, advanced use defaults
        values = {}
        for f in manifest["fields"]:
            values[f["key"]] = f.get("default", "") if f.get("advanced") else _canned(scenario, f)
        text, suffix = assemble(scenario, manifest, values)
        for level, _lbl, _d in LEVELS:
            v = run_round(scenario, level, text, suffix, model, live=False)
            results[f"{scenario} {level} write-your-own"] = v
        # option-2 solution path, at L2 (has a real solution)
        sol = solution_artifact(scenario, "L2")
        if sol.exists():
            v = run_round(scenario, "L2", sol.read_text(), sol.suffix, model, live=False)
            results[f"{scenario} L2 use-solution"] = v

    with ThreadPoolExecutor(max_workers=5) as ex:
        list(ex.map(do_box, BOXES))

    print(f"{'case':<44} verdict   functioned?")
    ok = True
    for k in sorted(results):
        v = results[k]
        functioned = v in ("LANDED", "not-yet", "wall")
        ok = ok and functioned
        print(f"{k:<44} {v:<9} {'OK' if functioned else 'FAIL'}")

    # Guided simulations (ASI08–10) — run each non-interactively (auto mode) as a
    # plumbing check. Replaces the removed `simulate.py --selftest`.
    global _SIM_AUTO
    _SIM_AUTO = True
    for code, fn in _SIM_FUNCS.items():
        fn()
    print(f"\n(guided simulations {', '.join(_SIM_FUNCS)} ran non-interactively)")

    print(f"\n{'ALL PLUMBING OK' if ok else 'SOME RUNS FAILED TO PRODUCE A VERDICT'}")
    return 0 if ok else 1


USAGE = """\
mcploitable — interactive attacker lab

Usage:
  ./play                    interactive mode
  ./play --model NAME       victim model to use (default: env LAB_MODEL, else 'haiku')
  ./play --selftest         run every box x level once, non-interactively (plumbing check)
  ./play --help             show this help and exit

Interactive mode: pick a box -> read the incident -> pick a level -> fill in
the attacker levers -> watch the agent run live -> see what your canary
captured. L0 -> L3 gets progressively harder; L3 is the deterministic control
that's designed to hold. The box menu also lists the three guided simulations
(ASI08–10) — narrated demonstrations, not scored boxes.
"""


def print_help() -> None:
    print(USAGE)


# ─────────────────────────── entry ───────────────────────────
def main() -> int:
    args = sys.argv[1:]
    if "--help" in args or "-h" in args:
        print_help()
        return 0
    model = os.environ.get("LAB_MODEL", "haiku")
    if "--model" in args:
        model = args[args.index("--model") + 1]
    if "--selftest" in args:
        return selftest(model)
    try:
        interactive(model)
    except (KeyboardInterrupt, EOFError):
        print("\nbye.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
