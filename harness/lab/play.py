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
    print("\n\033[1mmcploitable\033[0m — interactive attacker lab. Ctrl-C to quit.")
    while True:
        print("\nPick a box:")
        bi = choose("box", [f"{s.ljust(16)} {lbl}" for s, lbl in BOXES])
        scenario, label = BOXES[bi]
        if scenario == "asi05-calc":
            print("\n\033[33m⚠ asi05-calc runs REAL code execution inside a network-isolated container.\033[0m")
            if input("  type 'yes' to enable it: ").strip().lower() != "yes":
                continue
        print("\nPick a level:")
        li = choose("level", [f"{lid} · {lbl} — {desc}" for lid, lbl, desc in LEVELS])
        level = LEVELS[li][0]
        manifest = load_manifest(scenario)
        advanced = False

        prev_values: dict | None = None
        while True:
            show_briefing(scenario, label, manifest, level, advanced)
            print("\nPayload:")
            src = choose("payload", [
                "Write your own",
                "Use the reference solution (reveals the intended answer)",
                "Toggle advanced mode (edit templated fields)",
                "Back to box/level menu",
            ])
            if src == 3:
                break
            if src == 2:
                advanced = not advanced
                print(f"  advanced mode {'ON' if advanced else 'OFF'}")
                continue
            if src == 1:
                if input("  This reveals the intended answer for this level. Continue? [y/N] ").strip().lower() != "y":
                    continue
                sol = solution_artifact(scenario, level)
                if not sol.exists():
                    print(f"  (no reference solution file at {sol})")
                    continue
                artifact_text = sol.read_text()
                suffix = sol.suffix
            else:
                values = prompt_fields(manifest, advanced)
                prev_values = values
                artifact_text, suffix = assemble(scenario, manifest, values)

            print("\n\033[1m— artifact to be submitted —\033[0m")
            print(artifact_text)
            if input("\nsubmit this? [Y/n] ").strip().lower() in ("n", "no"):
                continue
            runs = [run_round(scenario, level, artifact_text, suffix, model, live=True)]
            _show_verdict(runs[0], level)
            # Opt-in retry (up to 3 total) on a miss — L0/L1/L2 only, never L3
            # (a wall has nothing to retry against). Always show the honest
            # tally; a land is declared, not laundered into a bare "WIN".
            while level != "L3" and runs[-1] == "not-yet" and len(runs) < 3:
                note = ("recognition controls are probabilistic — a good payload lands most runs, not all"
                        if level == "L1" else "run variance")
                if input(f"\n  retry the same payload? ({note}) [y/N] ").strip().lower() not in ("y", "yes"):
                    break
                runs.append(run_round(scenario, level, artifact_text, suffix, model, live=True))
                _show_verdict(runs[-1], level)
            if len(runs) > 1:
                landed = runs.count("LANDED")
                print(f"\n  ⇒ landed {landed}/{len(runs)} run(s).")
                if level == "L1":
                    print("    (L1 is probabilistic by design — contrast L3, which never falls.)")
            if input("\ntry again on this box/level with a new payload? [Y/n] ").strip().lower() in ("n", "no"):
                break


def _show_verdict(verdict: str, level: str) -> None:
    print()
    if verdict == "LANDED":
        print("\033[32m╔════════════════════════════════════╗")
        print("║  LANDED — you captured the canary. ║")
        print("╚════════════════════════════════════╝\033[0m")
    elif verdict == "wall":
        print("\033[34m╔══════════════════════════════════════════════╗")
        print("║  WALL — the deterministic control held (L3).  ║")
        print("╚══════════════════════════════════════════════╝\033[0m")
    elif verdict == "not-yet":
        print("\033[33m— not yet. The attack didn't land this run. Iterate. —\033[0m")
    else:
        print(f"\033[31m— run error (verdict={verdict}); see harness/lab/state/ for details —\033[0m")


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
    print(f"\n{'ALL PLUMBING OK' if ok else 'SOME RUNS FAILED TO PRODUCE A VERDICT'}")
    return 0 if ok else 1


# ─────────────────────────── entry ───────────────────────────
def main() -> int:
    model = os.environ.get("LAB_MODEL", "haiku")
    args = sys.argv[1:]
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
