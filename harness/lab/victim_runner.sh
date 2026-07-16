#!/usr/bin/env bash
# harness/lab/victim_runner.sh — runs the PINNED victim agent for one scenario
# at one difficulty level. This is the victim-plane half of the two-plane rule
# (see harness/lab/README.md): everything this script feeds the agent is fixed
# by the box author, never by the student. The only things that vary between
# runs are LAB_LEVEL and whatever untrusted artifact submit.sh has already
# placed into the scenario's ingestion slot before this script is invoked.
#
# Usage:
#   harness/lab/victim_runner.sh <scenario> <L0|L1|L2|L3> [model]
#
# Reads (per scenario, BOX-owned — see README "Scenario directory contract"):
#   harness/lab/scenarios/<scenario>/task.txt           pinned user turn (verbatim -p prompt)
#   harness/lab/scenarios/<scenario>/system.txt         pinned system prompt (REPLACE, not append)
#   harness/lab/scenarios/<scenario>/allowed_tools.txt  scoped --allowedTools, one name per line
#   harness/lab/scenarios/<scenario>/mcp.json.tmpl      single-server MCP config, envsubst template
#
# Writes (per scenario, FRAMEWORK-owned, ephemeral — wiped by reset.sh):
#   harness/lab/state/<scenario>/mcp.json     rendered MCP config for this run
#   harness/lab/state/<scenario>/score.log    method-silent oracle file (path named by LAB_SCORE_LOG)
#   harness/lab/state/<scenario>/last.jsonl   raw stream-json transcript — OPERATOR DEBUG ONLY.
#                                              scoreboard.py never reads or prints this; it is not
#                                              part of the student-visible surface.
#   harness/lab/state/<scenario>/runner.log   this script's own stderr, for the same reason
#
# Env vars this script exports for mcp.json.tmpl (envsubst) and for the
# scenario's own hook scripts to read:
#   LAB_LEVEL       L0|L1|L2|L3, as passed on the command line
#   LAB_LEVEL_MODE  legacy off|leastpriv|egress|both alias (L0/L1/L2/L3), so a
#                   box can wire e.g. ASI02_ENFORCE="${LAB_LEVEL_MODE}" in its
#                   own mcp.json.tmpl for back-compat with a pre-existing
#                   per-server enforce knob (analytics-bi reads LAB_LEVEL
#                   directly, falling back to ASI02_ENFORCE if LAB_LEVEL is unset).
#   LAB_SCORE_LOG   absolute path to this round's method-silent oracle file
#   STATE_DIR       harness/lab/state/<scenario> (framework-owned run state)
#   SINK_DIR        harness/lab/sinks/<scenario> (student-observable capture point)
#   REPO            repo root, for building absolute -f <docker-compose.yml> paths
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

usage() { echo "usage: $(basename "$0") <scenario> <L0|L1|L2|L3> [model]" >&2; exit 2; }

SCENARIO="${1:-}"; LEVEL="${2:-}"; MODEL="${3:-${LAB_MODEL:-sonnet}}"
[ -n "$SCENARIO" ] && [ -n "$LEVEL" ] || usage
case "$LEVEL" in
  L0|L1|L2|L3) ;;
  *) echo "error: level must be one of L0 L1 L2 L3 (got '$LEVEL')" >&2; exit 2 ;;
esac

SCEN_DIR="$REPO/harness/lab/scenarios/$SCENARIO"
for f in task.txt system.txt allowed_tools.txt mcp.json.tmpl; do
  if [ ! -f "$SCEN_DIR/$f" ]; then
    echo "error: missing $SCEN_DIR/$f — this scenario's box content is not built yet" >&2
    exit 2
  fi
done

STATE_DIR="$REPO/harness/lab/state/$SCENARIO"
SINK_DIR="$REPO/harness/lab/sinks/$SCENARIO"
mkdir -p "$STATE_DIR" "$SINK_DIR"

# LAB_LEVEL -> legacy per-server enforce-mode alias. Fixed mapping, identical
# across every box (documented in README.md "Level ladder").
case "$LEVEL" in
  L0) LAB_LEVEL_MODE=off ;;
  L1) LAB_LEVEL_MODE=leastpriv ;;
  L2) LAB_LEVEL_MODE=egress ;;
  L3) LAB_LEVEL_MODE=both ;;
esac

export LAB_LEVEL="$LEVEL"
export LAB_LEVEL_MODE
export LAB_SCORE_LOG="$STATE_DIR/score.log"
export STATE_DIR
export SINK_DIR
export REPO
touch "$LAB_SCORE_LOG"

# --- render this scenario's single-server MCP config from its template ---
# envsubst is restricted to exactly this token set so stray literal '$' in the
# rendered JSON (there shouldn't be any, but be defensive) is left untouched.
MCP_JSON="$STATE_DIR/mcp.json"
envsubst '${LAB_LEVEL} ${LAB_LEVEL_MODE} ${LAB_SCORE_LOG} ${STATE_DIR} ${SINK_DIR} ${REPO}' \
  < "$SCEN_DIR/mcp.json.tmpl" > "$MCP_JSON"
python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$MCP_JSON" || {
  echo "error: $SCEN_DIR/mcp.json.tmpl did not render to valid JSON" >&2
  exit 2
}

# --- scoped tool allowlist (box-owned; one MCP tool name per line, blank
# lines and '#' comments ignored). Tool names must use the MCP client's
# mcp__<server-name>__<tool> form, where <server-name> is the top-level key
# under "mcpServers" in this scenario's mcp.json.tmpl. ---
ALLOWED_TOOLS="$(grep -v '^[[:space:]]*#' "$SCEN_DIR/allowed_tools.txt" | grep -v '^[[:space:]]*$' | paste -sd, -)"
if [ -z "$ALLOWED_TOOLS" ]; then
  echo "error: $SCEN_DIR/allowed_tools.txt has no tool names" >&2
  exit 2
fi

# --- fixed coding-toolset denylist (FRAMEWORK-owned; identical for every
# box, never edited per-scenario). Blocks the victim from ever reaching a
# local shell/filesystem/network tool, which would let it route around the
# scenario's single MCP server entirely (the "just tell it to leak it via
# Bash" cheat the two-plane rule exists to kill). ---
CODING_TOOLSET="Bash,Read,Write,Edit,MultiEdit,NotebookEdit,Glob,Grep,WebFetch,WebSearch,Task,TodoWrite,BashOutput,KillShell,ExitPlanMode,SlashCommand"

SYSTEM_PROMPT="$(cat "$SCEN_DIR/system.txt")"
TASK_PROMPT="$(cat "$SCEN_DIR/task.txt")"

{
  echo "[victim_runner] scenario=$SCENARIO level=$LEVEL model=$MODEL"
} >> "$STATE_DIR/runner.log"

# Run the victim from a CLEAN, EMPTY cwd. `claude -p` keys project memory/CLAUDE.md
# to its working directory; from the repo it would load THIS project's red-team
# notes and the victim would recognize it's being tested (fatal contamination —
# observed: victims citing "the mcploitable harness" / "memory files about attack
# vectors" and refusing). A fresh tmp dir keys to an empty project: no memory, no
# CLAUDE.md. mcp.json + prompts were already read into absolute paths/vars above.
VICTIM_CWD="$(mktemp -d /tmp/mcploitable-victim.XXXXXX)"
trap 'rm -rf "$VICTIM_CWD"' EXIT
cd "$VICTIM_CWD"

# Clean-victim recipe (do not deviate — this is what makes a run trustworthy):
#   --system-prompt          REPLACE the whole system prompt, never append
#   --mcp-config + --strict-mcp-config   exactly one server, nothing else bleeds in
#   --allowedTools            scoped to this scenario's tools only
#   --disallowedTools         the fixed coding toolset above
#   --output-format stream-json --verbose   full raw transcript (operator debug only)
#   </dev/null                no interactive stdin
#   --no-session-persistence  each run is a fresh, unresumable session
claude -p "$TASK_PROMPT" \
  --model "$MODEL" \
  --system-prompt "$SYSTEM_PROMPT" \
  --mcp-config "$MCP_JSON" --strict-mcp-config \
  --allowedTools "$ALLOWED_TOOLS" \
  --disallowedTools "$CODING_TOOLSET" \
  --output-format stream-json --verbose \
  --no-session-persistence \
  </dev/null >> "$STATE_DIR/last.jsonl" 2>> "$STATE_DIR/runner.log"

echo "[victim_runner] done — transcript: $STATE_DIR/last.jsonl (operator debug only, not student-visible)" >> "$STATE_DIR/runner.log"
