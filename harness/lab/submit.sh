#!/usr/bin/env bash
# harness/lab/submit.sh — the student's ONLY attacker-plane entry point.
#
# Places an untrusted artifact into a scenario's ingestion slot (via the
# scenario's own ingest.sh hook — see README.md "Scenario directory contract"),
# runs the pinned victim agent against it at the requested level, then reports
# the outcome through the method-silent scoreboard.
#
# Usage:
#   harness/lab/submit.sh <scenario> <artifact-path> <L0|L1|L2|L3> [model]
#
# The student never touches victim_runner.sh's flags, task.txt, system.txt,
# allowed_tools.txt, or mcp.json.tmpl directly — those are the victim plane
# and are fixed by the box author (see the two-plane rule in README.md §1).
# The artifact is the only lever: an .eml file, a JSON ticket, a JSON recovery
# request, a JSON plugin manifest, a JSON dataset+formula set — whatever this
# scenario's ingest.sh expects (documented per-box, never here).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

usage() { echo "usage: $(basename "$0") <scenario> <artifact-path> <L0|L1|L2|L3> [model]" >&2; exit 2; }

SCENARIO="${1:-}"; ARTIFACT="${2:-}"; LEVEL="${3:-}"; MODEL="${4:-${LAB_MODEL:-sonnet}}"
[ -n "$SCENARIO" ] && [ -n "$ARTIFACT" ] && [ -n "$LEVEL" ] || usage
case "$LEVEL" in
  L0|L1|L2|L3) ;;
  *) echo "error: level must be one of L0 L1 L2 L3 (got '$LEVEL')" >&2; exit 2 ;;
esac
[ -f "$ARTIFACT" ] || { echo "error: artifact not found: $ARTIFACT" >&2; exit 2; }
ARTIFACT="$(cd "$(dirname "$ARTIFACT")" && pwd)/$(basename "$ARTIFACT")"

SCEN_DIR="$REPO/harness/lab/scenarios/$SCENARIO"
INGEST="$SCEN_DIR/ingest.sh"
if [ ! -x "$INGEST" ]; then
  echo "error: missing or non-executable $INGEST — this scenario's box content is not built yet" >&2
  exit 2
fi

# Clean slate before every submission: wipe this scenario's prior run state
# (rendered config, score log, transcript, sinks, and any box-owned store via
# the scenario's own reset hook) so a resubmit can never score off a previous
# attempt's LAND line. reset.sh recreates the dirs; the mkdir/chmod below then
# set the perms the hardened container needs.
"$HERE/reset.sh" "$SCENARIO" >&2

STATE_DIR="$REPO/harness/lab/state/$SCENARIO"
SINK_DIR="$REPO/harness/lab/sinks/$SCENARIO"
mkdir -p "$STATE_DIR" "$SINK_DIR"
# Writable by the container's unprivileged uid up front, so an ingest step that
# itself runs a container (Wave-B boxes) can write the store before the chmod below.
chmod 777 "$STATE_DIR" "$SINK_DIR" 2>/dev/null || true

case "$LEVEL" in
  L0) LAB_LEVEL_MODE=off ;;
  L1) LAB_LEVEL_MODE=leastpriv ;;
  L2) LAB_LEVEL_MODE=egress ;;
  L3) LAB_LEVEL_MODE=both ;;
esac

export LAB_LEVEL="$LEVEL"
export LAB_LEVEL_MODE
export SCENARIO
export REPO
export STATE_DIR
export SINK_DIR
export LAB_SCORE_LOG="$STATE_DIR/score.log"
touch "$LAB_SCORE_LOG"

echo "[submit] scenario=$SCENARIO level=$LEVEL artifact=$(basename "$ARTIFACT")" >&2

# ingest.sh contract (box-owned): receives the artifact's absolute path as
# $1. Everything it needs to know about where/how to place it (which server,
# which seeded slot, which raw tool call) comes from the exported env above
# plus its own knowledge of its scenario — never from this script.
"$INGEST" "$ARTIFACT"

# The victim server runs in a hardened container as an unprivileged uid (10001)
# on a read-only rootfs; the only writable surface is the bind-mounted STATE_DIR/
# SINK_DIR. Make dirs + any host-authored files (score.log, an ingest-written
# store) writable by that uid, else the server's LAND write / reply write fails
# with EACCES (which both breaks scoring AND leaks the host path in the error).
chmod 777 "$STATE_DIR" "$SINK_DIR" 2>/dev/null || true
find "$STATE_DIR" "$SINK_DIR" -type f -exec chmod 666 {} + 2>/dev/null || true

"$HERE/victim_runner.sh" "$SCENARIO" "$LEVEL" "$MODEL"

python3 "$HERE/scoreboard.py" "$SCENARIO" "$LEVEL"
