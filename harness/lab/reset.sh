#!/usr/bin/env bash
# harness/lab/reset.sh — per-round clean slate.
#
# Wipes the framework-owned run state (rendered mcp.json, the LAB_SCORE_LOG
# oracle file, transcripts) and the student-observable sinks for one
# scenario, or every scenario under harness/lab/scenarios/ if none is given.
# Also invokes the scenario's own reset.sh hook, if it supplies one, for any
# box-owned state that cannot be expressed as a path under STATE_DIR/SINK_DIR
# (an external on-disk store, a plugin registry, a mutable recovery-contact
# record, etc. — see README.md "Scenario directory contract").
#
# Usage:
#   harness/lab/reset.sh              # reset every scenario
#   harness/lab/reset.sh <scenario>   # reset just one
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
SCENARIOS_DIR="$REPO/harness/lab/scenarios"
STATE_ROOT="$REPO/harness/lab/state"
SINKS_ROOT="$REPO/harness/lab/sinks"

reset_one() {
  local scenario="$1"
  local state_dir="$STATE_ROOT/$scenario"
  local sink_dir="$SINKS_ROOT/$scenario"

  echo "[reset] $scenario" >&2
  rm -rf "$state_dir" "$sink_dir"
  mkdir -p "$state_dir" "$sink_dir"

  local hook="$SCENARIOS_DIR/$scenario/reset.sh"
  if [ -x "$hook" ]; then
    LAB_LEVEL="" LAB_SCORE_LOG="$state_dir/score.log" \
      STATE_DIR="$state_dir" SINK_DIR="$sink_dir" REPO="$REPO" SCENARIO="$scenario" \
      "$hook"
  fi
}

TARGET="${1:-}"
mkdir -p "$STATE_ROOT" "$SINKS_ROOT"

if [ -n "$TARGET" ]; then
  [ -d "$SCENARIOS_DIR/$TARGET" ] || {
    echo "error: no such scenario dir: $SCENARIOS_DIR/$TARGET" >&2
    exit 2
  }
  reset_one "$TARGET"
else
  if [ -d "$SCENARIOS_DIR" ]; then
    shopt -s nullglob
    for d in "$SCENARIOS_DIR"/*/; do
      reset_one "$(basename "$d")"
    done
    shopt -u nullglob
  else
    echo "[reset] no harness/lab/scenarios/ dir yet — nothing to reset" >&2
  fi
fi
