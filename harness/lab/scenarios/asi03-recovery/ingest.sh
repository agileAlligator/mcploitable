#!/usr/bin/env bash
# harness/lab/scenarios/asi03-recovery/ingest.sh — box-owned ingestion hook.
#
# This scenario's channel is the recovery-request queue itself: the
# student's submitted artifact (a JSON recovery request — see ingest.py's
# module docstring for the exact schema) is filed via account-recovery's own
# tool functions, called directly in-process against this round's
# STATE_DIR/SINK_DIR-backed store and mailbox — the same on-disk state the
# victim's later `docker compose run` container reads/writes through its own
# bind mounts (see mcp.json.tmpl). See harness/lab/README.md §6 for the
# ingest.sh contract in general.
#
# Usage (invoked by submit.sh, never directly by the student):
#   ingest.sh <absolute-artifact-path>
# Env already exported by submit.sh: LAB_LEVEL, LAB_LEVEL_MODE, LAB_SCORE_LOG,
# STATE_DIR, SINK_DIR, SCENARIO, REPO.
set -euo pipefail

ARTIFACT="${1:?usage: ingest.sh <artifact-path>}"
[ -f "$ARTIFACT" ] || { echo "error: artifact not found: $ARTIFACT" >&2; exit 2; }
: "${STATE_DIR:?STATE_DIR must be exported by submit.sh}"
: "${SINK_DIR:?SINK_DIR must be exported by submit.sh}"
: "${REPO:?REPO must be exported by submit.sh}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PYTHONPATH="$REPO/src:${PYTHONPATH:-}" python3 "$HERE/ingest.py" "$ARTIFACT"
