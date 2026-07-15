#!/usr/bin/env bash
# harness/lab/scenarios/asi05-calc/ingest.sh — the ONLY way this scenario's
# artifact reaches the calc server. Makes a raw stdio MCP tool call (via
# ingest_upload.py) against a throwaway `calc` container instance to upload
# the student's dataset — entirely separate from the victim agent's own,
# later container run. See harness/lab/README.md §1 (two-plane rule) and §6.
#
# Usage: ingest.sh <absolute-artifact-json-path>
# Env (exported by submit.sh): LAB_LEVEL, LAB_LEVEL_MODE, LAB_SCORE_LOG,
#   STATE_DIR, SINK_DIR, SCENARIO, REPO
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTIFACT="${1:?usage: ingest.sh <artifact-json-path>}"

python3 "$HERE/ingest_upload.py" "$ARTIFACT"
