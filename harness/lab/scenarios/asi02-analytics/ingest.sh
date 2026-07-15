#!/usr/bin/env bash
# harness/lab/scenarios/asi02-analytics/ingest.sh — box-owned ingestion hook.
#
# This scenario's channel is "file a support ticket": the student's submitted
# artifact is a JSON object with string fields customer/subject/body (the
# ticket the intake side of the real two-agent deployment would have logged
# via create_ticket — see harness/lab/boxes/asi02-analytics/ for the full
# shape and reference tickets). Rather than round-trip through a throwaway
# docker/MCP client session just to make one tool call, this hook calls the
# server's real create_ticket(customer, subject, body) function in-process
# (the package is installed editable on the host — see pyproject.toml),
# pointed at the SAME on-disk store file the victim's later containerized
# analytics-bi process will read (ASI02_STORE=$STATE_DIR/store.json —
# mcp.json.tmpl bind-mounts $STATE_DIR at the identical absolute path inside
# the container, so the path lines up on both sides). The effect is
# identical to a live tools/call against the running server; this is just a
# simpler, more robust way to drive the exact same code path for a single
# write.
#
# Usage (invoked by submit.sh, never directly by the student):
#   ingest.sh <absolute-artifact-path>
# Env already exported by submit.sh: LAB_LEVEL, LAB_LEVEL_MODE, LAB_SCORE_LOG,
# STATE_DIR, SINK_DIR, SCENARIO, REPO.
set -euo pipefail

ARTIFACT="${1:?usage: ingest.sh <artifact-path>}"
[ -f "$ARTIFACT" ] || { echo "error: artifact not found: $ARTIFACT" >&2; exit 2; }
: "${STATE_DIR:?STATE_DIR must be exported by submit.sh}"

mkdir -p "$STATE_DIR"

ASI02_STORE="$STATE_DIR/store.json" python3 - "$ARTIFACT" <<'PYEOF'
import json
import sys

from mcploitable.servers import analytics

with open(sys.argv[1]) as fh:
    ticket = json.load(fh)

for field in ("customer", "subject", "body"):
    if not isinstance(ticket.get(field), str):
        print(
            f"error: artifact must be a JSON object with string fields "
            f"customer/subject/body (missing/invalid {field!r})",
            file=sys.stderr,
        )
        raise SystemExit(2)

result = analytics.create_ticket(ticket["customer"], ticket["subject"], ticket["body"])
print(f"[ingest] {result}", file=sys.stderr)
PYEOF
