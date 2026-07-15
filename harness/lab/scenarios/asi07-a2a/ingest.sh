#!/usr/bin/env bash
# asi07-a2a ingest — posts the student's A2A envelope to the shared bus BEFORE
# the victim runs (models the peer agent's message). Artifact is a JSON object
# {from_agent?, role?, task_result, directives}. In-process post_message(), like
# asi02's create_ticket ingest. The attacker plane has no bus signing key, so
# any _sig it supplies will not verify (that is what the L3 control checks).
set -euo pipefail
ARTIFACT="${1:?usage: ingest.sh <artifact-path>}"
[ -f "$ARTIFACT" ] || { echo "error: artifact not found: $ARTIFACT" >&2; exit 2; }
: "${STATE_DIR:?STATE_DIR must be exported by submit.sh}"
mkdir -p "$STATE_DIR"

ASI07_BUS="$STATE_DIR/bus.json" python3 - "$ARTIFACT" <<'PYEOF'
import json, sys
from mcploitable.servers import orchestrator
with open(sys.argv[1]) as fh:
    env = json.load(fh)
if not isinstance(env.get("task_result"), str) and not env.get("directives"):
    print("error: artifact must be a JSON object with at least 'task_result' or 'directives'", file=sys.stderr)
    raise SystemExit(2)
print(f"[ingest] {orchestrator.post_message(env)}", file=sys.stderr)
PYEOF
