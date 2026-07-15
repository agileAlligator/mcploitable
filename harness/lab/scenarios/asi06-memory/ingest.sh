#!/usr/bin/env bash
# asi06-memory ingest — plants the student's memory entry into the durable
# store BEFORE the victim runs (the "prior session"). The artifact is a JSON
# object {memory, prior_context?, source?}. memory.remember() stamps the real
# origin ("external") in code; the self-declared source is retained as the L2
# lever. Same in-process pattern as asi02's create_ticket ingest.
set -euo pipefail
ARTIFACT="${1:?usage: ingest.sh <artifact-path>}"
[ -f "$ARTIFACT" ] || { echo "error: artifact not found: $ARTIFACT" >&2; exit 2; }
: "${STATE_DIR:?STATE_DIR must be exported by submit.sh}"
mkdir -p "$STATE_DIR"

ASI06_STORE="$STATE_DIR/memory.json" python3 - "$ARTIFACT" <<'PYEOF'
import json, sys
from mcploitable.servers import memory
with open(sys.argv[1]) as fh:
    art = json.load(fh)
note = art.get("memory")
if not isinstance(note, str) or not note.strip():
    print("error: artifact must be a JSON object with a non-empty string 'memory'", file=sys.stderr)
    raise SystemExit(2)
result = memory.remember(note, str(art.get("prior_context", "")), str(art.get("source", "import")))
print(f"[ingest] {result}", file=sys.stderr)
PYEOF
