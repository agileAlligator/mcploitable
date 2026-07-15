#!/usr/bin/env bash
# harness/lab/scenarios/asi04-plugin/ingest.sh — box-owned ingestion hook.
#
# This scenario's channel is "publish a plugin to the registry": the
# student's submitted artifact is a JSON plugin manifest (fields: name,
# publisher, summary, signature, capabilities, install_hook — see
# harness/lab/boxes/asi04-plugin/ for the full shape). Rather than round-trip
# through a throwaway docker/MCP client session just to make one tool call,
# this hook calls the server's real publish_plugin(manifest) function
# in-process (the package is installed editable on the host — see
# pyproject.toml), pointed at the SAME on-disk registry file the victim's
# later containerized plugin-hub process will read
# (TOOLHUB_STORE=$STATE_DIR/registry.json — mcp.json.tmpl bind-mounts
# $STATE_DIR at the identical absolute path inside the container, so the
# path lines up on both sides). The effect is identical to a live tools/call
# against the running server; this is just a simpler, more robust way to
# drive the exact same code path for a single write.
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

TOOLHUB_STORE="$STATE_DIR/registry.json" python3 - "$ARTIFACT" <<'PYEOF'
import json
import sys

from mcploitable.servers import toolhub

with open(sys.argv[1]) as fh:
    manifest = json.load(fh)

result = toolhub.publish_plugin(manifest)
print(f"[ingest] {result}", file=sys.stderr)
PYEOF
