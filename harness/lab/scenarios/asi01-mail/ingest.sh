#!/usr/bin/env bash
# harness/lab/scenarios/asi01-mail/ingest.sh — box-owned ingestion hook.
#
# This scenario's channel is a seeded inbox slot: the student's submitted
# artifact (a plain-text .eml-shaped email — From/To/Subject/Date headers
# plus a body) is copied verbatim into this round's STATE_DIR, where
# mcp.json.tmpl bind-mounts it (read-only) into the mail-assistant container
# and points MAIL_INJECT_PATH at it. mail.py's read_message tool then returns
# it as MSG-2, exactly as it would return any other retrieved inbox message —
# untrusted retrieved content, never a user instruction (see mail.py's module
# docstring for the two-plane rationale).
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
cp "$ARTIFACT" "$STATE_DIR/injected.eml"
