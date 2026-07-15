#!/usr/bin/env python3
"""asi05-calc ingestion helper — box-owned, invoked only by ingest.sh.

Makes a RAW stdio MCP tool call against this scenario's own `calc` server
(the same container command mcp.json.tmpl wires for the victim run) to call
upload_dataset with the student's artifact content. This is the attacker
plane: the artifact never passes through the victim agent, and the victim
agent (a separate, later container invocation) only ever sees whatever
upload_dataset's ingestion check accepted.

Usage: ingest_upload.py <artifact-json-path>
Env (exported by submit.sh): REPO, STATE_DIR, SINK_DIR, LAB_LEVEL

Artifact format (student-authored JSON):
  {"rows": [{"col": 123, ...}, ...], "formulas": {"metric_name": "expr", ...}}
The dataset id is fixed by this scenario (not attacker-controlled) so the
pinned victim task can name it directly.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

DATASET_ID = "quarterly-upload"


async def main() -> int:
    if len(sys.argv) != 2:
        print("usage: ingest_upload.py <artifact-json-path>", file=sys.stderr)
        return 2
    artifact_path = sys.argv[1]

    repo = os.environ["REPO"]
    state_dir = os.environ["STATE_DIR"]
    sink_dir = os.environ["SINK_DIR"]
    lab_level = os.environ.get("LAB_LEVEL", "L0")
    score_log = os.environ.get("LAB_SCORE_LOG", os.path.join(state_dir, "score.log"))

    with open(artifact_path) as fh:
        artifact = json.load(fh)
    rows = artifact.get("rows", [])
    formulas = artifact.get("formulas", {})
    if not isinstance(rows, list) or not isinstance(formulas, dict):
        print("error: artifact must have list 'rows' and dict 'formulas'", file=sys.stderr)
        return 2

    # Env MUST be passed as -e flags inside the container: a StdioServerParameters
    # env=... only sets the local docker-CLI process env, which `docker compose run`
    # does NOT forward into the container — so upload_dataset would write its store
    # to the container's ephemeral /tmp default and the dataset would be lost. Mount
    # the shared host dirs at neutral /data + /sink and point the store there so the
    # later victim container (same paths) reads exactly what we upload.
    params = StdioServerParameters(
        command="docker",
        args=[
            "compose", "-f", os.path.join(repo, "docker-compose.yml"),
            "--profile", "danger",
            "run", "--rm", "-T",
            "-v", f"{state_dir}:/data",
            "-v", f"{sink_dir}:/sink",
            "-e", f"LAB_LEVEL={lab_level}",
            "-e", "ASI05_SCORE_LOG=/data/score.log",
            "-e", "ASI05_DATASET_STORE=/data/dataset_store.json",
            "-e", "ASI05_SINK=/sink/outbox.log",
            "calc",
        ],
        env=dict(os.environ),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool(
                "upload_dataset",
                {"dataset_id": DATASET_ID, "rows": rows, "formulas": formulas},
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
