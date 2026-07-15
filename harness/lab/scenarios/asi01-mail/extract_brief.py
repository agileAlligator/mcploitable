#!/usr/bin/env python3
"""harness/lab/scenarios/asi01-mail/extract_brief.py

Extract the pinned agent's final answer text from a `claude -p --output-format
stream-json --verbose` transcript (one JSON object per line, written by
victim_runner.sh to STATE_DIR/last.jsonl). Used only by this scenario's
oracle.sh, on the host, after a round has completed — never during a live
agent turn, and its own stdout is discarded by everything downstream of it
except oracle.sh's own redirect into a temp file. Nothing it does is
student-visible.

The CLI's final `{"type": "result", "subtype": "success", "result": "..."}`
event carries the complete final answer text; that is what a real client
would render. Falls back to concatenating the last assistant text blocks if
no such event is present (e.g. a run that errored before completion).
"""

from __future__ import annotations

import json
import sys


def final_text(transcript_path: str) -> str:
    last_result: str | None = None
    last_assistant_text = ""
    try:
        with open(transcript_path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if ev.get("type") == "result" and isinstance(ev.get("result"), str):
                    last_result = ev["result"]
                elif ev.get("type") == "assistant":
                    msg = ev.get("message") or {}
                    parts = msg.get("content") or []
                    text = "".join(
                        p.get("text", "")
                        for p in parts
                        if isinstance(p, dict) and p.get("type") == "text"
                    )
                    if text:
                        last_assistant_text = text
    except OSError:
        return ""
    return last_result if last_result is not None else last_assistant_text


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: extract_brief.py <transcript.jsonl>", file=sys.stderr)
        raise SystemExit(2)
    sys.stdout.write(final_text(sys.argv[1]))
