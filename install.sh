#!/usr/bin/env bash
#
# install.sh — register the vulnerable MCP servers into Claude Code.
#
# Run this ON THE TARGET MACHINE, from inside a copy of this repo:
#
#   ./install.sh                  # Docker-isolated servers (default, recommended)
#   ./install.sh --local          # local console scripts (no Docker, unsandboxed)
#   ./install.sh --scope project  # scope: user (default) | project | local
#   ./install.sh --uninstall      # remove the servers and exit
#
# It is idempotent: re-running re-registers cleanly.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE="$REPO_DIR/docker-compose.yml"

# registration name : docker-compose service : local console script
SERVERS=(
  "mail-assistant:mail:mail-assistant"
  "analytics-bi:analytics:analytics-bi"
  "account-recovery:recovery:account-recovery"
  "plugin-hub:toolhub:plugin-hub"
  "calc:calc:calc"
)

MODE="docker"
SCOPE="user"
UNINSTALL=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --local)     MODE="local"; shift ;;
    --docker)    MODE="docker"; shift ;;
    --scope)     SCOPE="${2:?--scope needs a value}"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help)   grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -16; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

err()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo ">> $*"; }

command -v claude >/dev/null 2>&1 || err "the 'claude' CLI is not on PATH. Install Claude Code first."

if [[ "$UNINSTALL" == 1 ]]; then
  for entry in "${SERVERS[@]}"; do
    name="${entry%%:*}"
    claude mcp remove "$name" -s "$SCOPE" 2>/dev/null && info "removed $name" || true
  done
  info "done. Restart Claude Code for the change to take effect."
  exit 0
fi

if [[ "$MODE" == "docker" ]]; then
  command -v docker >/dev/null 2>&1 || err "docker not found. Install it (e.g. 'curl -fsSL https://get.docker.com | sudo sh')."
  docker compose version >/dev/null 2>&1 || err "the 'docker compose' v2 plugin is missing."
  if ! docker info >/dev/null 2>&1; then
    err "cannot reach the Docker daemon. Start it ('sudo systemctl enable --now docker') and ensure your user is in the 'docker' group ('sudo usermod -aG docker \$USER', then re-login)."
  fi
  info "building image (mcploitable:latest)..."
  docker compose -f "$COMPOSE" build
else
  PIP="$(command -v pip3 || command -v pip)" || err "pip not found; install Python 3.10+ and pip."
  info "installing the package (editable) so the console scripts exist..."
  "$PIP" install -e "$REPO_DIR" >/dev/null
fi

for entry in "${SERVERS[@]}"; do
  IFS=: read -r name service script <<<"$entry"
  claude mcp remove "$name" -s "$SCOPE" 2>/dev/null || true
  if [[ "$MODE" == "docker" ]]; then
    claude mcp add "$name" -s "$SCOPE" -- \
      docker compose -f "$COMPOSE" run --rm -T "$service"
  else
    claude mcp add "$name" -s "$SCOPE" -- "$script"
  fi
  info "registered $name ($MODE)"
done

cat <<EOF

All ${#SERVERS[@]} servers registered (scope: $SCOPE, mode: $MODE).

NEXT STEPS:
  1. Restart Claude Code so it picks up the new servers$( [[ "$MODE" == docker ]] && echo " (and your 'docker' group membership)" ).
  2. Verify with:  claude mcp list
  3. After any code change in Docker mode, rebuild:  docker compose -f "$COMPOSE" build
EOF
