#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/run-stack.sh start     Start Node
  ./scripts/run-stack.sh rebuild   Rebuild and start Node image
  ./scripts/run-stack.sh recreate  Force recreate Node
  ./scripts/run-stack.sh stop      Stop Node
  ./scripts/run-stack.sh down      Remove containers/networks but keep data
  ./scripts/run-stack.sh restart   Restart Node
  ./scripts/run-stack.sh status    Show Node status

Environment:
  Node reads env/node.env and optional env/node.local.env.
USAGE
}

case "${1:-}" in
  start|up)
    "$SCRIPT_DIR/run-node.sh" up -d
    ;;
  rebuild|build)
    "$SCRIPT_DIR/run-node.sh" up -d --build
    ;;
  recreate|force-recreate)
    "$SCRIPT_DIR/run-node.sh" up -d --force-recreate
    ;;
  stop)
    "$SCRIPT_DIR/run-node.sh" stop
    ;;
  down)
    "$SCRIPT_DIR/run-node.sh" down
    ;;
  restart)
    "$SCRIPT_DIR/run-node.sh" stop
    "$SCRIPT_DIR/run-node.sh" up -d
    ;;
  status|ps)
    echo "Node:"
    "$SCRIPT_DIR/run-node.sh" ps
    ;;
  ""|-h|--help|help)
    usage
    ;;
  *)
    echo "Unknown command: $1" >&2
    usage >&2
    exit 2
    ;;
esac
