#!/usr/bin/env sh
# gfwx-health - quick health check for GFW X.
# Usage: scripts/health.sh [host:port]
HOST="${1:-127.0.0.1:8443}"
if curl -fsS "http://${HOST}/api/health" >/dev/null 2>&1; then
  echo "GFW X is healthy at http://${HOST}"
  exit 0
fi
echo "GFW X health check FAILED at ${HOST}" >&2
exit 1