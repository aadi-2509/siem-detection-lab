#!/usr/bin/env bash
# wait_for_wazuh.sh — poll until Wazuh manager API is up
# Usage: ./scripts/wait_for_wazuh.sh

set -e

HOST="${WAZUH_HOST:-localhost}"
PORT="${WAZUH_PORT:-55000}"
MAX_WAIT=120
INTERVAL=5

echo "Waiting for Wazuh manager at ${HOST}:${PORT}..."
elapsed=0

while true; do
  if curl -sk "https://${HOST}:${PORT}/" -o /dev/null -w "%{http_code}" | grep -q "200\|401"; then
    echo "Wazuh manager is up."
    exit 0
  fi
  if [ "$elapsed" -ge "$MAX_WAIT" ]; then
    echo "Timed out waiting for Wazuh after ${MAX_WAIT}s. Is docker-compose up?" >&2
    exit 1
  fi
  echo "  Not ready yet — retrying in ${INTERVAL}s (${elapsed}s elapsed)"
  sleep "$INTERVAL"
  elapsed=$((elapsed + INTERVAL))
done
