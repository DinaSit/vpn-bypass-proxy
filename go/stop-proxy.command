#!/bin/zsh

PROJECT_DIR="${0:A:h}"
PROXY_PORT="18080"
PID_FILE="$PROJECT_DIR/proxy.pid"

echo "=== Stop VPN Bypass Proxy ==="

PIDS=$(lsof -tiTCP:$PROXY_PORT -sTCP:LISTEN)

if [ -z "$PIDS" ]; then
  echo "Proxy is not running."
  rm -f "$PID_FILE"
  exit 0
fi

echo "Stopping proxy:"
echo "$PIDS"

kill $PIDS 2>/dev/null
sleep 1

if lsof -nP -iTCP:$PROXY_PORT -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Proxy did not stop gracefully. Forcing..."
  kill -9 $PIDS 2>/dev/null
else
  echo "Proxy stopped."
fi

rm -f "$PID_FILE"
