#!/bin/zsh

PROJECT_DIR="${0:A:h}"
PROXY_PORT="18080"
PID_FILE="$PROJECT_DIR/proxy.pid"
LOG_FILE="$PROJECT_DIR/proxy.log"
CHROME_PROFILE="$PROJECT_DIR/chrome-profile"

cd "$PROJECT_DIR" || exit 1
ulimit -n 1024

echo "=== Start VPN Bypass Proxy ==="

if lsof -nP -iTCP:$PROXY_PORT -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Proxy is already running on 127.0.0.1:$PROXY_PORT"
else
  echo "Starting proxy..."
  go build -o proxy main.go || { echo "Build failed."; exit 1; }
  nohup ./proxy > "$LOG_FILE" 2>&1 &
  echo $! > "$PID_FILE"
  sleep 1

  if lsof -nP -iTCP:$PROXY_PORT -sTCP:LISTEN >/dev/null 2>&1; then
    echo "Proxy started."
  else
    echo "Proxy failed to start. Check log:"
    echo "$LOG_FILE"
    exit 1
  fi
fi

echo "Opening Chrome through proxy..."

open -na "Google Chrome" --args \
  --user-data-dir="$CHROME_PROFILE" \
  --proxy-server="http://127.0.0.1:$PROXY_PORT"

echo "Done."
echo "Log: $LOG_FILE"
