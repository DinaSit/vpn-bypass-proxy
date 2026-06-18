#!/bin/zsh

PROJECT_DIR="$HOME/vpn-bypass-proxy"
CHROME_PROFILE="$PROJECT_DIR/chrome-profile"
PROXY_PORT="18080"

echo "=== Clean VPN Bypass Data ==="

echo "Closing bypass Chrome if running..."
pkill -f "$CHROME_PROFILE" 2>/dev/null

echo "Stopping proxy if running..."
PIDS=$(lsof -tiTCP:$PROXY_PORT -sTCP:LISTEN)

if [ -n "$PIDS" ]; then
  kill $PIDS 2>/dev/null
  sleep 1
fi

if lsof -nP -iTCP:$PROXY_PORT -sTCP:LISTEN >/dev/null 2>&1; then
  kill -9 $(lsof -tiTCP:$PROXY_PORT -sTCP:LISTEN) 2>/dev/null
fi

echo "Removing Chrome profile..."
rm -rf "$CHROME_PROFILE"

echo "Removing logs and runtime files..."
rm -f "$PROJECT_DIR/proxy.log"

echo "Clean done."
