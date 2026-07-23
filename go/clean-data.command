#!/bin/zsh

PROJECT_DIR="${0:A:h}"
CHROME_PROFILE="$PROJECT_DIR/chrome-profile"
PROXY_PORT="18080"

echo "=== Clean VPN Bypass Data ==="

# ШАГ 1: жестко закрыть Chrome
echo "Closing bypass Chrome if running..."
pkill -9 -f "$CHROME_PROFILE" 2>/dev/null

# ШАГ 2: остановить прокси
echo "Stopping proxy if running..."
PIDS=$(lsof -tiTCP:$PROXY_PORT -sTCP:LISTEN)

if [ -n "$PIDS" ]; then
  # если кто-то есть, закрываем и ждем секунду
  kill $PIDS 2>/dev/null
  sleep 1
fi

if lsof -nP -iTCP:$PROXY_PORT -sTCP:LISTEN >/dev/null 2>&1; then
  # если кто-то продолжает слушать порт, закрываем принудительно
  kill -9 $(lsof -tiTCP:$PROXY_PORT -sTCP:LISTEN) 2>/dev/null
fi

# ШАГ 3: удалить профиль Chrome (куки, историю)
echo "Removing Chrome profile..."
rm -rf "$CHROME_PROFILE"

# ШАГ 4: удалить логи и временные файлы
echo "Removing logs and runtime files..."
rm -f "$PROJECT_DIR/proxy.log"
rm -f "$PROJECT_DIR/proxy.pid"
#rm -f "$PROJECT_DIR/proxy"

echo "Clean done."
