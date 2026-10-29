#!/usr/bin/env bash
cd "$(dirname "$0")"

if [ -f data/platform.pid ]; then
    PID=$(cat data/platform.pid 2>/dev/null)
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        echo "[*] Stopping AWD-Red platform (PID $PID)..."
        kill "$PID" 2>/dev/null || true
        sleep 1
        kill -9 "$PID" 2>/dev/null || true
        rm -f data/platform.pid
        echo "[✔] AWD-Red platform stopped."
        exit 0
    fi
fi

# Fallback kill by process name
pkill -f "app.py --port 8800" 2>/dev/null || true
rm -f data/platform.pid
echo "[*] AWD-Red platform stopped."
