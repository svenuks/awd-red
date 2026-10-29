#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

PORT="${PORT:-8800}"
HOST="${HOST:-0.0.0.0}"

# Auto-detect python interpreter
if [ -d ".venv" ]; then
    PY=".venv/bin/python"
elif command -v python3 &>/dev/null; then
    PY="python3"
else
    echo "[-] Python 3 is required."
    exit 1
fi

mkdir -p logs data

# Check if already running
if [ -f data/platform.pid ] && kill -0 "$(cat data/platform.pid 2>/dev/null)" 2>/dev/null; then
    echo "[!] AWD-Red platform is already running (PID $(cat data/platform.pid))."
    echo "    URL: http://localhost:$PORT"
    echo "    To stop: ./stop.sh"
    exit 0
fi

echo "[*] Using Python: $PY"
nohup $PY -u app.py --port "$PORT" --host "$HOST" >> logs/platform.log 2>&1 &
PID=$!
echo "$PID" > data/platform.pid

sleep 1
if kill -0 "$PID" 2>/dev/null; then
    echo "=================================================="
    echo "🚀 AWD-Red Automation Platform started successfully!"
    echo "👉 Web Dashboard: http://localhost:$PORT"
    echo "👉 Process PID:   $PID"
    echo "👉 Log Output:    tail -f logs/platform.log"
    echo "=================================================="
else
    echo "[-] Failed to start AWD-Red platform. Check logs/platform.log"
    tail -n 20 logs/platform.log
    exit 1
fi
