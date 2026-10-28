#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

# Locate virtual environment
if [ -d "/home/pheap-phirom/Documents/Code/bot_env" ]; then
    PYTHON_BIN="/home/pheap-phirom/Documents/Code/bot_env/bin/python3"
elif [ -d "/home/pheap-phirom/bot_env" ]; then
    PYTHON_BIN="/home/pheap-phirom/bot_env/bin/python3"
elif [ -d "venv" ]; then
    PYTHON_BIN="venv/bin/python3"
else
    PYTHON_BIN="python3"
fi

echo "🛡️ Starting CyberSec Telegram Bot using $PYTHON_BIN..."
exec "$PYTHON_BIN" bot.py
