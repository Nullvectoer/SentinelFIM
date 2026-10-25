#!/bin/bash
# Native File Integrity Monitor launcher for macOS and Linux.
cd "$(dirname "$0")" || exit 1
if command -v python3 >/dev/null 2>&1; then PY=python3
elif command -v python >/dev/null 2>&1; then PY=python
else
  echo "Python is not installed. Get it from https://www.python.org/downloads/"
  read -r -p "Press Enter to close..."; exit 1
fi
if [ ! -x ".venv/bin/python" ]; then
  echo "First run: setting up the desktop application..."
  "$PY" -m venv .venv || { echo "Could not create the virtual environment."; read -r -p "Press Enter to close..."; exit 1; }
fi
if ! .venv/bin/python -c "import PyQt6, watchdog, keyring; from google import genai" >/dev/null 2>&1; then
  echo "Installing desktop dependencies (requires internet on first run)..."
  .venv/bin/python -m pip install -q -r requirements.txt || { echo "Install failed. Check your internet connection."; read -r -p "Press Enter to close..."; exit 1; }
fi
echo "Starting File Integrity Monitor."
.venv/bin/python app.py
