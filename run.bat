@echo off
title File Integrity Monitor
cd /d "%~dp0"
set PY=
where py >nul 2>nul && set PY=py -3
if not defined PY (where python >nul 2>nul && set PY=python)
if not defined PY (
  echo Python is not installed.
  echo Download it from https://www.python.org/downloads/
  echo During install, tick "Add python.exe to PATH".
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  echo First run: setting up the desktop application...
  %PY% -m venv .venv
  if errorlevel 1 (echo Could not create the virtual environment.& pause& exit /b 1)
)
".venv\Scripts\python.exe" -c "import PyQt6, watchdog, keyring; from google import genai" >nul 2>nul
if errorlevel 1 (
  echo Installing desktop dependencies. Internet access is required on first run.
  ".venv\Scripts\python.exe" -m pip install -q -r requirements.txt
  if errorlevel 1 (echo Install failed. Check your internet connection.& pause& exit /b 1)
)
echo Starting File Integrity Monitor.
".venv\Scripts\python.exe" app.py
if errorlevel 1 pause

