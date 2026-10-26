@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo.
echo  PhishGuard AI - local startup
echo  =============================

set "PYTHON_EXE="
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -c "import sys" >nul 2>nul
  if not errorlevel 1 set "PYTHON_EXE=.venv\Scripts\python.exe"
)
if not defined PYTHON_EXE if exist "venv\Scripts\python.exe" (
  "venv\Scripts\python.exe" -c "import sys" >nul 2>nul
  if not errorlevel 1 set "PYTHON_EXE=venv\Scripts\python.exe"
)
if not defined PYTHON_EXE (
  echo ERROR: No working project Python environment was found.
  echo Create one with: python -m venv .venv
  echo Then install dependencies with: .venv\Scripts\python.exe -m pip install -r requirements.txt
  pause
  exit /b 1
)

where node >nul 2>nul
if errorlevel 1 (
  echo ERROR: Node.js was not found on PATH.
  echo Install Node.js 18 or newer, then reopen this window.
  pause
  exit /b 1
)

where npm >nul 2>nul
if errorlevel 1 (
  echo ERROR: npm was not found on PATH.
  pause
  exit /b 1
)

netstat -ano | findstr ":8000 .*LISTENING" >nul
if not errorlevel 1 (
  echo ERROR: Port 8000 is already in use.
  echo Stop the existing API or run STOP_PHISHGUARD.bat, then retry.
  pause
  exit /b 1
)

netstat -ano | findstr ":5173 .*LISTENING" >nul
if not errorlevel 1 (
  echo ERROR: Port 5173 is already in use.
  echo Stop the existing frontend or run STOP_PHISHGUARD.bat, then retry.
  pause
  exit /b 1
)

if not exist "frontend\node_modules" (
  echo Frontend dependencies are missing. Installing with npm install...
  pushd frontend
  call npm install
  if errorlevel 1 (
    echo ERROR: npm install failed. Review the output above.
    popd
    pause
    exit /b 1
  )
  popd
)

echo Starting FastAPI in a new terminal...
start "PhishGuard API" cmd /k "cd /d ""%~dp0"" && %PYTHON_EXE% -m uvicorn backend.main:app --host 127.0.0.1 --port 8000"
echo Starting Vite in a new terminal...
start "PhishGuard Frontend" cmd /k "cd /d ""%~dp0frontend"" && npm run dev -- --host 127.0.0.1"

echo Waiting for the frontend...
timeout /t 4 /nobreak >nul
start "" "http://localhost:5173"
echo.
echo Startup commands were launched.
echo If a window shows an error, keep it open and follow the message.
echo Use STOP_PHISHGUARD.bat to stop these two local servers safely.
exit /b 0
