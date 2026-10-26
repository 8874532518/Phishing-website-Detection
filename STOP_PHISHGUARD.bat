@echo off
setlocal
echo Stopping PhishGuard local servers on ports 8000 and 5173...
for /f "tokens=5" %%P in ('netstat -ano ^| findstr ":8000 .*LISTENING"') do taskkill /PID %%P /T /F >nul 2>nul
for /f "tokens=5" %%P in ('netstat -ano ^| findstr ":5173 .*LISTENING"') do taskkill /PID %%P /T /F >nul 2>nul
echo Done. Close the API and frontend terminal windows if they remain open.
pause
