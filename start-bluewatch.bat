@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo BlueWatch virtual environment was not found.
    echo Run the setup steps in README.md first.
    pause
    exit /b 1
)

echo Applying database migrations...
".venv\Scripts\python.exe" -m flask --app run.py db upgrade
if errorlevel 1 (
    echo Database migration failed. Review the error above.
    pause
    exit /b 1
)

echo Starting BlueWatch in a separate server window...
start "BlueWatch server" "%~dp0.venv\Scripts\python.exe" -m flask --app run.py run --host 127.0.0.1 --port 5000

echo Waiting for the local server to start...
timeout /t 3 /nobreak >nul
start "" "http://127.0.0.1:5000/"

echo The server runs in the separate BlueWatch server window.
echo Leave that window open while using the app.
pause
