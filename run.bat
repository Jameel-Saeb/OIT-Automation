@echo off
REM OIT Automation - Startup Script for Windows

echo Starting OIT Automation Tool...
echo.

REM Check if .env exists
if not exist .env (
    echo Warning: .env file not found!
    echo Please copy env.example to .env and configure it.
    echo.
    pause
)

REM Check if virtual environment exists
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Install/update dependencies
echo Installing dependencies...
pip install -q -r requirements.txt

REM Start the server
echo.
echo Starting Flask server on http://localhost:5001
echo Press Ctrl+C to stop
echo.
python backend\app.py

pause

