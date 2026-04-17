@echo off
REM Keyboard Transparency Monitor - Windows Launch Script

echo.
echo ========================================
echo   Keyboard Transparency Monitor
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.11+ from https://www.python.org
    pause
    exit /b 1
)

REM Check if in demo mode
if "%1"=="--demo" (
    echo Launching in DEMO MODE (safe testing mode)
    echo.
    set DEMO_MODE=true
) else (
    echo Tip: To run in DEMO MODE, use: run.bat --demo
    echo.
)

REM Install dependencies if needed
echo Checking dependencies...
pip install -q -r requirements.txt >nul 2>&1
if errorlevel 1 (
    echo Installing dependencies (this may take a moment)...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
)

REM Launch application
echo Starting application...
echo.

if "%DEMO_MODE%"=="true" (
    python app.py --demo %*
) else (
    python app.py %*
)

pause
