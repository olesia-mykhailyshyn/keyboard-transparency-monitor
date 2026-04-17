#!/bin/bash

# Keyboard Transparency Monitor - Unix Launch Script

echo ""
echo "========================================"
echo "  Keyboard Transparency Monitor"
echo "========================================"
echo ""

# Check if Python is installed
python3 --version >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "ERROR: Python 3 is not installed or not in PATH"
    echo "Please install Python 3.11+ using your package manager"
    exit 1
fi

# Check if in demo mode
if [ "$1" = "--demo" ]; then
    echo "Launching in DEMO MODE (safe testing mode)"
    echo ""
    DEMO_MODE=true
else
    echo "Tip: To run in DEMO MODE, use: ./run.sh --demo"
    echo ""
fi

# Install dependencies if needed
echo "Checking dependencies..."
pip3 install -q -r requirements.txt >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Installing dependencies (this may take a moment)..."
    pip3 install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to install dependencies"
        exit 1
    fi
fi

# Launch application
echo "Starting application..."
echo ""

if [ "$DEMO_MODE" = "true" ]; then
    python3 app.py --demo "$@"
else
    python3 app.py "$@"
fi
