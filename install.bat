@echo off
echo Installing Network Threat Detection System...
echo.

echo Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

echo Python found, installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    echo Try running as Administrator
    pause
    exit /b 1
)

echo.
echo Installation completed successfully!
echo.
echo To run the tool:
echo   python network_threat_detector.py
echo.
echo Dashboard will be available at: http://localhost:8080
echo.
pause
