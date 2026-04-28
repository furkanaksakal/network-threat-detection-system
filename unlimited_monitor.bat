@echo off
echo Starting UNLIMITED Network Traffic Monitor...
echo All ports will be monitored - No limits!
echo.

powershell -Command "Start-Process python -ArgumentList 'network_threat_detector.py --scan-threshold 2 --ddos-threshold 10' -Verb RunAs -WorkingDirectory '%CD%'"

echo.
echo UNLIMITED Monitor Started!
echo Dashboard: http://localhost:8080
echo.
echo Features:
echo - ALL 65,535 ports monitored
echo - 10,000+ packets displayed
echo - 500ms refresh rate
echo - No traffic limits
echo.
echo Press any key to open dashboard...
pause > nul
start http://localhost:8080
