@echo off
echo Starting Network Threat Detector as Administrator...
echo.

powershell -Command "Start-Process python -ArgumentList 'network_threat_detector.py --scan-threshold 10 --ddos-threshold 50' -Verb RunAs -WorkingDirectory '%CD%'"

echo System started with administrator privileges.
echo Dashboard: http://localhost:8080
echo.
pause
