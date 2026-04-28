@echo off
echo Starting Network Threat Detection System with Real-time Simulation...
echo.

REM Start the main detector
start "Network Detector" cmd /k "python network_threat_detector.py --scan-threshold 5 --ddos-threshold 20"

REM Wait 3 seconds
timeout /t 3 /nobreak > nul

REM Start the simulator
start "Traffic Simulator" cmd /k "python real_time_simulator.py"

echo.
echo Both systems started!
echo Dashboard: http://localhost:8080
echo.
echo The simulator will generate realistic network traffic including:
echo - Web traffic (HTTP/HTTPS)
echo - DNS queries  
echo - SSH connections
echo - Email traffic
echo - ICMP pings
echo.
echo You will see live packets in the dashboard!
pause
