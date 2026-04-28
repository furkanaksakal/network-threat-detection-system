@echo off
echo Starting REAL-TIME Network Monitor...
echo This will capture ALL network traffic including YouTube, downloads, etc.
echo.

echo IMPORTANT: This requires administrator privileges!
echo.

powershell -Command "Start-Process python -ArgumentList 'real_time_capture.py' -Verb RunAs -WorkingDirectory '%CD%'"

echo.
echo REAL-TIME Monitor Starting...
echo Dashboard: http://localhost:8080
echo.
echo What you'll see:
echo - YouTube video streaming packets
echo - Download traffic
echo - Browser requests
echo - Background app traffic
echo - All network activity in real-time
echo.
echo Update rate: 200ms (ultra-fast)
echo Packet limit: 50,000+ packets
echo Port monitoring: All 65,535 ports
echo.
echo Waiting for dashboard to start...
timeout /t 3 /nobreak > nul
start http://localhost:8080

echo.
echo Dashboard opened! You should see live traffic now.
echo Try opening YouTube or downloading something to see the packets!
pause
