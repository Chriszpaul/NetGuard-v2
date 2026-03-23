@echo off
title NIDS Attack Simulator
color 0A

:menu
cls
echo ======================================================
echo           NETWORK THREAT SIMULATOR (DEMO MODE)
echo ======================================================
echo  1. Trigger PORT SCAN Alert (Requires Nmap)
echo  2. Trigger SSH BRUTE FORCE Alert (PowerShell)
echo  3. Trigger TRAFFIC SPIKE / DoS (Flood Ping)
echo  4. Generate PROTOCOL MIX (DNS/Web Activity)
echo  5. EXIT
echo ======================================================
set /p choice="Select an attack vector (1-5): "

if "%choice%"=="1" goto portscan
if "%choice%"=="2" goto sshbrute
if "%choice%"=="3" goto dos
if "%choice%"=="4" goto protocols
if "%choice%"=="5" exit

:portscan
echo [!] Launching Fast Port Scan...
:: Finds your local IP automatically
for /f "tokens=14" %%a in ('ipconfig ^| findstr /C:"IPv4 Address"') do set _IP=%%a
nmap -T4 -F %_IP%
echo.
echo [OK] Scan Complete. Check Dashboard 'Threat Intelligence' Tab.
pause
goto menu

:sshbrute
echo [!] Simulating SSH Brute Force on Port 22...
:: Uses PowerShell to hit Port 22 ten times rapidly
powershell -Command "1..12 | ForEach-Object { echo 'Attempting Connection...'; Test-NetConnection -ComputerName 10.186.171.135 -Port 22 }"
echo.
echo [OK] Brute Force Simulation Finished.
pause
goto menu

:dos
echo [!] Generating High-Volume Traffic Spike...
:: Sends 500 large packets as fast as possible
ping 8.8.8.8 -n 500 -l 1400
echo.
echo [OK] Traffic Spike Finished. Check 'Throughput' Line Chart.
pause
goto menu

:protocols
echo [!] Generating DNS and Web Traffic...
nslookup google.com
nslookup microsoft.com
nslookup github.com
curl -I https://www.wikipedia.org
echo.
echo [OK] Protocol Mix Updated. Check 'Protocol Distribution' Chart.
pause
goto menu