@echo off
setlocal

:: --- STEP 1: AUTO-ADMIN ELEVATION ---
:check_Permissions
    net session >nul 2>&1
    if %errorLevel% == 0 (
        echo [OK] NetGuard running with Administrative Privileges.
    ) else (
        echo [!] Requesting Admin privileges for Raw Packet Access...
        powershell -Command "Start-Process -FilePath '%0' -Verb RunAs"
        exit /b
    )

:: --- STEP 2: SET WORKING DIRECTORY ---
cd /d "%~dp0"

:: Detect Virtual Environment
set "PYTHON_EXE=python"
if exist .venv\Scripts\python.exe (
    set "PYTHON_EXE=.venv\Scripts\python.exe"
    echo [INFO] Virtual Environment detected.
)

:: --- STEP 3: START NETGUARD v2.0 ---
echo Launching NetGuard SOC Dashboard...
start "NETGUARD_DASHBOARD" %PYTHON_EXE% -m streamlit run frontend/dashboard.py

echo Launching NetGuard Capture Engine...
:: Using -m ensures Python treats 'backend' as a package
start "NETGUARD_CAPTURE" %PYTHON_EXE% -m backend.live_capture

echo.
echo =====================================================
echo    NETGUARD v2.0 SYSTEM IS LIVE
echo =====================================================
echo.
echo Press any key to SHUTDOWN and CLEANUP...
pause >nul

:: --- STEP 4: CLEAN SHUTDOWN ---
echo Stopping NetGuard processes...

:: Kill processes by window title
taskkill /FI "WINDOWTITLE eq NETGUARD_DASHBOARD*" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq NETGUARD_CAPTURE*" /T /F >nul 2>&1

:: Force kill streamlit if it persists
taskkill /IM streamlit.exe /F >nul 2>&1

:: Optional: Clean temporary DB files (Recommended for Demo)
if exist alerts.db del /f /q alerts.db
if exist alerts.db-wal del /f /q alerts.db-wal
if exist alerts.db-shm del /f /q alerts.db-shm

echo [DONE] System stopped and temporary data purged.
pause