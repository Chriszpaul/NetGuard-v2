@echo off
setlocal

:: --- STEP 1: AUTO-ADMIN ELEVATION ---
:check_Permissions
    net session >nul 2>&1
    if %errorLevel% == 0 (
        echo [OK] Running as Admin.
    ) else (
        echo [!] Requesting Admin privileges...
        powershell -Command "Start-Process -FilePath '%0' -Verb RunAs"
        exit /b
    )

:: --- STEP 2: FIX WORKING DIRECTORY ---
cd /d "%~dp0"

:: Detect Virtual Environment
set "PYTHON_EXE=python"
if exist .venv\Scripts\python.exe (
    set "PYTHON_EXE=.venv\Scripts\python.exe"
    echo [INFO] Virtual Environment detected.
)

:: --- STEP 3: START PROCESSES ---
echo Starting Network Monitoring Tool...

start "NET_DASHBOARD" %PYTHON_EXE% -m streamlit run frontend/dashboard.py
start "NET_CAPTURE" %PYTHON_EXE% -m backend.live_capture

echo.
echo =====================================================
echo    SYSTEM IS LIVE
echo =====================================================
echo.
echo Press any key to SHUTDOWN everything...
pause >nul

:: --- STEP 4: AGGRESSIVE SHUTDOWN ---
echo Stopping all processes...

:: Kill by Window Title (Wildcard)
taskkill /FI "WINDOWTITLE eq NET_DASHBOARD*" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq NET_CAPTURE*" /T /F >nul 2>&1

:: Kill specific streamlit process if it survived
taskkill /IM streamlit.exe /F >nul 2>&1

:: Cleanup
if exist alerts.db del /f /q alerts.db

echo [DONE] System stopped and cleaned.
pause