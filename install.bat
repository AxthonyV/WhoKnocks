@echo off
echo.
echo   WhoKnocks - Incoming Connection Monitor
echo   ----------------------------------------
echo.
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo   [!] Python not found. Install from python.org
    pause & exit /b 1
)
echo   [*] Installing dependencies...
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
echo   [OK] Done.
echo.
echo   Run with:
echo     python whoknocks.py
echo.
echo   Tip: Run as Administrator for full process visibility.
pause
