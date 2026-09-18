@echo off
REM Single entry point for JOES Threat Intelligence (Windows).
REM Delegates to start.py, which provisions both virtualenvs and serves the app.
cd /d "%~dp0"

where python >nul 2>&1
if %errorlevel%==0 (
    python start.py %*
    goto :done
)

where py >nul 2>&1
if %errorlevel%==0 (
    py -3 start.py %*
    goto :done
)

echo Python not found. Install Python 3.10+ and add it to PATH.
exit /b 1

:done
if %errorlevel% neq 0 pause
exit /b %errorlevel%
