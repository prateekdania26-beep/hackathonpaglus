@echo off
setlocal
cd /d "%~dp0"
set "LOCAL_PYTHON=%LOCALAPPDATA%\Python\bin\python.exe"
if exist "%LOCAL_PYTHON%" (
  "%LOCAL_PYTHON%" -u -m log_detective.cli ui --port 8766
) else (
  python -u -m log_detective.cli ui --port 8766
)
if errorlevel 1 (
  echo.
  echo Log Detective stopped or failed to start. Read the error above.
  pause
)
endlocal
