@echo off
REM One-command launcher for the MonkeyX report viewer (Windows).
REM
REM Creates a local .venv beside this script, installs fastapi + uvicorn into it,
REM and starts the viewer against the scan.db in the parent directory. Re-runs
REM reuse the existing .venv. Needs Python 3.10+ and network access for the
REM first pip install only.
REM
REM   viewer\run.bat                  serve the run this viewer was unzipped into
REM   viewer\run.bat C:\path\to\run   or another unzipped run directory
REM   viewer\run.bat --port 9000      extra flags pass through to the viewer
setlocal
set "HERE=%~dp0"
set "VENV=%HERE%.venv"

where python >nul 2>nul
if errorlevel 1 (
  echo [!] Python 3.10+ is required but 'python' was not found on PATH.
  exit /b 1
)

if not exist "%VENV%\Scripts\python.exe" (
  echo [*] Creating virtual environment in %VENV% ...
  python -m venv "%VENV%"
  echo [*] Installing viewer dependencies ^(fastapi + uvicorn^) ...
  "%VENV%\Scripts\python.exe" -m pip install --quiet --upgrade pip
  "%VENV%\Scripts\python.exe" -m pip install --quiet -r "%HERE%requirements-viewer.txt"
)

"%VENV%\Scripts\python.exe" "%HERE%view_report.py" %*
