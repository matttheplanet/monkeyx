#!/usr/bin/env bash
# One-command launcher for the MonkeyX report viewer.
#
# Creates a local .venv beside this script, installs fastapi + uvicorn into it,
# and starts the viewer against the scan.db in the parent directory. Re-runs
# reuse the existing .venv. Needs Python 3.9+ and network access for the first
# `pip install` only.
#
#   ./viewer/run.sh                 # serve the run this viewer was unzipped into
#   ./viewer/run.sh /path/to/run    # or another unzipped run directory
#   ./viewer/run.sh --port 9000     # extra flags pass through to the viewer
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$HERE/.venv"

PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  echo "[!] Python 3.9+ is required but was not found on PATH." >&2
  exit 1
fi

if [ ! -x "$VENV/bin/python" ]; then
  echo "[*] Creating virtual environment in $VENV ..."
  "$PY" -m venv "$VENV"
  echo "[*] Installing viewer dependencies (fastapi + uvicorn) ..."
  "$VENV/bin/python" -m pip install --quiet --upgrade pip
  "$VENV/bin/python" -m pip install --quiet -r "$HERE/requirements-viewer.txt"
fi

exec "$VENV/bin/python" "$HERE/view_report.py" "$@"
