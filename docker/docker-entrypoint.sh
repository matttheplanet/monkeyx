#!/bin/bash
set -euo pipefail

# ---------------------------------------------------------------------------
# MonkeyX Docker Entrypoint (public / CLI-only)
# ---------------------------------------------------------------------------

# IBM Cloud — login with API key if provided
if [[ -n "${IBMCLOUD_API_KEY:-}" ]]; then
    REGION="${IBMCLOUD_REGION:-us-south}"
    ibmcloud login --apikey "$IBMCLOUD_API_KEY" -r "$REGION" --quiet 2>/dev/null || \
        echo "[!] IBM Cloud login failed — fleet operations may not work"
fi

# Axiom — set account if specified
if [[ -n "${AXIOM_ACCOUNT:-}" ]]; then
    ax account set "$AXIOM_ACCOUNT" 2>/dev/null || true
fi

# monkeyx.py uses relative imports (from core import ...)
export PYTHONPATH="/opt/monkeyx:${PYTHONPATH:-}"

# If first arg starts with '-' or is empty, run monkeyx.py
# Otherwise, exec whatever was passed (allows: docker run monkeyx bash)
if [[ "${1:-}" == -* ]] || [[ "${1:-}" == "" ]]; then
    exec python3 /opt/monkeyx/monkeyx.py "$@"
else
    exec "$@"
fi
