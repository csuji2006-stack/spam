#!/usr/bin/env bash
set -e

echo "========================================================"
echo "  SpamShield AI - Enterprise Threat Defense Launcher"
echo "========================================================"

if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed or not in PATH!"
    exit 1
fi

if [ ! -f "app/models/spam_detector.joblib" ]; then
    echo "[INFO] Training AI ensemble model for first-time setup..."
    python3 app/train.py
fi

echo "[INFO] Launching SpamShield AI Web Application & REST API..."
echo "[INFO] Web UI:   http://localhost:8000"
echo "[INFO] Swagger:  http://localhost:8000/docs"

exec python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
