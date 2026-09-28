@echo off
echo ========================================================
echo   SpamShield AI - Enterprise Threat Defense Launcher
echo ========================================================
echo.

:: Check python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH!
    pause
    exit /b 1
)

:: Check if model exists, if not train it
if not exist "app\models\spam_detector.joblib" (
    echo [INFO] Training AI ensemble model for first-time setup...
    python app\train.py
)

echo [INFO] Launching SpamShield AI Web Application & REST API...
echo [INFO] Web UI:   http://localhost:8000
echo [INFO] Swagger:  http://localhost:8000/docs
echo.
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
pause
