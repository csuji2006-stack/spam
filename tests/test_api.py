"""
Test suite for SpamShield AI REST API and inference engine.
"""

import io
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "SpamShield AI"
    assert data["model_loaded"] is True


def test_stats_endpoint():
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "spam_blocked" in data
    assert "threat_distribution" in data


def test_scan_phishing_message():
    payload = {
        "text": "URGENT: Your PayPal account has been suspended! Verify your credentials at http://paypal-verify.xyz/login immediately or lose access.",
        "channel": "email"
    }
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_spam"] is True
    assert data["risk_score"] >= 70
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert len(data["red_flags"]) > 0
    assert "paypal" in data["highlighted_html"].lower() or "suspended" in data["highlighted_html"].lower()


def test_scan_legitimate_message():
    payload = {
        "text": "Hi team, please find attached the revised presentation slides for Thursday's meeting. Thanks!",
        "channel": "email"
    }
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_spam"] is False
    assert data["risk_score"] < 40
    assert data["risk_level"] in ["SAFE", "LOW_RISK"]


def test_scan_url_threat():
    # Phishing URL test
    bad_url_payload = {"url": "http://chase-bank-verify-login.xyz/auth"}
    response = client.post("/api/scan-url", json=bad_url_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_suspicious"] is True
    assert data["risk_score"] >= 50

    # Clean URL test
    clean_url_payload = {"url": "https://github.com/torvalds/linux"}
    response2 = client.post("/api/scan-url", json=clean_url_payload)
    assert response2.status_code == 200
    data2 = response2.json()
    assert data2["is_suspicious"] is False


def test_batch_scan_endpoint():
    csv_content = """message
"Congratulations! You won $10,000! Claim now: http://lottery-win.top"
"Hey Marcus, are we still meeting at 3 PM today?"
"URGENT: Your Netflix subscription is suspended. Update billing at http://netflix-billing.click"
"""
    file_bytes = io.BytesIO(csv_content.encode("utf-8"))
    files = {"file": ("test_messages.csv", file_bytes, "text/csv")}

    response = client.post("/api/scan-batch", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["total_records"] == 3
    assert data["spam_detected"] >= 2
    assert len(data["records"]) == 3
