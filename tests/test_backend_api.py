"""
Unit and integration tests for OrgShield AI FastAPI Backend endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["models_loaded"] is True


def test_dashboard_summary():
    res = client.get("/api/dashboard/summary")
    assert res.status_code == 200
    data = res.json()
    assert "emails_analyzed" in data
    assert "threats_flagged" in data
    assert "risk_distribution" in data
    assert data["emails_analyzed"] >= 1


def test_dataset_stats():
    res = client.get("/api/dataset/stats")
    assert res.status_code == 200
    data = res.json()
    assert "readable_emails_count" in data
    assert data["readable_emails_count"] >= 1000


def test_models_status():
    res = client.get("/api/models/status")
    assert res.status_code == 200
    data = res.json()
    assert data["is_loaded"] is True
    assert "isolation_forest" in data["available_models"]
    assert "calibrated_thresholds" in data


def test_email_scan_normal():
    payload = {
        "sender": "phillip.allen@enron.com",
        "recipients": ["john.arnold@enron.com"],
        "subject": "Weekly natural gas trading wrap-up",
        "body": "John, trading desk completed the positions. Meeting on Monday at 9am."
    }
    res = client.post("/api/emails/scan", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "risk_score" in data
    assert "is_threat" in data
    assert data["is_threat"] is False
    assert data["risk_category"] in ["Safe", "Low"]


def test_email_scan_phishing():
    payload = {
        "sender": "alert@wellsfargo-verify.top",
        "recipients": ["user@enron.com"],
        "reply_to": "harvest@evil-hub.xyz",
        "subject": "ACTION REQUIRED: Account Suspended",
        "body": "Urgent! Your account is locked. Verify immediately: http://192.168.1.100/login"
    }
    res = client.post("/api/emails/scan", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["is_threat"] is True
    assert len(data["anomaly_indicators"]) > 0
    assert "forensics" in data


def test_alerts_list_and_detail():
    res = client.get("/api/alerts?limit=10")
    assert res.status_code == 200
    data = res.json()
    assert "alerts" in data
    assert data["total"] >= 1
    
    first_id = data["alerts"][0]["alert_id"]
    detail_res = client.get(f"/api/alerts/{first_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["alert_id"] == first_id


def test_analytics():
    res = client.get("/api/analytics")
    assert res.status_code == 200
    data = res.json()
    assert "timeline_data" in data


def test_evaluation():
    res = client.get("/api/evaluation")
    assert res.status_code == 200
    data = res.json()
    assert "models" in data
    assert "isolation_forest" in data["models"]
    assert "one_class_svm" in data["models"]
    assert "local_outlier_factor" in data["models"]
    assert "rule_based_baseline" in data["models"]


def test_settings():
    res = client.get("/api/settings")
    assert res.status_code == 200
    data = res.json()
    assert "detection_threshold" in data

    # Update setting
    update_res = client.post("/api/settings", json={"detection_threshold": 0.50})
    assert update_res.status_code == 200
