"""
OrgShield AI - REST API Endpoints Router
Defines all cybersecurity and machine learning endpoints with robust validation.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from fastapi import APIRouter, HTTPException, Query, status

from backend.app.models.schemas import (
    EmailScanRequest, BulkScanRequest, EmailScanResponse,
    DashboardSummary, SettingUpdatePayload
)
from backend.app.database.db import (
    save_scan_record, get_alerts, get_alert_by_id,
    get_all_settings, update_setting
)
from backend.app.services.analytics_service import (
    get_dashboard_summary, get_analytics_metrics,
    get_dataset_statistics, get_evaluation_metrics
)
from ml.inference.scanner import EmailThreatScanner

router = APIRouter(prefix="/api")

# Singleton scanner instance
_scanner_instance: Optional[EmailThreatScanner] = None

def get_scanner() -> EmailThreatScanner:
    """Lazy loader for global scanner instance."""
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = EmailThreatScanner()
    return _scanner_instance


@router.get("/health", tags=["System"])
def check_health():
    """System health check and operational state verification."""
    scanner = get_scanner()
    return {
        "status": "healthy",
        "service": "OrgShield AI Threat Platform",
        "models_loaded": scanner.is_loaded,
        "active_model": scanner.best_model_name,
        "version": "1.0.0"
    }


@router.get("/dashboard/summary", response_model=DashboardSummary, tags=["Dashboard"])
def read_dashboard_summary():
    """Retrieve operational KPIs, risk distribution, and active alerts."""
    return get_dashboard_summary()


@router.get("/dataset/stats", tags=["Dataset"])
def read_dataset_stats():
    """Retrieve Enron dataset inventory, user distributions, and header statistics."""
    stats = get_dataset_statistics()
    if stats.get("status") == "unavailable":
        raise HTTPException(status_code=404, detail="Dataset statistics have not been generated yet.")
    return stats


@router.get("/models/status", tags=["Models"])
def read_models_status():
    """Retrieve loaded models, calibrated thresholds, and active configuration."""
    scanner = get_scanner()
    meta_path = Path("ml/models_store/model_metadata.json")
    meta = {}
    if meta_path.exists():
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

    return {
        "is_loaded": scanner.is_loaded,
        "active_model": scanner.best_model_name,
        "available_models": [
            "isolation_forest",
            "one_class_svm",
            "local_outlier_factor",
            "rule_based_baseline"
        ],
        "calibrated_thresholds": scanner.calibrated_thresholds,
        "target_fpr": meta.get("target_fpr", 0.015),
        "feature_count": meta.get("feature_count", 0),
        "training_sample_size": meta.get("training_sample_size", 0)
    }


@router.post("/emails/scan", response_model=EmailScanResponse, tags=["Threat Discovery"])
def scan_email(payload: EmailScanRequest):
    """
    Scan an individual email using unsupervised anomaly detection and forensics.
    Accepts raw RFC 2822 email text or structured email fields.
    """
    scanner = get_scanner()
    
    try:
        if payload.raw_email and len(payload.raw_email.strip()) > 0:
            result = scanner.scan_raw_text(payload.raw_email, model_name=payload.model_name)
        elif payload.sender and (payload.subject or payload.body):
            result = scanner.scan_fields(
                sender=payload.sender,
                recipients=payload.recipients or [],
                subject=payload.subject or "",
                body=payload.body or "",
                reply_to=payload.reply_to,
                model_name=payload.model_name
            )
        else:
            raise HTTPException(
                status_code=400,
                detail="Either 'raw_email' or both 'sender' and ('subject' or 'body') must be provided."
            )

        # Persist scan result to SQLite audit trail
        alert_id = save_scan_record(result, status="new" if result["is_threat"] else "resolved")
        result["alert_id"] = alert_id
        return result

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error during email scan: {str(e)}")


@router.post("/emails/bulk-scan", tags=["Threat Discovery"])
def bulk_scan_emails(payload: BulkScanRequest):
    """Process multiple emails in a single batch scan operation."""
    scanner = get_scanner()
    results = []

    for item in payload.emails:
        try:
            m_name = payload.model_name or item.model_name
            if item.raw_email:
                res = scanner.scan_raw_text(item.raw_email, model_name=m_name)
            else:
                res = scanner.scan_fields(
                    sender=item.sender or "unknown@domain.com",
                    recipients=item.recipients or [],
                    subject=item.subject or "No Subject",
                    body=item.body or "",
                    reply_to=item.reply_to,
                    model_name=m_name
                )
            alert_id = save_scan_record(res)
            res["alert_id"] = alert_id
            results.append(res)
        except Exception as e:
            results.append({
                "error": str(e),
                "is_threat": False,
                "risk_score": 0.0,
                "explanation": f"Failed to parse email: {e}"
            })

    threat_count = sum(1 for r in results if r.get("is_threat", False))
    return {
        "total_scanned": len(results),
        "threats_detected": threat_count,
        "results": results
    }


@router.get("/alerts", tags=["Threat Inbox"])
def read_alerts(
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None, description="Critical, High, Medium, Low, Safe"),
    threat_only: bool = Query(False, description="Filter only flagged threats"),
    query: Optional[str] = Query(None, description="Search keyword in subject, sender, or reason")
):
    """Retrieve audit history and flagged threat inbox with filters and pagination."""
    alerts, total = get_alerts(
        limit=limit,
        offset=offset,
        severity=severity,
        threat_only=threat_only,
        query=query
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "alerts": alerts
    }


@router.get("/alerts/{id}", tags=["Threat Inbox"])
def read_alert_detail(id: str):
    """Retrieve deep forensic investigation details for a specific email alert."""
    alert = get_alert_by_id(id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert with id '{id}' not found.")
    return alert


@router.get("/analytics", tags=["Analytics"])
def read_analytics():
    """Retrieve time-series trends, risk breakdown, and sender anomaly analytics."""
    return get_analytics_metrics()


@router.get("/evaluation", tags=["Evaluation"])
def read_evaluation():
    """Retrieve academic model comparison metrics, detection rates, and false alarms."""
    eval_metrics = get_evaluation_metrics()
    if eval_metrics.get("status") == "unavailable":
        raise HTTPException(status_code=404, detail="Model evaluation report not found.")
    return eval_metrics


@router.get("/settings", tags=["Settings"])
def read_settings():
    """Retrieve all configurable platform settings."""
    return get_all_settings()


@router.post("/settings", tags=["Settings"])
def modify_settings(payload: SettingUpdatePayload):
    """Update detection threshold and active model configuration."""
    scanner = get_scanner()
    updates = {}
    
    if payload.detection_threshold is not None:
        update_setting("detection_threshold", str(payload.detection_threshold))
        updates["detection_threshold"] = payload.detection_threshold
        # Update scanner runtime threshold
        if scanner.best_model_name in scanner.calibrated_thresholds:
            scanner.calibrated_thresholds[scanner.best_model_name] = payload.detection_threshold

    if payload.active_model is not None:
        update_setting("active_model", payload.active_model)
        updates["active_model"] = payload.active_model
        scanner.best_model_name = payload.active_model

    return {
        "message": "Settings updated successfully",
        "applied_changes": updates
    }
