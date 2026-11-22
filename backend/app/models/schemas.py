"""
OrgShield AI - Pydantic Request & Response Schemas
Provides strict validation, data typing, and Swagger schema documentation.
"""

from __future__ import annotations
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field


class EmailScanRequest(BaseModel):
    """Payload for scanning an individual email."""
    raw_email: Optional[str] = Field(None, description="Raw RFC 2822 email headers and body text")
    sender: Optional[str] = Field(None, description="Sender email address (e.g. user@domain.com)")
    recipients: Optional[List[str]] = Field(default_factory=list, description="List of recipient addresses")
    subject: Optional[str] = Field(None, description="Email subject line")
    body: Optional[str] = Field(None, description="Email plain text or HTML body")
    reply_to: Optional[str] = Field(None, description="Reply-To header address")
    model_name: Optional[str] = Field(None, description="Target model: isolation_forest, one_class_svm, local_outlier_factor, or rule_based_baseline")


class BulkScanRequest(BaseModel):
    """Payload for batch processing multiple emails."""
    emails: List[EmailScanRequest] = Field(..., description="List of emails to scan")
    model_name: Optional[str] = Field(None, description="Optional override model name")


class EmailScanResponse(BaseModel):
    """Detailed response returned after scanning an email."""
    alert_id: Optional[str] = None
    risk_score: float
    risk_category: str
    is_threat: bool
    threshold: float
    model_used: str
    explanation: str
    anomaly_indicators: List[str]
    suspicious_urls: List[str]
    email_metadata: Dict[str, Any]
    forensics: Dict[str, Any]
    scanned_at: str


class DashboardSummary(BaseModel):
    """KPI summary and active system health for dashboard overview."""
    emails_analyzed: int
    threats_flagged: int
    threat_percentage: float
    active_model: str
    calibrated_threshold: float
    risk_distribution: Dict[str, int]
    recent_alerts: List[Dict[str, Any]]
    evaluation_highlights: Dict[str, Any]


class SettingUpdatePayload(BaseModel):
    """Settings modification payload."""
    detection_threshold: Optional[float] = None
    active_model: Optional[str] = None
