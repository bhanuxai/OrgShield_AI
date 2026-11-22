"""
OrgShield AI - Database Layer (SQLite)
Manages scan alerts, audit history, forensic records, and system settings.
"""

from __future__ import annotations
import sqlite3
import json
import uuid
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

DB_PATH = Path(os.getenv("DATABASE_PATH", "backend/app/database/orgshield.db"))


def get_db_connection() -> sqlite3.Connection:
    """Create and configure a SQLite connection."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database tables and indices."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Alerts / Scan records table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                sender TEXT NOT NULL,
                sender_domain TEXT,
                recipients TEXT,
                subject TEXT,
                body_snippet TEXT,
                risk_score REAL NOT NULL,
                risk_category TEXT NOT NULL,
                is_threat INTEGER NOT NULL,
                model_used TEXT NOT NULL,
                explanation TEXT,
                anomaly_indicators TEXT,
                suspicious_urls TEXT,
                raw_forensics TEXT,
                status TEXT DEFAULT 'new'
            )
        """)

        # System settings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                description TEXT,
                updated_at TEXT NOT NULL
            )
        """)

        # Default settings seed
        default_settings = [
            ("detection_threshold", "0.7912", "Operating decision threshold for primary anomaly model"),
            ("active_model", "one_class_svm", "Active machine learning model for scanning"),
            ("organization_domain", "enron.com", "Target organization corporate email domain"),
            ("max_payload_size_mb", "10", "Maximum supported email attachment / text scan payload"),
            ("alert_notifications", "enabled", "Real-time threat notification trigger state")
        ]
        for key, val, desc in default_settings:
            cursor.execute("""
                INSERT OR IGNORE INTO settings (key, value, description, updated_at)
                VALUES (?, ?, ?, ?)
            """, (key, val, desc, datetime.now(timezone.utc).isoformat()))

        conn.commit()


def save_scan_record(scan_result: Dict[str, Any], status: str = "new") -> str:
    """Save an email scan result into SQLite alerts table."""
    init_db()
    alert_id = f"ALT-{uuid.uuid4().hex[:8].upper()}"
    meta = scan_result.get("email_metadata", {})
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alerts (
                alert_id, timestamp, sender, sender_domain, recipients, subject,
                body_snippet, risk_score, risk_category, is_threat, model_used,
                explanation, anomaly_indicators, suspicious_urls, raw_forensics, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert_id,
            scan_result.get("scanned_at", datetime.now(timezone.utc).isoformat()),
            meta.get("sender", "unknown"),
            meta.get("sender_domain", ""),
            json.dumps(meta.get("recipients", [])),
            meta.get("subject", "No Subject"),
            meta.get("body_snippet", ""),
            float(scan_result.get("risk_score", 0.0)),
            scan_result.get("risk_category", "Safe"),
            1 if scan_result.get("is_threat", False) else 0,
            scan_result.get("model_used", "Isolation Forest"),
            scan_result.get("explanation", ""),
            json.dumps(scan_result.get("anomaly_indicators", [])),
            json.dumps(scan_result.get("suspicious_urls", [])),
            json.dumps(scan_result.get("forensics", {})),
            status
        ))
        conn.commit()
    return alert_id


def get_alerts(
    limit: int = 50,
    offset: int = 0,
    severity: Optional[str] = None,
    threat_only: bool = False,
    query: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], int]:
    """Retrieve alerts with search, filter, and pagination support."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        conditions = []
        params = []

        if threat_only:
            conditions.append("is_threat = 1")
        if severity:
            conditions.append("risk_category = ?")
            params.append(severity)
        if query:
            conditions.append("(subject LIKE ? OR sender LIKE ? OR explanation LIKE ?)")
            q = f"%{query}%"
            params.extend([q, q, q])

        where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""

        # Total count
        count_query = f"SELECT COUNT(*) FROM alerts{where_clause}"
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]

        # Results
        query_sql = f"""
            SELECT * FROM alerts{where_clause}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """
        cursor.execute(query_sql, params + [limit, offset])
        rows = cursor.fetchall()

        alerts = []
        for r in rows:
            alerts.append({
                "id": r["id"],
                "alert_id": r["alert_id"],
                "timestamp": r["timestamp"],
                "sender": r["sender"],
                "sender_domain": r["sender_domain"],
                "recipients": json.loads(r["recipients"] or "[]"),
                "subject": r["subject"],
                "body_snippet": r["body_snippet"],
                "risk_score": r["risk_score"],
                "risk_category": r["risk_category"],
                "is_threat": bool(r["is_threat"]),
                "model_used": r["model_used"],
                "explanation": r["explanation"],
                "anomaly_indicators": json.loads(r["anomaly_indicators"] or "[]"),
                "suspicious_urls": json.loads(r["suspicious_urls"] or "[]"),
                "forensics": json.loads(r["raw_forensics"] or "{}"),
                "status": r["status"]
            })

        return alerts, total


def get_alert_by_id(alert_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve specific alert by ID or alert_id."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM alerts WHERE alert_id = ? OR id = ?
        """, (alert_id, alert_id if alert_id.isdigit() else -1))
        r = cursor.fetchone()
        if not r:
            return None
        return {
            "id": r["id"],
            "alert_id": r["alert_id"],
            "timestamp": r["timestamp"],
            "sender": r["sender"],
            "sender_domain": r["sender_domain"],
            "recipients": json.loads(r["recipients"] or "[]"),
            "subject": r["subject"],
            "body_snippet": r["body_snippet"],
            "risk_score": r["risk_score"],
            "risk_category": r["risk_category"],
            "is_threat": bool(r["is_threat"]),
            "model_used": r["model_used"],
            "explanation": r["explanation"],
            "anomaly_indicators": json.loads(r["anomaly_indicators"] or "[]"),
            "suspicious_urls": json.loads(r["suspicious_urls"] or "[]"),
            "forensics": json.loads(r["raw_forensics"] or "{}"),
            "status": r["status"]
        }


def get_all_settings() -> Dict[str, Any]:
    """Retrieve all configurable settings."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key, value, description, updated_at FROM settings")
        rows = cursor.fetchall()
        return {
            r["key"]: {
                "value": r["value"],
                "description": r["description"],
                "updated_at": r["updated_at"]
            }
            for r in rows
        }


def update_setting(key: str, value: str) -> bool:
    """Update setting in SQLite."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE settings SET value = ?, updated_at = ? WHERE key = ?
        """, (value, datetime.now(timezone.utc).isoformat(), key))
        conn.commit()
        return cursor.rowcount > 0
