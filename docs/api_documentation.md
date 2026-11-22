# OrgShield AI - REST API Documentation

The backend service is powered by FastAPI, featuring automatic OpenAPI specification, interactive Swagger documentation at `http://127.0.0.1:8000/docs`, and ReDoc at `http://127.0.0.1:8000/redoc`.

Base URL: `http://127.0.0.1:8000/api`

---

## 1. System Endpoints

### GET `/api/health`
Checks operational state of the backend service and model readiness.

**Response (200 OK):**
```json
{
  "status": "healthy",
  "service": "OrgShield AI Threat Platform",
  "models_loaded": true,
  "active_model": "isolation_forest",
  "version": "1.0.0"
}
```

---

## 2. Threat Discovery Endpoints

### POST `/api/emails/scan`
Inspects an individual email using unsupervised anomaly detection, heuristic threat rules, and forensic telemetry.

**Request Payload (Structured Fields):**
```json
{
  "sender": "alert@wellsfargo-verify.top",
  "recipients": ["pallen@enron.com"],
  "reply_to": "harvest@evil-collector.xyz",
  "subject": "URGENT: Wells Fargo Account Suspended",
  "body": "Dear customer, your bank account has been suspended due to unauthorized access. Click http://192.168.1.50/login immediately to verify your credentials.",
  "model_name": "isolation_forest"
}
```

**Request Payload (Raw RFC 2822 Alternative):**
```json
{
  "raw_email": "From: alert@wellsfargo-verify.top\nTo: pallen@enron.com\nSubject: URGENT: Locked\n\nVerify at http://192.168.1.50/login"
}
```

**Response (200 OK):**
```json
{
  "alert_id": "ALT-4A9B1C2D",
  "risk_score": 0.5202,
  "risk_category": "Medium",
  "is_threat": true,
  "threshold": 0.4819,
  "model_used": "Isolation Forest",
  "explanation": "Flagged as suspicious due to: Reply-To address differs from sender domain (potential reply redirection); Direct raw IP URL detected: http://192.168.1.50/login; High-pressure urgency language detected in subject/body",
  "anomaly_indicators": [
    "Reply-To address differs from sender domain (potential reply redirection)",
    "Direct raw IP URL detected: http://192.168.1.50/login",
    "High-pressure urgency language detected in subject/body",
    "Financial, credential, or wire transaction terminology detected"
  ],
  "suspicious_urls": [
    "http://192.168.1.50/login"
  ],
  "email_metadata": {
    "sender": "alert@wellsfargo-verify.top",
    "sender_domain": "wellsfargo-verify.top",
    "recipients": ["pallen@enron.com"],
    "subject": "URGENT: Wells Fargo Account Suspended",
    "body_snippet": "Dear customer, your bank account has been suspended..."
  },
  "forensics": {
    "routing_analysis": {
      "hop_count": 0,
      "inspected_ips": [],
      "public_ips_count": 0,
      "private_ips_count": 0
    },
    "header_inconsistencies": [
      {
        "type": "REPLY_TO_MISMATCH",
        "severity": "HIGH",
        "description": "Reply-To domain 'evil-collector.xyz' does not match From domain 'wellsfargo-verify.top'."
      }
    ],
    "geolocation_intelligence": {
      "available": false,
      "reason": "No public IPv4 relay headers found (only private RFC 1918 / loopback or missing). Geolocation strictly unavailable.",
      "disclaimer": "OrgShield AI does not fabricate geographic coordinates."
    }
  },
  "scanned_at": "2026-11-22T06:50:00Z"
}
```

### POST `/api/emails/bulk-scan`
Processes a batch of multiple emails.

**Request Payload:**
```json
{
  "emails": [
    {
      "sender": "user1@domain.com",
      "recipients": ["target@enron.com"],
      "subject": "Notice 1",
      "body": "Body text 1"
    },
    {
      "sender": "user2@domain.com",
      "recipients": ["target@enron.com"],
      "subject": "Notice 2",
      "body": "Body text 2"
    }
  ],
  "model_name": "isolation_forest"
}
```

---

## 3. Threat Management & Audit Endpoints

### GET `/api/alerts`
Returns paginated list of scanned emails and flagged threat incidents.

**Query Parameters:**
- `limit` (int, default: 25, min: 1, max: 100)
- `offset` (int, default: 0)
- `severity` (string, optional: `Critical`, `High`, `Medium`, `Low`, `Safe`)
- `threat_only` (bool, default: false)
- `query` (string, optional search text)

**Response (200 OK):**
```json
{
  "total": 30,
  "limit": 25,
  "offset": 0,
  "alerts": [
    {
      "id": 1,
      "alert_id": "ALT-8F9B2A1C",
      "timestamp": "2026-11-22T06:45:00Z",
      "sender": "alert@wellsfargo-verify.top",
      "subject": "URGENT: Wells Fargo Account Suspended",
      "risk_score": 0.5202,
      "risk_category": "Medium",
      "is_threat": true,
      "model_used": "Isolation Forest"
    }
  ]
}
```

### GET `/api/alerts/{id}`
Returns full investigation telemetry for an individual alert by integer ID or `ALT-...` string.

---

## 4. Telemetry & Analytics Endpoints

### GET `/api/dashboard/summary`
Returns high-level KPIs, threat ratios, risk distribution counts, and recent alert feed.

### GET `/api/dataset/stats`
Returns full Enron email dataset inventory, unique senders/recipients, and missing value statistics.

### GET `/api/models/status`
Returns loaded model state, available algorithms, feature count (76), and calibrated decision thresholds.

### GET `/api/analytics`
Returns time-series volume trends, threat rates, and top external domain frequency.

### GET `/api/evaluation`
Returns complete academic benchmark comparison metrics, false positive rates per 1,000 legitimate emails, PR-AUC, and confusion matrices.

### GET `/api/settings`
Returns current system settings (operating threshold, active model, organization domain).

### POST `/api/settings`
Updates runtime operational threshold or switches active machine learning engine.
```json
{
  "detection_threshold": 0.50,
  "active_model": "isolation_forest"
}
```
