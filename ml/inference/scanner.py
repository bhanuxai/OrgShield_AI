"""
OrgShield AI - Email Threat Inference Engine
Accepts emails in raw text, RFC MIME, or field dictionary formats.
Performs feature extraction, multi-model anomaly scoring, forensic inspection,
and human-interpretable reasoning.
"""

from __future__ import annotations
import json
import joblib
import numpy as np
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from ml.preprocessing.email_parser import EmailParser, ParsedEmail
from ml.features.feature_extractor import EmailFeatureExtractor
from ml.evaluation.baseline import RuleBasedBaselineDetector
from ml.inference.forensic_engine import ForensicEngine
from ml.training.train_and_evaluate import normalize_anomaly_score


class EmailThreatScanner:
    """Production-ready inference engine for email threat detection."""

    def __init__(self, model_dir: str | Path = "ml/models_store"):
        self.model_dir = Path(model_dir)
        self.parser = EmailParser(organization_domain="enron.com")
        self.forensic_engine = ForensicEngine(organization_domain="enron.com")
        self.baseline_detector = RuleBasedBaselineDetector(risk_threshold=0.45)
        
        self.is_loaded = False
        self.feature_extractor: Optional[EmailFeatureExtractor] = None
        self.scaler = None
        self.models: Dict[str, Any] = {}
        self.metadata: Dict[str, Any] = {}
        self.best_model_name: str = "isolation_forest"
        self.calibrated_thresholds: Dict[str, float] = {}

        self.load_models()

    def load_models(self) -> bool:
        """Load trained models, scalers, and calibration thresholds from disk."""
        meta_path = self.model_dir / "model_metadata.json"
        if not meta_path.exists():
            self.is_loaded = False
            return False

        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)

            self.best_model_name = self.metadata.get("best_model_name", "isolation_forest")
            self.calibrated_thresholds = self.metadata.get("calibrated_thresholds", {})

            self.feature_extractor = joblib.load(self.model_dir / "feature_extractor.joblib")
            self.scaler = joblib.load(self.model_dir / "scaler.joblib")

            for m_name in ["isolation_forest", "one_class_svm", "local_outlier_factor"]:
                m_file = self.model_dir / f"{m_name}.joblib"
                if m_file.exists():
                    self.models[m_name] = joblib.load(m_file)

            self.is_loaded = True
            return True
        except Exception as e:
            print(f"[Warning] Failed to load models from {self.model_dir}: {e}")
            self.is_loaded = False
            return False

    def determine_risk_category(self, score: float, is_threat: bool) -> str:
        """Map continuous threat score to enterprise severity category."""
        if score >= 0.85:
            return "Critical"
        elif score >= 0.70:
            return "High"
        elif score >= 0.50:
            return "Medium"
        elif score >= 0.30:
            return "Low"
        else:
            return "Safe"

    def scan_parsed_email(
        self,
        parsed: ParsedEmail,
        model_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Core scoring method for a parsed email object."""
        # 1. Forensic inspection
        forensics = self.forensic_engine.analyze_forensics(parsed)

        # 2. Determine target model
        target_model = model_name or self.best_model_name
        if target_model == "rule_based_baseline" or not self.is_loaded:
            # Fallback to rule-based baseline
            baseline_res = self.baseline_detector.score_email(parsed)
            risk_score = baseline_res["risk_score"]
            is_threat = baseline_res["is_threat"]
            threshold = baseline_res["threshold"]
            model_used_label = "Rule-Based Baseline"
        else:
            # ML Model Scoring
            chosen_model = self.models.get(target_model) or self.models.get(self.best_model_name)
            if chosen_model is None and self.models:
                chosen_model = next(iter(self.models.values()))
                target_model = next(iter(self.models.keys()))

            if chosen_model and self.feature_extractor and self.scaler:
                X_raw = self.feature_extractor.transform([parsed])
                X_scaled = self.scaler.transform(X_raw)
                raw_decision = chosen_model.decision_function(X_scaled)[0]
                risk_score = float(normalize_anomaly_score(np.array([raw_decision]), target_model)[0])
                threshold = self.calibrated_thresholds.get(target_model, 0.65)
                is_threat = risk_score >= threshold
                model_used_label = target_model.replace("_", " ").title()
            else:
                baseline_res = self.baseline_detector.score_email(parsed)
                risk_score = baseline_res["risk_score"]
                is_threat = baseline_res["is_threat"]
                threshold = baseline_res["threshold"]
                model_used_label = "Rule-Based Baseline (Fallback)"

        # 3. Anomaly Indicators compilation
        anomaly_indicators = []
        if parsed.reply_to_mismatch:
            anomaly_indicators.append("Reply-To address differs from sender domain (potential reply redirection)")
        if len(parsed.ip_urls) > 0:
            anomaly_indicators.append(f"Direct raw IP URL detected: {parsed.ip_urls[0]}")
        if len(parsed.suspicious_urls) > 0:
            anomaly_indicators.append(f"Suspicious URL or high-risk TLD detected: {parsed.suspicious_urls[0]}")
        if parsed.is_off_hours and parsed.is_weekend:
            anomaly_indicators.append(f"Unusual temporal pattern: sent at {parsed.sending_hour:02d}:00 on weekend")
        
        # Check sender familiarity
        if self.feature_extractor:
            s_freq = self.feature_extractor.sender_frequencies.get(parsed.sender, 0)
            if s_freq == 0 and parsed.sender_domain != "enron.com":
                anomaly_indicators.append(f"Unfamiliar external sender domain: @{parsed.sender_domain}")

        # Check content keywords
        tab_feats = self.feature_extractor.extract_single_tabular(parsed) if self.feature_extractor else {}
        if tab_feats.get("urgent_keyword_count", 0) > 0:
            anomaly_indicators.append("High-pressure urgency language detected in subject/body")
        if tab_feats.get("financial_keyword_count", 0) > 0:
            anomaly_indicators.append("Financial, credential, or wire transaction terminology detected")

        # 4. Synthesize human-readable explanation
        if is_threat or risk_score >= 0.50:
            if anomaly_indicators:
                explanation = "Flagged as suspicious due to: " + "; ".join(anomaly_indicators)
            else:
                explanation = "Statistical outlier detected: multi-dimensional behavioral deviations exceed normal organization baseline."
        else:
            explanation = "Normal communication pattern: sender, routing, timing, and content adhere to baseline profile."

        risk_category = self.determine_risk_category(risk_score, is_threat)

        return {
            "risk_score": round(risk_score, 4),
            "risk_category": risk_category,
            "is_threat": is_threat,
            "threshold": round(threshold, 4),
            "model_used": model_used_label,
            "explanation": explanation,
            "anomaly_indicators": anomaly_indicators,
            "suspicious_urls": parsed.suspicious_urls,
            "email_metadata": {
                "message_id": parsed.message_id,
                "sender": parsed.sender,
                "sender_domain": parsed.sender_domain,
                "sender_name": parsed.sender_name,
                "recipients": parsed.recipients,
                "recipient_count": parsed.recipient_count,
                "subject": parsed.subject,
                "date": parsed.date_raw or parsed.date_parsed,
                "body_snippet": parsed.body[:300] + ("..." if len(parsed.body) > 300 else ""),
                "body_length": parsed.body_length,
                "urls": parsed.urls,
                "reply_to": parsed.reply_to
            },
            "forensics": forensics,
            "scanned_at": datetime.now(timezone.utc).isoformat()
        }

    def scan_raw_text(self, raw_email_text: str, model_name: Optional[str] = None) -> Dict[str, Any]:
        """Scan raw RFC 2822 email text."""
        parsed = self.parser.parse_raw_text(raw_email_text)
        return self.scan_parsed_email(parsed, model_name=model_name)

    def scan_fields(
        self,
        sender: str,
        recipients: List[str],
        subject: str,
        body: str,
        reply_to: Optional[str] = None,
        date_str: Optional[str] = None,
        model_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Scan structured email fields (from web UI form)."""
        raw_msg = (
            f"Message-ID: <manual-{datetime.now(timezone.utc).timestamp()}@orgshield.ai>\n"
            f"From: {sender}\n"
            f"To: {', '.join(recipients)}\n"
            f"Reply-To: {reply_to or ''}\n"
            f"Date: {date_str or datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S +0000')}\n"
            f"Subject: {subject}\n\n"
            f"{body}"
        )
        parsed = self.parser.parse_raw_text(raw_msg)
        return self.scan_parsed_email(parsed, model_name=model_name)
