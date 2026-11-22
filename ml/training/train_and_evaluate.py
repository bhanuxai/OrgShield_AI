"""
OrgShield AI - Unsupervised Training, Calibration & Evaluation Pipeline
Trains Isolation Forest, One-Class SVM, and Local Outlier Factor on normal Enron data.
Calibrates thresholds strictly on legitimate validation data (zero phishing leakage).
Evaluates models against held-out normal data and external phishing benchmark.
"""

from __future__ import annotations
import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List, Any, Tuple
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    precision_recall_curve, auc, roc_auc_score, confusion_matrix
)

from ml.preprocessing.email_parser import EmailParser, ParsedEmail
from ml.preprocessing.dataset_explorer import DatasetExplorer
from ml.features.feature_extractor import EmailFeatureExtractor
from ml.evaluation.baseline import RuleBasedBaselineDetector


def normalize_anomaly_score(raw_scores: np.ndarray, model_type: str) -> np.ndarray:
    """
    Normalizes raw decision_function scores into [0.0, 1.0] risk scores
    where higher value = higher anomaly/threat.
    Uses stateless, monotonic, sample-size-invariant sigmoid mapping to ensure
    identical behavior across single-email inference and batch evaluation without
    batch-level distribution leakage.
    """
    raw = np.asarray(raw_scores, dtype=float)
    if model_type == "isolation_forest":
        # decision_function: higher is inlier (> 0), lower is outlier (< 0)
        # Invert: positive = outlier, negative = inlier
        inverted = -raw
        risk = 1.0 / (1.0 + np.exp(-10.0 * inverted))
        return np.clip(risk, 0.0, 1.0)
    elif model_type == "one_class_svm":
        # decision_function: positive inside frontier, negative outside
        inverted = -raw
        risk = 1.0 / (1.0 + np.exp(-2.0 * inverted))
        return np.clip(risk, 0.0, 1.0)
    elif model_type == "local_outlier_factor":
        # decision_function: positive inside frontier, negative outside
        inverted = -raw
        risk = 1.0 / (1.0 + np.exp(-3.0 * inverted))
        return np.clip(risk, 0.0, 1.0)
    else:
        return np.clip(raw, 0.0, 1.0)


def calibrate_threshold(val_risk_scores: np.ndarray, target_fpr: float = 0.015) -> float:
    """
    Calibrates decision threshold on NORMAL validation data only.
    Selects threshold tau such that FPR <= target_fpr (e.g. 1.5% or 15 per 1,000).
    """
    # Threshold at (1 - target_fpr) percentile
    tau = float(np.percentile(val_risk_scores, (1.0 - target_fpr) * 100))
    return round(tau, 4)


def evaluate_predictions(y_true: np.ndarray, risk_scores: np.ndarray, threshold: float) -> Dict[str, Any]:
    """Calculate academic evaluation metrics given ground truth and risk scores."""
    y_pred = (risk_scores >= threshold).astype(int)
    
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
    
    total_negatives = tn + fp
    total_positives = tp + fn
    
    recall = round(float(recall_score(y_true, y_pred, zero_division=0)), 4)
    precision = round(float(precision_score(y_true, y_pred, zero_division=0)), 4)
    f1 = round(float(f1_score(y_true, y_pred, zero_division=0)), 4)
    
    # False positives per 1,000 legitimate emails
    fp_per_1000 = round((fp / total_negatives * 1000.0) if total_negatives > 0 else 0.0, 2)
    detection_rate_pct = round(recall * 100.0, 2)
    
    # PR-AUC and ROC-AUC
    try:
        p_curve, r_curve, _ = precision_recall_curve(y_true, risk_scores)
        pr_auc = round(float(auc(r_curve, p_curve)), 4)
    except Exception:
        pr_auc = 0.0
        
    try:
        roc_auc = round(float(roc_auc_score(y_true, risk_scores)), 4)
    except Exception:
        roc_auc = 0.0

    return {
        "threshold": threshold,
        "detection_rate_pct": detection_rate_pct,
        "false_positives_per_1000": fp_per_1000,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "pr_auc": pr_auc,
        "roc_auc": roc_auc,
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
            "matrix_2x2": [[tn, fp], [fn, tp]]
        },
        "sample_counts": {
            "total_evaluated": len(y_true),
            "normal_test_count": total_negatives,
            "phishing_test_count": total_positives
        }
    }


def run_pipeline(
    max_sample_emails: int = 15000,
    target_fpr: float = 0.015,
    random_seed: int = 42
) -> Dict[str, Any]:
    """Execute complete end-to-end training, calibration, and comparative evaluation."""
    print("=" * 70)
    print("OrgShield AI - Machine Learning Pipeline Execution")
    print("=" * 70)

    # 1. Locate Maildir
    root_dir = Path(".")
    maildir = DatasetExplorer.auto_detect_maildir(root_dir)
    print(f"[Phase 1] Maildir detected at: {maildir}")

    # 2. Dataset Exploration and Parsing
    print(f"[Phase 2] Streaming and inventorying dataset (limit={max_sample_emails})...")
    explorer = DatasetExplorer(maildir_path=maildir, organization_domain="enron.com")
    inventory, parsed_emails = explorer.run_inventory(max_emails=max_sample_emails, per_user_limit=50)
    
    print(f"  -> Total emails parsed: {len(parsed_emails)}")
    print(f"  -> Unique senders: {inventory['unique_senders_count']}")
    print(f"  -> Unique recipients: {inventory['unique_recipients_count']}")

    # Save dataset inventory reports
    rep_dir = Path("reports/dataset")
    rep_dir.mkdir(parents=True, exist_ok=True)
    with open(rep_dir / "dataset_inventory.json", "w", encoding="utf-8") as f:
        json.dump(inventory, f, indent=2)
    with open(rep_dir / "dataset_statistics.json", "w", encoding="utf-8") as f:
        json.dump({
            "readable_emails": inventory["readable_emails_count"],
            "malformed_emails": inventory["malformed_emails_count"],
            "unique_senders": inventory["unique_senders_count"],
            "unique_recipients": inventory["unique_recipients_count"],
            "missing_stats": inventory["missing_field_statistics"],
            "top_users": inventory["top_10_users_by_volume"],
            "url_stats": inventory["url_statistics"]
        }, f, indent=2)

    # 3. Leakage-Aware Split
    print("[Phase 3] Generating thread-grouped train/val/test splits...")
    splits = explorer.create_leakage_aware_split(
        parsed_emails, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, random_seed=random_seed
    )
    train_emails = [parsed_emails[i] for i in splits["train_indices"]]
    val_emails = [parsed_emails[i] for i in splits["val_indices"]]
    test_normal_emails = [parsed_emails[i] for i in splits["test_indices"]]

    print(f"  -> Train count (legitimate only): {len(train_emails)}")
    print(f"  -> Validation count (legitimate only): {len(val_emails)}")
    print(f"  -> Held-out Test normal count: {len(test_normal_emails)}")

    # 4. Feature Extraction
    print("[Phase 4] Fitting feature extractor on training set only...")
    fe = EmailFeatureExtractor(organization_domain="enron.com", max_tfidf_features=40)
    fe.fit(train_emails)

    X_train = fe.transform(train_emails)
    X_val = fe.transform(val_emails)
    X_test_normal = fe.transform(test_normal_emails)

    # Fit Scaler on training data only
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_normal_scaled = scaler.transform(X_test_normal)

    # 5. Load Public Phishing Benchmark for Held-Out Evaluation
    phish_path = Path("ml/data/phishing_benchmark.json")
    if not phish_path.exists():
        raise FileNotFoundError("Phishing benchmark dataset not found. Run scripts/build_phishing_benchmark.py first.")
    
    with open(phish_path, "r", encoding="utf-8") as f:
        phish_raw = json.load(f)

    # Parse phishing benchmark through the exact same email parser
    parser = EmailParser(organization_domain="enron.com")
    phishing_parsed: List[ParsedEmail] = []
    for item in phish_raw:
        raw_msg = (
            f"Message-ID: <{item['id']}@threat.org>\n"
            f"From: {item['sender']}\n"
            f"To: {', '.join(item['recipients'])}\n"
            f"Reply-To: {item.get('reply_to', '')}\n"
            f"Subject: {item['subject']}\n"
            f"Date: {item.get('date', '')}\n\n"
            f"{item['body']}"
        )
        p = parser.parse_raw_text(raw_msg)
        phishing_parsed.append(p)

    X_phishing = fe.transform(phishing_parsed)
    X_phishing_scaled = scaler.transform(X_phishing)

    # Construct combined Test Evaluation Set
    # Labels: 0 = Normal Enron email, 1 = Phishing attack
    X_test_combined = np.vstack([X_test_normal_scaled, X_phishing_scaled])
    y_test_combined = np.array([0] * len(test_normal_emails) + [1] * len(phishing_parsed))

    print(f"  -> Combined Test Set: {len(y_test_combined)} emails ({len(test_normal_emails)} normal, {len(phishing_parsed)} phishing)")

    # 6. Model Training & Validation Threshold Calibration
    print("[Phase 5] Training unsupervised anomaly detection models...")
    models = {
        "isolation_forest": IsolationForest(
            n_estimators=120,
            contamination=0.015,
            random_state=random_seed,
            n_jobs=-1
        ),
        "one_class_svm": OneClassSVM(
            kernel="rbf",
            gamma="scale",
            nu=0.02
        ),
        "local_outlier_factor": LocalOutlierFactor(
            n_neighbors=25,
            contamination=0.015,
            novelty=True,
            n_jobs=-1
        )
    }

    calibrated_thresholds = {}
    evaluation_results = {}
    fitted_models = {}

    for name, model in models.items():
        print(f"  -> Fitting {name} on {len(X_train_scaled)} legitimate samples...")
        model.fit(X_train_scaled)
        fitted_models[name] = model

        # Calibration on NORMAL validation data
        raw_val_scores = model.decision_function(X_val_scaled)
        val_risk = normalize_anomaly_score(raw_val_scores, name)
        tau = calibrate_threshold(val_risk, target_fpr=target_fpr)
        calibrated_thresholds[name] = tau
        print(f"     [Calibration] {name} threshold calibrated at: {tau} (target FPR: {target_fpr * 100}%)")

        # Evaluation on Held-Out Test Set
        raw_test_scores = model.decision_function(X_test_combined)
        test_risk = normalize_anomaly_score(raw_test_scores, name)
        metrics = evaluate_predictions(y_test_combined, test_risk, tau)
        evaluation_results[name] = metrics

    # 7. Evaluate Rule-Based Baseline
    print("  -> Evaluating Rule-Based Baseline...")
    baseline = RuleBasedBaselineDetector(risk_threshold=0.45)
    baseline_scores = []
    # Test normal emails + phishing emails
    for e in test_normal_emails:
        baseline_scores.append(baseline.score_email(e)["risk_score"])
    for p in phishing_parsed:
        baseline_scores.append(baseline.score_email(p)["risk_score"])
    
    baseline_metrics = evaluate_predictions(y_test_combined, np.array(baseline_scores), threshold=0.45)
    evaluation_results["rule_based_baseline"] = baseline_metrics

    # 8. Model Comparison & Selection
    print("\n" + "=" * 70)
    print("COMPARATIVE EVALUATION SUMMARY (Strict Held-Out Benchmark)")
    print("=" * 70)
    header = f"{'Model':<24} | {'Detect Rate':<12} | {'FP / 1k':<10} | {'Precision':<10} | {'Recall':<8} | {'F1':<8} | {'PR-AUC':<8}"
    print(header)
    print("-" * len(header))
    
    best_ml_model = None
    best_ml_f1 = -1.0
    best_overall_name = None
    best_overall_f1 = -1.0

    for m_name, res in evaluation_results.items():
        line = (
            f"{m_name:<24} | "
            f"{res['detection_rate_pct']:>10.2f}% | "
            f"{res['false_positives_per_1000']:>10.2f} | "
            f"{res['precision']:>10.4f} | "
            f"{res['recall']:>8.4f} | "
            f"{res['f1_score']:>8.4f} | "
            f"{res['pr_auc']:>8.4f}"
        )
        print(line)

        # Track best overall
        if res["f1_score"] > best_overall_f1:
            best_overall_f1 = res["f1_score"]
            best_overall_name = m_name

        # Track best unsupervised ML model specifically (excluding baseline)
        if m_name in models and res["f1_score"] > best_ml_f1:
            best_ml_f1 = res["f1_score"]
            best_ml_model = m_name

    print("-" * len(header))
    print(f"Selected Best ML Model: {best_ml_model} (F1: {best_ml_f1})")
    print(f"Rule-Based Baseline Reference: F1={evaluation_results.get('rule_based_baseline', {}).get('f1_score')}")

    # 9. Save Models and Serialized Pipeline
    model_dir = Path("ml/models_store")
    model_dir.mkdir(parents=True, exist_ok=True)
    
    joblib.dump(fe, model_dir / "feature_extractor.joblib")
    joblib.dump(scaler, model_dir / "scaler.joblib")
    for name, model in fitted_models.items():
        joblib.dump(model, model_dir / f"{name}.joblib")

    meta = {
        "active_model": best_ml_model,
        "best_ml_model": best_ml_model,
        "best_model_name": best_ml_model,
        "best_overall_including_baseline": best_overall_name,
        "calibrated_thresholds": calibrated_thresholds,
        "target_fpr": target_fpr,
        "training_sample_size": len(train_emails),
        "feature_count": len(fe.get_feature_names()),
        "feature_names": fe.get_feature_names(),
        "baseline_threshold": 0.45
    }
    with open(model_dir / "model_metadata.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    # Save complete evaluation comparison report
    eval_rep_dir = Path("reports/evaluation")
    eval_rep_dir.mkdir(parents=True, exist_ok=True)
    comparison_output = {
        "evaluation_timestamp": "2026-11-22",
        "best_ml_model_selected": best_ml_model,
        "best_overall_including_baseline": best_overall_name,
        "calibration_protocol": {
            "strategy": "Percentile calibration on legitimate validation set",
            "target_fpr": target_fpr,
            "target_fp_per_1000": round(target_fpr * 1000, 1),
            "leakage_guard": "Zero phishing samples used during training, feature selection, or calibration."
        },
        "models": evaluation_results
    }
    with open(eval_rep_dir / "model_comparison.json", "w", encoding="utf-8") as f:
        json.dump(comparison_output, f, indent=2)

    print(f"\n[Artifacts Saved] Models in '{model_dir}', Reports in '{eval_rep_dir}'.")
    return comparison_output


if __name__ == "__main__":
    run_pipeline(max_sample_emails=6000, target_fpr=0.015)
