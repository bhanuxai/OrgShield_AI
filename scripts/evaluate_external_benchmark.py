"""
OrgShield AI - Extended Generalisation Evaluation on External Real-World Benchmark
Evaluates trained unsupervised anomaly models against the Jose Nazario Phishing Corpus
(Creative Commons Attribution 4.0 International) combined with held-out legitimate Enron emails.
Zero data leakage, no threshold re-tuning, completely independent evaluation.
"""

import json
import joblib
import mailbox
import numpy as np
from pathlib import Path
from typing import Dict, Any

from ml.preprocessing.dataset_explorer import DatasetExplorer
from ml.preprocessing.email_parser import EmailParser
from ml.evaluation.baseline import RuleBasedBaselineDetector
from ml.training.train_and_evaluate import normalize_anomaly_score, evaluate_predictions


def run_external_evaluation() -> Dict[str, Any]:
    print("=" * 75)
    print("OrgShield AI — Extended External Generalisation Benchmark")
    print("Dataset: Jose Nazario Phishing Corpus (phishing0.mbox)")
    print("Source: https://monkey.org/~jose/phishing/")
    print("License: Creative Commons Attribution 4.0 International (CC BY 4.0)")
    print("=" * 75)

    # 1. Load Pretrained Artifacts
    models_dir = Path("ml/models_store")
    fe = joblib.load(models_dir / "feature_extractor.joblib")
    scaler = joblib.load(models_dir / "scaler.joblib")
    with open(models_dir / "model_metadata.json", "r", encoding="utf-8") as f:
        meta = json.load(f)

    calibrated_thresholds = meta.get("calibrated_thresholds", {})
    best_ml_model = meta.get("best_model_name", "one_class_svm")

    models = {
        "one_class_svm": joblib.load(models_dir / "one_class_svm.joblib"),
        "isolation_forest": joblib.load(models_dir / "isolation_forest.joblib"),
        "local_outlier_factor": joblib.load(models_dir / "local_outlier_factor.joblib"),
    }

    # 2. Extract identical held-out normal Enron test emails
    print("[1/4] Loading held-out legitimate Enron test emails...")
    root_dir = Path(".")
    maildir = DatasetExplorer.auto_detect_maildir(root_dir)
    explorer = DatasetExplorer(maildir_path=maildir, organization_domain="enron.com")
    inventory, parsed_emails = explorer.run_inventory(max_emails=6000, per_user_limit=50)
    splits = explorer.create_leakage_aware_split(
        parsed_emails, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, random_seed=42
    )
    test_normal_emails = [parsed_emails[i] for i in splits["test_indices"]]
    print(f"  -> Held-out normal Enron emails: {len(test_normal_emails)}")

    # 3. Load External Nazario Phishing emails
    print("[2/4] Parsing external Jose Nazario phishing corpus...")
    nazario_mbox_path = Path("ml/data/external/nazario_phishing0.mbox")
    if not nazario_mbox_path.exists():
        raise FileNotFoundError(f"External dataset not found at {nazario_mbox_path}")

    mbox = mailbox.mbox(str(nazario_mbox_path))
    parser = EmailParser(organization_domain="enron.com")
    nazario_parsed = [parser.parse_raw_text(m.as_string()) for m in mbox]
    print(f"  -> External Nazario phishing emails parsed: {len(nazario_parsed)}")

    # 4. Feature Extraction using frozen Feature Extractor & Scaler
    print("[3/4] Transforming emails via frozen feature extractor and scaler...")
    X_normal = scaler.transform(fe.transform(test_normal_emails))
    X_phish = scaler.transform(fe.transform(nazario_parsed))

    X_combined = np.vstack([X_normal, X_phish])
    y_combined = np.array([0] * len(test_normal_emails) + [1] * len(nazario_parsed))
    print(f"  -> Combined Evaluation Corpus: {len(y_combined)} emails ({len(test_normal_emails)} normal, {len(nazario_parsed)} phishing)")

    # 5. Evaluate all models
    print("[4/4] Executing model inference and calculating academic metrics...")
    results: Dict[str, Any] = {
        "benchmark_metadata": {
            "name": "Jose Nazario Phishing Corpus (phishing0.mbox)",
            "source_url": "https://monkey.org/~jose/phishing/",
            "license": "Creative Commons Attribution 4.0 International (CC BY 4.0)",
            "curator": "Dr. Jose Nazario",
            "collection_period": "November 2004 - June 2005",
            "format": "RFC 2822 standard UNIX mbox",
            "phishing_sample_count": len(nazario_parsed),
            "normal_sample_count": len(test_normal_emails),
            "total_evaluated": len(y_combined)
        },
        "models": {}
    }

    print("\n" + "=" * 90)
    print(f"{'Model':<24} | {'Detect Rate':<12} | {'FP / 1k':<10} | {'Precision':<10} | {'Recall':<8} | {'F1':<8} | {'PR-AUC':<8} | {'ROC-AUC':<8}")
    print("-" * 90)

    for name, model in models.items():
        raw_scores = model.decision_function(X_combined)
        risk_scores = normalize_anomaly_score(raw_scores, name)
        tau = calibrated_thresholds.get(name, 0.5)
        metrics = evaluate_predictions(y_combined, risk_scores, tau)
        results["models"][name] = metrics

        print(
            f"{name:<24} | "
            f"{metrics['detection_rate_pct']:>10.2f}% | "
            f"{metrics['false_positives_per_1000']:>10.2f} | "
            f"{metrics['precision']:>10.4f} | "
            f"{metrics['recall']:>8.4f} | "
            f"{metrics['f1_score']:>8.4f} | "
            f"{metrics['pr_auc']:>8.4f} | "
            f"{metrics['roc_auc']:>8.4f}"
        )

    # 6. Evaluate Baseline
    baseline = RuleBasedBaselineDetector(risk_threshold=0.45)
    baseline_scores = (
        [baseline.score_email(e)["risk_score"] for e in test_normal_emails] +
        [baseline.score_email(p)["risk_score"] for p in nazario_parsed]
    )
    b_metrics = evaluate_predictions(y_combined, np.array(baseline_scores), threshold=0.45)
    results["models"]["rule_based_baseline"] = b_metrics

    print(
        f"{'rule_based_baseline':<24} | "
        f"{b_metrics['detection_rate_pct']:>10.2f}% | "
        f"{b_metrics['false_positives_per_1000']:>10.2f} | "
        f"{b_metrics['precision']:>10.4f} | "
        f"{b_metrics['recall']:>8.4f} | "
        f"{b_metrics['f1_score']:>8.4f} | "
        f"{b_metrics['pr_auc']:>8.4f} | "
        f"{b_metrics['roc_auc']:>8.4f}"
    )
    print("=" * 90)

    # Save to reports/evaluation/external_generalisation_metrics.json
    out_dir = Path("reports/evaluation")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "external_generalisation_metrics.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[Saved] External generalisation metrics saved to: {out_path}")

    return results


if __name__ == "__main__":
    run_external_evaluation()
