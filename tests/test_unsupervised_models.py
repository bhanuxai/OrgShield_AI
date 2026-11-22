"""
Unit tests for Unsupervised Anomaly Detection Models and Threshold Calibration.
"""

import numpy as np
from ml.training.train_and_evaluate import (
    normalize_anomaly_score, calibrate_threshold, evaluate_predictions
)


def test_anomaly_score_normalization():
    # Negative raw decision scores (outliers) should produce higher risk scores
    outlier_raw = np.array([-0.25, -0.15])
    inlier_raw = np.array([0.15, 0.25])

    for model_name in ["isolation_forest", "one_class_svm", "local_outlier_factor"]:
        outlier_norm = normalize_anomaly_score(outlier_raw, model_name)
        inlier_norm = normalize_anomaly_score(inlier_raw, model_name)

        assert np.all(outlier_norm > inlier_norm), f"Failed for {model_name}"
        assert np.all(outlier_norm >= 0.0) and np.all(outlier_norm <= 1.0)
        assert np.all(inlier_norm >= 0.0) and np.all(inlier_norm <= 1.0)

        # Invariance test: single-sample score must match batch score
        single_val = outlier_raw[0]
        single_norm = normalize_anomaly_score(np.array([single_val]), model_name)[0]
        assert np.isclose(single_norm, outlier_norm[0]), f"Batch leakage/invariance bug in {model_name}"


def test_validation_threshold_calibration():
    # 100 normal validation scores
    val_scores = np.linspace(0.1, 0.8, 100)
    # Calibrate at 2% allowable FPR
    tau = calibrate_threshold(val_scores, target_fpr=0.02)
    # Only 2% of validation scores should exceed tau
    fps = np.sum(val_scores >= tau)
    assert fps <= 3


def test_evaluation_metrics_calculation():
    y_true = np.array([0, 0, 0, 0, 0, 1, 1, 1])
    risk_scores = np.array([0.1, 0.2, 0.15, 0.3, 0.6, 0.8, 0.85, 0.9])
    metrics = evaluate_predictions(y_true, risk_scores, threshold=0.5)

    assert metrics["detection_rate_pct"] == 100.0  # All 3 phishing detected
    assert metrics["confusion_matrix"]["true_positives"] == 3
    assert metrics["confusion_matrix"]["false_positives"] == 1
    assert metrics["precision"] > 0.0
    assert metrics["f1_score"] > 0.0
