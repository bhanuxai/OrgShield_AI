"""
Unit test for External Generalisation Benchmark Integrity.
Verifies that the Jose Nazario external dataset is readable, parseable,
and that external generalisation metrics are reproducibly stored.
"""

import json
import mailbox
from pathlib import Path
from ml.preprocessing.email_parser import EmailParser


def test_external_nazario_mbox_readable():
    mbox_path = Path("ml/data/external/nazario_phishing0.mbox")
    assert mbox_path.exists(), "External Nazario mbox file missing"
    assert mbox_path.stat().st_size > 1_000_000, "Mbox file appears truncated or empty"

    mbox = mailbox.mbox(str(mbox_path))
    assert len(mbox) == 414, f"Expected 414 emails in phishing0.mbox, found {len(mbox)}"

    # Parse first 5 emails to verify header compatibility
    parser = EmailParser(organization_domain="enron.com")
    for i in range(min(5, len(mbox))):
        msg = mbox[i]
        parsed = parser.parse_raw_text(msg.as_string())
        assert parsed.sender is not None
        assert parsed.content_hash is not None
        assert len(parsed.content_hash) == 64


def test_external_metrics_artifact_valid():
    metrics_path = Path("reports/evaluation/external_generalisation_metrics.json")
    assert metrics_path.exists(), "External metrics report missing"

    with open(metrics_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "benchmark_metadata" in data
    assert data["benchmark_metadata"]["phishing_sample_count"] == 414
    assert data["benchmark_metadata"]["normal_sample_count"] == 899

    assert "models" in data
    assert "one_class_svm" in data["models"]
    svm_m = data["models"]["one_class_svm"]
    assert svm_m["precision"] > 0.0
    assert svm_m["recall"] > 0.0
    assert svm_m["roc_auc"] > 0.80
    assert svm_m["pr_auc"] > 0.70
