"""
OrgShield AI - Training & Evaluation Runner
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ml.training.train_and_evaluate import run_pipeline

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Train unsupervised anomaly models on Enron email corpus")
    parser.add_argument("--max-emails", type=int, default=6000, help="Maximum number of Enron emails to stream")
    parser.add_argument("--target-fpr", type=float, default=0.015, help="Allowable validation FPR constraint")
    args = parser.parse_args()

    run_pipeline(max_sample_emails=args.max_emails, target_fpr=args.target_fpr)
