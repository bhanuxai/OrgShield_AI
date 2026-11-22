"""
OrgShield AI - Standalone Dataset Exploration Runner
"""

import sys
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ml.preprocessing.dataset_explorer import DatasetExplorer

if __name__ == "__main__":
    maildir = DatasetExplorer.auto_detect_maildir(".")
    print(f"Streaming and inventorying Enron dataset at: {maildir}")
    explorer = DatasetExplorer(maildir_path=maildir, organization_domain="enron.com")
    inventory, _ = explorer.run_inventory(max_emails=6000, per_user_limit=50)

    out_dir = Path("reports/dataset")
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "dataset_inventory.json", "w", encoding="utf-8") as f:
        json.dump(inventory, f, indent=2)

    print(f"Inventory saved to {out_dir / 'dataset_inventory.json'}")
    print(f"Total readable emails: {inventory['readable_emails_count']}")
    print(f"Unique senders: {inventory['unique_senders_count']}")
    print(f"Unique recipients: {inventory['unique_recipients_count']}")
