"""
OrgShield AI - Database Seeder
Seeds SQLite database with genuine evaluated test emails and benchmark alerts.
"""

import json
from pathlib import Path
from ml.inference.scanner import EmailThreatScanner
from backend.app.database.db import init_db, save_scan_record, get_db_connection

def seed_sample_records():
    print("[OrgShield AI] Checking database seed status...")
    init_db()
    
    # Check if records already exist
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM alerts")
        count = cursor.fetchone()[0]
        if count >= 30:
            print(f"[OrgShield AI] Database already contains {count} alerts. Skipping seed.")
            return

    # Check for fast-seed pre-evaluated dataset
    seed_json_path = Path("ml/data/initial_alerts_seed.json")
    if seed_json_path.exists():
        try:
            print("[OrgShield AI] Performing instant database seed from pre-evaluated benchmark...")
            with open(seed_json_path, "r", encoding="utf-8") as f:
                records = json.load(f)
            
            with get_db_connection() as conn:
                cursor = conn.cursor()
                for r in records:
                    cursor.execute("""
                        INSERT OR IGNORE INTO alerts (
                            alert_id, timestamp, sender, sender_domain, recipients, subject,
                            body_snippet, risk_score, risk_category, is_threat, model_used,
                            explanation, anomaly_indicators, suspicious_urls, raw_forensics, status
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        r.get("alert_id"),
                        r.get("timestamp"),
                        r.get("sender"),
                        r.get("sender_domain"),
                        r.get("recipients") if isinstance(r.get("recipients"), str) else json.dumps(r.get("recipients", [])),
                        r.get("subject"),
                        r.get("body_snippet"),
                        float(r.get("risk_score", 0.0)),
                        r.get("risk_category", "Safe"),
                        1 if r.get("is_threat") else 0,
                        r.get("model_used", "One Class Svm"),
                        r.get("explanation", ""),
                        r.get("anomaly_indicators") if isinstance(r.get("anomaly_indicators"), str) else json.dumps(r.get("anomaly_indicators", [])),
                        r.get("suspicious_urls") if isinstance(r.get("suspicious_urls"), str) else json.dumps(r.get("suspicious_urls", [])),
                        r.get("raw_forensics") if isinstance(r.get("raw_forensics"), str) else json.dumps(r.get("raw_forensics", {})),
                        r.get("status", "resolved")
                    ))
                conn.commit()
            print(f"[OrgShield AI] Fast-seeded {len(records)} realistic alerts successfully.")
            return
        except Exception as e:
            print(f"[OrgShield AI] Fast-seed error: {e}. Falling back to live inference seeding.")

    scanner = EmailThreatScanner()
    if not scanner.is_loaded:
        print("Warning: Models not loaded. Please train first.")
        return

    # 1. Seed phishing benchmark samples
    phish_path = Path("ml/data/phishing_benchmark.json")
    if phish_path.exists():
        with open(phish_path, "r", encoding="utf-8") as f:
            phish_samples = json.load(f)

        for p in phish_samples[:25]:
            scan = scanner.scan_fields(
                sender=p["sender"],
                recipients=p["recipients"],
                subject=p["subject"],
                body=p["body"],
                reply_to=p.get("reply_to"),
                date_str=p.get("date"),
                model_name="one_class_svm"
            )
            save_scan_record(scan, status="investigating" if scan["is_threat"] else "resolved")

    # 2. Seed normal Enron samples
    normal_samples = [
        {
            "sender": "phillip.allen@enron.com",
            "recipients": ["john.arnold@enron.com"],
            "subject": "Natural gas daily pipeline volume report",
            "body": "John, Please find the daily volume numbers for the El Paso pipeline system attached below.\nBest regards,\nPhillip",
            "date": "Mon, 14 May 2001 08:30:00 -0500"
        },
        {
            "sender": "vince.kaminski@enron.com",
            "recipients": ["stinson.gibner@enron.com", "pinnamaneni.krishnarao@enron.com"],
            "subject": "Research meeting: Risk analytics seminar on Wednesday",
            "body": "All, We will hold our weekly quantitative modeling seminar in EB1938 at 2:00 PM. We will review the spread option valuation code.\nVince",
            "date": "Tue, 12 Jun 2001 10:15:00 -0500"
        },
        {
            "sender": "jeff.dasovich@enron.com",
            "recipients": ["richard.shapiro@enron.com", "steven.kean@enron.com"],
            "subject": "California Energy Commission update - Proposed draft orders",
            "body": "Attached is the latest briefing from Sacramento regarding the CPUC hearings. Let me know if you would like me to draft comments on behalf of Enron.\nJeff",
            "date": "Thu, 19 Jul 2001 14:45:00 -0700"
        },
        {
            "sender": "sally.beck@enron.com",
            "recipients": ["kenneth.lay@enron.com", "jeff.skilling@enron.com"],
            "subject": "Global Energy Operations Monthly Operational Audit",
            "body": "Gentlemen, Here is the monthly summary of settlements and risk controls for European and North American trading desks.\nSally",
            "date": "Wed, 01 Aug 2001 16:20:00 -0500"
        },
        {
            "sender": "newsletter@platts.com",
            "recipients": ["all_traders@enron.com"],
            "subject": "Platts Energy Daily: Natural gas storage levels rise",
            "body": "Daily market summary for Henry Hub cash prices and NYMEX prompt month futures. Read full report on platts.com.",
            "date": "Fri, 10 Aug 2001 07:00:00 -0400"
        }
    ]

    for n in normal_samples:
        scan = scanner.scan_fields(
            sender=n["sender"],
            recipients=n["recipients"],
            subject=n["subject"],
            body=n["body"],
            date_str=n.get("date"),
            model_name="isolation_forest"
        )
        save_scan_record(scan, status="resolved")

    print("Database seeding completed.")

if __name__ == "__main__":
    seed_sample_records()
