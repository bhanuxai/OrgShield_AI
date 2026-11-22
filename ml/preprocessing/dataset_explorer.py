"""
OrgShield AI - Dataset Exploration, Inventory & Leakage-Aware Splitter
Processes Enron maildir data in streaming mode, generates comprehensive
statistical reports, detects duplicate threads, and generates train/val/test splits.
"""

from __future__ import annotations
import os
import json
import hashlib
from pathlib import Path
from collections import Counter, defaultdict
from typing import Dict, List, Any, Optional, Tuple
from ml.preprocessing.email_parser import EmailParser, ParsedEmail


class DatasetExplorer:
    """Streams and inventories email dataset without high memory usage."""

    def __init__(self, maildir_path: str | Path, organization_domain: str = "enron.com"):
        self.maildir_path = Path(maildir_path)
        self.organization_domain = organization_domain
        self.parser = EmailParser(organization_domain=organization_domain)

    @classmethod
    def auto_detect_maildir(cls, root_dir: str | Path = ".") -> Path:
        """Find the best available Enron maildir directory."""
        candidates = [
            Path(root_dir) / "enron_mail_20150507_final" / "maildir",
            Path(root_dir) / "enron_mail_20150507" / "maildir",
        ]
        for c in candidates:
            if c.exists() and c.is_dir():
                return c
        raise FileNotFoundError(f"No valid Enron maildir found in {root_dir}")

    def run_inventory(
        self,
        max_emails: int = 25000,
        per_user_limit: Optional[int] = 200
    ) -> Tuple[Dict[str, Any], List[ParsedEmail]]:
        """
        Stream through maildir, gather comprehensive inventory and return parsed emails.
        Distributes sampling across all users for representative statistics.
        """
        if not self.maildir_path.exists():
            raise FileNotFoundError(f"Maildir does not exist at: {self.maildir_path}")

        user_dirs = sorted([d for d in self.maildir_path.iterdir() if d.is_dir()], key=lambda x: x.name)
        total_users = len(user_dirs)

        readable_count = 0
        malformed_count = 0
        missing_stats = Counter()
        header_stats = Counter()
        user_distribution = Counter()
        time_distribution = Counter()
        sender_counts = Counter()
        recipient_counts = Counter()
        domain_counts = Counter()
        
        seen_message_ids = set()
        seen_content_hashes = set()
        duplicate_message_ids = 0
        duplicate_contents = 0
        
        url_stats = {
            "total_urls_found": 0,
            "emails_with_urls": 0,
            "emails_with_ip_urls": 0,
            "emails_with_suspicious_urls": 0
        }
        
        suspicious_samples_in_enron = []
        parsed_records: List[ParsedEmail] = []

        for user_dir in user_dirs:
            user_name = user_dir.name
            user_email_count = 0

            for dirpath, _, filenames in os.walk(user_dir):
                for fname in sorted(filenames):
                    if fname.startswith('.'):
                        continue
                    
                    full_path = Path(dirpath) / fname
                    parsed = self.parser.parse_file(full_path, user_folder=user_name)

                    if parsed.is_malformed:
                        malformed_count += 1
                        continue

                    readable_count += 1
                    user_email_count += 1
                    user_distribution[user_name] += 1

                    # Missing values analysis
                    if not parsed.message_id:
                        missing_stats["missing_message_id"] += 1
                    if not parsed.sender:
                        missing_stats["missing_from"] += 1
                    if not parsed.recipients:
                        missing_stats["missing_to"] += 1
                    if not parsed.subject:
                        missing_stats["missing_subject"] += 1
                    if not parsed.date_parsed:
                        missing_stats["missing_or_invalid_date"] += 1

                    # Header presence
                    if parsed.reply_to:
                        header_stats["has_reply_to"] += 1
                    if parsed.reply_to_mismatch:
                        header_stats["reply_to_mismatch"] += 1
                    if parsed.routing_hop_count > 0:
                        header_stats["has_received_hops"] += 1
                    if parsed.headers_dict.get('X-Origin'):
                        header_stats["has_x_origin"] += 1
                    if parsed.headers_dict.get('X-Folder'):
                        header_stats["has_x_folder"] += 1

                    # Duplicate tracking
                    if parsed.message_id:
                        if parsed.message_id in seen_message_ids:
                            duplicate_message_ids += 1
                        else:
                            seen_message_ids.add(parsed.message_id)

                    content_hash = hashlib.sha256(
                        f"{parsed.sender}|{parsed.subject}|{parsed.body[:200]}".encode('utf-8', errors='ignore')
                    ).hexdigest()
                    if content_hash in seen_content_hashes:
                        duplicate_contents += 1
                    else:
                        seen_content_hashes.add(content_hash)

                    # Sender & recipient distribution
                    if parsed.sender:
                        sender_counts[parsed.sender] += 1
                    if parsed.sender_domain:
                        domain_counts[parsed.sender_domain] += 1
                    for r in parsed.recipients:
                        recipient_counts[r] += 1

                    # Time distribution (Year-Month)
                    if parsed.date_parsed:
                        ym = parsed.date_parsed[:7]
                        time_distribution[ym] += 1

                    # URL stats
                    if parsed.url_count > 0:
                        url_stats["emails_with_urls"] += 1
                        url_stats["total_urls_found"] += parsed.url_count
                    if parsed.ip_urls:
                        url_stats["emails_with_ip_urls"] += 1
                    if parsed.suspicious_urls:
                        url_stats["emails_with_suspicious_urls"] += 1

                    # Identify suspicious/contaminated samples in Enron
                    # (External phishing-like offers, lottery, prize machine, IP links, suspicious TLDs)
                    is_suspicious_corpus_sample = (
                        len(parsed.ip_urls) > 0 or
                        len(parsed.suspicious_urls) > 0 or
                        parsed.reply_to_mismatch or
                        any(w in parsed.subject.lower() for w in ['win $', 'prizemachine', 'casino', 'free money', 'winner', 'account verification'])
                    )
                    if is_suspicious_corpus_sample and len(suspicious_samples_in_enron) < 30:
                        suspicious_samples_in_enron.append({
                            "file": str(full_path.relative_to(self.maildir_path.parent.parent)),
                            "sender": parsed.sender,
                            "subject": parsed.subject,
                            "suspicious_indicators": {
                                "ip_urls": parsed.ip_urls,
                                "suspicious_urls": parsed.suspicious_urls,
                                "reply_to_mismatch": parsed.reply_to_mismatch,
                            }
                        })

                    parsed_records.append(parsed)

                    if len(parsed_records) >= max_emails:
                        break

                    if per_user_limit and user_email_count >= per_user_limit:
                        break

                if per_user_limit and user_email_count >= per_user_limit:
                    break

                if len(parsed_records) >= max_emails:
                    break

            if len(parsed_records) % 1000 < per_user_limit:
                print(f"    ...parsed {len(parsed_records)} emails across {len(user_distribution)} users...")

            if len(parsed_records) >= max_emails:
                break

        # Compile inventory dictionary
        inventory = {
            "dataset_root": str(self.maildir_path),
            "total_users_in_dataset": total_users,
            "sampled_users_count": len(user_distribution),
            "total_scanned_sample": len(parsed_records) + malformed_count,
            "readable_emails_count": readable_count,
            "malformed_emails_count": malformed_count,
            "unique_senders_count": len(sender_counts),
            "unique_recipients_count": len(recipient_counts),
            "unique_sender_domains_count": len(domain_counts),
            "duplicate_message_ids_count": duplicate_message_ids,
            "duplicate_content_hashes_count": duplicate_contents,
            "missing_field_statistics": dict(missing_stats),
            "header_presence_statistics": dict(header_stats),
            "url_statistics": url_stats,
            "top_10_users_by_volume": user_distribution.most_common(10),
            "top_10_sender_domains": domain_counts.most_common(10),
            "email_distribution_by_year_month": dict(sorted(time_distribution.items())),
            "corpus_contamination_notes": {
                "detected_count": len(suspicious_samples_in_enron),
                "summary": "The Enron corpus includes real-world historical unsolicited emails, commercial offers, lottery marketing, and IP-addressed communications received by employees.",
                "examples": suspicious_samples_in_enron[:5]
            }
        }

        return inventory, parsed_records

    @staticmethod
    def create_leakage_aware_split(
        parsed_emails: List[ParsedEmail],
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        test_ratio: float = 0.15,
        random_seed: int = 42
    ) -> Dict[str, Any]:
        """
        Disjoint-set union (Union-Find) clustering to strictly prevent:
        1. Duplicate emails from crossing partitions (content hash grouping).
        2. Email thread replies from crossing partitions (Message-ID, In-Reply-To, References).
        3. Normalized subject thread grouping (excluding empty subjects).
        """
        import random
        random.seed(random_seed)

        n = len(parsed_emails)
        parent = list(range(n))

        def find(i: int) -> int:
            path = []
            while parent[i] != i:
                path.append(i)
                i = parent[i]
            for node in path:
                parent[node] = i
            return i

        def union(i: int, j: int):
            root_i = find(i)
            root_j = find(j)
            if root_i != root_j:
                parent[root_i] = root_j

        # Track identifiers for graph connectivity
        msg_id_to_idx: Dict[str, int] = {}
        content_hash_to_idx: Dict[str, int] = {}
        subject_to_idx: Dict[str, int] = {}

        for idx, email_item in enumerate(parsed_emails):
            # 1. Exact Duplicate grouping via content hash
            ch = email_item.content_hash
            if ch:
                if ch in content_hash_to_idx:
                    union(idx, content_hash_to_idx[ch])
                else:
                    content_hash_to_idx[ch] = idx

            # 2. Message-ID mapping
            mid = email_item.message_id
            if mid:
                if mid in msg_id_to_idx:
                    union(idx, msg_id_to_idx[mid])
                else:
                    msg_id_to_idx[mid] = idx

            # 3. In-Reply-To linking
            irt = email_item.in_reply_to
            if irt and irt in msg_id_to_idx:
                union(idx, msg_id_to_idx[irt])

            # 4. References linking
            for ref in email_item.references:
                if ref in msg_id_to_idx:
                    union(idx, msg_id_to_idx[ref])

            # 5. Normalized subject grouping (ignoring generic empty subjects)
            subj = email_item.thread_id
            if subj and subj != "no_subject" and len(subj) > 3:
                if subj in subject_to_idx:
                    union(idx, subject_to_idx[subj])
                else:
                    subject_to_idx[subj] = idx

        # Gather disjoint connected clusters
        clusters = defaultdict(list)
        for idx in range(n):
            root = find(idx)
            clusters[root].append(idx)

        all_cluster_keys = list(clusters.keys())
        random.shuffle(all_cluster_keys)

        train_target = int(n * train_ratio)
        val_target = int(n * val_ratio)

        train_indices = []
        val_indices = []
        test_indices = []

        for key in all_cluster_keys:
            cluster_members = clusters[key]
            if len(train_indices) < train_target:
                train_indices.extend(cluster_members)
            elif len(val_indices) < val_target:
                val_indices.extend(cluster_members)
            else:
                test_indices.extend(cluster_members)

        split_summary = {
            "total_emails": n,
            "unique_threads": len(all_cluster_keys),
            "train_count": len(train_indices),
            "train_ratio": round(len(train_indices) / n, 4),
            "val_count": len(val_indices),
            "val_ratio": round(len(val_indices) / n, 4),
            "test_count": len(test_indices),
            "test_ratio": round(len(test_indices) / n, 4),
            "leakage_prevention_method": "Disjoint-Set Union clustering over Message-ID, In-Reply-To, References, Content Hash & Clean Subject",
            "train_indices": train_indices,
            "val_indices": val_indices,
            "test_indices": test_indices,
        }

        return split_summary
