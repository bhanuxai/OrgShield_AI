"""
OrgShield AI - Feature Engineering Pipeline
Extracts multi-domain behavioral, content, URL, sender, routing, and time features.
Fits frequency baselines and TF-IDF strictly on training data (leakage-free).
"""

from __future__ import annotations
import re
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter
from sklearn.feature_extraction.text import TfidfVectorizer
from ml.preprocessing.email_parser import ParsedEmail

# Core threat vocabulary heuristics
URGENT_KEYWORDS = {
    'urgent', 'urgently', 'immediate', 'immediately', 'action required',
    'account suspended', 'suspended', 'deactivated', 'verify your account',
    'expire', 'expires', 'unauthorized', 'security alert', 'compromised',
    'final notice', 'critical notice', 'confirm your identity', 'password expires'
}

FINANCIAL_CREDENTIAL_KEYWORDS = {
    'bank', 'wire', 'transfer', 'invoice', 'payment', 'payroll', 'w-2',
    'gift card', 'bitcoin', 'crypto', 'wallet', 'ssn', 'tax refund',
    'credit card', 'statement', 'login', 'credentials', 'authenticate'
}

SUSPICIOUS_GREETINGS = {
    'dear customer', 'dear user', 'dear account holder', 'dear client',
    'valued customer', 'attention user', 'undisclosed recipients'
}


class EmailFeatureExtractor:
    """
    Extracts structured numerical feature vectors from ParsedEmail objects.
    Learns training baselines (sender frequencies, domain counts, TF-IDF)
    without data leakage.
    """

    def __init__(
        self,
        organization_domain: str = "enron.com",
        max_tfidf_features: int = 50,
        ngram_range: Tuple[int, int] = (1, 2)
    ):
        self.organization_domain = organization_domain.lower()
        self.max_tfidf_features = max_tfidf_features
        self.ngram_range = ngram_range
        
        # Baselines learned strictly during fit()
        self.sender_frequencies: Dict[str, int] = Counter()
        self.domain_frequencies: Dict[str, int] = Counter()
        self.sender_recipient_pairs: Dict[Tuple[str, str], int] = Counter()
        self.total_training_emails: int = 0
        
        # Text vectorizer
        self.tfidf_vectorizer: Optional[TfidfVectorizer] = None
        self.tfidf_feature_names: List[str] = []
        
        # Feature column definitions
        self.tabular_feature_names = [
            # A. Sender Features
            "sender_freq_log",
            "domain_freq_log",
            "is_first_time_sender",
            "is_external_sender",
            "max_sender_recip_pair_freq",
            # B. Communication Behaviour
            "recipient_count",
            "cc_count",
            "bcc_count",
            "external_recipient_count",
            "external_recipient_ratio",
            "is_mass_email",
            # C. Content Statistics & Keywords
            "subject_length",
            "subject_word_count",
            "body_length",
            "body_word_count",
            "subject_caps_ratio",
            "body_caps_ratio",
            "urgent_keyword_count",
            "financial_keyword_count",
            "suspicious_greeting_flag",
            # D. URL Features
            "url_count",
            "has_ip_url",
            "has_suspicious_tld",
            "suspicious_url_count",
            "shortened_url_count",
            "has_multiple_urls",
            # E. Time Features
            "sending_hour",
            "day_of_week",
            "is_weekend",
            "is_off_hours",
            # F. Header Features
            "reply_to_mismatch",
            "has_reply_to",
            "routing_hop_count",
            "has_public_ip",
            "missing_message_id",
            "missing_date"
        ]

    def fit(self, training_emails: List[ParsedEmail]) -> EmailFeatureExtractor:
        """Fit sender/domain historical distributions and TF-IDF on normal training emails."""
        self.total_training_emails = len(training_emails)
        self.sender_frequencies.clear()
        self.domain_frequencies.clear()
        self.sender_recipient_pairs.clear()

        corpus_texts = []
        for e in training_emails:
            if e.sender:
                self.sender_frequencies[e.sender] += 1
            if e.sender_domain:
                self.domain_frequencies[e.sender_domain] += 1
            for r in e.recipients:
                if e.sender and r:
                    self.sender_recipient_pairs[(e.sender, r)] += 1
            
            # Combine subject and body for TF-IDF
            combined = f"{e.subject} {e.body[:1500]}"
            corpus_texts.append(combined)

        # Fit TF-IDF on training corpus
        min_df_val = 2 if len(corpus_texts) >= 50 else 1
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=self.max_tfidf_features,
            ngram_range=self.ngram_range,
            stop_words='english',
            min_df=min_df_val
        )
        if corpus_texts:
            try:
                self.tfidf_vectorizer.fit(corpus_texts)
                self.tfidf_feature_names = [f"tfidf_{w}" for w in self.tfidf_vectorizer.get_feature_names_out()]
            except ValueError:
                # If vocabulary is empty after pruning, fallback with no stop words or empty
                self.tfidf_vectorizer = None
                self.tfidf_feature_names = []
        else:
            self.tfidf_vectorizer = None
            self.tfidf_feature_names = []

        return self

    def extract_single_tabular(self, email: ParsedEmail) -> Dict[str, float]:
        """Extract hand-engineered tabular features for an email."""
        # A. Sender Features
        s_freq = self.sender_frequencies.get(email.sender, 0)
        d_freq = self.domain_frequencies.get(email.sender_domain, 0)
        is_first_time = 1.0 if s_freq == 0 else 0.0
        is_external = 1.0 if (email.sender_domain and email.sender_domain != self.organization_domain) else 0.0
        
        pair_freqs = [
            self.sender_recipient_pairs.get((email.sender, r), 0)
            for r in email.recipients
        ]
        max_pair_freq = max(pair_freqs) if pair_freqs else 0.0

        # B. Communication Behaviour
        ext_recip_count = sum(
            1 for d in email.recipient_domains if d and d != self.organization_domain
        )
        ext_recip_ratio = (ext_recip_count / email.recipient_count) if email.recipient_count > 0 else 0.0
        is_mass = 1.0 if email.recipient_count > 10 else 0.0

        # C. Content features
        subj_caps = sum(1 for c in email.subject if c.isupper()) / max(1, len(email.subject))
        body_caps = sum(1 for c in email.body if c.isupper()) / max(1, len(email.body))
        
        lower_body = email.body.lower()
        lower_subj = email.subject.lower()
        combined_text = f"{lower_subj} {lower_body}"

        urgent_count = sum(1 for kw in URGENT_KEYWORDS if kw in combined_text)
        financial_count = sum(1 for kw in FINANCIAL_CREDENTIAL_KEYWORDS if kw in combined_text)
        has_suspicious_greeting = 1.0 if any(g in lower_body[:200] for g in SUSPICIOUS_GREETINGS) else 0.0

        # D. URL features
        has_ip_url = 1.0 if len(email.ip_urls) > 0 else 0.0
        has_susp_tld = 1.0 if any(
            any(t in u for t in ['.xyz', '.top', '.buzz', '.tk', '.loan', '.click'])
            for u in email.urls
        ) else 0.0
        susp_url_count = float(len(email.suspicious_urls))
        shortened_url_count = float(len(email.shortened_urls))
        has_multiple_urls = 1.0 if email.url_count >= 3 else 0.0

        # E. Time features
        sending_hour = float(email.sending_hour)
        day_of_week = float(email.day_of_week)
        is_weekend = 1.0 if email.is_weekend else 0.0
        is_off_hours = 1.0 if email.is_off_hours else 0.0

        # F. Header features
        reply_mismatch = 1.0 if email.reply_to_mismatch else 0.0
        has_reply = 1.0 if (email.reply_to and len(email.reply_to) > 0) else 0.0
        routing_hops = float(email.routing_hop_count)
        has_public_ip = 1.0 if len(email.public_ips) > 0 else 0.0
        missing_msg_id = 1.0 if not email.message_id else 0.0
        missing_date = 1.0 if not email.date_parsed else 0.0

        return {
            "sender_freq_log": float(np.log1p(s_freq)),
            "domain_freq_log": float(np.log1p(d_freq)),
            "is_first_time_sender": is_first_time,
            "is_external_sender": is_external,
            "max_sender_recip_pair_freq": float(np.log1p(max_pair_freq)),
            "recipient_count": float(email.recipient_count),
            "cc_count": float(len(email.cc)),
            "bcc_count": float(len(email.bcc)),
            "external_recipient_count": float(ext_recip_count),
            "external_recipient_ratio": float(ext_recip_ratio),
            "is_mass_email": is_mass,
            "subject_length": float(email.subject_length),
            "subject_word_count": float(len(email.subject.split())),
            "body_length": float(email.body_length),
            "body_word_count": float(len(email.body.split())),
            "subject_caps_ratio": float(subj_caps),
            "body_caps_ratio": float(body_caps),
            "urgent_keyword_count": float(urgent_count),
            "financial_keyword_count": float(financial_count),
            "suspicious_greeting_flag": has_suspicious_greeting,
            "url_count": float(email.url_count),
            "has_ip_url": has_ip_url,
            "has_suspicious_tld": has_susp_tld,
            "suspicious_url_count": susp_url_count,
            "shortened_url_count": shortened_url_count,
            "has_multiple_urls": has_multiple_urls,
            "sending_hour": sending_hour,
            "day_of_week": day_of_week,
            "is_weekend": is_weekend,
            "is_off_hours": is_off_hours,
            "reply_to_mismatch": reply_mismatch,
            "has_reply_to": has_reply,
            "routing_hop_count": routing_hops,
            "has_public_ip": has_public_ip,
            "missing_message_id": missing_msg_id,
            "missing_date": missing_date
        }

    def transform(self, emails: List[ParsedEmail]) -> np.ndarray:
        """
        Transform a list of ParsedEmail objects into a complete feature matrix (N x M).
        Combines tabular features with TF-IDF features.
        """
        tabular_rows = [self.extract_single_tabular(e) for e in emails]
        df_tabular = pd.DataFrame(tabular_rows, columns=self.tabular_feature_names).fillna(0.0)
        
        if self.tfidf_vectorizer:
            corpus_texts = [f"{e.subject} {e.body[:1500]}" for e in emails]
            tfidf_matrix = self.tfidf_vectorizer.transform(corpus_texts).toarray()
            X_all = np.hstack([df_tabular.values, tfidf_matrix])
        else:
            X_all = df_tabular.values

        return X_all

    def get_feature_names(self) -> List[str]:
        """Return all combined feature column names."""
        return self.tabular_feature_names + self.tfidf_feature_names

    def get_feature_breakdown(self, email: ParsedEmail) -> Dict[str, Any]:
        """Provides human-interpretable breakdown of feature values for forensics."""
        tab = self.extract_single_tabular(email)
        return {
            "sender_analysis": {
                "sender": email.sender,
                "domain": email.sender_domain,
                "is_first_time": bool(tab["is_first_time_sender"]),
                "is_external": bool(tab["is_external_sender"]),
                "historical_sender_frequency": int(np.expm1(tab["sender_freq_log"])),
                "historical_domain_frequency": int(np.expm1(tab["domain_freq_log"]))
            },
            "communication_analysis": {
                "recipient_count": int(tab["recipient_count"]),
                "external_recipient_count": int(tab["external_recipient_count"]),
                "is_mass_email": bool(tab["is_mass_email"])
            },
            "content_heuristics": {
                "urgent_keywords": int(tab["urgent_keyword_count"]),
                "financial_keywords": int(tab["financial_keyword_count"]),
                "suspicious_greeting": bool(tab["suspicious_greeting_flag"]),
                "subject_caps_ratio": round(tab["subject_caps_ratio"], 3)
            },
            "url_analysis": {
                "total_urls": int(tab["url_count"]),
                "has_ip_url": bool(tab["has_ip_url"]),
                "suspicious_urls_count": int(tab["suspicious_url_count"]),
                "urls_detected": email.urls[:5]
            },
            "routing_headers": {
                "reply_to_mismatch": bool(tab["reply_to_mismatch"]),
                "routing_hops": int(tab["routing_hop_count"]),
                "public_ips": email.public_ips,
                "private_ips": email.private_ips
            },
            "temporal_profile": {
                "hour": int(tab["sending_hour"]),
                "is_weekend": bool(tab["is_weekend"]),
                "is_off_hours": bool(tab["is_off_hours"])
            }
        }
