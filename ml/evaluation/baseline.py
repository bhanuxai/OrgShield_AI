"""
OrgShield AI - Mandatory Keyword & Blocklist Baseline Detector
Serves as the deterministic rule-based benchmark evaluated alongside ML models.
"""

from __future__ import annotations
import re
from typing import Dict, List, Any
from ml.preprocessing.email_parser import ParsedEmail

# Baseline heuristic rules and keyword patterns
BASELINE_SUSPICIOUS_KEYWORDS = [
    r'\burgent\b', r'\baction required\b', r'\baccount suspended\b',
    r'\bverify your account\b', r'\bpassword expi', r'\bconfirm your identity\b',
    r'\bunauthorized access\b', r'\bsecurity alert\b', r'\bwire transfer\b',
    r'\bbank account\b', r'\blogin to verify\b', r'\bgift card\b',
    r'\bfree money\b', r'\bwon \$\d+\b', r'\blottery\b', r'\bprize\b',
    r'\bupdate your billing\b', r'\bpayroll update\b'
]

BASELINE_SUSPICIOUS_TLDS = ['.xyz', '.top', '.buzz', '.tk', '.ml', '.ga', '.cf', '.gq', '.loan', '.click']


class RuleBasedBaselineDetector:
    """
    Deterministic rule-based baseline combining keyword scanning,
    URL checks, and basic header mismatch detection.
    """

    def __init__(self, risk_threshold: float = 0.5):
        self.risk_threshold = risk_threshold
        self.keyword_patterns = [re.compile(p, re.IGNORECASE) for p in BASELINE_SUSPICIOUS_KEYWORDS]

    def score_email(self, email: ParsedEmail) -> Dict[str, Any]:
        """Score an email using deterministic heuristic rules."""
        rule_triggers = []
        score = 0.0

        # Rule 1: IP in URL
        if len(email.ip_urls) > 0:
            score += 0.40
            rule_triggers.append(f"Contains IP-based URL: {email.ip_urls[0]}")

        # Rule 2: Suspicious TLD
        for u in email.urls:
            for tld in BASELINE_SUSPICIOUS_TLDS:
                if tld in u.lower():
                    score += 0.35
                    rule_triggers.append(f"Contains high-risk TLD ({tld}): {u}")
                    break

        # Rule 3: Reply-To mismatch
        if email.reply_to_mismatch:
            score += 0.30
            rule_triggers.append(f"Reply-To domain ({email.reply_to_domain}) differs from From domain ({email.sender_domain})")

        # Rule 4: Suspicious keywords in Subject
        subj_matches = [p.pattern for p in self.keyword_patterns if p.search(email.subject)]
        if subj_matches:
            score += 0.25
            rule_triggers.append(f"Suspicious keyword in subject: {len(subj_matches)} matches")

        # Rule 5: Suspicious keywords in Body
        body_matches = [p.pattern for p in self.keyword_patterns if p.search(email.body)]
        if body_matches:
            score += min(0.35, 0.15 * len(body_matches))
            rule_triggers.append(f"Urgent/financial keywords in body: {len(body_matches)} matches")

        # Rule 6: Shortened URLs
        if len(email.shortened_urls) > 0:
            score += 0.20
            rule_triggers.append(f"Contains URL shortener: {email.shortened_urls[0]}")

        # Normalize score to [0.0, 1.0]
        final_score = min(1.0, round(score, 4))
        is_threat = final_score >= self.risk_threshold

        return {
            "model_name": "Rule-Based Baseline",
            "risk_score": final_score,
            "is_threat": is_threat,
            "threshold": self.risk_threshold,
            "triggered_rules": rule_triggers,
            "explanation": "; ".join(rule_triggers) if rule_triggers else "No baseline rules triggered"
        }
