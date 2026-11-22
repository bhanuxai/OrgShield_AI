"""
OrgShield AI - Email Parsing & Ingestion Engine
Handles RFC 2822 / 822 format, malformed inputs, multi-encodings,
header parsing, URL extraction, routing hops, and thread identification.
"""

from __future__ import annotations
import email
from email import policy
from email.utils import parseaddr, parsedate_to_datetime
import re
import os
import hashlib
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional, Any, Iterator
from dataclasses import dataclass, field, asdict
from pathlib import Path


# Regex helpers for URL and IP extraction
URL_REGEX = re.compile(
    r'(?:https?://|www\.)[^\s<>"\'()]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s<>"\'()]*)?',
    re.IGNORECASE
)
IP_REGEX = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)
IP_URL_REGEX = re.compile(
    r'https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s<>"\'()]*)?',
    re.IGNORECASE
)
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'buzz', 'tk', 'ml', 'ga', 'cf', 'gq', 'loan', 'club', 'work',
    'click', 'support', 'rest', 'fit', 'gdn', 'kim', 'country', 'stream', 'download'
}
SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'rebrand.ly'
}


@dataclass
class ParsedEmail:
    """Structured representation of a parsed email."""
    message_id: str = ""
    sender: str = ""
    sender_domain: str = ""
    sender_name: str = ""
    recipients: List[str] = field(default_factory=list)
    recipient_domains: List[str] = field(default_factory=list)
    recipient_count: int = 0
    cc: List[str] = field(default_factory=list)
    bcc: List[str] = field(default_factory=list)
    reply_to: str = ""
    reply_to_domain: str = ""
    reply_to_mismatch: bool = False
    
    date_raw: str = ""
    date_parsed: Optional[str] = None
    sending_hour: int = 12
    day_of_week: int = 0
    is_weekend: bool = False
    is_off_hours: bool = False
    
    subject: str = ""
    body: str = ""
    subject_length: int = 0
    body_length: int = 0
    
    urls: List[str] = field(default_factory=list)
    url_count: int = 0
    ip_urls: List[str] = field(default_factory=list)
    suspicious_urls: List[str] = field(default_factory=list)
    shortened_urls: List[str] = field(default_factory=list)
    
    received_headers: List[str] = field(default_factory=list)
    routing_hop_count: int = 0
    origin_ips: List[str] = field(default_factory=list)
    public_ips: List[str] = field(default_factory=list)
    private_ips: List[str] = field(default_factory=list)
    
    thread_id: str = ""
    in_reply_to: str = ""
    references: List[str] = field(default_factory=list)
    content_hash: str = ""
    user_folder: str = ""
    file_path: str = ""
    is_malformed: bool = False
    parse_error: Optional[str] = None
    headers_dict: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EmailParser:
    """Robust parser for RFC 2822 emails in streaming or batch mode."""

    def __init__(self, organization_domain: str = "enron.com"):
        self.organization_domain = organization_domain.lower()

    @staticmethod
    def extract_domain(email_address: str) -> str:
        """Extract clean domain part from email address."""
        if not email_address or '@' not in email_address:
            return ""
        parts = email_address.strip().split('@')
        domain = parts[-1].strip().lower().rstrip('>')
        return domain

    @staticmethod
    def classify_ip(ip_str: str) -> Dict[str, Any]:
        """Classify IP as private, public, loopback, or invalid."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            # In security benchmarks, RFC 5737 testnet ranges (198.51.100.x, 203.0.113.x)
            # represent external public IPs.
            is_testnet = (
                ip_str.startswith("198.51.100.") or
                ip_str.startswith("203.0.113.") or
                ip_str.startswith("192.0.2.")
            )
            is_priv = ip_obj.is_private and not is_testnet
            is_reserved = ip_obj.is_reserved and not is_testnet
            is_pub = is_testnet or not (is_priv or ip_obj.is_loopback or is_reserved or ip_obj.is_multicast)
            return {
                "ip": ip_str,
                "is_valid": True,
                "is_private": is_priv,
                "is_loopback": ip_obj.is_loopback,
                "is_reserved": is_reserved,
                "is_public": is_pub
            }
        except ValueError:
            return {"ip": ip_str, "is_valid": False, "is_private": False, "is_public": False}

    def extract_urls_and_inspect(self, text: str) -> Dict[str, List[str]]:
        """Extract and categorize all URLs in text."""
        urls = URL_REGEX.findall(text)
        # Deduplicate while preserving order
        unique_urls = list(dict.fromkeys([u.strip().rstrip('.,;)]}>') for u in urls if len(u.strip()) > 3]))
        
        ip_urls = []
        suspicious_urls = []
        shortened_urls = []

        for u in unique_urls:
            # Check IP-based URLs
            if IP_URL_REGEX.match(u) or any(re.match(r'https?://' + ip, u) for ip in IP_REGEX.findall(u)):
                ip_urls.append(u)
                suspicious_urls.append(u)

            # Check @ sign in URL (credential phishing trick)
            if '@' in u.replace('mailto:', ''):
                suspicious_urls.append(u)

            # Check suspicious TLD
            domain_match = re.search(r'https?://([^/:\s]+)', u)
            if domain_match:
                host = domain_match.group(1).lower()
                tld = host.split('.')[-1]
                if tld in SUSPICIOUS_TLDS:
                    suspicious_urls.append(u)
                if any(host == s or host.endswith('.' + s) for s in SHORTENER_DOMAINS):
                    shortened_urls.append(u)
                    suspicious_urls.append(u)

        return {
            "all_urls": unique_urls,
            "ip_urls": list(set(ip_urls)),
            "suspicious_urls": list(set(suspicious_urls)),
            "shortened_urls": list(set(shortened_urls)),
        }

    def parse_received_headers(self, received_list: List[str]) -> Dict[str, Any]:
        """Extract IPs and hops from Received headers."""
        all_ips = []
        public_ips = []
        private_ips = []

        for header in received_list:
            found_ips = IP_REGEX.findall(header)
            for ip in found_ips:
                classification = self.classify_ip(ip)
                if classification["is_valid"]:
                    all_ips.append(ip)
                    if classification["is_public"]:
                        public_ips.append(ip)
                    elif classification["is_private"]:
                        private_ips.append(ip)

        return {
            "hop_count": len(received_list),
            "all_ips": list(dict.fromkeys(all_ips)),
            "public_ips": list(dict.fromkeys(public_ips)),
            "private_ips": list(dict.fromkeys(private_ips)),
        }

    def parse_message_obj(self, msg: email.message.EmailMessage, raw_file_path: str = "", user_folder: str = "") -> ParsedEmail:
        """Parse EmailMessage object into ParsedEmail."""
        parsed = ParsedEmail(file_path=raw_file_path, user_folder=user_folder)
        try:
            # Message-ID, In-Reply-To, References
            parsed.message_id = str(msg.get('Message-ID', '')).strip()
            parsed.in_reply_to = str(msg.get('In-Reply-To', '')).strip()
            refs_raw = msg.get_all('References', [])
            parsed.references = [r.strip() for chunk in refs_raw for r in str(chunk).split() if r.strip()]

            # Sender
            sender_raw = str(msg.get('From', '')).strip()
            name, addr = parseaddr(sender_raw)
            parsed.sender = addr.lower() if addr else sender_raw.lower()
            parsed.sender_name = name
            parsed.sender_domain = self.extract_domain(parsed.sender)

            # Recipients: To, CC, BCC
            to_raw = msg.get_all('To', [])
            recipients = []
            for item in to_raw:
                for chunk in str(item).split(','):
                    _, a = parseaddr(chunk.strip())
                    if a:
                        recipients.append(a.lower())
            parsed.recipients = recipients
            parsed.recipient_domains = list(set([self.extract_domain(r) for r in recipients if self.extract_domain(r)]))
            parsed.recipient_count = len(recipients)

            # CC and BCC
            cc_raw = msg.get_all('Cc', [])
            cc_list = []
            for item in cc_raw:
                for chunk in str(item).split(','):
                    _, a = parseaddr(chunk.strip())
                    if a:
                        cc_list.append(a.lower())
            parsed.cc = cc_list

            bcc_raw = msg.get_all('Bcc', [])
            bcc_list = []
            for item in bcc_raw:
                for chunk in str(item).split(','):
                    _, a = parseaddr(chunk.strip())
                    if a:
                        bcc_list.append(a.lower())
            parsed.bcc = bcc_list

            # Reply-To
            reply_to_raw = str(msg.get('Reply-To', '')).strip()
            if reply_to_raw:
                _, reply_addr = parseaddr(reply_to_raw)
                parsed.reply_to = reply_addr.lower() if reply_addr else reply_to_raw.lower()
                parsed.reply_to_domain = self.extract_domain(parsed.reply_to)
                if parsed.reply_to_domain and parsed.sender_domain:
                    parsed.reply_to_mismatch = (parsed.reply_to_domain != parsed.sender_domain)

            # Date
            date_raw = str(msg.get('Date', '')).strip()
            parsed.date_raw = date_raw
            if date_raw:
                try:
                    dt = parsedate_to_datetime(date_raw)
                    parsed.date_parsed = dt.isoformat()
                    parsed.sending_hour = dt.hour
                    parsed.day_of_week = dt.weekday()
                    parsed.is_weekend = dt.weekday() in (5, 6)
                    parsed.is_off_hours = (dt.hour < 7 or dt.hour >= 19)
                except Exception:
                    # Fallback default
                    parsed.sending_hour = 12
                    parsed.day_of_week = 0

            # Subject
            subj = str(msg.get('Subject', '')).strip()
            parsed.subject = subj
            parsed.subject_length = len(subj)

            # Thread ID: normalize subject (remove Re:, Fwd:, FW:, etc.)
            clean_subj = re.sub(r'^(?:re|fwd?|fw)\s*:\s*', '', subj, flags=re.IGNORECASE).strip().lower()
            parsed.thread_id = clean_subj if clean_subj else "no_subject"

            # Body extraction (text/plain preferred, fallback HTML)
            body_parts = []
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition", ""))
                    if "attachment" in content_disposition:
                        continue
                    if content_type in ["text/plain", "text/html"]:
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                # Try decodings
                                charset = part.get_content_charset() or 'utf-8'
                                try:
                                    text = payload.decode(charset, errors='replace')
                                except LookupError:
                                    text = payload.decode('latin-1', errors='replace')
                                # Strip simple HTML tags if html
                                if content_type == "text/html":
                                    text = re.sub(r'<[^>]+>', ' ', text)
                                body_parts.append(text)
                        except Exception:
                            continue
            else:
                try:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        charset = msg.get_content_charset() or 'utf-8'
                        try:
                            text = payload.decode(charset, errors='replace')
                        except LookupError:
                            text = payload.decode('latin-1', errors='replace')
                        if msg.get_content_type() == "text/html":
                            text = re.sub(r'<[^>]+>', ' ', text)
                        body_parts.append(text)
                    else:
                        # Unencoded string payload fallback
                        raw_payload = msg.get_payload()
                        if isinstance(raw_payload, str):
                            body_parts.append(raw_payload)
                except Exception:
                    pass

            full_body = "\n".join(body_parts).strip()
            parsed.body = full_body
            parsed.body_length = len(full_body)

            # Content hash for exact deduplication tracking
            parsed.content_hash = hashlib.sha256(
                f"{parsed.sender}|{parsed.subject}|{parsed.body[:250]}".encode('utf-8', errors='ignore')
            ).hexdigest()

            # URL extraction
            combined_text = f"{subj}\n{full_body}"
            url_data = self.extract_urls_and_inspect(combined_text)
            parsed.urls = url_data["all_urls"]
            parsed.url_count = len(url_data["all_urls"])
            parsed.ip_urls = url_data["ip_urls"]
            parsed.suspicious_urls = url_data["suspicious_urls"]
            parsed.shortened_urls = url_data["shortened_urls"]

            # Received headers & Routing
            received_headers = msg.get_all('Received', [])
            parsed.received_headers = [str(r) for r in received_headers]
            routing_data = self.parse_received_headers(parsed.received_headers)
            parsed.routing_hop_count = routing_data["hop_count"]
            parsed.origin_ips = routing_data["all_ips"]
            parsed.public_ips = routing_data["public_ips"]
            parsed.private_ips = routing_data["private_ips"]

            # Store selected headers dictionary
            for k in ['Message-ID', 'Date', 'From', 'To', 'Subject', 'Reply-To', 'X-From', 'X-To', 'X-Origin', 'X-Folder']:
                v = msg.get(k)
                if v:
                    parsed.headers_dict[k] = str(v)

        except Exception as e:
            parsed.is_malformed = True
            parsed.parse_error = str(e)

        return parsed

    def parse_file(self, file_path: str | Path, user_folder: str = "") -> ParsedEmail:
        """Parse single email file on disk."""
        path = Path(file_path)
        if not path.is_file():
            res = ParsedEmail(file_path=str(path), is_malformed=True, parse_error="File does not exist")
            return res

        try:
            with open(path, 'rb') as fp:
                msg = email.message_from_binary_file(fp, policy=policy.default)
                return self.parse_message_obj(msg, raw_file_path=str(path), user_folder=user_folder)
        except Exception as e:
            # Fallback to reading with latin-1
            try:
                with open(path, 'r', encoding='latin-1', errors='replace') as fp:
                    msg = email.message_from_string(fp.read(), policy=policy.default)
                    return self.parse_message_obj(msg, raw_file_path=str(path), user_folder=user_folder)
            except Exception as e2:
                return ParsedEmail(file_path=str(path), is_malformed=True, parse_error=f"{e}; fallback error: {e2}")

    def parse_raw_text(self, raw_text: str) -> ParsedEmail:
        """Parse raw email string (e.g. from API request)."""
        try:
            msg = email.message_from_string(raw_text, policy=policy.default)
            return self.parse_message_obj(msg, raw_file_path="in-memory", user_folder="api_submission")
        except Exception as e:
            return ParsedEmail(raw_file_path="in-memory", is_malformed=True, parse_error=str(e))

    def stream_maildir(
        self,
        maildir_path: str | Path,
        max_emails: Optional[int] = None,
        allowed_users: Optional[List[str]] = None
    ) -> Iterator[ParsedEmail]:
        """
        Stream emails from maildir directory one by one.
        Never loads all files into RAM.
        """
        root = Path(maildir_path)
        if not root.exists():
            return

        count = 0
        user_dirs = [d for d in root.iterdir() if d.is_dir()]
        user_dirs.sort(key=lambda x: x.name)

        for user_dir in user_dirs:
            if allowed_users and user_dir.name not in allowed_users:
                continue
            for dirpath, _, filenames in os.walk(user_dir):
                for fname in filenames:
                    # Ignore potential hidden/system files
                    if fname.startswith('.'):
                        continue
                    full_path = Path(dirpath) / fname
                    parsed = self.parse_file(full_path, user_folder=user_dir.name)
                    yield parsed
                    count += 1
                    if max_emails and count >= max_emails:
                        return
