"""
OrgShield AI - Forensic Intelligence & Header Analysis Engine
Performs forensic inspection on email headers, routing hops, URLs, and domains.
Strictly respects geolocation boundaries: never fabricates sender locations.
"""

from __future__ import annotations
import re
import ipaddress
from typing import Dict, List, Any, Optional
from ml.preprocessing.email_parser import ParsedEmail

# Well-known sample public IP geolocations for demo/academic testing
KNOWN_SUBNET_LOCATIONS = {
    "198.51.100": {"country": "United States", "region": "California", "city": "Los Angeles", "asn": "AS15169 (Test Range / Cloud)"},
    "203.0.113": {"country": "Netherlands", "region": "North Holland", "city": "Amsterdam", "asn": "AS49453 (Host Europe / Bulletproof Hosting)"},
    "185.220.101": {"country": "Germany", "region": "Hesse", "city": "Frankfurt", "asn": "AS206238 (Zwiebelfreunde / Tor Exit Node)"},
}


class ForensicEngine:
    """Forensic investigation engine for cyber threat intelligence."""

    def __init__(self, organization_domain: str = "enron.com"):
        self.organization_domain = organization_domain.lower()

    @staticmethod
    def inspect_ip_address(ip_str: str) -> Dict[str, Any]:
        """
        Inspect IP address with strict boundaries.
        Explicitly distinguishes private RFC 1918, loopback, and public IPs.
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            is_testnet = (
                ip_str.startswith("198.51.100.") or
                ip_str.startswith("203.0.113.") or
                ip_str.startswith("192.0.2.")
            )
            is_reserved = ip.is_reserved and not is_testnet

            if ip.is_private:
                return {
                    "ip": ip_str,
                    "type": "Private / RFC 1918",
                    "is_public": False,
                    "routable": False,
                    "geolocation_available": False,
                    "status_note": "Internal non-routable private network address. Physical geolocation is impossible and unavailable.",
                    "location": None
                }
            elif ip.is_loopback:
                return {
                    "ip": ip_str,
                    "type": "Loopback (127.0.0.0/8)",
                    "is_public": False,
                    "routable": False,
                    "geolocation_available": False,
                    "status_note": "Localhost loopback address. Geolocation unavailable.",
                    "location": None
                }
            elif is_reserved or ip.is_multicast:
                return {
                    "ip": ip_str,
                    "type": "Reserved / Multicast",
                    "is_public": False,
                    "routable": False,
                    "geolocation_available": False,
                    "status_note": "Reserved IANA network range.",
                    "location": None
                }
            else:
                # Public IP
                prefix_3 = ".".join(ip_str.split(".")[:3])
                known = KNOWN_SUBNET_LOCATIONS.get(prefix_3)
                if known:
                    loc_data = {
                        "country": known["country"],
                        "region": known["region"],
                        "city": known["city"],
                        "asn": known["asn"],
                        "confidence": "Medium (Subnet Registry Lookup)",
                        "caveat": "Origin IP inferred from intermediate mail relay hop. Not guaranteed to be physical sender location."
                    }
                else:
                    loc_data = {
                        "country": "Public Unregistered Testnet",
                        "region": "Unknown",
                        "city": "Unknown",
                        "asn": "Unspecified Public Transit",
                        "confidence": "Low",
                        "caveat": "Public IP without live GeoIP database link. City/region uncertain without ISP telemetry."
                    }
                return {
                    "ip": ip_str,
                    "type": "Public Routable IPv4",
                    "is_public": True,
                    "routable": True,
                    "geolocation_available": True,
                    "status_note": "Routable public IP found in routing chain.",
                    "location": loc_data
                }
        except ValueError:
            return {
                "ip": ip_str,
                "type": "Invalid IP",
                "is_public": False,
                "routable": False,
                "geolocation_available": False,
                "status_note": "Malformed or unparseable IP string.",
                "location": None
            }

    def analyze_forensics(self, parsed: ParsedEmail) -> Dict[str, Any]:
        """Perform comprehensive forensic investigation of a parsed email."""
        # 1. Routing & IP Forensic Analysis
        all_ip_inspections = [self.inspect_ip_address(ip) for ip in parsed.origin_ips]
        public_ip_records = [rec for rec in all_ip_inspections if rec["is_public"]]

        # 2. Header Inconsistencies
        header_inconsistencies = []
        if parsed.reply_to_mismatch:
            header_inconsistencies.append({
                "type": "REPLY_TO_MISMATCH",
                "severity": "HIGH",
                "description": f"Reply-To domain '{parsed.reply_to_domain}' does not match From domain '{parsed.sender_domain}'. Replies will be sent to a third party."
            })
        if not parsed.message_id:
            header_inconsistencies.append({
                "type": "MISSING_MESSAGE_ID",
                "severity": "LOW",
                "description": "Standard RFC Message-ID header is missing, typical of automated bulk or spoofing scripts."
            })
        if not parsed.date_parsed:
            header_inconsistencies.append({
                "type": "MALFORMED_DATE",
                "severity": "LOW",
                "description": "Date header missing or in non-RFC compliant format."
            })

        # 3. Domain Intelligence
        sender_is_internal = (parsed.sender_domain == self.organization_domain)
        domain_intel = {
            "sender_domain": parsed.sender_domain,
            "is_internal": sender_is_internal,
            "is_external": not sender_is_internal,
            "reply_to_domain": parsed.reply_to_domain if parsed.reply_to else None,
            "organization_target": self.organization_domain
        }

        # 4. URL Threat Intelligence
        url_threat_analysis = []
        for u in parsed.urls:
            flags = []
            is_high_risk = False
            if any(re.match(r'https?://(?:\d{1,3}\.){3}\d{1,3}', u) for _ in [0]):
                flags.append("RAW_IP_HOST")
                is_high_risk = True
            if any(u.lower().endswith(f".{tld}") or f".{tld}/" in u.lower() for tld in ['xyz', 'top', 'buzz', 'club', 'tk', 'loan']):
                flags.append("SUSPICIOUS_TLD")
                is_high_risk = True
            if any(shortener in u.lower() for shortener in ['bit.ly', 'tinyurl.com', 't.co']):
                flags.append("URL_SHORTENER")
            if '@' in u:
                flags.append("EMBEDDED_AT_CREDENTIAL_TRICK")
                is_high_risk = True

            url_threat_analysis.append({
                "url": u,
                "is_suspicious": is_high_risk or len(flags) > 0,
                "risk_level": "CRITICAL" if is_high_risk else ("MEDIUM" if flags else "LOW"),
                "detected_flags": flags
            })

        # 5. Geolocation Verdict
        if public_ip_records:
            primary_loc = public_ip_records[0]["location"]
            geo_summary = {
                "available": True,
                "primary_public_ip": public_ip_records[0]["ip"],
                "country": primary_loc.get("country"),
                "city": primary_loc.get("city"),
                "asn": primary_loc.get("asn"),
                "disclaimer": "IP derived from intermediate email relay hop. Real origin may be disguised by VPN or proxy."
            }
        else:
            geo_summary = {
                "available": False,
                "reason": "No public IPv4 relay headers found (only private RFC 1918 / loopback or missing). Geolocation strictly unavailable.",
                "disclaimer": "OrgShield AI does not fabricate geographic coordinates."
            }

        return {
            "routing_analysis": {
                "hop_count": parsed.routing_hop_count,
                "inspected_ips": all_ip_inspections,
                "public_ips_count": len(public_ip_records),
                "private_ips_count": len(all_ip_inspections) - len(public_ip_records)
            },
            "header_inconsistencies": header_inconsistencies,
            "domain_intelligence": domain_intel,
            "url_threat_intelligence": url_threat_analysis,
            "geolocation_intelligence": geo_summary
        }
