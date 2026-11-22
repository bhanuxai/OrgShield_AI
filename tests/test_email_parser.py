"""
Unit tests for OrgShield AI EmailParser and IP / URL extraction.
"""

from ml.preprocessing.email_parser import EmailParser


def test_clean_enron_email_parsing():
    parser = EmailParser()
    raw = """Message-ID: <12345.JavaMail.evans@thyme>
Date: Mon, 14 May 2001 09:30:00 -0500
From: phillip.allen@enron.com
To: john.arnold@enron.com, mike.grigsby@enron.com
Subject: Natural Gas Pipeline Update

John, Mike,
The storage capacity report is attached. Review before the trading desk opens.
"""
    parsed = parser.parse_raw_text(raw)
    assert parsed.is_malformed is False
    assert parsed.sender == "phillip.allen@enron.com"
    assert parsed.sender_domain == "enron.com"
    assert len(parsed.recipients) == 2
    assert parsed.sending_hour == 9
    assert parsed.is_weekend is False
    assert parsed.reply_to_mismatch is False


def test_phishing_url_and_reply_to_mismatch():
    parser = EmailParser()
    raw = """Message-ID: <threat-999@alert.xyz>
Date: Sun, 11 Nov 2001 02:15:00 -0600
From: alert@wellsfargo-verify.top
Reply-To: collector@evil-harvest.xyz
To: victim@enron.com
Subject: URGENT: Account Suspension Notice

Your account has been locked. Verify immediately at http://198.51.100.24/auth/login.php
"""
    parsed = parser.parse_raw_text(raw)
    assert parsed.reply_to_mismatch is True
    assert parsed.reply_to_domain == "evil-harvest.xyz"
    assert len(parsed.ip_urls) == 1
    assert "http://198.51.100.24/auth/login.php" in parsed.ip_urls
    assert parsed.is_off_hours is True
    assert parsed.is_weekend is True


def test_ip_classification():
    parser = EmailParser()
    private_res = parser.classify_ip("192.168.1.10")
    assert private_res["is_private"] is True
    assert private_res["is_public"] is False

    loopback_res = parser.classify_ip("127.0.0.1")
    assert loopback_res["is_loopback"] is True
    assert loopback_res["is_public"] is False

    public_res = parser.classify_ip("185.220.101.5")
    assert public_res["is_public"] is True
    assert public_res["is_private"] is False


def test_rfc2822_threading_and_content_hash():
    parser = EmailParser()
    raw = """Message-ID: <reply123@enron.com>
Date: Tue, 15 May 2001 10:00:00 -0500
From: john.arnold@enron.com
To: phillip.allen@enron.com
Subject: Re: Natural Gas Pipeline Update
In-Reply-To: <12345.JavaMail.evans@thyme>
References: <12345.JavaMail.evans@thyme>

Reviewed and agreed.
"""
    parsed = parser.parse_raw_text(raw)
    assert parsed.in_reply_to == "<12345.JavaMail.evans@thyme>"
    assert "<12345.JavaMail.evans@thyme>" in parsed.references
    assert len(parsed.content_hash) == 64  # SHA-256 hash
