"""Test for version extraction from banners - verifies the fix."""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.cybersec_cli.utils.version_detector import extract_version, VERSION_PATTERNS
import re

TEST_CASES = [
    # (banner, service, expected_version)
    (
        "220-host.secureserver.net ESMTP Exim 4.99.1 #2",
        "smtp",
        "4.99.1"
    ),
    (
        "SSH-2.0-OpenSSH_8.0",
        "ssh", 
        "8.0"
    ),
    (
        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        "ssh",
        "8.9p1"
    ),
    (
        "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n",
        "http",
        "1.24.0"
    ),
    (
        "X-Powered-By: Phusion Passenger(R) 6.1.2",
        "http",
        "6.1.2"
    ),
    (
        "+OK Dovecot ready.",
        "pop3",
        None  # Dovecot hides version — None is correct
    ),
    # Additional real-world test cases
    (
        "220-203.124.168.184.host.secureserver.net ESMTP Exim 4.99.1 #2 Fri, 20 Feb 2026 14:54:51 +0000",
        "smtp",
        "4.99.1"
    ),
    (
        "* OK [CAPABILITY IMAP4rev1 LOGIN-REFERRALS STARTTLS AUTH=PLAIN AUTH=LOGIN] Dovecot ready.",
        "imap",
        None  # Dovecot hides version
    ),
]

print("Testing version patterns...")
print("=" * 60)

all_pass = True
for banner, service, expected in TEST_CASES:
    result = extract_version(banner, service)
    got = result.version if result else None
    status = "✅" if got == expected else "❌"
    if got != expected:
        all_pass = False
    print(f"{status} service={service}: got={got!r} expected={expected!r}")

print()
print("=" * 60)
print("Real ggits.org scan scenario simulation:")
print("=" * 60)

REAL_BANNERS = [
    {
        "port": 22,
        "service": "ssh",
        "banner": "SSH-2.0-OpenSSH_8.0",
        "expected_version": "8.0"
    },
    {
        "port": 587,
        "service": "smtp",
        "banner": "220-203.124.168.184.host.secureserver.net "
                  "ESMTP Exim 4.99.1 #2 Fri, 20 Feb 2026 14:54:51 +0000",
        "expected_version": "4.99.1"
    },
    {
        "port": 80,
        "service": "http",
        "banner": "HTTP/1.1 200 OK\r\nServer: nginx\r\n"
                  "X-Powered-By: Next.js, Payload, "
                  "Phusion Passenger(R) 6.1.2\r\n",
        "expected_version": "6.1.2"  # Passenger version extracted
    },
    {
        "port": 110,
        "service": "pop3",
        "banner": "+OK Dovecot ready.",
        "expected_version": None  # Dovecot hides version — correct
    },
    {
        "port": 143,
        "service": "imap",
        "banner": "* OK [CAPABILITY IMAP4rev1 LOGIN-REFERRALS "
                  "STARTTLS AUTH=PLAIN AUTH=LOGIN] Dovecot ready.",
        "expected_version": None  # Dovecot hides version — correct
    },
    {
        "port": 111,
        "service": "unknown",
        "banner": "",
        "expected_version": None  # No banner
    },
]

print()
for case in REAL_BANNERS:
    result = extract_version(case["banner"], case["service"])
    got = result.version if result else None
    expected = case["expected_version"]
    status = "✅" if got == expected else "❌"
    if got != expected:
        all_pass = False
    print(f"{status} Port {case['port']} ({case['service']}): "
          f"got={got!r} expected={expected!r}")

print()
if all_pass:
    print("ALL BANNERS CORRECTLY PARSED")
    print("These ports would now show real versions instead of 'unknown'")
else:
    print("FAILURES REMAIN — fix patterns and re-run")
