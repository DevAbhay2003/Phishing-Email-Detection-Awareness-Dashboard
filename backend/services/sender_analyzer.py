"""
Defensive Sender Analysis Engine
Cybersecurity Project: Phishing Email Detection & Awareness Dashboard

Performs static heuristic analysis on email sender headers:
- Syntax and formatting
- Domain length and structure
- Excessive subdomains
- Typosquatting / brand spoofing in display name vs actual domain
- Suspicious TLDs and character combinations
"""

import re
from typing import Dict, Any, List
from .preprocessor import EmailPreprocessor

# Well-known brands frequently targeted by spearphishing
NOTABLE_BRANDS = [
    "microsoft", "office365", "google", "apple", "amazon", "paypal",
    "chase", "bankofamerica", "wellsfargo", "netflix", "dropbox",
    "dhl", "fedex", "usps", "irs", "helpdesk", "security"
]

# Suspicious domain keywords often found in phishing infrastructure
SUSPICIOUS_DOMAIN_TOKENS = [
    "verify", "alert", "secure", "auth", "login", "update",
    "account", "portal", "confirm", "billing", "support", "helpdesk",
    "security", "renew", "invoice", "service"
]


class SenderAnalyzer:
    """
    Evaluates risk signals associated with the sender's identity and domain.
    """

    @classmethod
    def analyze_sender(cls, sender_raw: str, expected_org: str = "") -> Dict[str, Any]:
        """
        Analyzes sender address, display name, and domain structure.
        Returns a sender risk score (0-100) and contextual findings.
        """
        parsed = EmailPreprocessor.extract_sender_parts(sender_raw)
        email_addr = parsed["email_address"]
        domain = parsed["domain"]
        display_name = parsed["display_name"]

        findings: List[str] = []
        score = 0

        if not sender_raw or not sender_raw.strip():
            return {
                "sender_risk_score": 30,
                "sender_email": "",
                "sender_domain": "",
                "display_name": "",
                "findings": ["Sender field is empty or missing"],
                "details": {"valid_format": False}
            }

        # 1. Format validation
        if not email_addr or "@" not in email_addr:
            findings.append("Invalid email address syntax (missing '@' or malformed)")
            score += 40
            return {
                "sender_risk_score": min(score, 100),
                "sender_email": email_addr,
                "sender_domain": domain,
                "display_name": display_name,
                "findings": findings,
                "details": {"valid_format": False}
            }

        domain_parts = domain.split(".")

        # 2. Subdomain analysis
        if len(domain_parts) > 3:
            findings.append(f"Excessive subdomains detected ({len(domain_parts)} parts: '{domain}')")
            score += 20

        # 3. Domain length check
        if len(domain) > 28:
            findings.append(f"Unusually long domain name ({len(domain)} characters)")
            score += 15

        # 4. Domain character anomalies (excessive hyphens, numbers)
        hyphen_count = domain.count("-")
        if hyphen_count >= 2:
            findings.append(f"Multiple hyphens in domain name ({hyphen_count} hyphens)")
            score += 15

        digits_in_domain = sum(c.isdigit() for c in domain)
        if digits_in_domain >= 3:
            findings.append(f"High number of numeric digits in domain ({digits_in_domain} digits)")
            score += 10

        # 5. Suspicious domain keywords
        matched_tokens = [tok for tok in SUSPICIOUS_DOMAIN_TOKENS if tok in domain]
        if matched_tokens:
            findings.append(f"Domain contains urgency/security keywords: {', '.join(matched_tokens)}")
            score += 20

        # 6. Display Name vs Domain Mismatch (Brand Impersonation / CEO Fraud)
        if display_name:
            norm_display = display_name.lower()
            for brand in NOTABLE_BRANDS:
                if brand in norm_display and brand not in domain:
                    findings.append(
                        f"Display name references '{brand.capitalize()}', but sender domain is '{domain}' (spoofing indicator)"
                    )
                    score += 35
                    break

            # If user provided an expected organization name
            if expected_org and expected_org.lower() in norm_display and expected_org.lower() not in domain:
                findings.append(
                    f"Display name mentions expected org '{expected_org}', but domain '{domain}' does not match"
                )
                score += 30

        # 7. Common Typosquatting / Leetspeak heuristics (e.g. micros0ft, paypa1)
        leetspeak_patterns = [
            (r'micros[0o]ft', 'microsoft'),
            (r'paypa[l1]', 'paypal'),
            (r'amaz[0o]n', 'amazon'),
            (r'app[l1]e', 'apple'),
            (r'g[0o]{2}gle', 'google')
        ]
        for pattern, brand in leetspeak_patterns:
            if re.search(pattern, domain) and domain != f"{brand}.com":
                findings.append(f"Potential typosquatting pattern detected mimicking '{brand}' in domain '{domain}'")
                score += 40

        # Context note: unfamiliar domains are not automatically malicious
        if not findings:
            findings.append("No obvious anomalies detected in sender address syntax or domain structure")

        return {
            "sender_risk_score": min(score, 100),
            "sender_email": email_addr,
            "sender_domain": domain,
            "display_name": display_name,
            "findings": findings,
            "details": {
                "domain_length": len(domain),
                "subdomain_count": max(0, len(domain_parts) - 2),
                "hyphen_count": hyphen_count,
                "has_display_mismatch": any("Display name" in f for f in findings)
            }
        }
