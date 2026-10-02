"""
Static URL Threat Analysis Engine
Cybersecurity Project: Phishing Email Detection & Awareness Dashboard

Performs safe, passive static string analysis of URLs extracted from emails.
NEVER connects to, pings, or resolves target URLs to maintain zero-trust isolation.
"""

import re
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs

# Known URL shortener services (and safe test representation)
URL_SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
    "ow.ly", "buff.ly", "adf.ly", "short.invalid.test"
]

# Sensitive phishing tokens frequently present in credential harvesting URLs
SUSPICIOUS_URL_KEYWORDS = [
    "verify", "verification", "login", "signin", "auth", "authenticate",
    "secure", "security", "account", "update", "confirm", "portal",
    "banking", "password", "credential", "recover", "session", "token",
    "webscr", "ebayisapi", "wp-content", "admin", "redirect"
]

# IPv4 pattern
IPV4_PATTERN = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')


class URLAnalyzer:
    """
    Safely dissects and scores URLs using lexical and syntactic risk heuristics.
    """

    @classmethod
    def analyze_url(cls, url: str, displayed_text: str = "") -> Dict[str, Any]:
        """
        Performs static analysis on a single URL string without any network interaction.
        """
        if not url or not url.strip():
            return {
                "url": "",
                "url_risk_score": 0,
                "findings": ["No URL provided"],
                "properties": {}
            }

        url = url.strip()
        findings: List[str] = []
        score = 0

        # Parse structure safely
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query

        # Strip optional port if present
        host_without_port = netloc.split(":")[0] if netloc else ""

        # 1. Scheme Analysis
        if scheme == "http":
            findings.append("Insecure protocol: Uses unencrypted HTTP instead of HTTPS")
            score += 15
        elif scheme == "https":
            findings.append(
                "Protocol is HTTPS (Note: TLS encrypts transit, but does NOT guarantee website legitimacy)"
            )
        elif scheme and scheme not in ["http", "https"]:
            findings.append(f"Unusual or non-standard protocol: '{scheme}'")
            score += 20

        # 2. Raw IP Address as Hostname
        is_raw_ip = bool(IPV4_PATTERN.match(host_without_port))
        if is_raw_ip:
            findings.append(f"Host uses a raw numerical IP address ({host_without_port}) instead of a registered domain")
            score += 40

        # 3. URL Shortening Services
        is_shortener = any(host_without_port == s or host_without_port.endswith("." + s) for s in URL_SHORTENER_DOMAINS)
        if is_shortener:
            findings.append(f"URL uses a link shortener service ('{host_without_port}'), masking the actual destination")
            score += 25

        # 4. Excessive Subdomains
        host_parts = [p for p in host_without_port.split(".") if p]
        if len(host_parts) > 3 and not is_raw_ip:
            findings.append(f"Excessive subdomains in host ({len(host_parts)} levels: '{host_without_port}')")
            score += 20

        # 5. Suspicious Keywords in Path or Query
        url_lower = url.lower()
        detected_keywords = [kw for kw in SUSPICIOUS_URL_KEYWORDS if kw in url_lower]
        if detected_keywords:
            findings.append(f"Contains credential/authentication keywords: {', '.join(detected_keywords[:4])}")
            score += min(len(detected_keywords) * 8, 25)

        # 6. Deceptive Characters in URL
        if "@" in url:
            findings.append("URL contains '@' character, which can be used in browser address spoofing attacks")
            score += 35

        if "%" in url:
            findings.append("Contains URL-encoded hexadecimal characters (possible obfuscation technique)")
            score += 10

        # 7. URL and Host Length Heuristics
        if len(url) > 90:
            findings.append(f"Unusually long URL length ({len(url)} characters)")
            score += 10

        if len(host_without_port) > 32 and not is_raw_ip:
            findings.append(f"Unusually long hostname ({len(host_without_port)} characters)")
            score += 10

        # 8. Display Text Mismatch (Hyperlink Spoofing)
        # e.g., Display text appears as a legitimate domain, but destination points elsewhere
        if displayed_text and displayed_text.strip():
            clean_display = displayed_text.strip().lower()
            if any(dom in clean_display for dom in [".com", ".org", ".net", ".edu", "http://", "https://"]):
                # Display text looks like a link
                if host_without_port not in clean_display:
                    findings.append(
                        f"Hyperlink spoofing: Display text claims '{displayed_text.strip()}' but href points to '{host_without_port}'"
                    )
                    score += 45

        final_score = min(score, 100)

        if not findings:
            findings.append("Standard URL format with no suspicious syntactic anomalies detected")

        return {
            "url": url,
            "url_risk_score": final_score,
            "findings": findings,
            "properties": {
                "scheme": scheme,
                "hostname": host_without_port,
                "path": path,
                "query": query,
                "is_raw_ip": is_raw_ip,
                "is_shortener": is_shortener,
                "subdomain_count": max(0, len(host_parts) - 2) if not is_raw_ip else 0,
                "url_length": len(url),
                "hostname_length": len(host_without_port)
            }
        }
