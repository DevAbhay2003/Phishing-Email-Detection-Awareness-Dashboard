"""
Email Feature Engineering Module
Cybersecurity Project: Phishing Email Detection & Awareness Dashboard

Transforms raw email metadata, linguistics, URL properties, and attachment data
into a structured numerical/boolean feature vector for machine learning and analytics.
"""

from typing import Dict, Any, List, Union
from .preprocessor import EmailPreprocessor
from .sender_analyzer import SenderAnalyzer
from .content_analyzer import ContentAnalyzer
from .url_analyzer import URLAnalyzer
from .attachment_analyzer import AttachmentAnalyzer


class FeatureExtractor:
    """
    Extracts standardized security features from email components.
    
    Feature Descriptions:
    1. urgent_keyword_count: Total phrases conveying extreme time urgency.
    2. credential_keyword_count: Mentions of password, login, credentials, authentication.
    3. financial_keyword_count: Invoicing, wire transfers, delinquent accounts, payments.
    4. threat_keyword_count: Account suspension, lockout, termination, legal threats.
    5. url_count: Total number of links embedded in the message.
    6. suspicious_url_count: Number of URLs with risk score >= 30.
    7. has_ip_url: 1 if any URL uses a dotted-quad IP address, else 0.
    8. has_shortened_url_pattern: 1 if any URL uses an obfuscating redirection service.
    9. sender_domain_length: Character count of sender's registered hostname.
    10. subdomain_count: Number of subdomain tiers in sender email.
    11. suspicious_attachment: 1 if attachment has dangerous script/executable/macro/double extension.
    12. generic_greeting: 1 if impersonal greeting ('Dear Customer') detected.
    13. contains_password_request: 1 if body solicits password reset or verification.
    14. contains_personal_info_request: 1 if body requests SSN, tax forms, or banking records.
    15. exclamation_count: Total frequency of '!' in subject and body.
    16. uppercase_ratio: Proportion of uppercase characters (indicative of psychological panic).
    17. body_length: Length of email body text in characters.
    18. subject_length: Length of subject line in characters.
    """

    @classmethod
    def extract_email_features(
        cls,
        sender: str,
        subject: str,
        body: str,
        urls: Union[str, List[str]] = "",
        attachment_name: str = ""
    ) -> Dict[str, Any]:
        """
        Extracts comprehensive tabular cybersecurity features.
        """
        # 1. URL extraction
        url_list: List[str] = []
        if isinstance(urls, list):
            url_list = urls
        elif isinstance(urls, str) and urls.strip():
            # If multiple URLs separated by commas or spaces, or extract from string
            extracted = EmailPreprocessor.extract_urls(urls)
            url_list = extracted if extracted else [urls.strip()]
        
        # Also extract any URLs embedded inside the body
        body_urls = EmailPreprocessor.extract_urls(body or "")
        for u in body_urls:
            if u not in url_list:
                url_list.append(u)

        # 2. Sub-component analyses
        sender_analysis = SenderAnalyzer.analyze_sender(sender)
        content_analysis = ContentAnalyzer.analyze_email_content(subject, body)
        attachment_analysis = AttachmentAnalyzer.analyze_attachment(attachment_name)

        analyzed_urls = [URLAnalyzer.analyze_url(u) for u in url_list]
        suspicious_urls = [res for res in analyzed_urls if res["url_risk_score"] >= 30]
        has_ip = any(res["properties"].get("is_raw_ip", False) for res in analyzed_urls)
        has_shortener = any(res["properties"].get("is_shortener", False) for res in analyzed_urls)

        # 3. Linguistic metrics
        categories = content_analysis.get("triggered_categories", {})
        body_metrics = EmailPreprocessor.calculate_text_metrics(body)
        subject_metrics = EmailPreprocessor.calculate_text_metrics(subject)

        features: Dict[str, Any] = {
            "urgent_keyword_count": len(categories.get("urgency", [])),
            "credential_keyword_count": len(categories.get("credential_request", [])),
            "financial_keyword_count": len(categories.get("financial_pressure", [])),
            "threat_keyword_count": len(categories.get("fear_threat", [])),
            "prize_keyword_count": len(categories.get("prize_reward", [])),
            "url_count": len(url_list),
            "suspicious_url_count": len(suspicious_urls),
            "has_ip_url": 1 if has_ip else 0,
            "has_shortened_url_pattern": 1 if has_shortener else 0,
            "sender_domain_length": sender_analysis["details"].get("domain_length", 0),
            "subdomain_count": sender_analysis["details"].get("subdomain_count", 0),
            "suspicious_attachment": 1 if attachment_analysis.get("attachment_risk_score", 0) >= 40 else 0,
            "generic_greeting": 1 if "generic_greeting" in categories else 0,
            "contains_password_request": 1 if "credential_request" in categories else 0,
            "contains_personal_info_request": 1 if "personal_info" in categories else 0,
            "exclamation_count": body_metrics["exclamation_count"] + subject_metrics["exclamation_count"],
            "uppercase_ratio": round((body_metrics["uppercase_ratio"] + subject_metrics["uppercase_ratio"]) / 2, 4),
            "body_length": body_metrics["char_length"],
            "subject_length": subject_metrics["char_length"]
        }

        return features
