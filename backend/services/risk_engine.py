"""
Rule-Based Phishing Risk Engine & Explainable Security Evaluator
Cybersecurity Project: Phishing Email Detection & Awareness Dashboard

Calculates a normalized threat score (0-100), maps it to a defensive classification tier,
and generates human-readable, explainable security justifications and actionable SOP guidance.
"""

from typing import Dict, Any, List, Union
from .preprocessor import EmailPreprocessor
from .sender_analyzer import SenderAnalyzer
from .content_analyzer import ContentAnalyzer
from .url_analyzer import URLAnalyzer
from .attachment_analyzer import AttachmentAnalyzer
from .feature_extractor import FeatureExtractor


class RiskEngine:
    """
    Synthesizes multi-vector email indicators into a unified, explainable risk score.
    """

    # Calibrated risk tier thresholds
    TIER_LOW = 20
    TIER_MODERATE = 40
    TIER_SUSPICIOUS = 70

    @classmethod
    def calculate_phishing_score(
        cls,
        sender: str,
        subject: str,
        body: str,
        urls: Union[str, List[str]] = "",
        attachment_name: str = "",
        expected_org: str = ""
    ) -> Dict[str, Any]:
        """
        Runs comprehensive heuristic analysis across all components and generates
        risk score, classification, explainable evidence, and defensive recommendations.
        """
        # 1. Component Level Analyses
        sender_res = SenderAnalyzer.analyze_sender(sender, expected_org)
        content_res = ContentAnalyzer.analyze_email_content(subject, body)
        attachment_res = AttachmentAnalyzer.analyze_attachment(attachment_name)

        # URLs extraction and analysis
        url_list: List[str] = []
        if isinstance(urls, list):
            url_list = [u.strip() for u in urls if u.strip()]
        elif isinstance(urls, str) and urls.strip():
            extracted = EmailPreprocessor.extract_urls(urls)
            url_list = extracted if extracted else [urls.strip()]
        
        # Include any URLs extracted directly from body
        body_urls = EmailPreprocessor.extract_urls(body or "")
        for u in body_urls:
            if u not in url_list:
                url_list.append(u)

        url_analyses = [URLAnalyzer.analyze_url(u) for u in url_list]
        max_url_score = max([u["url_risk_score"] for u in url_analyses], default=0)

        # 2. Weighted Score Aggregation
        # Weights represent the evidentiary strength of each vector
        raw_score = 0
        indicators_breakdown: List[Dict[str, Any]] = []

        # A. Attachment Vector (High malicious potential if executable/double-extension)
        att_score = attachment_res.get("attachment_risk_score", 0)
        if att_score >= 80:
            raw_score += 40
            indicators_breakdown.append({
                "type": "ATTACHMENT_CRITICAL",
                "severity": "CRITICAL",
                "points": 40,
                "description": f"Dangerous attachment type detected: {attachment_res.get('extension')} ({attachment_res.get('category')})"
            })
        elif att_score >= 40:
            raw_score += 20
            indicators_breakdown.append({
                "type": "ATTACHMENT_SUSPICIOUS",
                "severity": "HIGH",
                "points": 20,
                "description": f"Suspicious container or macro-enabled attachment: {attachment_res.get('extension')}"
            })

        # B. URL Vector (Raw IP, Shorteners, Credential Keywords)
        if max_url_score >= 40:
            raw_score += 30
            indicators_breakdown.append({
                "type": "URL_HIGH_RISK",
                "severity": "HIGH",
                "points": 30,
                "description": "Suspicious URL identified (Raw IP, spoofed text, or credential harvesting pattern)"
            })
        elif max_url_score >= 20:
            raw_score += 15
            indicators_breakdown.append({
                "type": "URL_MODERATE_RISK",
                "severity": "MEDIUM",
                "points": 15,
                "description": "URL with suspicious characteristics (HTTP protocol, excessive subdomains, or shortener)"
            })

        # C. Sender Vector (Spoofing, Lookalikes, Syntax)
        snd_score = sender_res.get("sender_risk_score", 0)
        if snd_score >= 35:
            raw_score += 25
            indicators_breakdown.append({
                "type": "SENDER_ANOMALY",
                "severity": "HIGH",
                "points": 25,
                "description": "High sender risk: Brand impersonation, typosquatting pattern, or excessive subdomains"
            })
        elif snd_score >= 15:
            raw_score += 12
            indicators_breakdown.append({
                "type": "SENDER_UNUSUAL",
                "severity": "MEDIUM",
                "points": 12,
                "description": "Sender domain contains unusual syntax or security keywords"
            })

        # D. Content Vectors
        categories = content_res.get("triggered_categories", {})
        if "credential_request" in categories:
            raw_score += 25
            indicators_breakdown.append({
                "type": "CONTENT_CREDENTIAL_SOLICITATION",
                "severity": "CRITICAL",
                "points": 25,
                "description": "Explicit request for credentials, login verification, or password confirmation"
            })

        if "urgency" in categories:
            raw_score += 12
            indicators_breakdown.append({
                "type": "CONTENT_ARTIFICIAL_URGENCY",
                "severity": "MEDIUM",
                "points": 12,
                "description": "High urgency language coercing quick action to bypass critical scrutiny"
            })

        if "fear_threat" in categories:
            raw_score += 15
            indicators_breakdown.append({
                "type": "CONTENT_FEAR_INTIMIDATION",
                "severity": "HIGH",
                "points": 15,
                "description": "Intimidation or punitive threats (account suspension, termination, legal claims)"
            })

        if "financial_pressure" in categories:
            raw_score += 12
            indicators_breakdown.append({
                "type": "CONTENT_FINANCIAL_PRESSURE",
                "severity": "MEDIUM",
                "points": 12,
                "description": "Financial coercion, fake invoice, or wire transfer solicitations"
            })

        if "prize_reward" in categories:
            raw_score += 15
            indicators_breakdown.append({
                "type": "CONTENT_UNREALISTIC_REWARD",
                "severity": "MEDIUM",
                "points": 15,
                "description": "Baiting tactic offering unsolicited prizes, gift cards, or sweepstakes"
            })

        if "personal_info" in categories:
            raw_score += 15
            indicators_breakdown.append({
                "type": "CONTENT_PII_REQUEST",
                "severity": "HIGH",
                "points": 15,
                "description": "Unprompted solicitation for sensitive PII (SSN, tax records, banking info)"
            })

        if "generic_greeting" in categories:
            raw_score += 5
            indicators_breakdown.append({
                "type": "CONTENT_GENERIC_GREETING",
                "severity": "LOW",
                "points": 5,
                "description": "Impersonal greeting ('Dear Customer') commonly seen in mass phishing campaigns"
            })

        # Cap score at 100
        final_score = min(max(raw_score, 0), 100)

        # 3. Defensive Classification Mapping
        if final_score <= cls.TIER_LOW:
            classification = "LOW RISK"
            color_code = "#22c55e"  # Green
            threat_level = "Informational / Benign"
        elif final_score <= cls.TIER_MODERATE:
            classification = "MODERATE RISK"
            color_code = "#eab308"  # Yellow
            threat_level = "Caution Advised"
        elif final_score <= cls.TIER_SUSPICIOUS:
            classification = "SUSPICIOUS"
            color_code = "#f97316"  # Orange
            threat_level = "Potential Threat"
        else:
            classification = "HIGH RISK / LIKELY PHISHING"
            color_code = "#ef4444"  # Red
            threat_level = "High Confidence Threat"

        # 4. Generate Actionable Security Recommendations
        recommendations = cls._generate_security_recommendations(
            classification, indicators_breakdown, has_attachment=attachment_res.get("has_attachment", False), has_url=len(url_list) > 0
        )

        # 5. Extract Tabular Features for ML / Analytics
        features = FeatureExtractor.extract_email_features(
            sender=sender, subject=subject, body=body, urls=url_list, attachment_name=attachment_name
        )

        return {
            "risk_score": final_score,
            "classification": classification,
            "threat_level": threat_level,
            "color_code": color_code,
            "indicators": indicators_breakdown,
            "recommendations": recommendations,
            "sender_analysis": sender_res,
            "content_analysis": content_res,
            "url_analyses": url_analyses,
            "attachment_analysis": attachment_res,
            "features": features
        }

    @staticmethod
    def _generate_security_recommendations(
        classification: str,
        indicators: List[Dict[str, Any]],
        has_attachment: bool,
        has_url: bool
    ) -> List[str]:
        """
        Tailors defensive advice according to the identified indicators and classification.
        """
        recs: List[str] = []

        if classification == "LOW RISK":
            recs.append("Email displays typical characteristics of legitimate communication.")
            recs.append("Continue to observe standard security hygiene: never share passwords via email.")
            return recs

        # For Moderate, Suspicious, or High Risk
        recs.append("DO NOT reply to this email or share any credentials, passwords, or personal details.")

        if has_url:
            recs.append("DO NOT click any hyperlinks or copy-paste URLs into your web browser.")
            recs.append("Navigate to the service directly by typing the known official domain in a fresh tab.")

        if has_attachment:
            recs.append("DO NOT download, preview, or open the email attachment under any circumstances.")

        recs.append("Verify the sender's authenticity using an independent, out-of-band communication channel (e.g. phone call or verified internal directory).")
        recs.append("Escalate and forward this message as an attachment (.eml) to your organization's Security Operations Center (SOC) or IT Helpdesk.")

        if any(ind["type"] == "SENDER_ANOMALY" for ind in indicators):
            recs.append("Be wary of sender domain spoofing; examine the actual email header domain rather than the friendly display name.")

        return recs
