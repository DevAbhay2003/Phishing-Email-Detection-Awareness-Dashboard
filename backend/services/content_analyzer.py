"""
Email Content & Social Engineering Analysis Engine
Cybersecurity Project: Phishing Email Detection & Awareness Dashboard

Scans email subject and body for psychological manipulation levers:
- Artificial Urgency & Scarcity
- Fear, Uncertainty, & Intimidation
- Financial Coercion / Impersonated Invoicing
- Credential Harvesting Requests
- Prize & Baiting Hooks
- Sensitive PII Collection
- Generic Impersonal Salutations
"""

import re
from typing import Dict, Any, List
from .preprocessor import EmailPreprocessor

# Dictionaries of psychological manipulation phrases
CATEGORY_PATTERNS = {
    "urgency": [
        r'\b(?:immediately|urgent(?:ly)?|act now|action required|hurry|at once)\b',
        r'\bwithin \d+ (?:hours?|minutes?|days?)\b',
        r'\b(?:today only|limited time|last chance|expires? (?:soon|today|in))\b',
        r'\b(?:immediate attention|do not delay|quick task)\b'
    ],
    "fear_threat": [
        r'\b(?:account (?:will be )?(?:suspended|disabled|terminated|closed|locked|deactivated))\b',
        r'\b(?:permanent(?:ly)? (?:deleted|deactivation|loss|lockout))\b',
        r'\b(?:unauthorized (?:access|login|transaction|activity))\b',
        r'\b(?:suspicious activity|security breach|law enforcement|legal action)\b',
        r'\b(?:failure to comply|violation of policy)\b'
    ],
    "financial_pressure": [
        r'\b(?:outstanding (?:balance|payment|invoice|amount))\b',
        r'\b(?:invoice (?:due|past due|attached|#\w+))\b',
        r'\b(?:wire transfer|remittance|delinquent|overdue)\b',
        r'\b(?:gift cards?|bitcoin|cryptocurrency|payout|unpaid balance)\b',
        r'\b(?:refund (?:pending|issued|approved))\b'
    ],
    "credential_request": [
        r'\b(?:verify (?:your )?(?:password|credentials|account|identity|login))\b',
        r'\b(?:confirm (?:your )?(?:password|login|credentials|pin))\b',
        r'\b(?:re-?authenticate|update (?:your )?(?:password|credentials|billing))\b',
        r'\b(?:enter (?:your )?(?:current password|user ?id|pin code))\b',
        r'\b(?:keep (?:the|your) same password|retain (?:your )?access)\b'
    ],
    "prize_reward": [
        r'\b(?:congratulations!|you (?:have )?won|grand prize|lottery|sweepstakes)\b',
        r'\b(?:claim your (?:prize|reward|gift card|bonus|cash))\b',
        r'\b(?:cashback bonus|selected (?:as winner|for cash payout))\b',
        r'\b(?:exclusive reward|free gift card)\b'
    ],
    "personal_info": [
        r'\b(?:social security|ssn|tax information|w-?2|date of birth)\b',
        r'\b(?:confirm (?:your )?(?:personal details|identity|banking details))\b',
        r'\b(?:credit card (?:number|details)|bank account (?:details|number))\b'
    ],
    "generic_greeting": [
        r'^(?:dear (?:customer|user|valued user|valued customer|sir/madam|member|client|account holder|employee))\b',
        r'\b(?:dear (?:customer|user|valued user|valued customer|sir/madam|member|client|account holder|employee))\b',
        r'\b(?:attention user|attention customer)\b'
    ]
}


class ContentAnalyzer:
    """
    Analyzes subject and body text for social engineering patterns.
    """

    @classmethod
    def analyze_email_content(cls, subject: str, body: str) -> Dict[str, Any]:
        """
        Scans subject and body for phishing and social engineering categories.
        Returns triggered categories, individual findings, matched terms, and content risk score.
        """
        combined_text = f"{subject or ''}\n{body or ''}"
        lower_combined = combined_text.lower()
        findings: List[str] = []
        triggered_categories: Dict[str, List[str]] = {}
        content_score = 0

        # 1. Match categories
        category_weights = {
            "urgency": 15,
            "fear_threat": 18,
            "financial_pressure": 15,
            "credential_request": 25,
            "prize_reward": 15,
            "personal_info": 20,
            "generic_greeting": 8
        }

        category_labels = {
            "urgency": "Urgency & Artificial Time Pressure",
            "fear_threat": "Fear & Intimidation Language",
            "financial_pressure": "Financial Coercion or Fake Billing",
            "credential_request": "Direct Credential Harvesting Request",
            "prize_reward": "Baiting / Unrealistic Reward Offer",
            "personal_info": "Sensitive Personal Data Request (PII)",
            "generic_greeting": "Generic Impersonal Salutation"
        }

        for cat_key, patterns in CATEGORY_PATTERNS.items():
            matched_snippets = []
            for pat in patterns:
                matches = re.findall(pat, lower_combined)
                if matches:
                    matched_snippets.extend(matches)
            
            if matched_snippets:
                unique_matches = list(dict.fromkeys(matched_snippets))
                triggered_categories[cat_key] = unique_matches
                weight = category_weights.get(cat_key, 10)
                content_score += weight
                findings.append(
                    f"{category_labels[cat_key]}: detected phrases like '{unique_matches[0]}'"
                )

        # 2. Subject line specific indicators
        if subject:
            sub_metrics = EmailPreprocessor.calculate_text_metrics(subject)
            if sub_metrics["uppercase_ratio"] > 0.45 and sub_metrics["char_length"] > 10:
                findings.append("Subject contains excessive uppercase letters (aggressive shouting)")
                content_score += 10
            if sub_metrics["exclamation_count"] >= 2:
                findings.append("Subject contains multiple exclamation marks (panic inducement)")
                content_score += 8

        # 3. Body text metrics
        body_metrics = EmailPreprocessor.calculate_text_metrics(body)
        if body_metrics["exclamation_count"] >= 3:
            findings.append("Body contains high frequency of exclamation marks")
            content_score += 6
        if body_metrics["uppercase_ratio"] > 0.35 and body_metrics["char_length"] > 40:
            findings.append("Body text contains abnormally high ratio of uppercase shouting")
            content_score += 8

        # Cap score between 0 and 100
        final_score = min(content_score, 100)

        if not findings:
            findings.append("No common social engineering or phishing manipulation language detected in body/subject")

        return {
            "content_risk_score": final_score,
            "triggered_categories": triggered_categories,
            "findings": findings,
            "metrics": {
                "subject_length": len(subject or ""),
                "body_length": len(body or ""),
                "uppercase_ratio": body_metrics["uppercase_ratio"],
                "exclamation_count": body_metrics["exclamation_count"]
            }
        }
