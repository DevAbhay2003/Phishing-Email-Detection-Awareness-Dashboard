"""
Defensive Email Preprocessing Module
Cybersecurity Project: Phishing Email Detection & Awareness Dashboard

Handles text cleaning, URL extraction, domain extraction, and tokenization
while carefully PRESERVING cybersecurity evidence (e.g. uppercase shouting,
exclamation marks, currency symbols, and URL parameters).
"""

import re
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse

# Regular expression to extract URLs without executing or requesting them
URL_REGEX = re.compile(
    r'(?:http[s]?://|ftp://|www\.)[^\s<>"\',;]+|(?:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?::[0-9]+)?(?:/[^\s<>"\',;]*)?)',
    re.IGNORECASE
)

# Email address extraction regex
EMAIL_REGEX = re.compile(r'[\w\.-]+@([\w\.-]+)', re.IGNORECASE)


class EmailPreprocessor:
    """
    Safely preprocesses raw email metadata and text while preserving security signals.
    
    Security Context:
    Aggressive standard NLP preprocessing (such as stripping all punctuation, lowercase-only,
    or removing non-alphanumeric tokens) erases vital phishing markers like all-caps panic
    ("URGENT"), excessive punctuation ("ACT NOW!!!"), raw IP addresses, and suspicious parameters.
    This preprocessor retains those signals while normalizing data for downstream analysis.
    """

    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """
        Extracts all candidate URLs from body or subject text using static regex.
        Never navigates to or opens the links.
        """
        if not text:
            return []
        matches = URL_REGEX.findall(text)
        cleaned_urls = []
        for url in matches:
            u = url.strip().rstrip(".)],>")
            if not u.startswith("http://") and not u.startswith("https://") and not u.startswith("ftp://"):
                u = "http://" + u
            if u not in cleaned_urls:
                cleaned_urls.append(u)
        return cleaned_urls

    @staticmethod
    def extract_sender_parts(sender_raw: str) -> Dict[str, str]:
        """
        Parses display name, email address, and domain from raw sender string.
        Examples:
            '"HR Service" <hr@corp.example.com>' -> display: "HR Service", email: "hr@corp.example.com", domain: "corp.example.com"
            'admin@account-check.invalid.test' -> display: "", email: "admin@account-check.invalid.test", domain: "account-check.invalid.test"
        """
        display_name = ""
        email_address = ""
        domain = ""

        if not sender_raw:
            return {"display_name": "", "email_address": "", "domain": ""}

        # Extract display name if enclosed in quotes or preceding angle brackets
        angle_match = re.search(r'^(.*?)\s*<([^>]+)>', sender_raw)
        if angle_match:
            display_name = angle_match.group(1).strip(' "\'')
            email_address = angle_match.group(2).strip()
        else:
            email_address = sender_raw.strip(' <>"')

        # Domain extraction
        domain_match = EMAIL_REGEX.search(email_address)
        if domain_match:
            domain = domain_match.group(1).lower().strip()
        elif "@" in email_address:
            domain = email_address.split("@")[-1].lower().strip()

        return {
            "display_name": display_name,
            "email_address": email_address.lower(),
            "domain": domain
        }

    @staticmethod
    def extract_attachment_extension(filename: str) -> Dict[str, Any]:
        """
        Extracts extension and checks for double extension anomalies (e.g. invoice.pdf.exe).
        """
        if not filename or not filename.strip():
            return {
                "has_attachment": False,
                "filename": "",
                "extension": "",
                "all_extensions": [],
                "is_double_extension": False
            }

        clean_name = filename.strip()
        parts = clean_name.split(".")
        extensions = [p.lower() for p in parts[1:]]

        return {
            "has_attachment": True,
            "filename": clean_name,
            "extension": ("." + extensions[-1]) if extensions else "",
            "all_extensions": extensions,
            "is_double_extension": len(extensions) > 1
        }

    @staticmethod
    def clean_text_for_nlp(text: str) -> str:
        """
        Lightweight text cleaning for machine learning algorithms.
        Removes excessive whitespace and HTML tags, but keeps character casing & terms.
        """
        if not text:
            return ""
        # Strip simple HTML markup safely
        cleaned = re.sub(r'<[^>]+>', ' ', text)
        # Normalize multiple spaces and tabs
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        return cleaned

    @staticmethod
    def calculate_text_metrics(text: str) -> Dict[str, Any]:
        """
        Calculates text signals: uppercase ratio, exclamation count, length.
        """
        if not text:
            return {
                "char_length": 0,
                "word_count": 0,
                "uppercase_count": 0,
                "uppercase_ratio": 0.0,
                "exclamation_count": 0,
                "question_count": 0
            }

        letters = [c for c in text if c.isalpha()]
        uppercase = [c for c in letters if c.isupper()]
        words = text.split()

        ratio = (len(uppercase) / len(letters)) if letters else 0.0

        return {
            "char_length": len(text),
            "word_count": len(words),
            "uppercase_count": len(uppercase),
            "uppercase_ratio": round(ratio, 4),
            "exclamation_count": text.count("!"),
            "question_count": text.count("?")
        }
