"""
Comprehensive Cybersecurity Automated Test Suite (25 Test Scenarios)
Project: Phishing Email Detection & Awareness Dashboard
"""

import pytest
import os
import sys

# Ensure root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.services.preprocessor import EmailPreprocessor
from backend.services.sender_analyzer import SenderAnalyzer
from backend.services.content_analyzer import ContentAnalyzer
from backend.services.url_analyzer import URLAnalyzer
from backend.services.attachment_analyzer import AttachmentAnalyzer
from backend.services.risk_engine import RiskEngine
from backend.services.hybrid_engine import HybridEngine
from backend.database import init_db, save_analysis, SessionLocal
from backend.models.schema import AnalysisRecord
from backend.app import app
from ml.predictor import MLPredictor


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Ensure database tables exist before testing."""
    init_db()
    MLPredictor.load_artifacts()


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# =========================================================================
# 1. Legitimate email
# =========================================================================
def test_01_legitimate_email():
    res = RiskEngine.calculate_phishing_score(
        sender="training@example.org",
        subject="Cybersecurity Workshop Reminder",
        body="Hello colleagues, this is a reminder for our training workshop on Thursday at 2 PM.",
        urls="https://corp.example.com/schedule",
        attachment_name="agenda.pdf"
    )
    assert res["risk_score"] <= 20
    assert res["classification"] == "LOW RISK"


# =========================================================================
# 2. Urgent phishing-style email
# =========================================================================
def test_02_urgent_phishing_style_email():
    res = RiskEngine.calculate_phishing_score(
        sender="security-alert@account-check.invalid.test",
        subject="URGENT: Verify Your Account Immediately",
        body="Your account will be suspended within 24 hours. Act now immediately!",
        urls="http://198.51.100.10/verify-account"
    )
    assert res["risk_score"] >= 70
    assert res["classification"] == "HIGH RISK / LIKELY PHISHING"


# =========================================================================
# 3. Credential request
# =========================================================================
def test_03_credential_request():
    res = ContentAnalyzer.analyze_email_content(
        subject="Password Verification",
        body="Please verify your password immediately to retain access."
    )
    assert "credential_request" in res["triggered_categories"]
    assert res["content_risk_score"] >= 25


# =========================================================================
# 4. Financial request
# =========================================================================
def test_04_financial_request():
    res = ContentAnalyzer.analyze_email_content(
        subject="Outstanding Invoice Due",
        body="Your account has an overdue outstanding payment of $4,850. Please execute wire transfer today."
    )
    assert "financial_pressure" in res["triggered_categories"]
    assert res["content_risk_score"] >= 15


# =========================================================================
# 5. Generic greeting
# =========================================================================
def test_05_generic_greeting():
    res = ContentAnalyzer.analyze_email_content(
        subject="Important Notice",
        body="Dear Valued Customer, please read our updated terms."
    )
    assert "generic_greeting" in res["triggered_categories"]


# =========================================================================
# 6. Safe URL
# =========================================================================
def test_06_safe_url():
    res = URLAnalyzer.analyze_url("https://corp.example.com/intranet/holidays")
    assert res["url_risk_score"] == 0
    assert res["properties"]["scheme"] == "https"
    assert not res["properties"]["is_raw_ip"]


# =========================================================================
# 7. Raw IP URL
# =========================================================================
def test_07_raw_ip_url():
    res = URLAnalyzer.analyze_url("http://198.51.100.10/verify-account")
    assert res["url_risk_score"] >= 40
    assert res["properties"]["is_raw_ip"] is True
    assert any("raw numerical IP" in f for f in res["findings"])


# =========================================================================
# 8. Non-HTTPS URL
# =========================================================================
def test_08_non_https_url():
    res = URLAnalyzer.analyze_url("http://example.com/welcome")
    assert res["properties"]["scheme"] == "http"
    assert any("Insecure protocol" in f for f in res["findings"])


# =========================================================================
# 9. Excessive subdomains
# =========================================================================
def test_09_excessive_subdomains():
    res = URLAnalyzer.analyze_url("http://auth.portal.security.update.example.com/login")
    assert res["properties"]["subdomain_count"] >= 3
    assert any("Excessive subdomains" in f for f in res["findings"])


# =========================================================================
# 10. Suspicious keyword in URL
# =========================================================================
def test_10_suspicious_keyword_in_url():
    res = URLAnalyzer.analyze_url("http://example.org/auth/login?redirect=account_verification")
    assert any("Contains credential/authentication keywords" in f for f in res["findings"])


# =========================================================================
# 11. No URL
# =========================================================================
def test_11_no_url():
    res = URLAnalyzer.analyze_url("")
    assert res["url_risk_score"] == 0
    assert "No URL provided" in res["findings"]


# =========================================================================
# 12. Multiple URLs
# =========================================================================
def test_12_multiple_urls():
    text = "Visit https://corp.example.com/home or check http://198.51.100.10/login"
    urls = EmailPreprocessor.extract_urls(text)
    assert len(urls) == 2
    assert "https://corp.example.com/home" in urls


# =========================================================================
# 13. Normal attachment
# =========================================================================
def test_13_normal_attachment():
    res = AttachmentAnalyzer.analyze_attachment("annual_report.pdf")
    assert res["attachment_risk_score"] == 0
    assert res["category"] == "SAFE / STANDARD"


# =========================================================================
# 14. Executable attachment
# =========================================================================
def test_14_executable_attachment():
    res = AttachmentAnalyzer.analyze_attachment("Security_Patch.exe")
    assert res["attachment_risk_score"] >= 80
    assert "Dangerous executable extension" in res["findings"][0]


# =========================================================================
# 15. Double extension
# =========================================================================
def test_15_double_extension():
    res = AttachmentAnalyzer.analyze_attachment("invoice.pdf.exe")
    assert res["details"]["is_double_extension"] is True
    assert res["attachment_risk_score"] >= 85
    assert any("Double Extension Deception" in f for f in res["findings"])


# =========================================================================
# 16. Empty subject
# =========================================================================
def test_16_empty_subject():
    res = RiskEngine.calculate_phishing_score(
        sender="notice@example.com",
        subject="",
        body="Here is standard informational text."
    )
    assert isinstance(res["risk_score"], int)
    assert res["risk_score"] <= 40


# =========================================================================
# 17. Empty body
# =========================================================================
def test_17_empty_body():
    res = RiskEngine.calculate_phishing_score(
        sender="notice@example.com",
        subject="Meeting at 2 PM",
        body=""
    )
    assert isinstance(res["risk_score"], int)
    assert res["classification"] in ["LOW RISK", "MODERATE RISK"]


# =========================================================================
# 18. Invalid sender
# =========================================================================
def test_18_invalid_sender():
    res = SenderAnalyzer.analyze_sender("invalid-sender-string-no-at-sign")
    assert res["sender_risk_score"] >= 40
    assert any("Invalid email address syntax" in f for f in res["findings"])


# =========================================================================
# 19. High uppercase ratio
# =========================================================================
def test_19_high_uppercase_ratio():
    res = ContentAnalyzer.analyze_email_content(
        subject="ATTENTION USER URGENT ACTION",
        body="PLEASE ACT IMMEDIATELY RIGHT NOW DO NOT DELAY"
    )
    assert any("uppercase" in f.lower() for f in res["findings"])


# =========================================================================
# 20. Multiple exclamation marks
# =========================================================================
def test_20_multiple_exclamation_marks():
    res = ContentAnalyzer.analyze_email_content(
        subject="Critical Security Alert!!!",
        body="Your account will be suspended today! Act immediately now!!!"
    )
    assert any("exclamation marks" in f for f in res["findings"])


# =========================================================================
# 21. Rule-score boundary
# =========================================================================
def test_21_rule_score_boundary():
    # Test capping at maximum 100
    res = RiskEngine.calculate_phishing_score(
        sender='"PayPal Security" <alert-verify@security-fake.invalid.test>',
        subject="URGENT: YOUR ACCOUNT SUSPENDED IN 2 HOURS!!!",
        body="Dear Customer, enter your password and social security number immediately at http://198.51.100.10/verify-account",
        urls="http://198.51.100.10/verify-account",
        attachment_name="UrgentForm.pdf.exe"
    )
    assert 0 <= res["risk_score"] <= 100
    assert res["risk_score"] >= 71
    assert res["classification"] == "HIGH RISK / LIKELY PHISHING"


# =========================================================================
# 22. Database save
# =========================================================================
def test_22_database_save():
    record = save_analysis(
        sender="test@example.org",
        sender_domain="example.org",
        subject="Test Automated Pipeline Email",
        risk_score=15,
        classification="LOW RISK",
        attachment_name="",
        indicators=[{"type": "TEST_IND", "description": "Automated test", "severity": "LOW"}],
        url_analyses=[]
    )
    assert record.analysis_id is not None
    assert record.subject == "Test Automated Pipeline Email"


# =========================================================================
# 23. API validation
# =========================================================================
def test_23_api_validation(client):
    # Sending completely empty body should yield 400 Bad Request
    response = client.post("/api/analyze", json={})
    assert response.status_code == 400
    data = response.get_json()
    assert data["success"] is False


# =========================================================================
# 24. ML prediction if enabled
# =========================================================================
def test_24_ml_prediction_if_enabled():
    res = MLPredictor.predict_phishing_probability(
        subject="Urgent Account Verification Alert",
        body="Please confirm your login password immediately to avoid suspension."
    )
    assert "phishing_probability" in res
    if res.get("available"):
        assert 0.0 <= res["phishing_probability"] <= 1.0


# =========================================================================
# 25. Analysis-history retrieval
# =========================================================================
def test_25_analysis_history_retrieval(client):
    response = client.get("/api/analyses")
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    assert isinstance(data["analyses"], list)
