"""
Analysis API Routes
Cybersecurity Project: Phishing Email Detection & Awareness Dashboard
"""

from flask import Blueprint, request, jsonify
from backend.services.hybrid_engine import HybridEngine
from backend.services.url_analyzer import URLAnalyzer
from backend.database import save_analysis
from backend.utils.helpers import sanitize_string, parse_eml_file

analyze_bp = Blueprint("analyze_bp", __name__)

# Preloaded safe demonstration samples for education and testing
SAMPLE_EMAILS = [
    {
        "id": "sample-phish-urgent",
        "name": "Urgent Account Verification (Phishing)",
        "sender": '"Security Alert" <security-alert@account-check.invalid.test>',
        "subject": "URGENT: Verify Your Account Immediately",
        "body": "Dear Customer,\n\nWe have detected unauthorized login attempts from an unrecognized device. Your account will be permanently deactivated within 24 hours unless you confirm your password and personal details immediately.\n\nClick the link below to verify:\nhttp://198.51.100.10/verify-account\n\nFailure to comply will result in immediate suspension.\n\nIT Security Operations",
        "urls": "http://198.51.100.10/verify-account",
        "attachment_name": ""
    },
    {
        "id": "sample-phish-invoice",
        "name": "Overdue Fake Invoice (Malicious Attachment)",
        "sender": '"Accounts Payable" <billing-dept@order-confirmations.invalid.test>',
        "subject": "FINAL NOTICE: Overdue Invoice #INV-99382",
        "body": "Dear Sir/Madam,\n\nPlease find attached the final overdue invoice for the amount of $4,850.00. Immediate payment is required today to prevent legal collection actions.\n\nPlease open the attached remittance statement immediately.\n\nAccounting Department",
        "urls": "http://short.invalid.test/verify-9921",
        "attachment_name": "Invoice_99382.pdf.exe"
    },
    {
        "id": "sample-phish-ceo",
        "name": "CEO Fraud / Wire Transfer (Social Engineering)",
        "sender": '"Chief Executive Officer" <ceo-office@it-support-desk.invalid.test>',
        "subject": "QUICK TASK: Are You At Your Desk Right Now?",
        "body": "Are you at your desk right now? I am currently in a confidential executive meeting and cannot take phone calls.\n\nI need you to process an urgent confidential wire transfer of $24,500 immediately. Access the instructions at http://secure-banking.invalid.test/auth/login?redirect=wire.\n\nKeep this strictly between us.",
        "urls": "http://secure-banking.invalid.test/auth/login?redirect=wire",
        "attachment_name": ""
    },
    {
        "id": "sample-legit-workshop",
        "name": "Security Workshop Notice (Legitimate)",
        "sender": '"Cybersecurity Training" <training@example.org>',
        "subject": "Cybersecurity Workshop Reminder",
        "body": "Hello team,\n\nThis is a friendly reminder that our annual defensive cybersecurity awareness workshop will take place this Thursday at 2:00 PM via the campus video bridge.\n\nYou can review the upcoming training schedule on the internal intranet: https://corp.example.com/intranet/holidays.\n\nNo login credentials or confidential actions are required.",
        "urls": "https://corp.example.com/intranet/holidays",
        "attachment_name": "workshop_agenda.pdf"
    }
]


@analyze_bp.route("/samples", methods=["GET"])
def get_sample_emails():
    """Returns safe demonstration emails for quick triage testing."""
    return jsonify({"success": True, "samples": SAMPLE_EMAILS})


@analyze_bp.route("/analyze", methods=["POST"])
def analyze_email():
    """
    Main triage endpoint.
    Accepts JSON body or multipart form (with optional .eml / .txt file upload).
    """
    sender = ""
    subject = ""
    body = ""
    urls = ""
    attachment_name = ""
    expected_org = ""

    # Check for file upload (.eml or .txt)
    if "file" in request.files:
        upload = request.files["file"]
        if upload.filename != "":
            raw_bytes = upload.read()
            if upload.filename.lower().endswith(".eml"):
                parsed = parse_eml_file(raw_bytes)
                if parsed["success"]:
                    sender = parsed["sender"]
                    subject = parsed["subject"]
                    body = parsed["body"]
                    attachment_name = parsed["attachment_name"]
            else:
                # Treat as raw text
                body = raw_bytes.decode("utf-8", errors="replace")

    # Read JSON or Form fields (form fields override parsed file if explicitly provided)
    if request.is_json:
        data = request.get_json() or {}
        sender = data.get("sender", sender)
        subject = data.get("subject", subject)
        body = data.get("body", body)
        urls = data.get("urls", urls)
        attachment_name = data.get("attachment_name", attachment_name)
        expected_org = data.get("expected_org", "")
    else:
        sender = request.form.get("sender", sender)
        subject = request.form.get("subject", subject)
        body = request.form.get("body", body)
        urls = request.form.get("urls", urls)
        attachment_name = request.form.get("attachment_name", attachment_name)
        expected_org = request.form.get("expected_org", "")

    # Sanitize inputs
    sender = sanitize_string(sender, 255)
    subject = sanitize_string(subject, 500)
    body = sanitize_string(body, 50000)
    urls = sanitize_string(urls, 2000)
    attachment_name = sanitize_string(attachment_name, 255)
    expected_org = sanitize_string(expected_org, 100)

    if not subject and not body and not sender:
        return jsonify({
            "success": False,
            "error": "At least one of sender, subject, or email body must be provided."
        }), 400

    # Run hybrid detection engine
    result = HybridEngine.evaluate(
        sender=sender,
        subject=subject,
        body=body,
        urls=urls,
        attachment_name=attachment_name,
        expected_org=expected_org
    )

    # Persist analysis metadata to database
    sender_domain = result["sender_analysis"].get("sender_domain", "")
    try:
        record = save_analysis(
            sender=sender,
            sender_domain=sender_domain,
            subject=subject,
            risk_score=result["risk_score"],
            classification=result["classification"],
            attachment_name=attachment_name,
            indicators=result["indicators"],
            url_analyses=result["url_analyses"]
        )
        analysis_id = record.analysis_id
    except Exception as e:
        print(f"[!] Warning: Database save failed: {e}")
        analysis_id = None

    result["analysis_id"] = analysis_id
    result["success"] = True

    return jsonify(result), 200


@analyze_bp.route("/analyze/url", methods=["POST"])
def analyze_single_url():
    """
    Dedicated endpoint for safe, passive URL inspection.
    """
    data = request.get_json() or {}
    url = sanitize_string(data.get("url", ""), 2000)
    displayed_text = sanitize_string(data.get("displayed_text", ""), 500)

    if not url:
        return jsonify({"success": False, "error": "URL parameter is required"}), 400

    analysis = URLAnalyzer.analyze_url(url=url, displayed_text=displayed_text)
    return jsonify({"success": True, "analysis": analysis}), 200
