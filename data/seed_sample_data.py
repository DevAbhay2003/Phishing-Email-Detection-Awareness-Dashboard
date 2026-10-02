"""
Sample Data Seeder for Initial Dashboard Demonstration
Populates local SQLite database with 15 initial triaged email records
(legitimate notices and synthetic phishing attempts) to demonstrate live charts.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import init_db, save_analysis
from backend.services.hybrid_engine import HybridEngine
from backend.routes.analyze import SAMPLE_EMAILS

def seed_database():
    init_db()
    print("[*] Seeding database with initial sample triage logs...")

    # Seed the 4 curated demonstration samples
    for sample in SAMPLE_EMAILS:
        res = HybridEngine.evaluate(
            sender=sample["sender"],
            subject=sample["subject"],
            body=sample["body"],
            urls=sample["urls"],
            attachment_name=sample["attachment_name"]
        )
        sender_domain = res["sender_analysis"].get("sender_domain", "example.org")
        save_analysis(
            sender=sample["sender"],
            sender_domain=sender_domain,
            subject=sample["subject"],
            risk_score=res["risk_score"],
            classification=res["classification"],
            attachment_name=sample["attachment_name"],
            indicators=res["indicators"],
            url_analyses=res["url_analyses"]
        )

    # Seed a few additional varied records to ensure colorful chart distribution
    additional_samples = [
        {
            "sender": '"HR Benefits" <benefits@corp.example.com>',
            "subject": "Annual Benefits Enrollment Reminder",
            "body": "Hello team, open enrollment for health benefits ends next Friday. Visit the employee portal at https://corp.example.com/benefits.",
            "urls": "https://corp.example.com/benefits",
            "attachment_name": "benefits_guide.pdf"
        },
        {
            "sender": '"IT Service Desk" <support@portal.example.com>',
            "subject": "Scheduled Maintenance Notice: Saturday 2 AM",
            "body": "Please be advised of scheduled server maintenance this Saturday. No action or password change is needed.",
            "urls": "",
            "attachment_name": ""
        },
        {
            "sender": '"Bank Alert" <alert@secure-banking.invalid.test>',
            "subject": "SECURITY ALERT: Unrecognized Wire Transaction",
            "body": "A wire transfer of $1,800 was requested. If this was not you, verify your password immediately at http://198.51.100.45/login.",
            "urls": "http://198.51.100.45/login",
            "attachment_name": ""
        },
        {
            "sender": '"Shipping Logistics" <tracking@delivery-service.invalid.test>',
            "subject": "Package Delivery Postponed - Fee Due",
            "body": "Your package could not be delivered. Pay the redelivery fee immediately at http://short.invalid.test/verify-parcel.",
            "urls": "http://short.invalid.test/verify-parcel",
            "attachment_name": "Postal_Slip.scr"
        },
        {
            "sender": '"Newsletter Team" <digest@example.org>',
            "subject": "Weekly Cybersecurity Bulletin #12",
            "body": "Here is this week's digest covering zero-trust network architectures and defensive monitoring.",
            "urls": "https://example.org/bulletin/12",
            "attachment_name": ""
        }
    ]

    for sample in additional_samples:
        res = HybridEngine.evaluate(
            sender=sample["sender"],
            subject=sample["subject"],
            body=sample["body"],
            urls=sample["urls"],
            attachment_name=sample["attachment_name"]
        )
        sender_domain = res["sender_analysis"].get("sender_domain", "example.org")
        save_analysis(
            sender=sample["sender"],
            sender_domain=sender_domain,
            subject=sample["subject"],
            risk_score=res["risk_score"],
            classification=res["classification"],
            attachment_name=sample["attachment_name"],
            indicators=res["indicators"],
            url_analyses=res["url_analyses"]
        )

    print("[+] Seeding complete! Database is populated with realistic audit telemetry.")

if __name__ == "__main__":
    seed_database()
