"""
Safe Synthetic Phishing & Legitimate Email Dataset Generator
Cybersecurity Project: Phishing Email Detection & Awareness Dashboard

Generates a balanced dataset of 600+ synthetic email records using exclusively
safe, fictional, and RFC-reserved domains (e.g., example.com, example.org, invalid.test,
RFC 5737 TEST-NET IP addresses). Absolutely no real malicious URLs or external targets.
"""

import os
import random
import pandas as pd

# Safe RFC 2606 / RFC 6761 reserved domains
SAFE_LEGIT_DOMAINS = [
    "example.com", "example.org", "example.net",
    "university.example.edu", "corp.example.com", "support.example.org",
    "portal.example.com", "library.example.edu", "billing.example.net"
]

SAFE_PHISHING_DOMAINS = [
    "account-verify.invalid.test", "security-alert.invalid.test",
    "login-update.invalid.test", "secure-banking.invalid.test",
    "payroll-portal.invalid.test", "hr-benefits.invalid.test",
    "order-confirmations.invalid.test", "prize-claim.invalid.test",
    "cloud-storage-notice.invalid.test", "it-support-desk.invalid.test"
]

# Safe RFC 5737 documentation IP addresses (TEST-NET-1, TEST-NET-2, TEST-NET-3)
SAFE_DOC_IPS = [
    "192.0.2.14", "198.51.100.10", "198.51.100.45", "203.0.113.8", "198.51.100.99"
]

# Legitimate email templates (various categories)
LEGIT_TEMPLATES = [
    {
        "category": "university_notice",
        "sender_name": "Registrar Office",
        "sender_prefix": "registrar",
        "subjects": [
            "Spring Semester Course Registration Schedule",
            "Campus Library Extended Hours During Finals Week",
            "Academic Calendar Update for Upcoming Term",
            "Campus Safety Escort Services and Contact Information"
        ],
        "bodies": [
            "Dear students, please be advised that registration for spring courses opens next Monday. You can review the course catalog through the university student portal at your convenience. No action is required if you have already submitted your advising plan.",
            "Hello faculty and students, the campus main library will remain open until midnight throughout the examination period. Group study rooms can be reserved at the front desk or via the campus intranet.",
            "Good morning campus community, please note the revised dates for the semester break. Detailed academic calendars are published on the university portal: https://university.example.edu/calendar.",
            "Campus notice: Escort services operate daily from 7:00 PM to 6:00 AM. For safety information or assistance, visit the student safety office located in Student Union room 102."
        ],
        "urls": ["https://university.example.edu/calendar", "https://university.example.edu/portal", ""],
        "attachments": ["course_schedule.pdf", "academic_calendar.pdf", "", ""]
    },
    {
        "category": "hr_update",
        "sender_name": "Human Resources",
        "sender_prefix": "hr",
        "subjects": [
            "Quarterly Benefits Enrollment Informational Session",
            "Annual Holiday Calendar and Office Closures",
            "Workplace Wellness Week: Schedule of Activities",
            "Employee Recognition Awards: Nominations Open"
        ],
        "bodies": [
            "Hello team, HR is hosting an optional informational session next Wednesday regarding upcoming benefits enrollment. A recorded webinar will be available afterwards on our internal knowledge base.",
            "Colleagues, please find the company holiday schedule for the upcoming fiscal year on the internal company intranet: https://corp.example.com/intranet/holidays.",
            "Join us next week for Wellness Week sessions, including ergonomics workshops and mindfulness sessions. Registration is optional via the company event portal.",
            "We are pleased to open nominations for the annual peer recognition awards. Submit nominations through your departmental manager by the end of this month."
        ],
        "urls": ["https://corp.example.com/intranet/holidays", "https://corp.example.com/wellness", ""],
        "attachments": ["wellness_schedule.pdf", "holiday_calendar.pdf", "", ""]
    },
    {
        "category": "project_update",
        "sender_name": "Engineering Operations",
        "sender_prefix": "dev-ops",
        "subjects": [
            "Sprint Retrospective and Planning Summary",
            "Database Maintenance Completed Successfully",
            "Release Notes: Version 3.4.0 Internal Tools",
            "Weekly Team Standup Notes and Action Items"
        ],
        "bodies": [
            "Hi everyone, thanks for participating in today's sprint retrospective. The summary action items have been logged in Jira. Next sprint begins on Thursday as planned.",
            "The scheduled weekend database index rebuild completed on schedule with zero unexpected downtime. Full telemetry is available in our monitoring dashboard.",
            "Release version 3.4.0 of our internal tooling is now deployed. Check the changelog at https://corp.example.com/docs/v3-4-0 for details on bug fixes.",
            "Attached are the action items from this morning's architecture review. Please review section 3 before our Thursday synchronization call."
        ],
        "urls": ["https://corp.example.com/docs/v3-4-0", "https://corp.example.com/wiki/sprint", ""],
        "attachments": ["meeting_minutes.pdf", "release_notes.txt", "", ""]
    },
    {
        "category": "meeting_reminder",
        "sender_name": "Calendar Service",
        "sender_prefix": "calendar-bot",
        "subjects": [
            "Reminder: Quarterly Security Committee Review",
            "Upcoming Meeting: Departmental All-Hands",
            "Invitation: Brown Bag Tech Talk on Cloud Architecture",
            "Accepted: 1-on-1 Catchup with Team Lead"
        ],
        "bodies": [
            "This is an automated reminder that your Quarterly Security Committee Review starts in 15 minutes in Conference Room C and over videoconference.",
            "Reminder: The quarterly departmental all-hands will occur tomorrow at 10:00 AM. The agenda includes roadmap updates and employee spotlight.",
            "You are invited to join our brown bag lunch session on container security this Friday at noon. Light refreshments will be provided.",
            "Your calendar invitation for 1-on-1 synchronization has been accepted. Feel free to add agenda topics directly to the collaborative document."
        ],
        "urls": ["https://corp.example.com/meet/room101", ""],
        "attachments": ["agenda.pdf", "", ""]
    },
    {
        "category": "shopping_confirmation",
        "sender_name": "Fictional Retail Support",
        "sender_prefix": "orders",
        "subjects": [
            "Your Order #89211 Has Shipped",
            "Receipt for Your Recent Store Purchase",
            "Order Confirmation: Order #44192",
            "Delivery Notification: Package Left at Reception"
        ],
        "bodies": [
            "Thank you for shopping with Fictional Store. Your package has been handed to the courier and is expected to arrive within 2-3 business days. Track your shipment at https://support.example.org/track/89211.",
            "Here is your official receipt for order #44192. You can view your purchase history and warranty documents anytime by logging into your account directly at our official website.",
            "Your order has been confirmed and is being processed by our fulfillment center. No action is needed from your side.",
            "Your delivery was safely deposited at your building reception desk. Thank you for choosing our delivery partner."
        ],
        "urls": ["https://support.example.org/track/89211", "https://support.example.org/receipts", ""],
        "attachments": ["receipt_44192.pdf", "invoice_summary.pdf", "", ""]
    },
    {
        "category": "security_notification_legit",
        "sender_name": "Official Identity Team",
        "sender_prefix": "identity-security",
        "subjects": [
            "Security Notice: New Login from Authorized Device",
            "Confirmation: Password Changed Successfully",
            "Two-Factor Authentication Setup Confirmed",
            "Annual Security Awareness Training Completed"
        ],
        "bodies": [
            "Hello, your account was successfully accessed from Firefox on Windows 11. If this was you, you may safely ignore this message. We will never ask you for your password via email.",
            "This email confirms that your organization account password was modified recently from an internal network workstation. If you did not make this change, please immediately inform the IT Helpdesk via phone extension 4357.",
            "Two-factor authentication has been successfully enabled on your user profile. Always keep your emergency recovery codes stored in a secure physical location.",
            "Congratulations on completing your mandatory annual cybersecurity awareness refresher. Your certificate of completion has been recorded in the compliance database."
        ],
        "urls": ["https://portal.example.com/security/activity", ""],
        "attachments": ["training_certificate.pdf", "", ""]
    },
    {
        "category": "newsletter",
        "sender_name": "Tech Digest Editorial",
        "sender_prefix": "newsletter",
        "subjects": [
            "Tech Digest Weekly: Innovations in Zero Trust Architecture",
            "Open Source Monthly: Issue #42",
            "Community Insights: Building Resilient Microservices",
            "Developer Newsletter: Python 3.13 Features and Highlights"
        ],
        "bodies": [
            "Welcome to this week's issue of Tech Digest! In this issue, we examine best practices for zero-trust network design, defense-in-depth methodologies, and kernel security. Read more at https://example.org/articles/zero-trust.",
            "Here are the top trending open-source projects this month across telemetry, observability, and container runtime security.",
            "Explore our architectural case study covering automated rollbacks, fault tolerance, and circuit breaker patterns in distributed environments.",
            "Discover the new performance improvements and typing enhancements introduced in modern Python releases."
        ],
        "urls": ["https://example.org/articles/zero-trust", "https://example.org/newsletter/unsub", ""],
        "attachments": ["", ""]
    }
]

# Synthetic phishing templates (various social-engineering vectors)
PHISH_TEMPLATES = [
    {
        "category": "fake_account_verification",
        "sender_name": "Security Center Alert",
        "sender_prefix": "security-alert",
        "subjects": [
            "URGENT: Verify Your Account Credentials Immediately",
            "Action Required: Suspicious Activity Detected on Your Account",
            "Account Lockout Warning: Confirm Identity Within 24 Hours",
            "Immediate Attention: Unauthorized Login Attempt Blocked"
        ],
        "bodies": [
            "Dear Customer, We have detected unusual login attempts from an unknown IP address. To prevent permanent suspension of your account, you must immediately verify your login credentials and personal identity by clicking the link below: {URL}. Failure to comply within 24 hours will result in permanent deactivation of your account and forfeiture of access.",
            "Warning: Your online access has been temporarily restricted due to non-compliance with our security policy. Click here immediately {URL} to restore full access and update your confidential credentials.",
            "ATTENTION USER: Suspicious transactions were flagged on your profile. You are required to confirm your identity right now by accessing {URL} and providing your password and social security details. Act now!",
            "Dear Valued User, Your account has been scheduled for deletion due to suspicious activities. Please click {URL} to verify your password immediately and cancel this action."
        ],
        "url_types": ["ip_url", "credential_query", "fake_shortener", "http_only"],
        "attachments": ["", "Verification_Form.html", "Security_Patch.exe", ""]
    },
    {
        "category": "fake_invoice",
        "sender_name": "Billing & Accounting Dept",
        "sender_prefix": "billing-dept",
        "subjects": [
            "Overdue Invoice #INV-99382 - Final Notice Before Collection",
            "Payment Past Due: Immediate Payment Required",
            "Invoice Attached: Outstanding Balance of $4,850.00",
            "Wire Transfer Confirmation Needed for Vendor Payment"
        ],
        "bodies": [
            "Dear Sir/Madam, Please find attached the final overdue invoice for the amount of $4,850.00. Payment must be remitted immediately to avoid legal collection procedures. Please open the attached remittance file or visit {URL} to finalize payment immediately.",
            "URGENT NOTICE: Your automatic recurring subscription failed to process. Outstanding payment of $1,299.00 is due today. Review your invoice details at {URL} or open the attached document right now.",
            "Attention Accounts Payable: We have not received payment for invoice #99218. Immediate wire transfer is required. Open the attached file {ATTACHMENT} immediately to view banking transfer instructions.",
            "Final notice regarding delinquent balance. Your services will be terminated today unless payment confirmation is submitted via {URL}."
        ],
        "url_types": ["ip_url", "credential_query", "fake_shortener"],
        "attachments": ["Invoice_99382.pdf.exe", "PastDue_Receipt.scr", "Wire_Instructions.vbs", "Invoice_Scan.js"]
    },
    {
        "category": "fake_prize_reward",
        "sender_name": "Prize Distribution Committee",
        "sender_prefix": "claims-department",
        "subjects": [
            "CONGRATULATIONS! You Have Won $50,000 in Annual Sweepstakes",
            "Exclusive Reward: Claim Your $500 Gift Card Before Midnight",
            "Winner Notification: Selected Account for Cash Payout",
            "Special Bonus Reward Credited to Your Account"
        ],
        "bodies": [
            "Congratulations! Your email address was randomly selected as our grand prize winner of $50,000! To claim your cash prize, you must verify your identity and bank account details immediately at {URL}. Hurry, unclaimed rewards expire in 12 hours!",
            "You have won a free $500 corporate gift card. Click here {URL} right now to enter your credit card number and mailing address for immediate dispatch.",
            "URGENT: Your annual bonus cashback of $2,500 is waiting for collection. Verify your personal information and online banking credentials at {URL} to receive the funds.",
            "Claim your exclusive electronic prize now! Click {URL} and confirm your personal confidential details today."
        ],
        "url_types": ["fake_shortener", "credential_query", "http_only"],
        "attachments": ["Prize_Claim_Form.docm", "Winner_Certificate.exe", ""]
    },
    {
        "category": "fake_password_expiration",
        "sender_name": "IT System Helpdesk",
        "sender_prefix": "helpdesk-admin",
        "subjects": [
            "CRITICAL: Your Password Expires in 2 Hours",
            "Office 365 Password Expiration Alert - Keep Same Password",
            "System Notice: IT Password Policy Reset Required",
            "Action Required: Retain Your Current Email Access"
        ],
        "bodies": [
            "Dear User, Your organizational account password will expire today in exactly 2 hours. To keep your current password and prevent email account suspension, you must immediately log in and verify your current credentials at: {URL}. Do not ignore this alert.",
            "IT Helpdesk Alert: System upgrade requires all employees to re-authenticate their active directory credentials at {URL} immediately. Failure to authenticate will lock you out of your workstation.",
            "Notice: Your email storage quota has exceeded 99%. All incoming messages are being rejected. Click {URL} immediately and submit your login credentials to restore incoming mail delivery.",
            "Urgent Security Requirement: All staff members must confirm their user account and current password at {URL} prior to maintenance."
        ],
        "url_types": ["ip_url", "credential_query", "http_only"],
        "attachments": ["Password_Reset_Tool.bat", "Helpdesk_Sync.ps1", ""]
    },
    {
        "category": "fake_delivery_notice",
        "sender_name": "Express Courier Tracking",
        "sender_prefix": "delivery-service",
        "subjects": [
            "Delivery Failed: Update Address to Receive Package #TX-4401",
            "Urgent: Unclaimed Parcel Awaiting Customs Clearance",
            "Package Delivery Exception - Redelivery Fee Required",
            "Courier Notice: Complete Customs Verification"
        ],
        "bodies": [
            "Your courier package could not be delivered due to an incorrect home address. A redelivery fee of $2.50 must be paid immediately. Click {URL} to confirm your shipping details and submit your payment card details now.",
            "Parcel Notification: Package #USPS-9921 is held at the local depot. Complete online customs verification immediately at {URL} to prevent return of package to sender.",
            "Urgent parcel notice: We attempted delivery today at 11:20 AM. Open the attached delivery slip {ATTACHMENT} or visit {URL} immediately to reschedule.",
            "Delivery Exception Alert: Update your contact phone number and payment credentials at {URL} within 24 hours to claim your parcel."
        ],
        "url_types": ["ip_url", "fake_shortener", "credential_query"],
        "attachments": ["Postal_Slip.pdf.exe", "Shipping_Label.scr", ""]
    },
    {
        "category": "fake_hr_request",
        "sender_name": "Executive HR Management",
        "sender_prefix": "hr-payroll",
        "subjects": [
            "Mandatory HR Compliance: Review Revised Salary Structure",
            "Immediate Action: Submit Updated W-2 Tax Information",
            "Urgent: Employee Health Insurance Portal Verification",
            "Confidential: Performance Review Documents Requiring Signature"
        ],
        "bodies": [
            "Dear Employee, The human resources management team has released updated corporate salary brackets. Please click {URL} immediately to log in with your corporate credentials and review your personal adjustment.",
            "Urgent Tax Notice: Discrepancies have been identified on your W-2 tax declaration. Please access the payroll portal at {URL} immediately and re-enter your Social Security Number and bank account details.",
            "All personnel are required to complete mandatory open enrollment verification today. Visit {URL} immediately and provide your confidential employee credentials.",
            "Confidential HR Memo: Your annual performance assessment requires immediate acknowledgment. Open the attached document {ATTACHMENT} or access {URL} now."
        ],
        "url_types": ["credential_query", "fake_shortener", "http_only"],
        "attachments": ["Payroll_Portal.html", "Salary_Adjustment.docm", "Employee_Form.xlsm"]
    },
    {
        "category": "fake_executive_request",
        "sender_name": "Chief Executive Officer",
        "sender_prefix": "ceo-office",
        "subjects": [
            "QUICK TASK: Are You At Your Desk Right Now?",
            "CONFIDENTIAL: Urgent Wire Transfer Required for Acquisition",
            "Strictly Confidential: Need Immediate Assistance",
            "Urgent Gift Cards Request for Client Closing"
        ],
        "bodies": [
            "Are you at your desk right now? I am currently in a closed-door meeting with external partners and cannot take calls. I need you to execute a confidential wire transfer of $24,500 immediately. Send me your personal cell number and visit {URL} for remittance details.",
            "I need a discreet favor immediately. Please purchase five $200 Apple gift cards for a confidential client closing gift. Scratch off the backs, photograph the PIN codes, and upload them to {URL} right away. I will reimburse you today.",
            "Quick confidential assignment: We are finalizing an urgent vendor acquisition. Review the confidential instructions at {URL} immediately. Do not discuss this with anyone on the team.",
            "I am relying on your prompt assistance with an urgent confidential matter. Access the executive instruction sheet at {URL} and confirm compliance immediately."
        ],
        "url_types": ["fake_shortener", "ip_url", "credential_query"],
        "attachments": ["Confidential_Acquisition.zip", "Wire_Mandate.pdf.exe", ""]
    }
]

def make_safe_phishing_url(url_type: str, domain: str) -> str:
    """Generate safe, RFC-compliant synthetic phishing URLs for demonstration."""
    doc_ip = random.choice(SAFE_DOC_IPS)
    if url_type == "ip_url":
        # Raw IP RFC 5737
        paths = ["/verify-account", "/login.php", "/update-credentials", "/session/auth"]
        return f"http://{doc_ip}{random.choice(paths)}"
    elif url_type == "credential_query":
        # Safe dummy test domain with credential query string
        return f"http://{domain}/auth/login?redirect=account_verification&token=99281"
    elif url_type == "fake_shortener":
        # Safe fictional shortener pattern
        return f"http://short.invalid.test/verify-{random.randint(1000, 9999)}"
    else:
        # Non-HTTPS HTTP link
        return f"http://{domain}/secure-login/verification"

def generate_synthetic_dataset(total_records: int = 650) -> pd.DataFrame:
    """Generate a balanced synthetic dataset of legitimate and phishing emails."""
    random.seed(42)
    records = []
    
    half = total_records // 2
    
    # 1. Generate Legitimate Emails
    for i in range(half):
        tmpl = random.choice(LEGIT_TEMPLATES)
        sender_domain = random.choice(SAFE_LEGIT_DOMAINS)
        sender_email = f"{tmpl['sender_prefix']}{random.randint(10, 99)}@{sender_domain}"
        sender_full = f'"{tmpl["sender_name"]}" <{sender_email}>'
        subject = random.choice(tmpl["subjects"])
        body = random.choice(tmpl["bodies"])
        url = random.choice(tmpl["urls"])
        attachment = random.choice(tmpl["attachments"])
        
        records.append({
            "email_id": f"EML-LEGIT-{i+1:04d}",
            "sender": sender_full,
            "sender_domain": sender_domain,
            "subject": subject,
            "body": body,
            "urls": url,
            "attachment_name": attachment,
            "label": "LEGITIMATE"
        })
        
    # 2. Generate Synthetic Phishing Emails
    for i in range(half):
        tmpl = random.choice(PHISH_TEMPLATES)
        phish_domain = random.choice(SAFE_PHISHING_DOMAINS)
        sender_email = f"{tmpl['sender_prefix']}-{random.randint(100, 999)}@{phish_domain}"
        sender_full = f'"{tmpl["sender_name"]}" <{sender_email}>'
        subject = random.choice(tmpl["subjects"])
        
        url_type = random.choice(tmpl["url_types"])
        generated_url = make_safe_phishing_url(url_type, phish_domain)
        attachment = random.choice(tmpl["attachments"])
        
        body_raw = random.choice(tmpl["bodies"])
        body = body_raw.replace("{URL}", generated_url).replace("{ATTACHMENT}", attachment if attachment else "document")
        
        records.append({
            "email_id": f"EML-PHISH-{i+1:04d}",
            "sender": sender_full,
            "sender_domain": phish_domain,
            "subject": subject,
            "body": body,
            "urls": generated_url,
            "attachment_name": attachment,
            "label": "PHISHING"
        })
        
    # Shuffle records
    random.shuffle(records)
    df = pd.DataFrame(records)
    return df

def main():
    target_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)))
    target_csv = os.path.join(target_dir, "phishing_email_dataset.csv")
    
    print(f"[*] Generating 650 synthetic email records...")
    df = generate_synthetic_dataset(650)
    df.to_csv(target_csv, index=False)
    print(f"[+] Dataset generated successfully with {len(df)} records.")
    print(f"[+] Saved to: {target_csv}")
    print("\nClass Distribution:")
    print(df["label"].value_counts())
    print("\nSample Record Preview:")
    print(df.head(2)[["email_id", "sender", "subject", "label"]])

if __name__ == "__main__":
    main()
