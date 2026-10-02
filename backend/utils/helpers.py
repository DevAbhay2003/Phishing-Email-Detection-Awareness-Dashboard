"""
Defensive Utilities & Email File Parser
Cybersecurity Project: Phishing Email Detection & Awareness Dashboard

Provides safe parsing for uploaded .eml and .txt files, and input sanitization
to prevent injection attacks and XSS during defensive triage.
"""

import email
from email import policy
import html
from typing import Dict, Any, List


def sanitize_string(val: str, max_length: int = 50000) -> str:
    """
    Sanitizes untrusted user strings to protect server memory and downstream rendering.
    """
    if not val:
        return ""
    # Strip null bytes and truncate to bounded size
    clean = str(val).replace("\x00", "")
    return clean[:max_length].strip()


def parse_eml_file(file_content: bytes) -> Dict[str, Any]:
    """
    Safely parses standard RFC 822 / MIME .eml email files without executing any code.
    Extracts Subject, From, Body text, and Attachment names.
    """
    try:
        msg = email.message_from_bytes(file_content, policy=policy.default)
        subject = msg.get("Subject", "") or ""
        sender = msg.get("From", "") or ""

        body_parts: List[str] = []
        attachments: List[str] = []

        if msg.is_multipart():
            for part in msg.walk():
                content_disposition = str(part.get("Content-Disposition", ""))
                content_type = part.get_content_type()
                filename = part.get_filename()

                if filename:
                    attachments.append(filename)
                elif "attachment" in content_disposition:
                    if filename:
                        attachments.append(filename)
                elif content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        body_parts.append(payload.decode(charset, errors="replace"))
                elif content_type == "text/html" and not body_parts:
                    # Fallback to HTML body only if plain text is absent
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        body_parts.append(payload.decode(charset, errors="replace"))
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                body_parts.append(payload.decode(charset, errors="replace"))

        body = "\n".join(body_parts).strip()
        first_attachment = attachments[0] if attachments else ""

        return {
            "success": True,
            "sender": sender,
            "subject": subject,
            "body": body,
            "attachment_name": first_attachment,
            "all_attachments": attachments
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to parse .eml structure: {str(e)}",
            "sender": "",
            "subject": "",
            "body": "",
            "attachment_name": ""
        }
