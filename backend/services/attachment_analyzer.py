"""
Defensive Email Attachment Analyzer
Cybersecurity Project: Phishing Email Detection & Awareness Dashboard

Performs passive static filename and extension analysis.
Strictly NEVER parses binary code or executes files.
"""

from typing import Dict, Any, List
from .preprocessor import EmailPreprocessor

# Highly dangerous executable extensions commonly abused in spearphishing
EXECUTABLE_EXTENSIONS = {
    ".exe": "Windows Executable Binary",
    ".scr": "Windows Screensaver Executable (frequent malware vector)",
    ".bat": "Windows Batch Script",
    ".cmd": "Windows Command Script",
    ".ps1": "PowerShell Script",
    ".vbs": "VBScript File",
    ".js": "JavaScript File (Windows Script Host)",
    ".wsf": "Windows Script File",
    ".hta": "HTML Application Executable",
    ".msi": "Windows Installer Package",
    ".pif": "Program Information File"
}

# Macro-enabled office documents
MACRO_EXTENSIONS = {
    ".docm": "Word Macro-Enabled Document",
    ".xlsm": "Excel Macro-Enabled Spreadsheet",
    ".pptm": "PowerPoint Macro-Enabled Presentation"
}

# Container and disk image formats frequently used to bypass Secure Email Gateways (SEGs)
ARCHIVE_OR_CONTAINER_EXTENSIONS = {
    ".iso": "Disk Image (Mountable Container bypassing MOTW)",
    ".img": "Disk Image File",
    ".vhd": "Virtual Hard Disk Image",
    ".zip": "Compressed Archive",
    ".rar": "RAR Archive",
    ".7z": "7-Zip Archive"
}

# Normal low-risk common document extensions
BENIGN_EXTENSIONS = {
    ".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".png", ".jpg", ".jpeg", ".csv"
}


class AttachmentAnalyzer:
    """
    Evaluates threat potential of email attachment filenames and extension masquerades.
    """

    @classmethod
    def analyze_attachment(cls, filename: str) -> Dict[str, Any]:
        """
        Statically assesses attachment risk based on extension syntax and evasion tactics.
        """
        if not filename or not filename.strip():
            return {
                "has_attachment": False,
                "filename": "",
                "attachment_risk_score": 0,
                "category": "NONE",
                "findings": ["No attachment associated with this email"],
                "details": {}
            }

        parsed = EmailPreprocessor.extract_attachment_extension(filename)
        ext = parsed["extension"]
        all_exts = parsed["all_extensions"]
        is_double = parsed["is_double_extension"]
        clean_name = parsed["filename"]

        findings: List[str] = []
        score = 0
        category = "LOW RISK"

        # 1. Double extension detection (e.g. invoice.pdf.exe or order.docx.scr)
        if is_double and len(all_exts) >= 2:
            real_ext = "." + all_exts[-1]
            fake_ext = "." + all_exts[-2]
            if real_ext in EXECUTABLE_EXTENSIONS or real_ext in [".vbs", ".bat", ".scr", ".js", ".ps1"]:
                findings.append(
                    f"Double Extension Deception: Filename poses as '{fake_ext}' but executes as '{real_ext}' ({EXECUTABLE_EXTENSIONS.get(real_ext, 'Executable')})"
                )
                score += 85
                category = "CRITICAL / DANGEROUS"

        # 2. Executable / Script Direct Detection
        if ext in EXECUTABLE_EXTENSIONS:
            desc = EXECUTABLE_EXTENSIONS[ext]
            findings.append(f"Dangerous executable extension '{ext}' ({desc}) - High risk of payload execution")
            score = max(score, 80)
            category = "HIGH RISK / MALICIOUS INDICATOR"

        # 3. Macro-enabled Office Formats
        elif ext in MACRO_EXTENSIONS:
            desc = MACRO_EXTENSIONS[ext]
            findings.append(
                f"Macro-enabled document '{ext}' ({desc}) - Often contains malicious VBA code designed to download payloads"
            )
            score = max(score, 50)
            category = "SUSPICIOUS / MACRO RISK"

        # 4. Container / Disk Image Formats
        elif ext in ARCHIVE_OR_CONTAINER_EXTENSIONS:
            desc = ARCHIVE_OR_CONTAINER_EXTENSIONS[ext]
            if ext in [".iso", ".img", ".vhd"]:
                findings.append(
                    f"Container format '{ext}' ({desc}) - Commonly abused by threat actors to evade Mark-of-the-Web (MOTW)"
                )
                score = max(score, 45)
                category = "SUSPICIOUS CONTAINER"
            else:
                findings.append(f"Archive file '{ext}' ({desc}) - Can conceal malicious payloads from basic perimeter scanners")
                score = max(score, 20)
                category = "MODERATE RISK"

        # 5. Standard benign document
        elif ext in BENIGN_EXTENSIONS:
            findings.append(f"Standard document extension '{ext}' - Common business format")
            score = max(score, 0)
            category = "SAFE / STANDARD"

        else:
            findings.append(f"Uncommon or unrecognized attachment extension '{ext}'")
            score = max(score, 25)
            category = "UNUSUAL"

        final_score = min(score, 100)

        return {
            "has_attachment": True,
            "filename": clean_name,
            "extension": ext,
            "attachment_risk_score": final_score,
            "category": category,
            "findings": findings,
            "details": {
                "is_double_extension": is_double,
                "all_extensions": all_exts
            }
        }
