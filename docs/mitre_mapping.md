# MITRE ATT&CK® Framework Mapping

## Project: Phishing Email Detection & Awareness Dashboard (SentinelPhish)

### Overview

Mapping defensive detections to the **MITRE ATT&CK® Enterprise Matrix** standardizes threat classification, assists Security Operations Centers (SOC) in contextualizing incoming alerts, and aligns automated defenses with real-world adversary tactics, techniques, and procedures (TTPs).

SentinelPhish maps its heuristic and probabilistic detectors to the **Initial Access** and **Execution** tactical categories.

---

### Matrix Mapping Table

| Tactic | Technique ID | Technique Name | Adversary Objective | SentinelPhish Defensive Capability |
| :--- | :--- | :--- | :--- | :--- |
| **Initial Access (TA0001)** | `T1566.001` | Spearphishing Attachment | Adversaries attach malicious files (executables, scripts, macro-enabled documents, or compressed containers) to execute code on recipient systems. | Static filename and extension analysis in [`AttachmentAnalyzer`](file:///backend/services/attachment_analyzer.py). Detects dangerous binaries (`.exe`, `.scr`), scripts (`.vbs`, `.ps1`), macros (`.docm`, `.xlsm`), and evasion techniques like double extensions (`invoice.pdf.exe`). |
| **Initial Access (TA0001)** | `T1566.002` | Spearphishing Link | Adversaries embed hyperlinks within emails that lead victims to credential-harvesting web forms or drive-by payload downloads. | Static URL risk extraction in [`URLAnalyzer`](file:///backend/services/url_analyzer.py). Identifies raw IP addresses, unencrypted HTTP transport, link shorteners, and credential harvesting keywords (`verify`, `login`, `bank`, `update`). |
| **Initial Access (TA0001)** | `T1566.003` | Spearphishing via Service | Adversaries leverage legitimate third-party services or social platforms to send lures or impersonate trusted corporate infrastructure. | Brand impersonation and display name mismatch heuristics in [`SenderAnalyzer`](file:///backend/services/sender_analyzer.py). Compares display identity with authoritative sender domain headers. |
| **Execution (TA0002)** | `T1204.001` | User Execution: Malicious Link | An adversary relies on social engineering to trick a user into clicking a link that triggers malicious actions. | Linguistic social-engineering triage in [`ContentAnalyzer`](file:///backend/services/content_analyzer.py) flagging urgency, fear, and panic inducement intended to bypass deliberate verification. |
| **Execution (TA0002)** | `T1204.002` | User Execution: Malicious File | An adversary relies on a user opening a malicious attachment. | Clear actionable recommendations and warning badges discouraging user execution and attachment decompression. |
| **Credential Access (TA0006)** | `T1056.003` | Input Capture: Web Portal Phishing | Adversaries establish deceptive clones of enterprise portals to harvest user authentication tokens and credentials. | Content analyzer heuristics that flag credential solicitation phrases ("verify your password", "confirm login credentials", "re-authenticate"). |

---

### Why Framework Mapping Matters for Defensive Security

1. **Interoperability**: Standardized technique IDs (`T1566.001`, `T1566.002`) enable seamless telemetry sharing between Security Information and Event Management (SIEM) systems, EDR agents, and SOAR playbooks.
2. **Gap Analysis**: Security teams can determine which attack vectors have automated coverage and which vectors require enhanced controls or training.
3. **Analyst Communication**: When an alert surfaces in the SOC, junior analysts can reference MITRE ATT&CK remediation playbooks instantly rather than evaluating alerts in isolation.
4. **Defensive Validation**: Enables red/blue table-top exercises to test security defenses against known threat actor playbooks.
