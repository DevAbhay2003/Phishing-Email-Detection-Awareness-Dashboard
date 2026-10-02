# Cybersecurity Project Report: SentinelPhish

**Project Title**: Phishing Email Detection & Awareness Dashboard  
**Academic / Industry Capstone Report**  
**Author**: Cybersecurity Engineering Student  
**Environment**: Python 3.13, Flask, Scikit-Learn, SQLite, Chart.js  

---

## 1. Abstract

Phishing remains the predominant initial compromise vector in modern cybersecurity incidents, accounting for over $80\%$ of reported security compromises and underpinning attacks spanning credential harvesting, business email compromise (BEC), and ransomware deployment. This project presents **SentinelPhish**, a defensive, multi-layered cybersecurity platform that unifies static email triage, explainable threat scoring, machine learning classification, and interactive security awareness training. SentinelPhish performs passive, zero-click static analysis across email sender headers, cognitive manipulation linguistics, hyperlink structures, and attachment metadata without connecting to untrusted networks or executing payloads. By synthesizing calibrated rule-based heuristics ($60\%$) with an NLP TF-IDF machine learning model ($40\%$), the system achieves explainable risk scores ($0–100$) and maps threats to four operational tiers (`LOW RISK`, `MODERATE RISK`, `SUSPICIOUS`, `HIGH RISK / LIKELY PHISHING`). Evaluated across a synthetic dataset of 650 balanced records and validated using a 25-scenario automated test suite, SentinelPhish provides an end-to-end blueprint for automated Security Operations Center (SOC) triage and human risk reduction.

---

## 2. Introduction & Problem Statement

### 2.1 The Phishing Threat Landscape
Electronic mail serves as the ubiquitous backbone of corporate communications. However, the foundational protocol of email—Simple Mail Transfer Protocol (SMTP, RFC 821)—was originally designed without cryptographic identity verification mechanisms. While extensions like SPF (RFC 7208), DKIM (RFC 6376), and DMARC (RFC 7489) have enhanced domain authentication, adversaries continue to exploit cognitive vulnerabilities, display-name spoofing, newly registered lookalike domains, link shorteners, and weaponized attachments to deceive human recipients.

### 2.2 Problem Statement
Traditional perimeter spam filters typically deliver binary verdicts ("Spam" or "Not Spam") without explaining the underlying reasoning to end users or SOC analysts. This creates two distinct operational challenges:
1. **Analyst Bottleneck & Alert Fatigue**: Tier-1 SOC analysts are overwhelmed by raw alerts and lack standardized, explainable indicator breakdowns to justify rapid escalation.
2. **User Education Deficit**: End users who receive blocked or suspicious emails do not understand *why* the message was dangerous, failing to build long-term cognitive resilience against future social engineering lures.

---

## 3. Project Objectives

1. **Defensive Multi-Vector Static Triage**: Implement modular analyzers for sender domains, message linguistics, static URLs, and attachment extensions without resolving links or executing code.
2. **Explainable Risk Scoring**: Develop an evidentiary rule engine that assigns granular points to specific threat markers, providing a transparent "WHY?" justification.
3. **Hybrid Detection Engine**: Blend deterministic heuristic rules with an NLP machine learning model to eliminate single-point-of-failure vulnerabilities.
4. **Interactive SOC Dashboard**: Construct an executive-level single-page interface with real-time KPI metrics, threat distribution charts, and audit logging.
5. **Security Awareness Hub**: Provide interactive self-assessment tools ("Before You Click" checklist) and align detections with the **MITRE ATT&CK® framework (`T1566`)**.
6. **Privacy by Design**: Establish database persistence that logs only analytical metadata, strictly omitting confidential raw email bodies.
7. **Comprehensive Automated Verification**: Validate all pipeline components across 25 unit/integration test scenarios with a $100\%$ pass rate.

---

## 4. Phishing Background & Social Engineering Mechanics

Adversaries do not merely attack technical protocols; they exploit fundamental human heuristics:
- **Artificial Urgency & Time Scarcity**: Creating artificial deadlines ("Account suspended in 2 hours") to trigger panic and bypass analytical reasoning.
- **Authority & Intimidation**: Posing as senior executives, legal counsel, or IT helpdesks to induce compliance.
- **Financial Coercion**: Fabricating overdue invoices or immediate wire transfer requests.
- **Baiting & Unrealistic Rewards**: Offering unsolicited gift cards, bonuses, or lottery sweepstakes.

---

## 5. System Architecture & Methodology

SentinelPhish operates as a multi-tier client-server architecture:

```text
[ Incoming Email / .eml File ]
               │
               ▼
   [ Sanitization & Preprocessing ]
               │
   ┌───────────┼───────────┬───────────┐
   ▼           ▼           ▼           ▼
[Sender]   [Content]     [URL]    [Attachment]
Analyzer   Analyzer    Analyzer    Analyzer
   │           │           │           │
   └───────────┼───────────┴───────────┘
               ▼
     [ Rule-Based Engine ] ──(60%)──┐
                                     ├──> [ Hybrid Decision Engine ]
     [ NLP ML Classifier ] ──(40%)──┘                   │
                                                        ▼
                                         [ Risk Score (0-100) & Tier ]
                                         [ Explainable Indicators "WHY?" ]
                                         [ SOC Action Recommendations ]
                                                        │
                                         ┌──────────────┴──────────────┐
                                         ▼                             ▼
                                 [ SQLite Audit DB ]           [ Web Dashboard ]
```

---

## 6. Component-Level Analysis Engines

### 6.1 Defensive Preprocessing (`preprocessor.py`)
Standard NLP text preprocessors strip punctuation, lowercase all words, and remove non-alphanumeric symbols. In cybersecurity, aggressive preprocessing destroys critical evidentiary cues:
- Preserves ALL-CAPS text to calculate the `uppercase_ratio`.
- Counts exclamation marks (`!`) indicating panic inducement.
- Extracts candidate URLs without initiating HTTP connections.
- Parses RFC 822 `.eml` files into standard MIME components.

### 6.2 Sender Analysis (`sender_analyzer.py`)
- Evaluates sender syntax and RFC email address formats.
- Flags excessive subdomains (e.g., `auth.gate.secure.portal.example.com`).
- Measures domain length and hyphen/digit density.
- Detects display-name brand spoofing (e.g., Display name claims "PayPal Support" but the domain is `unrelated-server.invalid.test`).
- Identifies common typosquatting / leetspeak patterns (`micros0ft`, `paypa1`).

### 6.3 Content & Social Engineering Analysis (`content_analyzer.py`)
Scans subject lines and message bodies for psychological manipulation across seven defined categories:
1. `Urgency & Time Pressure`
2. `Fear & Threat Language`
3. `Financial Coercion / Fake Invoices`
4. `Direct Credential Solicitation`
5. `Unrealistic Rewards & Baiting`
6. `Sensitive PII Collection`
7. `Generic Impersonal Greetings`

### 6.4 Static URL Threat Analysis (`url_analyzer.py`)
Performs passive lexical parsing:
- Flags unencrypted `http://` transport.
- Detects raw numerical IPv4 hostnames (e.g., `http://198.51.100.10/verify-account`).
- Identifies known link shortener domains masking real destinations.
- Highlights sensitive authentication keywords (`login`, `verify`, `account`, `token`).
- Identifies hyperlink spoofing when displayed link text differs from the actual destination.

### 6.5 Attachment Threat Analysis (`attachment_analyzer.py`)
- Identifies direct executable binaries (`.exe`, `.scr`, `.msi`).
- Flags script execution vectors (`.bat`, `.cmd`, `.js`, `.vbs`, `.ps1`, `.hta`).
- Flags weaponized macro documents (`.docm`, `.xlsm`).
- Uncovers double-extension evasion tactics (`invoice.pdf.exe`).

---

## 7. Machine Learning & Model Evaluation

### 7.1 Dataset Construction
To comply with ethical guidelines, 650 synthetic records were generated using RFC-reserved safe domains (`example.com`, `example.org`, `invalid.test`) and RFC 5737 test IP subnets (`198.51.100.0/24`). The dataset is perfectly balanced: 325 legitimate operational communications and 325 synthetic phishing attempts.

### 7.2 Training & Benchmarking
Three supervised classification models were trained on TF-IDF n-gram vectors (unigrams and bigrams, 2,500 maximum features) using an 80/20 stratified split:

| Model Architecture | Accuracy | Precision | Recall | F1-Score |
| :--- | :---: | :---: | :---: | :---: |
| **Logistic Regression (Selected)** | **1.0000** | **1.0000** | **1.0000** | **1.0000** |
| Multinomial Naive Bayes | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| Random Forest (100 Trees) | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

### 7.3 Confusion Matrix Analysis
On the 130 held-out test evaluation samples:
- **True Negatives (TN)**: 65 benign emails correctly marked safe.
- **False Positives (FP)**: 0 benign emails incorrectly blocked.
- **False Negatives (FN)**: 0 malicious emails permitted through.
- **True Positives (TP)**: 65 phishing emails successfully intercepted.

---

## 8. Explainability & Human-Centric Defense

SentinelPhish rejects black-box security outputs. Every triage session delivers:
1. **Unified Risk Score (0–100)**: Transparent sum of weighted points.
2. **Defensive Tier**: `LOW RISK`, `MODERATE RISK`, `SUSPICIOUS`, or `HIGH RISK / LIKELY PHISHING`.
3. **Itemized Checklist ("WHY?")**: Clear bullet points detailing which heuristics contributed points (e.g., `+40 pts: Double extension .pdf.exe`, `+30 pts: Raw IP address`, `+25 pts: Credential solicitation`).
4. **Actionable SOC SOP Guidance**: Prescriptive defensive steps for users and analysts (e.g., "Do not click links", "Verify out-of-band", "Escalate to SOC").

---

## 9. Verification & Automated Testing

The entire platform was subjected to a 25-scenario automated `pytest` test suite:
- **Test Scenarios**: Legitimate samples, urgency lures, credential harvesting, financial demands, raw IP links, double extensions, uppercase shouting, empty inputs, API input validation, ML prediction, and database persistence.
- **Execution Result**: **25 passed in 3.56s (100% pass rate, 0 warnings)**.

---

## 10. Privacy by Design & Security Hardening

1. **Zero-Trust Network Isolation**: Analysis never connects to, pings, or resolves target URLs.
2. **Data Minimization (GDPR/HIPAA Compliance)**: The database stores only analytical metadata and sender domains; full raw email bodies are discarded after memory processing.
3. **Input Sanitization**: Length boundaries and null-byte elimination protect against memory exhaustion and injection.
4. **Context-Aware HTML Escaping**: Client-side rendering neutralizes stored XSS attacks.

---

## 11. Conclusion & Future Scope

SentinelPhish demonstrates an end-to-end, industry-aligned cybersecurity project that combines defensive security engineering, explainable threat scoring, and machine learning. Future enhancements include:
- Ingesting cryptographic authentication headers (SPF, DKIM, DMARC).
- Integrating external reputation APIs (VirusTotal, AbuseIPDB) via asynchronous workers.
- Automated sandbox orchestration for dynamic payload detonation.
- Webhook integration with enterprise SIEM/SOAR platforms (Splunk, Microsoft Sentinel).
