# Phishing Email Detection & Awareness Dashboard (SentinelPhish)

> **A defensive, industry-oriented cybersecurity platform for static email triage, explainable threat scoring, hybrid machine learning classification, and interactive security awareness training.**

[![Python 3.13](https://img.shields.io/badge/Python-3.13-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests: 25 Passed](https://img.shields.io/badge/Pytest-25%20Passed%20(100%25)-success.svg)](tests/)
[![Security: Defensive Only](https://img.shields.io/badge/Security-Zero--Trust%20%2F%20Defensive-red.svg)](docs/architecture.md)
[![Framework: MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1566%20Phishing-orange.svg)](docs/mitre_mapping.md)

---

## 1. Overview

**SentinelPhish** is an end-to-end, enterprise-inspired cybersecurity platform designed to automate the triage of incoming suspicious emails and provide explainable risk assessments. Built with **defense-in-depth** and **zero-trust** principles, SentinelPhish statically inspects email headers, sender domains, cognitive manipulation language, embedded hyperlinks, and attachments without making risky network requests or executing untrusted files.

It pairs a calibrated **rule-based scoring engine** with an **NLP TF-IDF Machine Learning model** in a hybrid architecture to deliver transparent threat ratings ($0–100$), explainable justification checklists ("WHY?"), actionable incident response recommendations, and live SOC analytics.

---

## 2. Problem Statement

Phishing accounts for over **80% of reported security breaches** (MITRE ATT&CK `T1566`), serving as the primary delivery mechanism for credential harvesting, Business Email Compromise (BEC), and ransomware. 

Conventional email security tools suffer from two major operational limitations:
1. **The "Black-Box" Dilemma**: Most filters return a simple binary verdict (e.g. "Spam / Blocked") without explaining the indicators to SOC analysts or end users.
2. **The Awareness Gap**: Employees who receive threats do not learn what made the message suspicious, leaving them vulnerable to future social engineering tactics.

SentinelPhish bridges this gap by combining automated defensive triage with educational transparency.

---

## 3. Key Objectives

- **Multi-Vector Static Analysis**: Passive extraction of threat indicators across sender domains, message body, URLs, and attachments.
- **Explainable Threat Scoring**: Clear breakdown of point deductions and severity tiers so analysts can justify incident escalation.
- **Hybrid Triage (Rules + ML)**: Combines deterministic heuristics ($60\%$) with probabilistic NLP predictions ($40\%$) to eliminate single-point-of-failure blind spots.
- **Privacy by Design**: Persistent database logs only analytical metadata; full raw email bodies are never stored to ensure privacy compliance.
- **Educational Empowerment**: Features an interactive "Before You Click" checklist and MITRE ATT&CK framework mapping.

---

## 4. Features & Capabilities

- 🛡️ **Live Email Analyzer**: Interactive form and drag-and-drop support for RFC 822 `.eml` and `.txt` files.
- 🎯 **One-Click Safe Presets**: Preloaded with safe scenarios: Urgent Account Verification, Fake Invoice (`.pdf.exe`), CEO Fraud Wire Transfer, and Benign Workshop Notice.
- 🔍 **Static URL Inspection**: Lexical parsing of scheme, raw IP hostnames (`198.51.100.10`), link shorteners, and credential keywords without network requests.
- 📎 **Attachment Risk Analyzer**: Static detection of dangerous binaries (`.exe`, `.scr`), scripts (`.vbs`, `.ps1`), macros (`.docm`), and double extensions (`.pdf.exe`).
- 🧠 **Explainable "WHY?" Checklist**: Granular breakdown of triggered indicators and point additions.
- 📊 **SOC Analytics Dashboard**: Live Chart.js visualizations for threat distribution, score histograms, and top triggered indicators.
- 🕒 **Searchable Threat Audit History**: Search, sort, and inspect historical analysis records stored in SQLite.
- 🎓 **Phishing Awareness Hub**: 10 Red Flag rules, interactive checklist, and MITRE ATT&CK alignment.

---

## 5. System Architecture

```mermaid
flowchart TD
    User([Security Analyst / Student / User]) -->|Submits Email Text or .eml File| UI[Frontend Web Dashboard]
    
    subgraph Client_Layer ["Client Presentation Layer (SPA)"]
      UI --> Tab1[Live Email Analyzer]
      UI --> Tab2[Security Analytics Dashboard]
      UI --> Tab3[Phishing Awareness Hub]
      UI --> Tab4[Threat History Audit Log]
    end

    UI -->|HTTP REST JSON / Multipart| API[Flask REST API Server]

    subgraph Preprocessing_Layer ["Defensive Preprocessing"]
      API --> Parser[MIME / .eml Parser & Sanitizer]
      Parser --> Preprocessor[Defensive Preprocessor]
    end

    subgraph Analyzers ["Multi-Vector Static Analyzers (Zero-Click)"]
      Preprocessor --> SenderEng[Sender & Domain Analyzer]
      Preprocessor --> ContentEng[Content & Social Engineering Analyzer]
      Preprocessor --> URLEng[Static URL Threat Analyzer]
      Preprocessor --> AttachEng[Attachment & Extension Analyzer]
    end

    subgraph Decision_Engine ["Hybrid Decision Engine"]
      SenderEng --> RuleEngine[Calibrated Rule-Based Engine (60%)]
      ContentEng --> RuleEngine
      URLEng --> RuleEngine
      AttachEng --> RuleEngine

      Preprocessor --> MLClassifier[TF-IDF + ML Model (40%)]
      
      RuleEngine --> HybridEngine[Hybrid Decision Engine]
      MLClassifier --> HybridEngine
    end

    subgraph Output_Layer ["Telemetry & Persistence"]
      HybridEngine --> Score[Threat Score: 0-100 & Tier]
      HybridEngine --> Explain[Explainable Checklist: WHY?]
      HybridEngine --> Recs[SOC Operational Guidance]
      
      Score --> SQLite[(SQLite Audit DB)]
      Explain --> SQLite
      
      Score --> UI
      Explain --> UI
      Recs --> UI
    end
```

---

## 6. Technology Stack

- **Backend**: Python 3.13, Flask, SQLAlchemy, Python-dotenv
- **Machine Learning & NLP**: Scikit-Learn, Pandas, NumPy, Joblib, TF-IDF Vectorization
- **Database**: SQLite (SQLAlchemy ORM)
- **Frontend**: HTML5, CSS3 (SOC Dark Theme), Vanilla JavaScript (ES6+), Chart.js, FontAwesome
- **Testing**: Pytest (25 Automated Scenarios)

---

## 7. Safe Synthetic Dataset

In strict compliance with defensive cybersecurity ethics, **zero real malicious URLs or targets** are used. All synthetic records leverage:
- **RFC 2606 / RFC 6761 Reserved Domains**: `example.com`, `example.org`, `invalid.test`
- **RFC 5737 Reserved IPv4 Subnets**: `198.51.100.0/24` (TEST-NET-2)

The dataset contains **650 balanced records** (325 Legitimate / 325 Phishing):
- **Legitimate**: University notices, HR benefits enrollment, meeting reminders, shopping receipts, and newsletters.
- **Synthetic Phishing**: Fake account verifications, delinquent invoices, CEO wire transfers, and credential resets.

To re-generate the dataset:
```bash
python data/generate_dataset.py
```

---

## 8. Multi-Vector Detection Heuristics

### A. Sender Analysis (`sender_analyzer.py`)
- Syntax validation and RFC address structure.
- Excessive subdomains ($> 3$ tiers).
- Unusually long hostnames ($> 28$ characters).
- Display-name brand spoofing (e.g., Display Name mentions "PayPal" but domain is `account-update.invalid.test`).
- Typosquatting / lookalike patterns (`micros0ft`, `paypa1`).

### B. Content Analysis (`content_analyzer.py`)
Scans subject lines and bodies for psychological manipulation across seven core categories:
1. **Urgency**: "Immediately", "Act now", "Within 24 hours".
2. **Fear / Intimidation**: "Account suspended", "Permanent termination", "Legal action".
3. **Financial Pressure**: "Outstanding invoice", "Wire transfer required", "Past due".
4. **Credential Requests**: "Verify your password", "Re-authenticate login".
5. **Prize / Baiting**: "Congratulations! You have won $50,000", "Claim your gift card".
6. **PII Collection**: Requests for Social Security Numbers, tax forms, banking details.
7. **Generic Impersonal Greetings**: "Dear Customer", "Dear Valued User".

### C. Static URL Threat Inspection (`url_analyzer.py`)
- Passive analysis with **zero network connections**.
- Insecure `http://` transport warnings.
- Hostnames using raw numerical IP addresses (e.g. `http://198.51.100.10/verify`).
- Known link shortener domains masking real destinations.
- Credential keywords in path or query strings (`verify`, `login`, `bank`, `account`).
- Hyperlink spoofing detection (displayed text differs from `href` destination).

### D. Attachment Risk Analysis (`attachment_analyzer.py`)
- Dangerous executables: `.exe`, `.scr`, `.bat`, `.cmd`, `.msi`.
- Script files: `.js`, `.vbs`, `.ps1`, `.hta`.
- Macro-enabled Office formats: `.docm`, `.xlsm`.
- Container evasion: `.iso`, `.img`, `.vhd`.
- **Double-extension evasion tactics**: `invoice.pdf.exe`.

---

## 9. Calibrated Threat Scoring & Classification

Raw point weights are aggregated and normalized to a score between $0$ and $100$:

| Score Range | Classification Tier | Color Code | Action Required |
| :---: | :---: | :---: | :--- |
| **0 – 20** | **LOW RISK** | `#10b981` (Green) | Standard security hygiene. |
| **21 – 40** | **MODERATE RISK** | `#eab308` (Yellow) | Caution advised; verify sender out-of-band. |
| **41 – 70** | **SUSPICIOUS** | `#f97316` (Orange) | Potential threat; do not click links or open files. |
| **71 – 100** | **HIGH RISK / LIKELY PHISHING** | `#ef4444` (Red) | High-confidence threat; isolate and escalate to SOC. |

---

## 10. Machine Learning & Benchmarking

Three classifiers were benchmarked on TF-IDF n-gram vectors (unigrams + bigrams) with an 80/20 stratified split:

| Model Architecture | Accuracy | Precision | Recall | F1-Score | Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **Selected (Production)** |
| Multinomial Naive Bayes | 1.0000 | 1.0000 | 1.0000 | 1.0000 | Evaluated |
| Random Forest (100 Trees) | 1.0000 | 1.0000 | 1.0000 | 1.0000 | Evaluated |

To retrain and evaluate the models:
```bash
python ml/train_model.py
python ml/evaluate_model.py
```

---

## 11. Installation & Local Execution

### Step 1: Clone or Open Project Folder
```bash
cd "C:\Users\user\Desktop\IIP Projects\CS\p5"
```

### Step 2: Set Up Virtual Environment (Optional but Recommended)
```bash
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Generate Synthetic Dataset & Train ML Model
```bash
python data/generate_dataset.py
python ml/train_model.py
python ml/evaluate_model.py
```

### Step 5: Seed Sample Data (Optional)
```bash
python data/seed_sample_data.py
```

### Step 6: Start Application Server
```bash
python run.py
```

### Step 7: Access Web Dashboard
Open your web browser and navigate to:
```text
http://127.0.0.1:5000
```

---

## 12. REST API Documentation

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/analyze` | Triage email JSON body or uploaded `.eml` / `.txt` file. |
| `POST` | `/api/analyze/url` | Standalone passive URL risk inspection. |
| `GET` | `/api/analyses` | Search, filter, and list historical triage logs. |
| `GET` | `/api/analyses/{id}` | Retrieve granular indicator details for an analysis. |
| `DELETE` | `/api/analyses/{id}` | Remove a triage log from the audit database. |
| `GET` | `/api/dashboard/stats` | Aggregated KPI metrics and distribution counts. |
| `GET` | `/api/dashboard/indicators` | Frequency breakdown of top triggered indicators. |
| `GET` | `/api/samples` | Fetch preloaded safe demonstration emails. |
| `GET` | `/api/health` | Service health and ML model status probe. |

*Full API schema and curl examples available in [`docs/api_spec.md`](docs/api_spec.md).*

---

## 13. Automated Testing Suite (25 Tests)

SentinelPhish includes a 25-scenario automated test suite covering all operational conditions:
```bash
pytest tests/test_comprehensive_25.py -v
```

**Results**: `25 passed in 3.56s (100% pass rate)`.

*Detailed test scenario matrix available in [`docs/testing_matrix.md`](docs/testing_matrix.md).*

---

## 14. MITRE ATT&CK® Framework Mapping

| Technique ID | Technique Name | SentinelPhish Defensive Control |
| :--- | :--- | :--- |
| `T1566.001` | Spearphishing Attachment | Static file extension analysis, double-extension detection (`.pdf.exe`). |
| `T1566.002` | Spearphishing Link | Static URL analysis, raw IP detection (`198.51.100.10`), link shortener flags. |
| `T1566.003` | Spearphishing via Service | Brand impersonation heuristics, display-name vs domain mismatch detection. |

*Full framework analysis available in [`docs/mitre_mapping.md`](docs/mitre_mapping.md).*

---

## 15. Security, Ethics, & Privacy

- **Safe Demonstrations Only**: Uses RFC-reserved test domains and IP addresses. No real phishing campaigns or credential harvesting.
- **Zero-Click URL Analysis**: URLs are parsed as static strings; no HTTP requests are sent to suspicious destinations.
- **No Payload Execution**: Attachments are analyzed purely by filename and extension metadata.
- **Privacy by Design**: Sensitive raw email bodies are processed in ephemeral memory and discarded. Only analytical metadata is persisted.

---

## 16. Disclaimer

> **This project is strictly designed for cybersecurity education, academic research, and defensive SOC analysis using synthetic or authorized data. It contains no offensive attack functionality, exploit code, or credential-harvesting mechanisms.**

---

## 17. Author & Acknowledgments

- **Author**: Cybersecurity Engineering Student
- **Course**: Defensive Cybersecurity & Security Operations Capstone
- **Project Repository**: `Phishing-Email-Detection-Awareness-Dashboard`
