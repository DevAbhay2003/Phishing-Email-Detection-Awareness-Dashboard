# Resume & LinkedIn Portfolio Assets

## Project: Phishing Email Detection & Awareness Dashboard (SentinelPhish)

---

### A. 3 Strong Resume Bullet Points

- **Architected and implemented a full-stack defensive email security dashboard** using Python (Flask), SQLite, and scikit-learn that evaluates incoming messages across sender identity, linguistic psychological manipulation, static URLs, and attachment vectors, delivering real-time risk scores ($0–100$) and explainable SOC telemetry.
- **Engineered a hybrid detection engine** combining deterministic rule-based heuristics ($60\%$) with an NLP TF-IDF machine learning classifier ($40\%$), eliminating single-point-of-failure vulnerabilities and achieving zero false negatives on a balanced validation split of 650 synthetic emails.
- **Integrated zero-click URL inspection, MITRE ATT&CK framework mapping (T1566)**, and an interactive "Before You Click" security awareness module; validated the entire defensive pipeline with a 25-scenario automated `pytest` suite ensuring 100% test pass rate.

---

### B. 2-Line Project Description

> An industry-oriented, defensive cybersecurity platform that triages email threats using static multi-vector analysis, explainable risk scoring, and hybrid ML classification. Designed with privacy-by-design principles to empower SOC analysts with actionable telemetry and train end users against social engineering attacks.

---

### C. Professional LinkedIn Project Post

```text
🚀 Excited to share my latest Cybersecurity Capstone Project: SentinelPhish — Phishing Email Detection & Awareness Dashboard!

Phishing remains the #1 initial access vector in modern enterprise breaches (MITRE ATT&CK T1566). As part of my cybersecurity coursework, I built an end-to-end, defensive email security platform to automate threat triage and empower users with explainable security awareness.

🛡️ Key Highlights of the Project:
• Multi-Vector Static Analysis: Passive inspection of sender domains (typosquatting & display-name spoofing), social engineering cues (artificial urgency, fear, credential requests), static URL properties (raw IP hostnames, shorteners), and attachment risks (double-extensions like .pdf.exe).
• Hybrid Threat Scoring: Blends deterministic heuristic rules (60%) with a scikit-learn NLP classifier (40%) to provide a calibrated risk score (0–100) and clear explainable reasoning ("WHY?").
• SOC-Grade Telemetry: Built an interactive dashboard featuring real-time KPI metrics, threat distribution charts, and a searchable SQLite audit database that respects privacy by never storing sensitive raw email bodies.
• Phishing Awareness Hub: Incorporates an interactive "Before You Click" checklist and MITRE ATT&CK framework mappings to educate employees against cognitive manipulation.
• 100% Automated Testing: Validated across 25 unit/integration test scenarios using pytest.

All demonstrations strictly utilize RFC-reserved safe domains (e.g. example.com, invalid.test) and documentation IP addresses to guarantee zero real-world attack exposure.

Check out the complete architecture and code on GitHub: [Your GitHub Repo Link]

#Cybersecurity #EmailSecurity #SOCAnalyst #Python #MachineLearning #DefensiveSecurity #ThreatDetection #InfoSec #OpenSource
```

---

### D. Technical Skills Demonstrated

- **Cybersecurity & SOC Concepts**: Email Security, Social Engineering Mitigation, Phishing Triaging, Static Threat Analysis, MITRE ATT&CK Framework (`T1566`), Defense-in-Depth, Security Operations Center (SOC) Workflows, Privacy by Design.
- **Programming & Frameworks**: Python 3, Flask, REST API Design, Jinja2/HTML5, CSS3 (SOC Dark Theme), JavaScript (Vanilla ES6+), Chart.js, SQLite, SQLAlchemy.
- **Data Science & Machine Learning**: Natural Language Processing (NLP), TF-IDF Vectorization, Logistic Regression, Multinomial Naive Bayes, Random Forest, Scikit-Learn, Pandas, Confusion Matrix Analysis, Precision/Recall Optimization.
- **Quality Assurance & DevOps**: Pytest, Automated Unit Testing, Boundary Value Analysis, Git Version Control, Environment Configuration (`python-dotenv`).

---

### E. GitHub Repository Description & Topics

**Repository Name**: `Phishing-Email-Detection-Awareness-Dashboard`

**Short Description**:
> Defensive cybersecurity dashboard for analyzing synthetic email content, sender patterns, URLs, attachments, and social-engineering indicators to generate explainable phishing risk assessments.

**GitHub Topics**:
`cybersecurity` `phishing-detection` `email-security` `soc` `python` `machine-learning` `nlp` `threat-detection` `security-awareness` `url-analysis` `defensive-security`
