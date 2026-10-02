# 13-Day Proof-of-Work Development History

This document outlines the step-by-step engineering roadmap executed to build the **Phishing Email Detection & Awareness Dashboard**. Use this structure for LinkedIn posts, portfolio updates, and interview talking points to prove authentic hands-on project execution.

---

### DAY 1: Architecture & Repository Initialization
- **Files Created**: `README.md`, `.gitignore`, `.env.example`, `requirements.txt`, `docs/architecture.md`
- **Functionality**: Defined system data flow, zero-trust static parsing boundaries, security requirements, and environment configuration.
- **GitHub Commit**: `"Initialize phishing detection project and define defensive architecture"`
- **Screenshot**: `screenshots/01_project_structure.png`
- **What It Proves**: Strong project planning, defensive design fundamentals, and enterprise project structuring.

---

### DAY 2: Safe Synthetic Dataset Engineering
- **Files Created**: `data/generate_dataset.py`, `data/phishing_email_dataset.csv`
- **Functionality**: Programmatically synthesized 650 balanced records (325 legitimate, 325 phishing) across university notices, HR announcements, fake invoices, and CEO fraud using strictly RFC-reserved safe domains (`example.com`, `invalid.test`) and test IP subnets (`198.51.100.0/24`).
- **GitHub Commit**: `"Add synthetic email dataset generator with RFC-safe domains"`
- **Screenshot**: `screenshots/04_dataset_class_distribution.png`
- **What It Proves**: Ethical cybersecurity practices, programmatic data synthesis, and understanding of social engineering lures.

---

### DAY 3: Defensive Email Preprocessing
- **Files Created**: `backend/services/preprocessor.py`, `backend/utils/helpers.py`
- **Functionality**: Built text normalization that deliberately preserves cyber threat evidence (uppercase shouting, exclamation panic marks, raw URLs, and parameters) without executing external network calls. Added RFC 822 `.eml` MIME parsing.
- **GitHub Commit**: `"Implement email preprocessing preserving security indicators"`
- **Screenshot**: `screenshots/24_api_json_response.png`
- **What It Proves**: Understanding why standard NLP cleaning can accidentally erase malicious intent in security operations.

---

### DAY 4: Sender & Linguistic Social Engineering Analyzers
- **Files Created**: `backend/services/sender_analyzer.py`, `backend/services/content_analyzer.py`
- **Functionality**: Implemented brand lookalike / typosquatting heuristics, display-name vs domain mismatch detection, and psychological categorization (Urgency, Fear/Intimidation, Financial Pressure, Credential Harvesting, and PII Requests).
- **GitHub Commit**: `"Add sender heuristic analysis and social engineering content detector"`
- **Screenshot**: `screenshots/08_sender_risk_findings.png`
- **What It Proves**: Ability to analyze cognitive attack vectors and header spoofing tactics.

---

### DAY 5: Passive Static URL Risk Engine
- **Files Created**: `backend/services/url_analyzer.py`
- **Functionality**: Constructed a zero-click lexical URL analyzer extracting schemes, hostnames, subdomain depth, raw IP address usage, link shorteners, credential-harvesting keywords, and hyperlink display spoofing.
- **GitHub Commit**: `"Add static URL risk analysis with zero-click security isolation"`
- **Screenshot**: `screenshots/09_url_risk_findings.png`
- **What It Proves**: Zero-trust URL inspection techniques and awareness that HTTPS does not equal legitimacy.

---

### DAY 6: Attachment & Extension Inspector
- **Files Created**: `backend/services/attachment_analyzer.py`
- **Functionality**: Static filename inspection detecting executable formats (`.exe`, `.scr`), scripts (`.vbs`, `.ps1`), weaponized macros (`.docm`, `.xlsm`), container evasion (`.iso`), and double-extension deception (`.pdf.exe`).
- **GitHub Commit**: `"Implement attachment filename and double-extension analysis"`
- **Screenshot**: `screenshots/10_attachment_analysis.png`
- **What It Proves**: Awareness of malicious delivery techniques and payload evasion methods.

---

### DAY 7: Calibrated Phishing Risk Engine & Explainability
- **Files Created**: `backend/services/risk_engine.py`, `backend/services/feature_extractor.py`
- **Functionality**: Aggregated multi-vector evidentiary findings into a normalized threat score (0–100), mapped scores to defensive tiers (`LOW RISK` to `HIGH RISK / LIKELY PHISHING`), and generated explainable "WHY?" breakdowns and SOC SOP recommendations.
- **GitHub Commit**: `"Build phishing risk scoring engine with explainable telemetry"`
- **Screenshot**: `screenshots/12_explainable_indicators.png`
- **What It Proves**: Explainable AI/heuristics in cybersecurity; analysts can justify incident escalation.

---

### DAY 8: Machine Learning Classifier Pipeline
- **Files Created**: `ml/train_model.py`, `ml/evaluate_model.py`, `ml/predictor.py`, `backend/services/hybrid_engine.py`
- **Functionality**: Trained Logistic Regression, Naive Bayes, and Random Forest using TF-IDF n-grams. Generated precision, recall, F1, and an SVG confusion matrix. Constructed a hybrid triage engine blending rule scores ($60\%$) with ML predictions ($40\%$).
- **GitHub Commit**: `"Add optional ML detection model and hybrid decision engine"`
- **Screenshot**: `screenshots/19_confusion_matrix_svg.png`
- **What It Proves**: Applied machine learning for defensive threat detection and benchmarking.

---

### DAY 9: SOC Analytics & Executive Dashboard
- **Files Created**: `frontend/index.html`, `frontend/styles.css`, `frontend/app.js`, `backend/routes/dashboard.py`
- **Functionality**: Created dark-mode SOC interface with metric KPI cards, Chart.js visualizations (Classification Distribution, Risk Score Buckets, Top Triggered Indicators), and live email triage forms.
- **GitHub Commit**: `"Build cybersecurity dashboard with live telemetry charts"`
- **Screenshot**: `screenshots/14_dashboard_analytics_kpi.png`
- **What It Proves**: Full-stack capability and ability to present security telemetry to management.

---

### DAY 10: Security Awareness & MITRE ATT&CK Mapping
- **Files Created**: Updates to `frontend/index.html`, `docs/mitre_mapping.md`
- **Functionality**: Built an educational hub detailing 10 Phishing Red Flags, an interactive "Before You Click" checklist with dynamic scoring, and aligned features to MITRE ATT&CK (`T1566.001`, `T1566.002`, `T1566.003`).
- **GitHub Commit**: `"Add phishing awareness module and MITRE ATT&CK framework mapping"`
- **Screenshot**: `screenshots/21_awareness_hub_checklist.png`
- **What It Proves**: End-user security awareness training, human risk mitigation, and threat framework literacy.

---

### DAY 11: Audit Database & Threat History Log
- **Files Created**: `backend/database.py`, `backend/models/schema.py`, `backend/routes/history.py`, `data/seed_sample_data.py`
- **Functionality**: Implemented SQLite database logging threat audit records without retaining raw email bodies (privacy by design). Added search, filtering by classification, sorting, and telemetry inspection modals.
- **GitHub Commit**: `"Implement threat audit logging and analysis history with SQLite"`
- **Screenshot**: `screenshots/20_threat_history_audit_log.png`
- **What It Proves**: Database design, audit compliance, privacy engineering, and incident tracking.

---

### DAY 12: Automated Security Testing Suite
- **Files Created**: `tests/test_comprehensive_25.py`, `docs/testing_matrix.md`
- **Functionality**: Implemented 25 automated unit and integration tests covering benign emails, urgent lures, raw IP URLs, double extensions, uppercase panic, database transactions, and API validation. Achieved 100% pass rate.
- **GitHub Commit**: `"Add comprehensive 25-scenario automated testing suite"`
- **Screenshot**: `screenshots/23_pytest_25_tests_passed.png`
- **What It Proves**: Test-driven development, software verification, and high software quality.

---

### DAY 13: Final Packaging & Documentation
- **Files Created**: `README.md`, `docs/project_report.md`, `docs/api_spec.md`, `docs/interview_preparation.md`, `docs/resume_linkedin.md`
- **Functionality**: Comprehensive documentation, user execution guides, interview talking points, and resume bullet points.
- **GitHub Commit**: `"Complete production documentation, project report, and interview guide"`
- **Screenshot**: `screenshots/26_readme_documentation_preview.png`
- **What It Proves**: Professional communication, placement-readiness, and mentorship excellence.
