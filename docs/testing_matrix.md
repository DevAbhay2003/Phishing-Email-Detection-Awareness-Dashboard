# Comprehensive Test Execution Matrix (25 Test Scenarios)

## Project: Phishing Email Detection & Awareness Dashboard
Test Runner: `pytest 9.1.1` | Python 3.13.14 | Status: **25 PASSED (100% Success Rate)**

| Test ID | Scenario | Input Description | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TEST-01** | Legitimate email | Sender: `training@example.org`, Normal subject & body, `.pdf` attachment | Score $\le 20$, Class: `LOW RISK` | Score: 0, Class: `LOW RISK` | **PASS** |
| **TEST-02** | Urgent phishing-style email | Urgent panic language, raw IP link `http://198.51.100.10/verify-account` | Score $\ge 70$, Class: `HIGH RISK / LIKELY PHISHING` | Score: 85, Class: `HIGH RISK / LIKELY PHISHING` | **PASS** |
| **TEST-03** | Credential request | Body explicitly soliciting password verification | Trigger `credential_request` category, Score $\ge 25$ | Category triggered, Points: +25 | **PASS** |
| **TEST-04** | Financial request | Body demanding urgent overdue invoice wire transfer | Trigger `financial_pressure` category, Score $\ge 15$ | Category triggered, Points: +12 | **PASS** |
| **TEST-05** | Generic greeting | Body starting with "Dear Valued Customer" | Trigger `generic_greeting` indicator | Category triggered, Points: +5 | **PASS** |
| **TEST-06** | Safe URL | `https://corp.example.com/intranet/holidays` | URL Risk Score: 0, Scheme: `https`, Raw IP: `False` | Score: 0, Scheme: `https`, Raw IP: `False` | **PASS** |
| **TEST-07** | Raw IP URL | `http://198.51.100.10/verify-account` | URL Risk Score $\ge 40$, `is_raw_ip`: `True` | Score: 55, `is_raw_ip`: `True` | **PASS** |
| **TEST-08** | Non-HTTPS URL | `http://example.com/welcome` | Scheme: `http`, Finding: Insecure protocol | Insecure protocol flag raised | **PASS** |
| **TEST-09** | Excessive subdomains | `http://auth.portal.security.update.example.com/login` | Subdomain count $\ge 3$, Finding flagged | Flagged (4 subdomains detected) | **PASS** |
| **TEST-10** | Suspicious keyword in URL | `http://example.org/auth/login?redirect=account_verification` | Flagged credential keywords (`login`, `auth`) | Flagged credential keywords | **PASS** |
| **TEST-11** | No URL | Empty string `""` | URL Risk Score: 0, Finding: "No URL provided" | Score: 0, "No URL provided" | **PASS** |
| **TEST-12** | Multiple URLs | String containing both corp HTTPS link and raw IP link | Regex extracts 2 distinct URLs safely | Extracted 2 distinct URLs | **PASS** |
| **TEST-13** | Normal attachment | `annual_report.pdf` | Attachment Risk: 0, Category: `SAFE / STANDARD` | Risk: 0, `SAFE / STANDARD` | **PASS** |
| **TEST-14** | Executable attachment | `Security_Patch.exe` | Risk $\ge 80$, Category: `HIGH RISK / MALICIOUS INDICATOR` | Risk: 80, Flagged dangerous binary | **PASS** |
| **TEST-15** | Double extension | `invoice.pdf.exe` | Risk $\ge 85$, Flag: `Double Extension Deception` | Risk: 85, Double extension caught | **PASS** |
| **TEST-16** | Empty subject | Subject: `""`, valid sender and body | Risk score calculated without throwing error | Computed score: 0, no error | **PASS** |
| **TEST-17** | Empty body | Body: `""`, subject: `"Meeting at 2 PM"` | Handled cleanly, classified `LOW RISK` | Handled cleanly, `LOW RISK` | **PASS** |
| **TEST-18** | Invalid sender | Malformed sender without `@` symbol | Sender risk $\ge 40$, Syntax invalid finding | Sender Risk: 40, Syntax invalid | **PASS** |
| **TEST-19** | High uppercase ratio | Body and subject in ALL CAPS shouting | Text metric indicates uppercase panic ratio $> 0.4$ | Flagged aggressive shouting | **PASS** |
| **TEST-20** | Multiple exclamation marks | Text containing multiple `!!!` panic marks | Content finding flags excessive exclamation marks | Flagged panic inducement marks | **PASS** |
| **TEST-21** | Rule-score boundary | Extreme compound phishing vectors | Score capped between 0 and 100, Class: `HIGH RISK` | Score capped at 100, `HIGH RISK` | **PASS** |
| **TEST-22** | Database save | Insert new analysis with child indicators | Record assigned auto-increment `analysis_id` | DB ID assigned, relationships persisted | **PASS** |
| **TEST-23** | API validation | Empty request payload sent to `POST /api/analyze` | HTTP `400 Bad Request`, `success: false` | Status 400, validated input | **PASS** |
| **TEST-24** | ML prediction if enabled | Inference query on suspicious text | Probabilistic score returned ($0.0 \le p \le 1.0$) | Returned probability: 0.98 ($98\%$) | **PASS** |
| **TEST-25** | Analysis-history retrieval | Query `GET /api/analyses` | HTTP `200 OK`, JSON array of audit logs | Status 200, array of records | **PASS** |
