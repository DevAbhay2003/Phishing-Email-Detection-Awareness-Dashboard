# REST API Specification

## SentinelPhish: Phishing Email Detection & Awareness Dashboard

Base URL: `http://127.0.0.1:5000/api`

---

### 1. Ingest & Analyze Email
- **Endpoint**: `POST /api/analyze`
- **Description**: Evaluates an email across sender, content, URL, and attachment vectors using the hybrid rule-based and ML engine. Persists metadata to SQLite audit database.
- **Content-Type**: `application/json` or `multipart/form-data`
- **Request Body (JSON)**:
```json
{
  "sender": "\"Security Desk\" <security-alert@account-check.invalid.test>",
  "subject": "URGENT: Verify Your Account Immediately",
  "body": "Dear customer, your account will be suspended. Verify immediately at http://198.51.100.10/verify-account",
  "urls": "http://198.51.100.10/verify-account",
  "attachment_name": "Invoice.pdf.exe",
  "expected_org": "Example Bank"
}
```
- **Multipart Form Upload**:
  - `file`: Uploaded `.eml` or `.txt` email file.
  - Optional override fields: `sender`, `subject`, `body`, `urls`, `attachment_name`.
- **Response (200 OK)**:
```json
{
  "success": true,
  "analysis_id": 42,
  "risk_score": 85,
  "classification": "HIGH RISK / LIKELY PHISHING",
  "threat_level": "High Confidence Threat",
  "color_code": "#ef4444",
  "rule_score": 90,
  "ml_assessment": {
    "available": true,
    "phishing_probability": 0.98,
    "percentage": 98.0,
    "label": "PHISHING"
  },
  "hybrid_mode_active": true,
  "indicators": [
    {
      "type": "ATTACHMENT_CRITICAL",
      "severity": "CRITICAL",
      "points": 40,
      "description": "Double Extension Deception: Filename poses as '.pdf' but executes as '.exe'"
    },
    {
      "type": "URL_HIGH_RISK",
      "severity": "HIGH",
      "points": 30,
      "description": "Host uses a raw numerical IP address (198.51.100.10)"
    }
  ],
  "recommendations": [
    "DO NOT reply to this email or share any credentials, passwords, or personal details.",
    "DO NOT click any hyperlinks or copy-paste URLs into your web browser.",
    "DO NOT download, preview, or open the email attachment under any circumstances."
  ]
}
```
- **Error Responses**:
  - `400 Bad Request`: When sender, subject, and body are all empty.
  - `500 Internal Server Error`: Server failure during triage.

---

### 2. Standalone URL Analysis
- **Endpoint**: `POST /api/analyze/url`
- **Description**: Statically dissects a candidate URL without connecting to it.
- **Request Body (JSON)**:
```json
{
  "url": "http://198.51.100.10/verify-account?token=99281",
  "displayed_text": "https://secure.example.com"
}
```
- **Response (200 OK)**:
```json
{
  "success": true,
  "analysis": {
    "url": "http://198.51.100.10/verify-account?token=99281",
    "url_risk_score": 85,
    "findings": [
      "Insecure protocol: Uses unencrypted HTTP instead of HTTPS",
      "Host uses a raw numerical IP address (198.51.100.10) instead of a registered domain",
      "Contains credential/authentication keywords: verify, account",
      "Hyperlink spoofing: Display text claims 'https://secure.example.com' but href points to '198.51.100.10'"
    ],
    "properties": {
      "scheme": "http",
      "hostname": "198.51.100.10",
      "is_raw_ip": true,
      "is_shortener": false
    }
  }
}
```

---

### 3. List Analysis History
- **Endpoint**: `GET /api/analyses`
- **Query Parameters**:
  - `search` (string): Keyword matching subject or domain.
  - `classification` (string): Filter by tier (`HIGH RISK / LIKELY PHISHING`, `SUSPICIOUS`, etc.).
  - `sort` (string): `newest`, `oldest`, `highest_risk`, `lowest_risk`.
  - `limit` (integer): Maximum records to retrieve (default 50).
- **Response (200 OK)**:
```json
{
  "success": true,
  "count": 1,
  "analyses": [
    {
      "analysis_id": 1,
      "sender": "\"Security Alert\" <alert@account-check.invalid.test>",
      "sender_domain": "account-check.invalid.test",
      "subject": "URGENT: Verify Your Account Immediately",
      "risk_score": 85,
      "classification": "HIGH RISK / LIKELY PHISHING",
      "attachment_name": "",
      "created_at": "2026-10-02T16:46:12"
    }
  ]
}
```

---

### 4. Get Analysis Details
- **Endpoint**: `GET /api/analyses/{id}`
- **Response (200 OK)**: Full telemetry including child indicator list and URL analyses.
- **Response (404 Not Found)**: If record ID does not exist.

---

### 5. Delete Analysis Record
- **Endpoint**: `DELETE /api/analyses/{id}`
- **Response (200 OK)**:
```json
{
  "success": true,
  "message": "Analysis #42 deleted."
}
```

---

### 6. Dashboard Telemetry Statistics
- **Endpoint**: `GET /api/dashboard/stats`
- **Response (200 OK)**: Aggregated counts, average risk score, classification distribution, and score histograms.

---

### 7. Top Indicators
- **Endpoint**: `GET /api/dashboard/indicators`
- **Response (200 OK)**: Frequency count of top triggered indicators across historical analyses.

---

### 8. Safe Demonstration Presets
- **Endpoint**: `GET /api/samples`
- **Response (200 OK)**: Curated list of 4 safe demonstration emails.

---

### 9. Service Health Check
- **Endpoint**: `GET /api/health`
- **Response (200 OK)**: Service status and ML model artifact readiness.
