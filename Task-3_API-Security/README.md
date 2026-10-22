# 🌐 API Security Risk Analysis (OWASP API Top 10)
### Future Interns — Cyber Security Internship (Task 3)

[![Scope](https://img.shields.io/badge/Scope-API%20Security%20Audit-blue.svg)](https://github.com)
[![Standard](https://img.shields.io/badge/Framework-OWASP%20API%20Security%20Top%2010%20(2023)-orange.svg)](https://owasp.org/www-project-api-security/)
[![Target](https://img.shields.io/badge/Target-ReqRes%20API%20(reqres.in)-green.svg)](https://reqres.in)
[![CVSS](https://img.shields.io/badge/Highest%20CVSS-7.5%20(High)-red.svg)](reports/API_Security_Risk_Analysis_Report.md)

---

## 📌 Executive Overview

Modern applications and SaaS platforms rely heavily on REST APIs to exchange data between mobile applications, single-page web dashboards, and microservices. Because APIs expose underlying database models directly to clients, insecure APIs present critical risks of unauthorized data harvesting, account takeover, and cross-origin data theft.

This repository contains the read-only, non-intrusive **API Security Risk Analysis** conducted on the **ReqRes API Platform** (`https://reqres.in`), an industry-standard mock REST platform referenced in the Future Interns curriculum.

The evaluation is aligned with the **OWASP API Security Top 10 (2023)** standard, covering endpoint authorization, token hygiene, Cross-Origin Resource Sharing (CORS), and data exposure.

---

## 🛠️ Testing Tools & Methodology

* **API Testing Engines:** Python 3 HTTP Client, Postman v2.1.0 Collection, Browser DevTools
* **Audit Scope:** Read-Only inspection of `https://reqres.in/api/*` endpoints
* **Standard:** OWASP API Security Top 10 (2023)
* **Risk Evaluation:** Common Vulnerability Scoring System (CVSS v3.1)

---

## 📊 Summary of Identified API Vulnerabilities

| Finding ID | OWASP API Category | Vulnerability Title | Severity | CVSS | Primary Business Impact |
| :---: | :--- | :--- | :---: | :---: | :--- |
| **SEC-API-01** | **API1:2023 BOLA** | Broken Object Level Authorization & Sequential Enumeration | **HIGH** | **7.5** | Unauthenticated callers can harvest all registered user records using sequential IDs (`1, 2, 3...`). |
| **SEC-API-02** | **API2:2023 Broken Auth** | Weak & Opaque Token Hygiene (No Expiration / Signatures) | **MEDIUM** | **6.5** | Issued tokens lack cryptographic signatures and expiry, granting indefinite session access if stolen. |
| **SEC-API-03** | **API3:2023 Property Auth** | Excessive Data Exposure in User Resource Responses | **MEDIUM** | **5.3** | Internal database models are dumped into API responses without response DTO filtering. |
| **SEC-API-04** | **API7:2023 Misconfig** | Overly Permissive Wildcard CORS (`Access-Control-Allow-Origin: *`) | **MEDIUM** | **5.3** | Malicious third-party websites can read cross-origin API responses in authenticated user browsers. |
| **SEC-API-05** | **API7:2023 Misconfig** | Technology Stack Information Disclosure in Headers | **LOW** | **3.3** | Server response headers broadcast backend routing and hosting metadata (`X-Powered-By`, `Via`). |

---

## 📂 Repository Directory Structure

```text
Task-3_API-Security/
├── evidence/
│   ├── logs/
│   │   ├── api_endpoint_audit.txt         # Detailed request/response logs for all 5 endpoints
│   │   ├── owasp_api_findings_matrix.txt  # Findings categorized by OWASP API 2023 criteria
│   │   └── full_api_audit_summary.json    # Machine-readable JSON audit output
│   ├── postman/
│   │   └── ReqRes_API_Security_Audit.postman_collection.json # Ready-to-import Postman collection
│   └── screenshots/
│       └── SCREENSHOTS_GUIDE.md           # Instructions for capturing Postman / DevTools evidence
├── reports/
│   ├── API_Security_Risk_Analysis_Report.pdf  # [SUBMISSION READY] Formatted PDF report
│   ├── API_Security_Risk_Analysis_Report.html # Print-ready interactive web report
│   └── API_Security_Risk_Analysis_Report.md   # Full markdown report
├── scripts/
│   └── api_security_scanner.py            # Automated OWASP API security audit script
└── README.md                              # Project overview and engagement documentation
```

---

## 🚀 How to Reproduce the Audit

### 1. Run the Automated Python Scanner
```bash
python scripts/api_security_scanner.py
```
This queries the 5 target endpoints, validates CORS headers, evaluates token structure, and generates the findings matrix in `evidence/logs/`.

### 2. Using Postman
1. Open Postman.
2. Click **Import** and select:
   `evidence/postman/ReqRes_API_Security_Audit.postman_collection.json`
3. Execute the pre-configured requests to inspect requests and responses interactively.

---

## 📄 Viewing the Final Report

* **PDF Version:** Open `reports/API_Security_Risk_Analysis_Report.pdf`
* **Web/Print Version:** Open `reports/API_Security_Risk_Analysis_Report.html` in Chrome/Edge and click **Print / Save as PDF**.

---

## ✍️ Author & Submission Information

* **Intern Name:** Harsha H
* **Program:** Cyber Security Internship (Future Interns)
* **Task ID:** Task 3 — API Security Risk Analysis (Modern SaaS Skill)
* **Cohort:** 2026
