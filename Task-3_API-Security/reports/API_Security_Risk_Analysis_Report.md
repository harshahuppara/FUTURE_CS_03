# API SECURITY RISK ANALYSIS REPORT
## Application Security (AppSec) Audit & Risk Assessment
**Target API:** ReqRes REST API Platform (`https://reqres.in`)  
**Assessment Standard:** OWASP API Security Top 10 (2023)  
**Program:** Cyber Security Internship (Future Interns)  
**Task Deliverable:** Task 3 — API Security Risk Analysis (Modern SaaS Skill)  
**Assessor:** Harsha H (AppSec & Cybersecurity Intern)  
**Date:** October 2026  
**Classification:** Confidential / Client Deliverable  

---

## 1. Executive Summary

Modern web and mobile architectures have transitioned away from monolithic applications toward **API-driven microservices and SaaS ecosystems**. While APIs dramatically enhance agility and integration capabilities, they also expand an organization's attack surface by exposing backend data models directly to client applications.

In October 2026, a non-intrusive, read-only API Security Risk Assessment was performed against the **ReqRes API** (`https://reqres.in`). The evaluation was conducted strictly in accordance with ethical security guidelines and aligned with the **OWASP API Security Top 10 (2023)** standard.

### Key Assessment Findings
The audit identified **5 primary security weaknesses** across authorization, authentication, configuration, and data exposure:
- **High Severity (1):** Broken Object Level Authorization (BOLA) & Sequential ID Enumeration
- **Medium Severity (3):** Broken Authentication (Opaque Token Hygiene), Excessive Data Exposure, Overly Permissive CORS (`*`)
- **Low Severity (1):** Backend Technology Information Disclosure in HTTP Headers

### Business Impact Summary
Without mandatory object-level authorization, external threat actors can iterate sequential integer identifiers (`1, 2, 3...`) to harvest the entire registered customer database. Furthermore, the issuance of static, unsigned tokens without expiration mechanisms compromises session security, exposing SaaS platforms to account takeover, unauthorized cross-origin data exfiltration, and regulatory non-compliance (GDPR, SOC 2).

---

## 2. Scope & Ethical Testing Rules

| Test Category | Permitted & Executed (Read-Only) | Strictly Prohibited |
| :--- | :--- | :--- |
| **Endpoint Inspection** | `GET` requests to public endpoints & safe simulated `POST /api/login` | Malicious payload injection, SQLi, or unauthorized DB updates |
| **Authentication Audit** | Token structure inspection & header parameter validation | Credential stuffing, brute-force attacks, or password spray |
| **Volume & Load** | Single-request functional testing | Automated Denial of Service (DoS) or volume fuzzing |
| **Scope** | Public demonstration endpoints (`https://reqres.in/api/*`) | Targeting private infrastructure or third-party integrations |

---

## 3. OWASP API Security Top 10 (2023) Findings Matrix

| Finding ID | OWASP API Category | Vulnerability Title | Severity | CVSS 3.1 | Status |
| :---: | :--- | :--- | :---: | :---: | :---: |
| **SEC-API-01** | **API1:2023 BOLA** | Unrestricted Object Access via Sequential Enumeration | **HIGH** | **7.5** | Non-Compliant |
| **SEC-API-02** | **API2:2023 Broken Auth** | Opaque Token Generation Lacking Expiry & Signatures | **MEDIUM** | **6.5** | Non-Compliant |
| **SEC-API-03** | **API3:2023 Broken Object Property** | Excessive Data Exposure in User Resource Responses | **MEDIUM** | **5.3** | Non-Compliant |
| **SEC-API-04** | **API7:2023 Misconfiguration** | Overly Permissive CORS Policy (`Access-Control-Allow-Origin: *`) | **MEDIUM** | **5.3** | Non-Compliant |
| **SEC-API-05** | **API7:2023 Misconfiguration** | Technology Stack Disclosure in HTTP Response Headers | **LOW** | **3.3** | Informational |

---

## 4. In-Depth Technical Findings & Remediation

---

### SEC-API-01: Broken Object Level Authorization (BOLA / IDOR)
* **OWASP Category:** API1:2023 Broken Object Level Authorization
* **Severity:** **HIGH** (CVSS: 7.5 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
* **Affected Endpoints:** `GET /api/users`, `GET /api/users/{id}`

#### 1. Technical Analysis
The API exposes user profile objects directly to the public Internet without validating whether the caller is authenticated or possesses the authority to view the specified object.
- Request: `GET /api/users/2 HTTP/1.1` (No `Authorization: Bearer <token>` header supplied).
- Response: `HTTP/1.1 200 OK` — Returns complete profile (ID, email, first name, last name, avatar).
- Furthermore, IDs are predictable sequential integers (`1, 2, 3...`), facilitating automated mass scraping.

#### 2. Business Impact (Non-Technical Explanation)
Imagine an online bank or medical portal where simply changing the number in the web address from `user/10` to `user/11` lets you see someone else's complete private profile. This flaw enables automated data harvesting, violating data privacy mandates such as GDPR and CCPA.

#### 3. Practical Remediation Steps
1. **Mandate Authorization on All Object Endpoints:** Verify that every request includes a valid Bearer token.
2. **Implement Object-Level Ownership Checks:** Verify that the user ID embedded in the caller's JWT matches the requested resource ID:
   ```javascript
   if (req.user.id !== requestedUserId && !req.user.roles.includes('ADMIN')) {
       return res.status(403).json({ error: "Access Denied" });
   }
   ```
3. **Migrate to Non-Sequential UUIDs:** Replace predictable integer IDs (`/api/users/1`) with randomized UUIDv4 identifiers (`/api/users/f47ac10b-58cc-4372-a567-0e02b2c3d479`) to neutralize brute-force enumeration.

---

### SEC-API-02: Broken Authentication & Weak Token Hygiene
* **OWASP Category:** API2:2023 Broken Authentication
* **Severity:** **MEDIUM** (CVSS: 6.5)
* **Affected Endpoints:** `POST /api/login`, `POST /api/register`

#### 1. Technical Analysis
When a user authenticates via `POST /api/login`, the API issues an opaque string token:
```json
{
    "token": "QpwL5tke4Pnpja7X4"
}
```
- The token is a static, non-cryptographic string without standard JWT segments (`header.payload.signature`).
- The token contains no expiration claim (`exp`), no issuance timestamp (`iat`), and no user scope.
- Protected endpoints do not validate this token; they return data regardless of whether the token is provided or invalid.

#### 2. Business Impact
If an attacker intercepts or steals this token, it never expires, granting indefinite access to the compromised session. Furthermore, storing tokens in browser LocalStorage without `HttpOnly` protection leaves them vulnerable to client-side Cross-Site Scripting (XSS) theft.

#### 3. Practical Remediation Steps
1. **Adopt Standards-Compliant JWTs (RFC 7519):** Issue digitally signed JWTs utilizing asymmetric algorithms (e.g., `RS256` or `ES256`).
2. **Enforce Short Token Lifespans:** Set access token expiration to **15 minutes** with secure refresh token rotation.
3. **Transmit Tokens via Secure Cookies:** Return session tokens within `Set-Cookie: token=...; Secure; HttpOnly; SameSite=Strict` rather than raw JSON response bodies.

---

### SEC-API-03: Excessive Data Exposure (Property-Level Authorization)
* **OWASP Category:** API3:2023 Broken Object Property Level Authorization
* **Severity:** **MEDIUM** (CVSS: 5.3)
* **Affected Endpoints:** `GET /api/users`, `GET /api/users/{id}`

#### 1. Technical Analysis
The API serialization logic dumps the entire backend database model directly into the HTTP response body without field masking or client-specific scoping.

#### 2. Business Impact
When applications rely on client-side code (React/Vue/Mobile) to hide sensitive fields, the raw data remains completely visible to anyone opening browser DevTools or Postman. If backend models expand to include sensitive attributes (e.g., hashed passwords, internal role flags, PII), they are unintentionally leaked to public callers.

#### 3. Practical Remediation Steps
1. **Implement Data Transfer Objects (DTOs):** Define explicit response serialization models that selectively include only necessary public attributes.
2. **Adopt Response Filtering Gateways:** Configure the API gateway to strip internal metadata before responses leave the perimeter.

---

### SEC-API-04: Overly Permissive Cross-Origin Resource Sharing (CORS: *)
* **OWASP Category:** API7:2023 Security Misconfiguration
* **Severity:** **MEDIUM** (CVSS: 5.3)
* **Affected Endpoints:** All API routes

#### 1. Technical Analysis
The server responds with:
```http
Access-Control-Allow-Origin: *
```
This wildcard configuration instructs web browsers to allow script code running on **any arbitrary domain** to read responses returned by the API.

#### 2. Business Impact
If an authenticated employee visits a rogue website while logged into the SaaS platform, malicious JavaScript on the rogue site can make API calls and harvest data across origins.

#### 3. Practical Remediation Steps
Replace the wildcard `*` with an explicit whitelist of authorized origin domains:
```http
Access-Control-Allow-Origin: https://app.example.com
```

---

### SEC-API-05: Information Disclosure in Server Headers
* **OWASP Category:** API7:2023 Security Misconfiguration
* **Severity:** **LOW** (CVSS: 3.3)
* **Affected Endpoints:** All API routes

#### 1. Technical Analysis
The API broadcasts technical infrastructure banners in its response headers:
```http
X-Powered-By: ReqRes.in - Deploy backends in 30 seconds
Via: 1.1 heroku-router
Server: cloudflare
```

#### 2. Business Impact
While not directly exploitable, it assists attackers in automated reconnaissance and fingerprinting backend middleware engines.

#### 3. Practical Remediation Steps
Configure the API gateway or reverse proxy to strip `X-Powered-By` and `Via` headers before serving responses.

---

## 5. Developer Remediation Roadmap

```
[Phase 1: Immediate Sprint (1-2 Weeks)]
 ├── Mandate Bearer Token validation on all /api/users/* routes (SEC-API-01)
 └── Restrict CORS Access-Control-Allow-Origin to trusted origins (SEC-API-04)

[Phase 2: Authentication Hardening (Month 1)]
 ├── Transition from static tokens to RS256-signed JWTs with 15-minute expiry (SEC-API-02)
 └── Deliver tokens via Secure; HttpOnly; SameSite=Strict cookies

[Phase 3: Data Architecture & Posture (Quarter 1)]
 ├── Replace sequential integer IDs with UUIDv4 across all database schemas (SEC-API-01)
 ├── Implement DTO serialization to prevent excessive data exposure (SEC-API-03)
 └── Enforce API rate limiting (RateLimit-Limit: 100/min per IP/Token)
```

---

## 6. Conclusion & Auditor Sign-Off

Securing modern APIs requires treating backend services as untrusted, zero-trust environments. By implementing strong object-level authorization, cryptographic JWT tokens, strict CORS policies, and UUID identifiers, SaaS engineering teams can eliminate high-risk exposure and ensure long-term architectural resilience.

**Assessor:** Harsha H  
**Specialization:** Application Security & API Risk Assessment  
**Program:** Future Interns (Cohort 2026)  
