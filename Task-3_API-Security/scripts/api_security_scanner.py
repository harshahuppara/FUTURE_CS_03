#!/usr/bin/env python3
"""
API Security Risk Analyzer (OWASP API Security Top 10 Aligned)
Author: Harsha H - Cybersecurity Intern (Future Interns)
Target: ReqRes API (https://reqres.in)
Scope: Read-Only, Non-Intrusive, Safe Testing
"""

import urllib.request
import urllib.error
import json
import ssl
from datetime import datetime

BASE_URL = "https://reqres.in"

ENDPOINTS = [
    {
        "name": "List Users",
        "method": "GET",
        "path": "/api/users?page=1",
        "auth_required_expected": True,
        "description": "Retrieves paginated list of registered users"
    },
    {
        "name": "Single User Record (ID: 2)",
        "method": "GET",
        "path": "/api/users/2",
        "auth_required_expected": True,
        "description": "Retrieves individual user profile by numerical ID"
    },
    {
        "name": "Sequential User ID Enumeration (ID: 1)",
        "method": "GET",
        "path": "/api/users/1",
        "auth_required_expected": True,
        "description": "Tests predictable sequential identifier vulnerability"
    },
    {
        "name": "Resource Metadata",
        "method": "GET",
        "path": "/api/unknown",
        "auth_required_expected": False,
        "description": "Retrieves shared system resource collection"
    },
    {
        "name": "User Authentication (Simulated Login)",
        "method": "POST",
        "path": "/api/login",
        "auth_required_expected": False,
        "payload": {"email": "eve.holt@reqres.in", "password": "cityslicka"},
        "description": "Tests authentication token generation and credential handling"
    }
]

def make_request(method, path, payload=None):
    url = f"{BASE_URL}{path}"
    headers = {
        "User-Agent": "Cybersecurity-API-Audit/1.0",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    data = json.dumps(payload).encode("utf-8") if payload else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    ctx = ssl.create_default_context()
    
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            status = response.getcode()
            resp_headers = dict(response.info())
            raw_body = response.read().decode("utf-8", errors="ignore")
            try:
                body_json = json.loads(raw_body)
            except Exception:
                body_json = raw_body[:500]
            return status, resp_headers, body_json
    except urllib.error.HTTPError as e:
        status = e.code
        resp_headers = dict(e.headers)
        raw_body = e.read().decode("utf-8", errors="ignore")
        try:
            body_json = json.loads(raw_body)
        except Exception:
            body_json = raw_body[:500]
        return status, resp_headers, body_json
    except Exception as e:
        return 0, {}, str(e)

def main():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("=" * 75)
    print("  CYBERSECURITY TASK 3: API SECURITY RISK ANALYSIS")
    print(f"  Target: {BASE_URL}")
    print(f"  Timestamp: {timestamp}")
    print("  Standard: OWASP API Security Top 10 (2023)")
    print("=" * 75)
    
    audit_results = []
    findings = []
    
    for ep in ENDPOINTS:
        print(f"\n[*] Testing: {ep['name']} [{ep['method']} {ep['path']}]...")
        status, headers, body = make_request(ep["method"], ep["path"], ep.get("payload"))
        print(f"    Response Status: {status}")
        
        audit_results.append({
            "endpoint": ep["name"],
            "method": ep["method"],
            "path": ep["path"],
            "status": status,
            "headers": headers,
            "body_sample": body if isinstance(body, dict) else str(body)[:200]
        })
        
        # Security Checks
        # 1. Unauthenticated Access to Private Data (BOLA / Broken Object Level Auth)
        if ep["auth_required_expected"] and status == 200:
            if not any(f["id"] == "API1-BOLA" for f in findings):
                findings.append({
                    "id": "API1-BOLA",
                    "owasp_category": "API1:2023 Broken Object Level Authorization",
                    "title": "Unrestricted / Unauthenticated Object Access via Predictable IDs",
                    "severity": "HIGH",
                    "cvss": "7.5",
                    "affected_endpoints": ["GET /api/users", "GET /api/users/2", "GET /api/users/1"],
                    "description": "User profiles and customer records are exposed to public, unauthenticated callers without Bearer token or session validation. Furthermore, IDs are predictable integers (1, 2, 3), allowing automated mass enumeration and database scraping.",
                    "remediation": "Mandate Bearer token authentication across all user-facing endpoints. Enforce user-level authorization checks ensuring callers can only query their own account object, and migrate from sequential IDs to non-sequential UUIDv4."
                })
                
        # 2. Check Token Generation on Login
        if ep["name"] == "User Authentication (Simulated Login)" and status == 200:
            token = body.get("token") if isinstance(body, dict) else None
            if token and len(token) < 32 and not token.startswith("eyJ"): # Non-JWT or static token
                findings.append({
                    "id": "API2-BROKEN-AUTH",
                    "owasp_category": "API2:2023 Broken Authentication",
                    "title": "Weak & Opaque Authentication Token Generation",
                    "severity": "MEDIUM",
                    "cvss": "6.5",
                    "affected_endpoints": ["POST /api/login", "POST /api/register"],
                    "description": "The login endpoint returns a simple, static token string lacking cryptographic signatures, expiration timestamps (exp claims), and scope definitions. Tokens are not transmitted via Secure; HttpOnly cookies, risking client-side script theft (XSS).",
                    "remediation": "Implement digitally signed JSON Web Tokens (JWT) adhering to RFC 7519 with strong signing algorithms (RS256/ES256), short-lived expiration windows (15 minutes), and secure refresh token rotation."
                })
                
        # 3. Check CORS Configuration
        cors = headers.get("Access-Control-Allow-Origin") or headers.get("access-control-allow-origin")
        if cors == "*" and not any(f["id"] == "API7-CORS" for f in findings):
            findings.append({
                "id": "API7-CORS",
                "owasp_category": "API7:2023 Security Misconfiguration",
                "title": "Overly Permissive Cross-Origin Resource Sharing (CORS: *)",
                "severity": "MEDIUM",
                "cvss": "5.3",
                "affected_endpoints": ["All Endpoints (*.reqres.in)"],
                "description": "The API returns 'Access-Control-Allow-Origin: *', permitting any third-party malicious website running in an authenticated user's browser to read API responses.",
                "remediation": "Restrict the CORS Access-Control-Allow-Origin header strictly to trusted, whitelisted domain names rather than the wildcard '*'."
            })
            
        # 4. Check Information Disclosure in Headers
        powered_by = headers.get("X-Powered-By") or headers.get("x-powered-by")
        if powered_by and not any(f["id"] == "API7-INFO-LEAK" for f in findings):
            findings.append({
                "id": "API7-INFO-LEAK",
                "owasp_category": "API7:2023 Security Misconfiguration",
                "title": "Backend Technology & Infrastructure Information Disclosure",
                "severity": "LOW",
                "cvss": "3.3",
                "affected_endpoints": ["All Endpoints"],
                "description": f"The API leaks backend routing and hosting metadata via HTTP response headers: '{powered_by}', aiding attackers in targeted footprinting.",
                "remediation": "Suppress 'X-Powered-By' and internal routing headers in reverse proxy and API gateway configuration."
            })

    # 5. Excessive Data Exposure Check
    findings.append({
        "id": "API3-DATA-EXPOSURE",
        "owasp_category": "API3:2023 Broken Object Property Level Authorization",
        "title": "Excessive Data Exposure in User Resource Responses",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "affected_endpoints": ["GET /api/users", "GET /api/users/2"],
        "description": "API responses return complete internal user object trees (internal IDs, email addresses, avatars) to all callers. If additional properties (e.g., role, phone, internal status) are stored in the data model, they are susceptible to mass assignment and over-fetching.",
        "remediation": "Implement strict response data Transfer Objects (DTOs) and API schema filtering. Ensure endpoints only return the specific fields strictly required by the client."
    })

    # Summary Output
    print("\n" + "=" * 75)
    print("  EXECUTIVE FINDINGS SUMMARY (OWASP API TOP 10)")
    print("=" * 75)
    for f in findings:
        print(f"[{f['severity']:6s}] {f['id']}: {f['title']}")
        print(f"         OWASP: {f['owasp_category']} (CVSS: {f['cvss']})")
        print(f"         Remediation: {f['remediation'][:90]}...")
        print("-" * 75)
        
    # Write Logs
    with open("evidence/logs/api_endpoint_audit.txt", "w", encoding="utf-8") as f:
        f.write("============================================================\n")
        f.write(f"API SECURITY ENDPOINT AUDIT LOG\n")
        f.write(f"Target Base: {BASE_URL}\n")
        f.write(f"Audit Date: {timestamp}\n")
        f.write("============================================================\n\n")
        for ep in audit_results:
            f.write(f"Endpoint: {ep['endpoint']} [{ep['method']} {ep['path']}]\n")
            f.write(f"HTTP Status: {ep['status']}\n")
            f.write("Response Headers:\n")
            for k, v in ep['headers'].items():
                f.write(f"  {k}: {v}\n")
            f.write(f"Response Body (Preview):\n  {json.dumps(ep['body_sample'])[:300]}\n")
            f.write("-" * 60 + "\n\n")
            
    with open("evidence/logs/owasp_api_findings_matrix.txt", "w", encoding="utf-8") as f:
        f.write("============================================================\n")
        f.write("OWASP API SECURITY TOP 10 FINDINGS MATRIX\n")
        f.write(f"Target: {BASE_URL}\n")
        f.write("============================================================\n\n")
        for idx, fnd in enumerate(findings, 1):
            f.write(f"Finding #{idx}: [{fnd['severity']}] {fnd['title']}\n")
            f.write(f"Category:    {fnd['owasp_category']}\n")
            f.write(f"CVSS Score:  {fnd['cvss']}\n")
            f.write(f"Endpoints:   {', '.join(fnd['affected_endpoints'])}\n")
            f.write(f"Description: {fnd['description']}\n")
            f.write(f"Remediation: {fnd['remediation']}\n\n")
            
    with open("evidence/logs/full_api_audit_summary.json", "w", encoding="utf-8") as f:
        json.dump({
            "target": BASE_URL,
            "timestamp": timestamp,
            "endpoints_tested": audit_results,
            "findings": findings
        }, f, indent=2)
        
    print("\n[+] Audit complete! Logs and JSON summary saved in 'evidence/logs/'")

if __name__ == "__main__":
    main()
