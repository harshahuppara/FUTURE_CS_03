# API Security Testing Evidence & Screenshots Guide

This guide details how to capture evidence screenshots for **Task 3: API Security Risk Analysis** on **ReqRes API (`https://reqres.in`)**.

---

### Option A: Using Postman (Recommended by Future Interns)
1. Download and open [Postman](https://www.postman.com/downloads/).
2. Click **Import** (top-left) and select:
   `Task-3_API-Security/evidence/postman/ReqRes_API_Security_Audit.postman_collection.json`
3. Click on **"01. BOLA Check - Unauthenticated User List"** and click **Send**.
4. Take a screenshot showing the `200 OK` status and the JSON user list returned without an `Authorization` header.
   * Save as: `evidence/screenshots/01_postman_bola_unauthenticated.png`
5. Click on **"03. Authentication - Simulated Login"** and click **Send**.
   * Take a screenshot showing the `"token": "QpwL5tke4Pnpja7X4"` response.
   * Save as: `evidence/screenshots/02_postman_login_token_response.png`

---

### Option B: Using Browser DevTools (If Postman is not installed)
1. Open Google Chrome or Microsoft Edge.
2. Navigate to: `https://reqres.in/api/users?page=1`
3. Press `F12` to open Developer Tools, click the **Network** tab, refresh the page (`F5`), and click on `users?page=1`.
4. Capture the screenshot showing the `200 OK` response status and the JSON data.

---

### Option C: Terminal Scanner Output
1. Open PowerShell in `Task-3_API-Security`.
2. Run:
   ```powershell
   python scripts\api_security_scanner.py
   ```
3. Capture a screenshot of the completed **OWASP API TOP 10 EXECUTIVE FINDINGS SUMMARY**.
   * Save as: `evidence/screenshots/03_api_scanner_terminal_output.png`

---
