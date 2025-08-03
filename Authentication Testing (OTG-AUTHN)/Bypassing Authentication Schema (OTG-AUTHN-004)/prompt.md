# AI Coding Agent Prompt: Test Bypassing Authentication Schema (OTG-AUTHN-004)

## Objective

Create a detailed and comprehensive prompt for an AI coding agent to generate a **Python-based security testing script** that evaluates the **authentication bypass vulnerabilities** in **DVWA (Damn Vulnerable Web Application)** running on a **localhost XAMPP environment** (`http://localhost/dvwa`). The test must align with **OWASP Testing Guide v4.2** test case **OTG-AUTHN-004: Testing for Bypassing Authentication Schema**.

The script should:
- Attempt to access authenticated pages without logging in.
- Test common authentication bypass techniques (e.g., direct URL access, parameter tampering, path traversal).
- Analyze access control enforcement on protected resources.
- Generate a professional, **OWASP/OSCP-style HTML report** with findings, risk assessment, and remediation guidance.

The final output must be a standalone, well-documented `.py` script suitable for **educational, lab-based penetration testing** environments.

---

## Prompt for AI Coding Agent

> You are a cybersecurity automation engineer specializing in authentication and access control testing. Your task is to develop a Python script that performs an automated assessment of **OTG-AUTHN-004: Bypassing Authentication Schema** on **DVWA** hosted locally via **XAMPP**.

---

### 🎯 Target Environment

- **Application**: DVWA (Damn Vulnerable Web Application)
- **Base URL**: `http://localhost/dvwa`
- **Login Page**: `http://localhost/dvwa/login.php`
- **Protected Pages**:
  - `http://localhost/dvwa/index.php`
  - `http://localhost/dvwa/vulnerabilities/brute/`
  - `http://localhost/dvwa/vulnerabilities/sqli/`
  - `http://localhost/dvwa/security/`
  - `http://localhost/dvwa/phpinfo.php`
- **Authentication Mechanism**: Session-based (PHPSESSID cookie)

---

### ✅ Functional Requirements

#### 1. **Authentication Flow Handling**
- Use `requests.Session()` to manage cookies and simulate unauthenticated and authenticated sessions.
- Parse login page with `BeautifulSoup` to extract CSRF tokens (`user_token`) when needed.

#### 2. **Authentication Bypass Techniques to Test**
Implement the following bypass methods:

##### a) **Direct Access to Authenticated Pages**
- Attempt to access `index.php` and other protected pages **without logging in**.
- Check if server returns 200 OK or redirects to login.

##### b) **URL Parameter Tampering**
- Test if modifying parameters (e.g., `?login=true`, `?auth=1`) grants access.
- Try common bypass strings in GET/POST:
  - `?admin=1`
  - `?access=granted`
  - `?role=admin`

##### c) **Path Traversal / Alternate Entry Points**
- Attempt to access backend scripts directly (e.g., `http://localhost/dvwa/includes/autologin.php` if exists).
- Test for misconfigured `.htaccess` or exposed config files.

##### d) **Cookie Manipulation (Simulated)**
- Attempt to set forged session cookies (e.g., `PHPSESSID=admin`, `user=admin`).
- Test if invalid or common session values grant access.

##### e) **HTTP Method Tampering**
- Send `GET` requests to POST-only endpoints.
- Use `HEAD`, `OPTIONS` to probe for information leakage.

> Note: All tests must be **non-destructive** and safe for lab use.

#### 3. **Access Control Analysis**
For each test:
- Record:
  - Request method and URL
  - Parameters or headers used
  - HTTP status code
  - Response length
  - Presence of login form or "access denied" messages
  - Successful access indicators (e.g., "Welcome", "DVWA", "Security Level")

#### 4. **Detection Logic**
- Define a successful bypass as:
  - HTTP 200 response
  - Presence of authenticated content
  - Absence of login form or redirect
- Log all attempts and outcomes.

---

### 📄 Report Generation Requirements

After testing, generate a **standalone HTML report** named:  
`OTG-AUTHN-004_Report.html`

The report must follow **OSCP-style formatting** and include:

#### 📑 Report Sections
- **Title**: `OTG-AUTHN-004: Testing for Bypassing Authentication Schema`
- **Test Date & Time**
- **Target URL**
- **Test Result**: `Failed` (bypass possible) or `Passed` (no bypass found)
- **Vulnerability Description**: Explain how weak authentication checks allow unauthorized access.
- **Impact**: High — full system compromise possible.
- **Findings**:
  - List of tested bypass methods.
  - Highlight any successful technique.
  - Include response snippets or status codes.
- **Proof of Concept (PoC)**:
  - cURL commands showing successful bypass.
  - Example: `curl -v "http://localhost/dvwa/index.php?admin=1"`
- **Remediation**:
  - Enforce server-side authentication checks.
  - Validate session integrity before granting access.
  - Avoid relying on client-side parameters.
  - Implement proper access control on all endpoints.
- **References**:
  - [OWASP Authentication Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema)
  - [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)

---

### 🎨 Report Design (OSCP Style)

- **Font**: Monospace (`Courier New`, `Consolas`)
- **Color Scheme**:
  - Header: Dark blue (`#003366`) with white text
  - Status: Red (`#cc0000`) for "Failed", Green (`#008800`) for "Passed"
- **Layout**:
  - Clean, centered container
  - Section headers with bottom borders
  - Pre-formatted blocks for PoC and logs
- **Styling**: Use **inline CSS only** (no external files)
- **Print-Friendly**: Ensure readability in PDF/print format

---

### 🖨️ Output & Console Logging

- Print real-time progress: