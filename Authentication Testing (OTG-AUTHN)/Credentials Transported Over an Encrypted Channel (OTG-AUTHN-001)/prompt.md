# AI Coding Agent Prompt: Test Credentials Transported over an Encrypted Channel (OTG-AUTHN-001)

## Objective

Create a Python script that automatically tests whether credentials are transported over an encrypted channel (e.g., HTTPS) during the login process in **DVWA (Damn Vulnerable Web App)** running on a local XAMPP server (`http://localhost/dvwa`). The script should analyze the login request and determine if sensitive data (username and password) is sent over HTTP (insecure) or HTTPS (secure). Based on the findings, generate a professional, well-structured, OWASP/OSCP-style security assessment report in **HTML format**, styled to resemble official OSCP penetration test reports.

---

## Prompt for AI Coding Agent

> You are a cybersecurity automation assistant specialized in vulnerability assessment and reporting. Your task is to generate a complete Python script that performs the following:

### 1. **Target Environment**
- The target is DVWA running locally via XAMPP at: `http://localhost/dvwa`
- The login page is accessible at: `http://localhost/dvwa/login.php`
- The login form submits credentials via POST to the same endpoint.

### 2. **Functionality Requirements**
- Use `requests` and `BeautifulSoup` (or similar) to:
  - Fetch the login page.
  - Parse the login form to extract hidden fields (e.g., CSRF tokens if present).
  - Simulate a login attempt with dummy credentials (e.g., `admin` / `password`).
  - Analyze the **request scheme** (HTTP vs HTTPS) used during form submission.
  - Check if the request is sent over an unencrypted channel (HTTP).
  - Detect presence of SSL/TLS (HTTPS) — if the site supports HTTPS, check if login redirects or uses it by default.
- If the login request is made over **HTTP**, flag it as a finding.
- If the server supports HTTPS but does not enforce it, note that as a recommendation.

### 3. **Report Generation**
- After analysis, generate a detailed **HTML report** with the following sections:
  - **Title**: "OWASP Testing Guide - OTG-AUTHN-001: Credentials Transported over an Encrypted Channel"
  - **Test Date**: Current date and time
  - **Target URL**: `http://localhost/dvwa`
  - **Test Result**: "Failed" (if HTTP is used), "Passed" (if HTTPS enforced)
  - **Vulnerability Description**: Explain the risk of transmitting credentials over unencrypted channels.
  - **Impact**: Medium to High — potential for credential interception via MITM.
  - **Remediation**: Enforce HTTPS via HSTS, redirect HTTP to HTTPS, use TLS 1.2+.
  - **Proof of Concept**: Include a formatted cURL command or request details showing the insecure transmission.
  - **References**:
    - [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
    - [OTG-AUTHN-001](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authentication_Testing/01-Testing_for_Credentials_Transported_over_an_Encrypted_Channel)

### 4. **Report Styling (OSCP Style)**
- Design the HTML report with a clean, professional look:
  - Monospace font (e.g., `Courier New`, `Consolas`)
  - Dark blue header with white text
  - Section dividers with lines or subtle borders
  - Code blocks in gray with black text
  - Use inline CSS (no external files) for portability
  - Include a simple logo or "OSCP-Style Report" badge
  - Ensure mobile readability and print-friendliness

### 5. **Output**
- Save the HTML report as: `OTG-AUTHN-001_Report.html`
- Print summary to console: