# AI Coding Agent Prompt: Test Weak Lock Out Mechanism (OTG-AUTHN-003)

## Objective

Create a detailed and comprehensive prompt for an AI coding agent to generate a **Python-based security testing script** that evaluates the **account lockout mechanism** of **DVWA (Damn Vulnerable Web Application)** running on a **localhost XAMPP environment** (`http://localhost/dvwa`). The test must align with **OWASP Testing Guide v4.2** test case **OTG-AUTHN-003: Testing for Weak Lock Out Mechanism**.

The script should:
- Automatically attempt multiple failed login attempts.
- Analyze whether the application enforces account or IP-based lockout.
- Measure thresholds and lockout duration (if applicable).
- Generate a professional, **OWASP/OSCP-style HTML report** with findings, risk assessment, and remediation guidance.

The final output must be a standalone, well-documented `.py` script suitable for **educational, lab-based penetration testing** environments.

---

## Prompt for AI Coding Agent

> You are a cybersecurity automation engineer specializing in authentication security testing. Your task is to develop a Python script that performs an automated assessment of **OTG-AUTHN-003: Weak Lock Out Mechanism** on **DVWA** hosted locally via **XAMPP**.

---

### 🎯 Target Environment

- **Application**: DVWA (Damn Vulnerable Web Application)
- **Base URL**: `http://localhost/dvwa`
- **Login Page**: `http://localhost/dvwa/login.php`
- **Form Submission**: `POST` to `login.php`
- **Form Fields**:
  - `username`
  - `password`
  - `Login` (submit button)
  - `user_token` (CSRF token — required in Medium/High security levels)

---

### ✅ Functional Requirements

#### 1. **Authentication Flow Handling**
- Use `requests.Session()` to maintain cookies and session state.
- Parse the login page with `BeautifulSoup` to extract the `user_token` CSRF token (if present).
- Handle CSRF tokens dynamically for each request.

#### 2. **Brute-Force Simulation (Controlled)**
- Simulate **failed login attempts** using an invalid password (e.g., `"wrongpass"`) with a **valid username** (e.g., `"admin"`).
- Perform up to **30 consecutive failed login attempts** (configurable).
- Track:
  - Number of attempts before lockout (if any).
  - Response time per request.
  - HTTP status codes and response content (e.g., presence of "too many login attempts", "account locked", etc.).
  - Whether the same account, different accounts, or IP is blocked.

#### 3. **Lockout Detection Logic**
Implement detection for:
- **No lockout**: All attempts succeed in sending requests without restriction.
- **Soft lockout**: Warning messages but no enforced delay/block.
- **Account lockout**: Specific user account is blocked after threshold.
- **IP-based rate limiting**: Delay or block based on source IP.
- **Time-based lockout**: Temporary block (e.g., 15 minutes).
- **Permanent lockout**: Requires admin reset.

> Use response analysis (content, status, timing) and exception handling to infer behavior.

#### 4. **Threshold & Behavior Analysis**
- Record:
  - Threshold (e.g., "Lockout after 5 failed attempts").
  - Duration of lockout (if temporary).
  - Recovery method (e.g., manual unlock, time expiry).
- If no lockout is observed after 30 attempts, conclude: **"No effective lockout mechanism"**.

---

### 📄 Report Generation Requirements

After testing, generate a **standalone HTML report** named:  
`OTG-AUTHN-003_Report.html`

The report must follow **OSCP-style formatting** and include:

#### 📑 Report Sections
- **Title**: `OTG-AUTHN-003: Testing for Weak Lock Out Mechanism`
- **Test Date & Time**
- **Target URL**
- **Test Result**: `Failed` (weak/no lockout) or `Passed` (strong lockout enforced)
- **Vulnerability Description**: Explain risks of weak or missing account lockout.
- **Impact**: Medium — enables credential brute-forcing.
- **Findings**:
  - Number of failed attempts allowed.
  - Observed lockout behavior (or lack thereof).
  - Evidence from responses (e.g., no blocking after 30 attempts).
- **Proof of Concept (PoC)**:
  - cURL command showing multiple failed logins.
  - Python snippet demonstrating automation.
- **Remediation**:
  - Enforce account lockout after 5–10 failed attempts.
  - Implement incremental delays or CAPTCHA.
  - Avoid permanent lockouts without recovery.
  - Log and alert on repeated failures.
- **References**:
  - [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
  - [OTG-AUTHN-003 - OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism)

---

### 🎨 Report Design (OSCP Style)

- **Font**: Monospace (`Courier New`, `Consolas`, or `monospace`)
- **Color Scheme**:
  - Header: Dark blue (`#003366`) with white text
  - Status: Red (`#cc0000`) for "Failed", Green (`#008800`) for "Passed"
- **Layout**:
  - Clean, centered container
  - Section headers with bottom borders
  - Pre-formatted blocks for logs and PoC
- **Styling**: Use **inline CSS only** (no external files)
- **Print-Friendly**: Ensure readability in PDF/print format

---

### 🖨️ Output & Console Logging

- Print real-time progress: