# AI Coding Agent Prompt: Test Weak Password Change or Reset Functionalities (OTG-AUTHN-009)

## Objective

Create a detailed and comprehensive prompt for an AI coding agent to generate a **Python-based security testing script** that evaluates **Password Change and Reset Functionalities** in **DVWA (Damn Vulnerable Web Application)** running on a **localhost XAMPP environment** (`http://localhost/dvwa`). The test must align with **OWASP Testing Guide v4.2** test case **OTG-AUTHN-009: Testing for Weak Password Change or Reset Functionalities**.

The script should:
- Analyze the password change functionality in DVWA.
- Test for insecure implementation such as missing old password verification, CSRF vulnerability, and weak token generation.
- Evaluate whether users can change passwords without proper authentication or authorization.
- Generate a professional, **OWASP/OSCP-style HTML report** with findings, risk assessment, and remediation guidance.

The final output must be a standalone, well-documented `.py` script suitable for **educational, lab-based penetration testing** environments.

---

## Prompt for AI Coding Agent

> You are a cybersecurity automation engineer specializing in authentication and session security testing. Your task is to develop a Python script that performs an automated assessment of **OTG-AUTHN-009: Weak Password Change or Reset Functionalities** on **DVWA** hosted locally via **XAMPP**.

---

### 🎯 Target Environment

- **Application**: DVWA (Damn Vulnerable Web Application)
- **Base URL**: `http://localhost/dvwa`
- **Relevant Pages**:
  - `http://localhost/dvwa/login.php` – Login
  - `http://localhost/dvwa/vulnerabilities/csrf/` – Password change form
- **Authentication Mechanism**: Session-based (PHPSESSID cookie)
- **Default Credentials**: `admin:password`

> Note: DVWA does **not** have a password reset function (no "Forgot Password?" page), but it **does** have a password change functionality accessible via the CSRF vulnerability page. The script must:
> - Focus only on the **password change** functionality.
> - Explicitly state that **password reset** is not implemented in DVWA.
> - Test whether the change function requires the old password.
> - Test for **CSRF vulnerability** in the password change process.
> - Check if users can change other users' passwords (if applicable).

---

### ✅ Functional Requirements

#### 1. **Authentication Flow Handling**
- Use `requests.Session()` to simulate login and maintain session state.
- Parse login and CSRF pages with `BeautifulSoup` to extract CSRF tokens (`user_token`).
- Log in with default credentials (`admin:password`).

#### 2. **Password Change Functionality Testing**
Implement the following tests:

##### a) **Old Password Requirement**
- Attempt to change the password **without providing the old password**.
- Determine if the application enforces old password verification.

##### b) **CSRF Vulnerability Testing**
- Access the password change form without logging in.
- Submit a password change request **from a different session or user context**.
- Check if the application validates session integrity or tokens.
- If the password change succeeds without proper session context, it's **CSRF-vulnerable**.

##### c) **Cross-User Password Change (if possible)**
- Attempt to change another user's password (not applicable in DVWA, but test logic should acknowledge this).
- Check for user ID or username parameters that could be manipulated.

##### d) **Token and Session Validation**
- Check if the application regenerates the session ID after password change.
- Verify if the `user_token` CSRF protection is properly validated server-side.

##### e) **Response Analysis**
- Look for indicators of success: `"Password Changed."`
- Look for error messages indicating old password requirement or access control.

> All tests must be **non-destructive** — change the password only temporarily and restore it afterward.

---

### 📄 Report Generation Requirements

After testing, generate a **standalone HTML report** named:  
`OTG-AUTHN-009_Report.html`

The report must follow **OSCP-style formatting** and include:

#### 📑 Report Sections
- **Title**: `OTG-AUTHN-009: Testing for Weak Password Change or Reset Functionalities`
- **Test Date & Time**
- **Target URL**
- **Test Result**: `Failed` (insecure implementation) or `Passed` (secure)
- **Vulnerability Description**: Explain risks of weak password change mechanisms allowing unauthorized changes or CSRF attacks.
- **Impact**: High — can lead to full account takeover.
- **Findings**:
  - Whether old password is required.
  - Whether CSRF protection is effective.
  - Whether password change can be forced without user interaction.
  - Summary of test outcomes.
- **Proof of Concept (PoC)**:
  - cURL command showing password change without old password.
  - Example of CSRF exploit:  
    `<img src="http://localhost/dvwa/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change" />`
- **Remediation**:
  - Always require the old password for changes.
  - Implement CSRF tokens and validate them server-side.
  - Regenerate session IDs after password change.
  - Do not expose password change functionality without authentication.
- **References**:
  - [OWASP WSTG - OTG-AUTHN-009](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionalities)
  - [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#password-requirements)
  - [NIST 800-63B - Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

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
  - Table for test results
- **Styling**: Use **inline CSS only** (no external files)
- **Print-Friendly**: Ensure readability in PDF/print format

---

### 🖨️ Output & Console Logging

- Print real-time progress: