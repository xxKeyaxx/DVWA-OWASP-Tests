# AI Coding Agent Prompt: Test Weak Password Policy (OTG-AUTHN-007)

## Objective

Create a detailed and comprehensive prompt for an AI coding agent to generate a **Python-based security testing script** that evaluates the **password policy enforcement** in **DVWA (Damn Vulnerable Web Application)** running on a **localhost XAMPP environment** (`http://localhost/dvwa`). The test must align with **OWASP Testing Guide v4.2** test case **OTG-AUTHN-007: Testing for Weak Password Policy**.

The script should:
- Analyze the application's password requirements during registration or password change.
- Attempt to set weak passwords (e.g., short, common, non-complex).
- Check for enforcement of length, complexity, history, and expiration rules.
- Generate a professional, **OWASP/OSCP-style HTML report** with findings, risk assessment, and remediation guidance.

The final output must be a standalone, well-documented `.py` script suitable for **educational, lab-based penetration testing** environments.

---

## Prompt for AI Coding Agent

> You are a cybersecurity automation engineer specializing in authentication and identity security testing. Your task is to develop a Python script that performs an automated assessment of **OTG-AUTHN-007: Weak Password Policy** on **DVWA** hosted locally via **XAMPP**.

---

### 🎯 Target Environment

- **Application**: DVWA (Damn Vulnerable Web Application)
- **Base URL**: `http://localhost/dvwa`
- **Password Change Page**: `http://localhost/dvwa/security.php` (to set security level) and password change functionality
- **Password Change Endpoint**: Typically via `security.php` or user profile (simulate if not directly available)
- **Authentication Mechanism**: Session-based (PHPSESSID cookie)
- **Default Credentials**: `admin:password`

> Note: DVWA does not have a native user registration or password change form. The script should:
> - Log in as admin.
> - Attempt to change password to weak values via the security page or simulate the logic.
> - Analyze whether weak passwords are accepted.

---

### ✅ Functional Requirements

#### 1. **Authentication Flow Handling**
- Use `requests.Session()` to maintain login state.
- Parse login and security pages with `BeautifulSoup` to extract CSRF tokens (`user_token`).
- Log in with default credentials.

#### 2. **Password Policy Testing Techniques**
Implement the following tests:

##### a) **Minimum Length Enforcement**
- Attempt to set passwords of varying lengths:
  - 1 character
  - 4 characters
  - 8 characters
- Check if short passwords are accepted.

##### b) **Complexity Requirements**
Test passwords lacking:
- Uppercase letters (e.g., `password123`)
- Lowercase letters (e.g., `PASSWORD123`)
- Numbers (e.g., `Password`)
- Special characters (e.g., `Password123`)

##### c) **Common/Weak Passwords**
Test with known weak passwords:
- `password`
- `123456`
- `admin`
- `letmein`
- `welcome`

##### d) **Password Reuse**
- Attempt to reuse the current password (if applicable).
- Check if password history is enforced.

##### e) **Password Expiration**
- Check page or response for indicators of password expiration policies.
- Look for messages like "change password every 90 days".

##### f) **Feedback Analysis**
- Analyze error messages for password policy hints.
- Check if the application reveals specific requirements (good), or allows weak passwords (bad).

> All tests must be **non-destructive** — do not permanently change the admin password unless necessary, and restore it afterward if possible.

#### 3. **Security Assessment Logic**
- Define a **weak password policy** if:
  - Passwords < 8 characters are accepted.
  - No complexity requirements (uppercase, lowercase, number, special char).
  - Common passwords are accepted.
  - No password history or expiration.
- Flag each missing control.

---

### 📄 Report Generation Requirements

After testing, generate a **standalone HTML report** named:  
`OTG-AUTHN-007_Report.html`

The report must follow **OSCP-style formatting** and include:

#### 📑 Report Sections
- **Title**: `OTG-AUTHN-007: Testing for Weak Password Policy`
- **Test Date & Time**
- **Target URL**
- **Test Result**: `Failed` (weak policy) or `Passed` (strong policy enforced)
- **Vulnerability Description**: Explain risks of weak password policies leading to brute-force, guessing, or credential stuffing.
- **Impact**: Medium — increases likelihood of account compromise.
- **Findings**:
  - Summary of which password rules are enforced or missing.
  - Table of test attempts and outcomes.
  - Screenshot-like text of error messages or success indicators.
- **Proof of Concept (PoC)**:
  - Example: "Password '123' accepted for user 'admin'"
  - cURL command showing password change with weak password.
- **Remediation**:
  - Enforce minimum 8-character passwords.
  - Require 3 of 4: uppercase, lowercase, number, special character.
  - Block common passwords using deny lists.
  - Implement password history (last 4–5 passwords).
  - Enforce rotation every 60–90 days.
- **References**:
  - [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#password-requirements)
  - [NIST 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
  - [OTG-AUTHN-007 - OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authentication_Testing/07-Testing_for_Weak_Password_Policy)

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
  - Table for password test results
- **Styling**: Use **inline CSS only** (no external files)
- **Print-Friendly**: Ensure readability in PDF/print format

---

### 🖨️ Output & Console Logging

- Print real-time progress: