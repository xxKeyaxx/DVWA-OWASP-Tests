# AI Coding Agent Prompt: Test Remember Password Functionality (OTG-AUTHN-005)

## Objective

Create a detailed and comprehensive prompt for an AI coding agent to generate a **Python-based security testing script** that evaluates the **"Remember Password"** or **"Remember Me"** functionality in **DVWA (Damn Vulnerable Web Application)** running on a **localhost XAMPP environment** (`http://localhost/dvwa`). The test must align with **OWASP Testing Guide v4.2** test case **OTG-AUTHN-005: Testing for Remember Password Functionality**.

The script should:
- Analyze how the "Remember Me" feature stores and handles credentials.
- Inspect cookies, local storage (if applicable), and form fields for insecure storage of sensitive data.
- Test for weak token generation, persistence, and revocation mechanisms.
- Generate a professional, **OWASP/OSCP-style HTML report** with findings, risk assessment, and remediation guidance.

The final output must be a standalone, well-documented `.py` script suitable for **educational, lab-based penetration testing** environments.

---

## Prompt for AI Coding Agent

> You are a cybersecurity automation engineer specializing in authentication and session security testing. Your task is to develop a Python script that performs an automated assessment of **OTG-AUTHN-005: Remember Password Functionality** on **DVWA** hosted locally via **XAMPP**.

---

### 🎯 Target Environment

- **Application**: DVWA (Damn Vulnerable Web Application)
- **Base URL**: `http://localhost/dvwa`
- **Login Page**: `http://localhost/dvwa/login.php`
- **Authentication Mechanism**: Session-based (PHPSESSID cookie)
- **"Remember Me" Feature**: Checkbox on login form (if present or modifiable)

> Note: DVWA does not natively implement a "Remember Me" function. The script should simulate or test for insecure implementations by:
> - Checking if credentials are stored in cookies.
> - Testing if a persistent login token is created.
> - Analyzing cookie attributes (Secure, HttpOnly, SameSite).

---

### ✅ Functional Requirements

#### 1. **Authentication Flow Handling**
- Use `requests.Session()` to simulate login with and without "Remember Me" behavior.
- Parse login page with `BeautifulSoup` to extract CSRF tokens (`user_token`) when needed.
- Simulate "Remember Me" by inspecting post-login cookies and headers.

#### 2. **Remember Password Testing Techniques**
Implement the following checks:

##### a) **Cookie Analysis**
- After successful login, inspect all cookies set by the server:
  - Name, value, expiration date
  - Flags: `Secure`, `HttpOnly`, `SameSite`
  - Whether any cookie contains username, password, or predictable tokens

##### b) **Persistent Login Token Detection**
- Check if any long-lived cookie is set (e.g., `remember_me`, `auth_token`, `login_token`)
- Analyze token entropy and predictability (e.g., base64, MD5, sequential values)

##### c) **Token Revocation Testing**
- Log in with "Remember Me" simulated.
- Log out.
- Attempt to access a protected page using the same session/cookie.
- Check if the persistent token is still valid (should be invalidated on logout).

##### d) **Insecure Storage Detection**
- Detect if credentials or tokens are stored in:
  - Cookies without `HttpOnly` or `Secure` flags
  - Plain text or weakly encoded (e.g., base64, hex)
  - URL parameters or localStorage (if JS is involved)

##### e) **Session Fixation Check**
- Reuse a pre-existing session cookie during login.
- Check if the server regenerates the session ID or reuses it.

> All tests must be **non-destructive** and safe for lab use.

#### 3. **Security Assessment Logic**
- Define vulnerabilities if:
  - Credentials or tokens are stored in plain text.
  - Tokens are predictable or static.
  - "Remember Me" tokens are not revoked on logout.
  - Cookies lack `Secure`, `HttpOnly`, or `SameSite` attributes.
  - Session fixation is possible.

---

### 📄 Report Generation Requirements

After testing, generate a **standalone HTML report** named:  
`OTG-AUTHN-005_Report.html`

The report must follow **OSCP-style formatting** and include:

#### 📑 Report Sections
- **Title**: `OTG-AUTHN-005: Testing for Remember Password Functionality`
- **Test Date & Time**
- **Target URL**
- **Test Result**: `Failed` (insecure implementation) or `Passed` (secure or no feature)
- **Vulnerability Description**: Explain risks of insecure "Remember Me" implementations.
- **Impact**: Medium — long-term unauthorized access possible.
- **Findings**:
  - List of cookies and their attributes.
  - Token analysis (entropy, expiration).
  - Logout revocation test result.
  - Session fixation result.
- **Proof of Concept (PoC)**:
  - Example of insecure cookie: `Set-Cookie: remember_token=admin:password; expires=...`
  - cURL command showing persistent access after logout.
- **Remediation**:
  - Use random, high-entropy tokens.
  - Store tokens securely (HttpOnly, Secure, SameSite=Strict).
  - Invalidate tokens on logout and password change.
  - Avoid storing actual credentials.
  - Implement token expiration (e.g., 30 days).
- **References**:
  - [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#remember-me-feature)
  - [OTG-AUTHN-005 - OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authentication_Testing/05-Testing_for_Rember_Password_Functionality)

---

### 🎨 Report Design (OSCP Style)

- **Font**: Monospace (`Courier New`, `Consolas`)
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