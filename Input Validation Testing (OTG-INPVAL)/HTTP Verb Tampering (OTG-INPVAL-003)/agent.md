# AI Coding Agent Prompt: HTTP Verb Tampering Testing Script for DVWA (OTG-INPVAL-003)

## 📌 Overview
Create a Python-based automated testing script that identifies and validates **HTTP Verb Tampering vulnerabilities** (aligned with **OWASP OTG-INPVAL-003**) on **Damn Vulnerable Web Application (DVWA)** running locally via **XAMPP on `localhost`**. Upon completion, the script must generate a **professional, well-designed HTML report** in the style of **OWASP** and **OSCP penetration testing reports**.

---

## 🎯 Target Environment
- **Application**: DVWA (Damn Vulnerable Web Application)
- **Deployment**: XAMPP on `localhost`
- **URL**: `http://localhost/dvwa/`
- **Test Modules**: 
  - Login page (`/dvwa/login.php`)
  - Command Execution (`/dvwa/vulnerabilities/exec/`)
  - XSS (Reflected) (`/dvwa/vulnerabilities/xss_r/`)
  - Any form-based input pages
- **Authentication Required**: Yes (script must handle login and session)
- **Security Level**: Low (assumed for testing)

---

## 🛠️ Script Requirements

### 1. **Core Functionality**
- **Authentication Automation**:
  - Log in to DVWA using provided credentials (e.g., `admin:password`).
  - Handle CSRF tokens (`user_token`) and maintain session cookies.
- **HTTP Verb Tampering Testing**:
  - Identify form endpoints that expect `POST` requests.
  - Attempt to access these endpoints using alternative HTTP methods:
    - `GET`
    - `PUT`
    - `DELETE`
    - `OPTIONS`
    - `HEAD`
    - `PATCH`
    - `TRACE`
  - For each method, record:
    - Response status code
    - Response length
    - Whether authentication was bypassed
    - Whether sensitive functionality was accessible
- **Vulnerability Detection**:
  - Flag endpoints that:
    - Allow `GET` instead of `POST` for form submission
    - Permit `PUT`/`DELETE` for data modification
    - Return sensitive data via `OPTIONS`
    - Execute actions without CSRF protection when using alternate verbs
- **Session Handling**:
  - Maintain authenticated session throughout the test.
  - Re-authenticate if session expires.

### 2. **Reporting**
- Generate a **single, self-contained HTML report** (`http_verb_tampering_report.html`) with:
  - **Title**: "HTTP Verb Tampering Assessment – DVWA (OTG-INPVAL-003)"
  - **Executive Summary**: Brief overview of findings and risk.
  - **Test Details**:
    - Target URL
    - Vulnerability Type: HTTP Verb Tampering
    - OWASP Test ID: OTG-INPVAL-003
    - Risk Level: Medium to High (depending on impact)
    - Date & Time of Test
  - **Methodology**:
    - Steps taken (login → endpoint discovery → verb tampering → analysis)
    - Tools used (script name, Python modules)
  - **Findings**:
    - Table of tested endpoints and methods
    - For each vulnerable endpoint:
      - Original expected method
      - Allowed methods
      - Impact (e.g., authentication bypass, data exposure)
      - Evidence (response snippets or status codes)
    - Proof of Concept (PoC) code
  - **Remediation Recommendations**:
    - Enforce strict HTTP method validation
    - Use CSRF tokens for state-changing operations
    - Implement proper access controls
    - Disable unnecessary HTTP methods
  - **References**:
    - OWASP Testing Guide: OTG-INPVAL-003
    - CWE-444: Inconsistent Interpretation of HTTP Requests
    - NIST SP 800-115

### 3. **HTML Report Design**
- **Style**: Clean, professional, OSCP/OWASP-like
- **Colors**: Dark blue, white, gray (security-themed)
- **Fonts**: Monospace for code, sans-serif for body
- **Structure**:
  - Header with logo (optional placeholder)
  - Navigation sidebar or sections
  - Collapsible technical details
  - Responsive layout
- Include embedded CSS (no external files)
- Ensure **all HTML output is properly escaped** to prevent rendering issues

### 4. **Technical Specifications**
- **Language**: Python 3.7+
- **Libraries**:
  - `requests` – for HTTP handling
  - `BeautifulSoup4` – for parsing HTML
  - `argparse` – for CLI arguments
  - `datetime`, `os`, `json` – for logging and data
- **Command-Line Arguments**:
  - `--url`: Target URL (default: `http://localhost/dvwa`)
  - `--username`: DVWA username (default: `admin`)
  - `--password`: DVWA password (default: `password`)
  - `--output`: Output report path (default: `reports/http_verb_report.html`)
  - `--timeout`: Request timeout (default: 10 seconds)
- **Logging**:
  - Print progress to console
  - Save raw responses for debugging (optional)

---

## 🧾 Expected Output
- A Python script: `dvwa_http_verb_tampering.py`
- Generated HTML report: `http_verb_tampering_report.html` (or as specified)
- Report includes:
  - ✅ Vulnerability confirmed
  - ✅ Endpoints tested
  - ✅ Methods allowed
  - ✅ Risk assessment
  - ✅ Remediation advice
  - ✅ Professional presentation

---

## 📝 Example Usage
```bash
python dvwa_http_verb_tampering.py \
  --url http://localhost/dvwa \
  --username admin \
  --password password \
  --output reports/http_verb_tampering_$(date +%F).html